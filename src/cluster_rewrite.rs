//! Rewriting of upstream topology replies so cluster-aware clients connect
//! back through the local proxy listeners.
//!
//! `CLUSTER SLOTS` is synthesized locally from discovery (see
//! [`crate::cluster`]). Clients that discover the cluster with
//! `CLUSTER SHARDS` (Relay, redis-py, Lettuce) or `CLUSTER NODES`
//! (hiredis-cluster, ioredis) receive the upstream reply with every node
//! address that maps to a local listener rewritten to it. Nodes without a
//! local listener are removed from the reply rather
//! than leaked as upstream addresses that would let the client bypass the
//! proxy.

use tracing::{debug, warn};

use crate::cli::TcpEndpoint;
use crate::cluster::ClusterRedirectionMap;
use crate::resp::Frame;

pub fn is_cluster_shards(argv: &[String]) -> bool {
    is_cluster_subcommand(argv, "SHARDS")
}

pub fn is_cluster_nodes(argv: &[String]) -> bool {
    is_cluster_subcommand(argv, "NODES")
}

fn is_cluster_subcommand(argv: &[String], subcommand: &str) -> bool {
    argv.len() == 2
        && argv[0].eq_ignore_ascii_case("CLUSTER")
        && argv[1].eq_ignore_ascii_case(subcommand)
}

/// Rewrite a `CLUSTER SHARDS` reply, in either its RESP2 (flat key/value
/// arrays) or RESP3 (maps) shape. A reply that is not an array of shards is
/// returned unchanged so an upstream error still reaches the client.
pub fn rewrite_cluster_shards(
    reply: &Frame,
    map: &ClusterRedirectionMap,
) -> Frame {
    let Frame::Array(Some(shards)) = reply else {
        return reply.clone();
    };

    Frame::Array(Some(
        shards
            .iter()
            .filter_map(|shard| rewrite_shard(shard, map))
            .collect(),
    ))
}

fn rewrite_shard(shard: &Frame, map: &ClusterRedirectionMap) -> Option<Frame> {
    let Some(mut entries) = MapEntries::parse(shard) else {
        warn!("dropping CLUSTER SHARDS shard with an unrecognized shape");
        return None;
    };

    let mut has_nodes = false;
    for (key, value) in &mut entries.pairs {
        if !key_is(key, "nodes") {
            continue;
        }
        let Frame::Array(Some(nodes)) = value else {
            continue;
        };
        let kept = nodes
            .iter()
            .filter_map(|node| rewrite_shard_node(node, map))
            .collect::<Vec<_>>();
        has_nodes = !kept.is_empty();
        *value = Frame::Array(Some(kept));
    }

    if has_nodes {
        Some(entries.into_frame())
    } else {
        debug!("dropping CLUSTER SHARDS shard without a locally mapped node");
        None
    }
}

fn rewrite_shard_node(
    node: &Frame,
    map: &ClusterRedirectionMap,
) -> Option<Frame> {
    let mut entries = MapEntries::parse(node)?;
    let id = entries.string("id");
    let port = entries.integer("port")?;
    let host = entries
        .string("ip")
        .or_else(|| entries.string("endpoint"))
        .or_else(|| entries.string("hostname"))
        .unwrap_or_default();

    let Some(local) = local_endpoint(map, id.as_deref(), &host, port) else {
        debug!(
            host,
            port, "dropping CLUSTER SHARDS node without a local listener"
        );
        return None;
    };

    for (key, value) in &mut entries.pairs {
        if key_is(key, "ip")
            || key_is(key, "endpoint")
            || key_is(key, "hostname")
        {
            *value = Frame::BulkString(Some(local.host.clone().into_bytes()));
        } else if key_is(key, "port") {
            *value = Frame::Integer(i64::from(local.port));
        }
    }

    Some(entries.into_frame())
}

/// Rewrite a `CLUSTER NODES` reply. Each line names a node as
/// `<id> <ip:port@cport[,hostname[,aux=value]...]> <flags> ...`; the address
/// is mapped to the local listener, the announced hostname is blanked so a
/// hostname-preferring client cannot use it to reach upstream, and lines
/// for nodes without a local listener are removed.
pub fn rewrite_cluster_nodes(
    reply: &Frame,
    map: &ClusterRedirectionMap,
) -> Frame {
    let (text, verbatim) = match reply {
        Frame::BulkString(Some(bytes)) => (bytes, false),
        Frame::VerbatimString(bytes) => (bytes, true),
        _ => return reply.clone(),
    };

    let mut rewritten = String::with_capacity(text.len());
    for line in String::from_utf8_lossy(text).lines() {
        match rewrite_nodes_line(line, map) {
            Some(line) => {
                rewritten.push_str(&line);
                rewritten.push('\n');
            }
            None => {
                debug!(
                    line,
                    "dropping CLUSTER NODES line without a local listener"
                );
            }
        }
    }

    if verbatim {
        Frame::VerbatimString(rewritten.into_bytes())
    } else {
        Frame::BulkString(Some(rewritten.into_bytes()))
    }
}

fn rewrite_nodes_line(
    line: &str,
    map: &ClusterRedirectionMap,
) -> Option<String> {
    let mut fields = line.splitn(3, ' ');
    let id = fields.next()?;
    let address = fields.next()?;
    let rest = fields.next().unwrap_or_default();

    let (socket, bus) = address
        .split_once('@')
        .map_or((address, None), |(socket, bus)| (socket, Some(bus)));
    let local = map.rewrite_node(Some(id.as_bytes()), socket)?;

    let mut rewritten = local;
    if let Some(bus) = bus {
        rewritten.push('@');
        let mut extra = bus.split(',');
        rewritten.push_str(extra.next().unwrap_or_default());
        for (index, field) in extra.enumerate() {
            rewritten.push(',');
            if index > 0 {
                rewritten.push_str(field);
            }
        }
    }

    Some(if rest.is_empty() {
        format!("{id} {rewritten}")
    } else {
        format!("{id} {rewritten} {rest}")
    })
}

fn local_endpoint(
    map: &ClusterRedirectionMap,
    node_id: Option<&str>,
    host: &str,
    port: i64,
) -> Option<TcpEndpoint> {
    let port = u16::try_from(port).ok()?;
    let upstream = if host.is_empty() || host == "?" {
        format!(":{port}")
    } else {
        TcpEndpoint {
            host: host.to_owned(),
            port,
        }
        .connect_addr()
    };
    map.rewrite_node(node_id.map(str::as_bytes), &upstream)?
        .parse()
        .ok()
}

/// Key/value pairs of a RESP3 map or of the flat RESP2 array Redis uses in
/// its place, remembering which shape to rebuild.
struct MapEntries {
    flat: bool,
    pairs: Vec<(Frame, Frame)>,
}

impl MapEntries {
    fn parse(frame: &Frame) -> Option<Self> {
        match frame {
            Frame::Map(pairs) => Some(Self {
                flat: false,
                pairs: pairs.clone(),
            }),
            Frame::Array(Some(items)) if items.len().is_multiple_of(2) => {
                let pairs = items
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|[key, value]| (key.clone(), value.clone()))
                    .collect::<Vec<_>>();
                if pairs.iter().all(|(key, _)| string_of(key).is_some()) {
                    Some(Self { flat: true, pairs })
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn into_frame(self) -> Frame {
        if self.flat {
            Frame::Array(Some(
                self.pairs
                    .into_iter()
                    .flat_map(|(key, value)| [key, value])
                    .collect(),
            ))
        } else {
            Frame::Map(self.pairs)
        }
    }

    fn value(&self, name: &str) -> Option<&Frame> {
        self.pairs
            .iter()
            .find(|(key, _)| key_is(key, name))
            .map(|(_, value)| value)
    }

    fn string(&self, name: &str) -> Option<String> {
        let value = string_of(self.value(name)?)?;
        (!value.is_empty()).then_some(value)
    }

    fn integer(&self, name: &str) -> Option<i64> {
        match self.value(name)? {
            Frame::Integer(value) => Some(*value),
            other => string_of(other)?.parse().ok(),
        }
    }
}

fn key_is(key: &Frame, name: &str) -> bool {
    string_of(key).is_some_and(|key| key.eq_ignore_ascii_case(name))
}

fn string_of(frame: &Frame) -> Option<String> {
    match frame {
        Frame::BulkString(Some(bytes)) | Frame::VerbatimString(bytes) => {
            Some(String::from_utf8_lossy(bytes).into_owned())
        }
        Frame::SimpleString(value) => Some(value.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resp::parse_frame;

    fn map() -> ClusterRedirectionMap {
        ClusterRedirectionMap::from_mappings([
            (
                TcpEndpoint {
                    host: "127.0.0.1".to_owned(),
                    port: 7100,
                },
                "127.0.0.1:7200".to_owned(),
            ),
            (
                TcpEndpoint {
                    host: "127.0.0.1".to_owned(),
                    port: 7101,
                },
                "127.0.0.1:7201".to_owned(),
            ),
        ])
    }

    fn bulk(value: &str) -> Frame {
        Frame::BulkString(Some(value.as_bytes().to_vec()))
    }

    fn resp3_node(id: &str, port: i64, role: &str) -> Frame {
        Frame::Map(vec![
            (bulk("id"), bulk(id)),
            (bulk("port"), Frame::Integer(port)),
            (bulk("ip"), bulk("127.0.0.1")),
            (bulk("endpoint"), bulk("127.0.0.1")),
            (bulk("role"), bulk(role)),
            (bulk("replication-offset"), Frame::Integer(1)),
            (bulk("health"), bulk("online")),
        ])
    }

    fn resp3_shard(nodes: Vec<Frame>) -> Frame {
        Frame::Map(vec![
            (
                bulk("slots"),
                Frame::Array(Some(vec![
                    Frame::Integer(0),
                    Frame::Integer(5460),
                ])),
            ),
            (bulk("nodes"), Frame::Array(Some(nodes))),
        ])
    }

    #[test]
    fn resp3_shards_map_primaries_to_local_listeners_and_drop_replicas() {
        let reply = Frame::Array(Some(vec![resp3_shard(vec![
            resp3_node("primary", 7100, "master"),
            resp3_node("replica", 7300, "replica"),
        ])]));

        let rewritten = rewrite_cluster_shards(&reply, &map());

        let Frame::Array(Some(shards)) = rewritten else {
            panic!("expected shard array");
        };
        assert_eq!(shards.len(), 1);
        let Frame::Map(shard) = &shards[0] else {
            panic!("expected shard map");
        };
        assert_eq!(shard[0].0, bulk("slots"));
        let Frame::Array(Some(nodes)) = &shard[1].1 else {
            panic!("expected node array");
        };
        assert_eq!(nodes.len(), 1);
        let Frame::Map(node) = &nodes[0] else {
            panic!("expected node map");
        };
        assert_eq!(node[0], (bulk("id"), bulk("primary")));
        assert_eq!(node[1], (bulk("port"), Frame::Integer(7200)));
        assert_eq!(node[2], (bulk("ip"), bulk("127.0.0.1")));
        assert_eq!(node[3], (bulk("endpoint"), bulk("127.0.0.1")));
        assert_eq!(node[4], (bulk("role"), bulk("master")));
        assert_eq!(node.len(), 7);
    }

    #[test]
    fn resp2_shards_keep_their_flat_shape() {
        let reply = parse_frame(
            b"*1\r\n*4\r\n$5\r\nslots\r\n*2\r\n:0\r\n:16383\r\n$5\r\nnodes\r\n*1\r\n*6\r\n$2\r\nid\r\n$1\r\na\r\n$4\r\nport\r\n:7101\r\n$2\r\nip\r\n$9\r\n127.0.0.1\r\n",
        )
        .unwrap();

        let rewritten = rewrite_cluster_shards(&reply, &map());

        assert_eq!(
            rewritten.encode(),
            b"*1\r\n*4\r\n$5\r\nslots\r\n*2\r\n:0\r\n:16383\r\n$5\r\nnodes\r\n*1\r\n*6\r\n$2\r\nid\r\n$1\r\na\r\n$4\r\nport\r\n:7201\r\n$2\r\nip\r\n$9\r\n127.0.0.1\r\n"
        );
    }

    #[test]
    fn shards_without_a_mapped_node_are_dropped() {
        let reply = Frame::Array(Some(vec![
            resp3_shard(vec![resp3_node("primary", 7100, "master")]),
            resp3_shard(vec![resp3_node("elsewhere", 7999, "master")]),
        ]));

        let rewritten = rewrite_cluster_shards(&reply, &map());

        let Frame::Array(Some(shards)) = rewritten else {
            panic!("expected shard array");
        };
        assert_eq!(shards.len(), 1);
    }

    #[test]
    fn unknown_ip_falls_back_to_a_unique_upstream_port() {
        let node = Frame::Map(vec![
            (bulk("id"), bulk("a")),
            (bulk("port"), Frame::Integer(7101)),
            (bulk("ip"), bulk("?")),
            (bulk("endpoint"), bulk("?")),
        ]);
        let reply = Frame::Array(Some(vec![resp3_shard(vec![node])]));

        let rewritten = rewrite_cluster_shards(&reply, &map());

        let encoded = rewritten.encode();
        assert!(encoded.windows(7).any(|window| window == b":7201\r\n"));
        assert!(!encoded.windows(6).any(|window| window == b"$1\r\n?\r"));
    }

    #[test]
    fn non_array_shards_replies_pass_through() {
        let reply = Frame::SimpleError(
            "ERR This instance has cluster support disabled".to_owned(),
        );

        assert_eq!(rewrite_cluster_shards(&reply, &map()), reply);
    }

    #[test]
    fn cluster_nodes_lines_are_rewritten_and_replicas_removed() {
        let text = "\
a1 127.0.0.1:7100@17100,,shard-id=s1 myself,master - 0 0 1 connected 0-5460\n\
b2 127.0.0.1:7101@17101,upstream.example master - 0 1 2 connected 5461-16383\n\
c3 127.0.0.1:7300@17300 slave a1 0 1 1 connected\n";
        let reply = Frame::BulkString(Some(text.as_bytes().to_vec()));

        let rewritten = rewrite_cluster_nodes(&reply, &map());

        let Frame::BulkString(Some(bytes)) = rewritten else {
            panic!("expected bulk string");
        };
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "a1 127.0.0.1:7200@17100,,shard-id=s1 myself,master - 0 0 1 connected 0-5460\n\
             b2 127.0.0.1:7201@17101, master - 0 1 2 connected 5461-16383\n"
        );
    }

    #[test]
    fn cluster_nodes_without_bus_port_are_rewritten() {
        let reply = Frame::VerbatimString(
            b"a1 127.0.0.1:7100 myself,master - 0 0 1 connected\n".to_vec(),
        );

        let rewritten = rewrite_cluster_nodes(&reply, &map());

        assert_eq!(
            rewritten,
            Frame::VerbatimString(
                b"a1 127.0.0.1:7200 myself,master - 0 0 1 connected\n".to_vec()
            )
        );
    }

    #[test]
    fn non_string_nodes_replies_pass_through() {
        let reply = Frame::SimpleError("ERR unknown subcommand".to_owned());

        assert_eq!(rewrite_cluster_nodes(&reply, &map()), reply);
    }
}
