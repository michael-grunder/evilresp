use std::collections::BTreeMap;
use std::net::SocketAddr;

use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, info};

use crate::cli::{Endpoint, TcpEndpoint};
use crate::error::{AppError, AppResult};
use crate::resp::{Frame, parse_frame, read_raw_frame};

#[derive(Clone, Debug)]
pub enum Topology {
    Standalone {
        target: ProxyTarget,
    },
    Cluster {
        targets: Vec<ProxyTarget>,
        slots: Vec<LocalSlotRange>,
    },
}

impl Topology {
    pub fn targets(&self) -> &[ProxyTarget] {
        match self {
            Topology::Standalone { target } => std::slice::from_ref(target),
            Topology::Cluster { targets, .. } => targets,
        }
    }

    pub fn local_slots_response(&self) -> Option<Frame> {
        match self {
            Topology::Standalone { .. } => None,
            Topology::Cluster { slots, .. } => Some(Frame::Array(Some(
                slots.iter().map(LocalSlotRange::to_resp_frame).collect(),
            ))),
        }
    }

    pub fn local_redirection_map(&self) -> ClusterRedirectionMap {
        match self {
            Topology::Standalone { .. } => ClusterRedirectionMap::default(),
            Topology::Cluster { slots, .. } => {
                ClusterRedirectionMap::from_slot_ranges(slots)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProxyTarget {
    pub upstream: Endpoint,
    pub listen: Endpoint,
}

#[derive(Clone, Debug)]
pub struct LocalSlotRange {
    start: u16,
    end: u16,
    primary: LocalNode,
    replicas: Vec<LocalNode>,
}

#[derive(Clone, Debug)]
struct LocalNode {
    upstream: TcpEndpoint,
    local: SocketAddr,
    node_id: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Default)]
pub struct ClusterRedirectionMap {
    local_by_upstream: BTreeMap<String, String>,
    local_by_unique_upstream_port: BTreeMap<u16, String>,
    local_by_node_id: BTreeMap<Vec<u8>, String>,
}

impl ClusterRedirectionMap {
    fn from_slot_ranges(slots: &[LocalSlotRange]) -> Self {
        let nodes = || slots.iter().flat_map(LocalSlotRange::nodes);
        let mappings = nodes().map(|node| {
            (
                node.upstream.clone(),
                socket_addr_to_endpoint(node.local).connect_addr(),
            )
        });
        let mut map = Self::from_mappings(mappings);
        for node in nodes() {
            if let Some(id) = &node.node_id {
                map.local_by_node_id.insert(
                    id.clone(),
                    socket_addr_to_endpoint(node.local).connect_addr(),
                );
            }
        }
        map
    }

    pub fn from_mappings(
        mappings: impl IntoIterator<Item = (TcpEndpoint, String)>,
    ) -> Self {
        let mut local_by_upstream = BTreeMap::new();
        let mut local_by_upstream_port = BTreeMap::<u16, Option<String>>::new();

        for (upstream, local) in mappings {
            local_by_upstream.insert(upstream.connect_addr(), local.clone());
            local_by_upstream_port
                .entry(upstream.port)
                .and_modify(|existing| {
                    if existing.as_deref() != Some(local.as_str()) {
                        *existing = None;
                    }
                })
                .or_insert(Some(local));
        }

        let local_by_unique_upstream_port = local_by_upstream_port
            .into_iter()
            .filter_map(|(port, local)| local.map(|local| (port, local)))
            .collect();

        Self {
            local_by_upstream,
            local_by_unique_upstream_port,
            local_by_node_id: BTreeMap::new(),
        }
    }

    pub fn rewrite_node(
        &self,
        node_id: Option<&[u8]>,
        server: &str,
    ) -> Option<String> {
        node_id
            .and_then(|id| self.local_by_node_id.get(id).cloned())
            .or_else(|| self.rewrite_server(server))
    }

    pub fn rewrite_server(&self, server: &str) -> Option<String> {
        if let Ok(endpoint) = server.parse::<TcpEndpoint>() {
            return self
                .local_by_upstream
                .get(&endpoint.connect_addr())
                .or_else(|| {
                    self.local_by_unique_upstream_port.get(&endpoint.port)
                })
                .cloned();
        }

        let port = server.rsplit_once(':')?.1.parse::<u16>().ok()?;
        self.local_by_unique_upstream_port.get(&port).cloned()
    }
}

impl LocalSlotRange {
    fn nodes(&self) -> impl Iterator<Item = &LocalNode> {
        std::iter::once(&self.primary).chain(&self.replicas)
    }

    fn to_resp_frame(&self) -> Frame {
        let mut parts = vec![
            Frame::Integer(i64::from(self.start)),
            Frame::Integer(i64::from(self.end)),
        ];
        parts.extend(self.nodes().map(LocalNode::to_resp_frame));
        Frame::Array(Some(parts))
    }
}

impl LocalNode {
    fn to_resp_frame(&self) -> Frame {
        let node_id = self.node_id.clone().unwrap_or_else(|| {
            format!("evilresp-{}", self.local.port()).into_bytes()
        });
        Frame::Array(Some(vec![
            Frame::BulkString(Some(self.local.ip().to_string().into_bytes())),
            Frame::Integer(i64::from(self.local.port())),
            Frame::BulkString(Some(node_id)),
        ]))
    }
}

pub async fn discover(
    proxy: Endpoint,
    listen: Endpoint,
) -> AppResult<Topology> {
    let (tcp_proxy, tcp_listen) = match (proxy.as_tcp(), listen.as_tcp()) {
        (Some(proxy), Some(listen)) => {
            (proxy.clone(), listen.connect_addr().parse::<SocketAddr>()?)
        }
        _ => {
            debug!(
                "AF_UNIX endpoint configured; using standalone proxy mode without cluster discovery"
            );
            return Ok(Topology::Standalone {
                target: ProxyTarget {
                    upstream: proxy,
                    listen,
                },
            });
        }
    };

    let slots = match fetch_cluster_slots(&tcp_proxy).await {
        Ok(slots) if slots.is_empty() => {
            debug!(
                "CLUSTER SLOTS returned an empty topology; using standalone proxy mode"
            );
            return Ok(Topology::Standalone {
                target: ProxyTarget {
                    upstream: Endpoint::Tcp(tcp_proxy),
                    listen,
                },
            });
        }
        Ok(slots) => slots,
        Err(error) => {
            debug!(%error, "cluster probe failed; using standalone proxy mode");
            return Ok(Topology::Standalone {
                target: ProxyTarget {
                    upstream: Endpoint::Tcp(tcp_proxy),
                    listen,
                },
            });
        }
    };

    map_cluster_slots(slots, tcp_listen)
}

fn map_cluster_slots(
    mut slots: Vec<LocalSlotRange>,
    listen: SocketAddr,
) -> AppResult<Topology> {
    if listen.port() == 0 {
        return Err(AppError::Proxy(
            "cluster proxy mode requires a non-zero --listen port".to_owned(),
        ));
    }

    let mut local_by_upstream = BTreeMap::<String, SocketAddr>::new();
    let mut local_by_node_id = BTreeMap::<Vec<u8>, SocketAddr>::new();
    let mut node_id_by_local = BTreeMap::<SocketAddr, Vec<u8>>::new();
    let mut targets = Vec::new();
    // Allocate every primary first to preserve existing primary ports.
    let nodes = slots
        .iter()
        .map(|slot| &slot.primary)
        .chain(slots.iter().flat_map(|slot| &slot.replicas));
    for node in nodes {
        let key = node.upstream.connect_addr();
        let by_endpoint = local_by_upstream.get(&key).copied();
        let by_id = node
            .node_id
            .as_ref()
            .and_then(|id| local_by_node_id.get(id))
            .copied();
        if let (Some(endpoint), Some(id)) = (by_endpoint, by_id)
            && endpoint != id
        {
            return Err(AppError::Proxy(
                "cluster node ID conflicts with endpoint mapping".to_owned(),
            ));
        }
        if let Some(local) = by_id.or(by_endpoint) {
            local_by_upstream.insert(key, local);
            if let Some(id) = &node.node_id {
                if let Some(existing) = node_id_by_local.get(&local)
                    && existing != id
                {
                    return Err(AppError::Proxy(
                        "cluster endpoint has conflicting node IDs".to_owned(),
                    ));
                }
                local_by_node_id.insert(id.clone(), local);
                node_id_by_local.insert(local, id.clone());
            }
            continue;
        }

        let offset = u16::try_from(targets.len()).map_err(|_| {
            AppError::Proxy(
                "cluster has more local nodes than u16 ports".to_owned(),
            )
        })?;
        let port = listen.port().checked_add(offset).ok_or_else(|| {
            AppError::Proxy(format!(
                "cluster local port mapping from {} overflows u16",
                listen.port()
            ))
        })?;
        let mut local = listen;
        local.set_port(port);
        local_by_upstream.insert(key, local);
        if let Some(id) = &node.node_id {
            local_by_node_id.insert(id.clone(), local);
            node_id_by_local.insert(local, id.clone());
        }
        targets.push(ProxyTarget {
            upstream: Endpoint::Tcp(node.upstream.clone()),
            listen: Endpoint::Tcp(socket_addr_to_endpoint(local)),
        });
    }

    for slot in &mut slots {
        for node in std::iter::once(&mut slot.primary).chain(&mut slot.replicas)
        {
            // Every node endpoint was registered in the allocation pass.
            node.local = local_by_upstream[&node.upstream.connect_addr()];
        }
    }

    info!(
        nodes = targets.len(),
        "detected cluster topology and mapped local node listeners"
    );

    Ok(Topology::Cluster { targets, slots })
}

async fn fetch_cluster_slots(
    proxy: &TcpEndpoint,
) -> AppResult<Vec<LocalSlotRange>> {
    let stream = TcpStream::connect(proxy.connect_addr()).await?;
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);

    write.write_all(&cluster_slots_command().encode()).await?;
    write.flush().await?;

    let raw = read_raw_frame(&mut read).await?;
    let frame = parse_frame(&raw)?;
    match frame {
        Frame::Array(Some(items)) => parse_cluster_slots(items, proxy),
        Frame::SimpleError(error) => {
            Err(AppError::Proxy(format!("CLUSTER SLOTS failed: {error}")))
        }
        other => Err(AppError::Proxy(format!(
            "CLUSTER SLOTS returned unexpected frame {other:?}"
        ))),
    }
}

fn cluster_slots_command() -> Frame {
    Frame::Array(Some(vec![
        Frame::BulkString(Some(b"CLUSTER".to_vec())),
        Frame::BulkString(Some(b"SLOTS".to_vec())),
    ]))
}

fn parse_cluster_slots(
    items: Vec<Frame>,
    bootstrap: &TcpEndpoint,
) -> AppResult<Vec<LocalSlotRange>> {
    items
        .into_iter()
        .map(|item| parse_slot_range(item, bootstrap))
        .collect()
}

fn parse_slot_range(
    item: Frame,
    bootstrap: &TcpEndpoint,
) -> AppResult<LocalSlotRange> {
    let Frame::Array(Some(parts)) = item else {
        return Err(AppError::Proxy(
            "cluster slot entry is not an array".to_owned(),
        ));
    };
    if parts.len() < 3 {
        return Err(AppError::Proxy(
            "cluster slot entry has fewer than three items".to_owned(),
        ));
    }

    let start = as_slot(parts.first(), "start slot")?;
    let end = as_slot(parts.get(1), "end slot")?;
    let primary = parse_node(&parts[2], bootstrap)?;
    let replicas = parts[3..]
        .iter()
        .map(|node| parse_node(node, bootstrap))
        .collect::<AppResult<Vec<_>>>()?;

    Ok(LocalSlotRange {
        start,
        end,
        primary,
        replicas,
    })
}

fn parse_node(node: &Frame, bootstrap: &TcpEndpoint) -> AppResult<LocalNode> {
    let Frame::Array(Some(parts)) = node else {
        return Err(AppError::Proxy(
            "cluster slot node is not an array".to_owned(),
        ));
    };
    if parts.len() < 2 {
        return Err(AppError::Proxy(
            "cluster slot node has fewer than two items".to_owned(),
        ));
    }

    let host = match &parts[0] {
        Frame::BulkString(Some(bytes)) | Frame::VerbatimString(bytes) => {
            let host = String::from_utf8_lossy(bytes);
            if host.is_empty() || host == "?" {
                bootstrap.host.clone()
            } else {
                host.into_owned()
            }
        }
        Frame::SimpleString(host) => host.clone(),
        _ => {
            return Err(AppError::Proxy(
                "cluster slot node host is not a string".to_owned(),
            ));
        }
    };

    let port = match parts.get(1) {
        Some(Frame::Integer(port)) => u16::try_from(*port).map_err(|_| {
            AppError::Proxy(format!("invalid cluster node port {port}"))
        })?,
        _ => {
            return Err(AppError::Proxy(
                "cluster slot node port is not an integer".to_owned(),
            ));
        }
    };

    let node_id = match parts.get(2) {
        Some(Frame::BulkString(Some(bytes)))
        | Some(Frame::VerbatimString(bytes)) => Some(bytes.clone()),
        Some(Frame::SimpleString(value)) => Some(value.as_bytes().to_vec()),
        _ => None,
    };

    Ok(LocalNode {
        upstream: TcpEndpoint { host, port },
        local: SocketAddr::from(([127, 0, 0, 1], 0)),
        node_id: node_id.filter(|id| !id.is_empty()),
    })
}

fn as_slot(frame: Option<&Frame>, name: &str) -> AppResult<u16> {
    match frame {
        Some(Frame::Integer(value)) => u16::try_from(*value).map_err(|_| {
            AppError::Proxy(format!("{name} {value} is outside u16 range"))
        }),
        _ => Err(AppError::Proxy(format!("{name} is not an integer"))),
    }
}

fn socket_addr_to_endpoint(addr: SocketAddr) -> TcpEndpoint {
    TcpEndpoint {
        host: addr.ip().to_string(),
        port: addr.port(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_rewrite::{
        rewrite_cluster_nodes, rewrite_cluster_shards,
    };
    use crate::resp::parse_frame;
    use crate::topology_evil::normalize_redirection;

    fn bulk(value: &str) -> Frame {
        Frame::BulkString(Some(value.as_bytes().to_vec()))
    }

    fn node(host: &str, port: i64, id: &str) -> Frame {
        Frame::Array(Some(vec![bulk(host), Frame::Integer(port), bulk(id)]))
    }

    fn range(start: i64, end: i64, nodes: Vec<Frame>) -> Frame {
        let mut parts = vec![Frame::Integer(start), Frame::Integer(end)];
        parts.extend(nodes);
        Frame::Array(Some(parts))
    }

    fn mapped_cluster() -> Topology {
        let slots = parse_cluster_slots(
            vec![
                range(
                    0,
                    100,
                    vec![
                        node("primary-a", 6379, "p1"),
                        node("replica-a", 6379, "r1"),
                        node("replica-b", 6379, "r2"),
                    ],
                ),
                range(
                    101,
                    200,
                    vec![
                        node("primary-b", 6379, "p2"),
                        node("replica-c", 6379, "r3"),
                    ],
                ),
                range(
                    201,
                    16383,
                    vec![
                        node("primary-a", 6379, "p1"),
                        node("replica-a-alias", 6379, "r1"),
                        node("replica-b", 6379, "r2"),
                    ],
                ),
            ],
            &"bootstrap:6379".parse().unwrap(),
        )
        .unwrap();
        map_cluster_slots(slots, "127.0.0.1:6380".parse().unwrap()).unwrap()
    }

    #[test]
    fn replicas_follow_primaries_and_repeated_nodes_share_listeners() {
        let topology = mapped_cluster();
        let endpoints: Vec<_> = topology
            .targets()
            .iter()
            .map(|target| {
                (target.upstream.to_string(), target.listen.to_string())
            })
            .collect();
        assert_eq!(
            endpoints,
            vec![
                ("primary-a:6379".to_owned(), "127.0.0.1:6380".to_owned()),
                ("primary-b:6379".to_owned(), "127.0.0.1:6381".to_owned()),
                ("replica-a:6379".to_owned(), "127.0.0.1:6382".to_owned()),
                ("replica-b:6379".to_owned(), "127.0.0.1:6383".to_owned()),
                ("replica-c:6379".to_owned(), "127.0.0.1:6384".to_owned()),
            ]
        );
        let expected = Frame::Array(Some(vec![
            range(
                0,
                100,
                vec![
                    node("127.0.0.1", 6380, "p1"),
                    node("127.0.0.1", 6382, "r1"),
                    node("127.0.0.1", 6383, "r2"),
                ],
            ),
            range(
                101,
                200,
                vec![
                    node("127.0.0.1", 6381, "p2"),
                    node("127.0.0.1", 6384, "r3"),
                ],
            ),
            range(
                201,
                16383,
                vec![
                    node("127.0.0.1", 6380, "p1"),
                    node("127.0.0.1", 6382, "r1"),
                    node("127.0.0.1", 6383, "r2"),
                ],
            ),
        ]));
        assert_eq!(topology.local_slots_response().unwrap(), expected);
        assert_eq!(
            mapped_cluster().local_slots_response().unwrap().encode(),
            expected.encode()
        );

        let map = topology.local_redirection_map();
        for host in ["replica-a", "replica-a-alias"] {
            assert_eq!(
                map.rewrite_server(&format!("{host}:6379")),
                Some("127.0.0.1:6382".to_owned())
            );
        }
        assert_eq!(map.rewrite_server("unknown:6379"), None);
        assert_eq!(map.rewrite_server(":6379"), None);
        assert_eq!(
            map.rewrite_node(Some(b"r3"), "another-alias:6379"),
            Some("127.0.0.1:6384".to_owned())
        );
        assert_eq!(
            normalize_redirection(
                &Frame::SimpleError("MOVED 42 replica-a:6379".to_owned()),
                &map,
            ),
            Some(Frame::SimpleError("MOVED 42 127.0.0.1:6382".to_owned()))
        );
    }

    fn shard_node(
        id: &str,
        host: &str,
        port: i64,
        role: &str,
        flat: bool,
    ) -> Frame {
        let entries = vec![
            (bulk("id"), bulk(id)),
            (bulk("ip"), bulk(host)),
            (bulk("endpoint"), bulk(host)),
            (bulk("hostname"), bulk(host)),
            (bulk("port"), Frame::Integer(port)),
            (bulk("role"), bulk(role)),
            (bulk("replication-offset"), Frame::Integer(123)),
            (bulk("health"), bulk("online")),
        ];
        if flat {
            Frame::Array(Some(
                entries.into_iter().flat_map(|(k, v)| [k, v]).collect(),
            ))
        } else {
            Frame::Map(entries)
        }
    }

    fn shard(nodes: Vec<Frame>, flat: bool) -> Frame {
        let slots =
            Frame::Array(Some(vec![Frame::Integer(0), Frame::Integer(100)]));
        let nodes = Frame::Array(Some(nodes));
        Frame::Array(Some(vec![if flat {
            Frame::Array(Some(vec![bulk("slots"), slots, bulk("nodes"), nodes]))
        } else {
            Frame::Map(vec![(bulk("slots"), slots), (bulk("nodes"), nodes)])
        }]))
    }

    #[test]
    fn all_discovery_replies_use_the_same_replica_mapping_and_keep_roles() {
        let map = mapped_cluster().local_redirection_map();
        for flat in [false, true] {
            let reply = shard(
                vec![
                    shard_node("p1", "primary-a", 6379, "master", flat),
                    shard_node(
                        "r1",
                        "alternate-replica-ip",
                        6379,
                        "replica",
                        flat,
                    ),
                    shard_node("r2", "replica-b", 6379, "replica", flat),
                    shard_node(
                        "unmapped",
                        "new-replica",
                        6379,
                        "replica",
                        flat,
                    ),
                ],
                flat,
            );
            let expected = shard(
                vec![
                    shard_node("p1", "127.0.0.1", 6380, "master", flat),
                    shard_node("r1", "127.0.0.1", 6382, "replica", flat),
                    shard_node("r2", "127.0.0.1", 6383, "replica", flat),
                ],
                flat,
            );
            assert_eq!(rewrite_cluster_shards(&reply, &map), expected);
        }

        let reply = bulk(
            "p1 primary-a:6379@16379 master - 0 0 1 connected 0-100 201-16383\n\
            r1 alternate-replica-ip:6379@16379,replica.example slave p1 0 0 1 connected\n\
            r2 replica-b:6379@16379 slave p1 0 0 1 connected\n\
            unknown new-replica:6379@16379 slave p1 0 0 1 connected\n",
        );
        assert_eq!(
            rewrite_cluster_nodes(&reply, &map),
            bulk(
                "p1 127.0.0.1:6380@16379 master - 0 0 1 connected 0-100 201-16383\n\
            r1 127.0.0.1:6382@16379, slave p1 0 0 1 connected\n\
            r2 127.0.0.1:6383@16379 slave p1 0 0 1 connected\n"
            )
        );
    }

    #[test]
    fn malformed_replicas_fail_discovery_parsing() {
        for replica in [
            Frame::Integer(1),
            Frame::Array(Some(vec![bulk("host")])),
            node("host", -1, "r1"),
            node("host", 65536, "r1"),
            Frame::Array(Some(vec![Frame::Integer(1), Frame::Integer(6379)])),
            Frame::Array(Some(vec![bulk("host"), bulk("invalid-port")])),
        ] {
            assert!(
                parse_cluster_slots(
                    vec![range(
                        0,
                        16383,
                        vec![node("primary", 6379, "p1"), replica,]
                    )],
                    &"bootstrap:6379".parse().unwrap()
                )
                .is_err()
            );
        }
    }

    #[test]
    fn replicas_count_toward_port_overflow_and_zero_port_is_rejected() {
        let slots = parse_cluster_slots(
            vec![range(
                0,
                16383,
                vec![node("primary", 6379, "p1"), node("replica", 6379, "r1")],
            )],
            &"bootstrap:6379".parse().unwrap(),
        )
        .unwrap();
        let error = map_cluster_slots(
            slots.clone(),
            "127.0.0.1:65535".parse().unwrap(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("overflows u16"));
        let error = map_cluster_slots(slots, "127.0.0.1:0".parse().unwrap())
            .unwrap_err();
        assert!(error.to_string().contains("non-zero"));
    }

    #[test]
    fn replicas_without_ids_use_endpoints_and_unique_port_fallback() {
        let slots = parse_cluster_slots(
            vec![range(
                0,
                16383,
                vec![
                    node("primary", 6379, ""),
                    node("replica", 6380, ""),
                    Frame::Array(Some(vec![
                        bulk("replica"),
                        Frame::Integer(6380),
                    ])),
                ],
            )],
            &"bootstrap:6379".parse().unwrap(),
        )
        .unwrap();
        let topology =
            map_cluster_slots(slots, "[::1]:7000".parse().unwrap()).unwrap();
        assert_eq!(topology.targets().len(), 2);
        assert_eq!(
            topology
                .local_redirection_map()
                .rewrite_server("alias:6380"),
            Some("[::1]:7001".to_owned())
        );
        assert_eq!(
            topology.local_slots_response().unwrap(),
            Frame::Array(Some(vec![range(
                0,
                16383,
                vec![
                    node("::1", 7000, "evilresp-7000"),
                    node("::1", 7001, "evilresp-7001"),
                    node("::1", 7001, "evilresp-7001"),
                ]
            )]))
        );
    }

    #[test]
    fn distinct_node_ids_cannot_share_an_upstream_endpoint() {
        let slots = parse_cluster_slots(
            vec![range(
                0,
                16383,
                vec![
                    node("same-host", 6379, "p1"),
                    node("same-host", 6379, "r1"),
                ],
            )],
            &"bootstrap:6379".parse().unwrap(),
        )
        .unwrap();
        let error = map_cluster_slots(slots, "127.0.0.1:6380".parse().unwrap())
            .unwrap_err();
        assert!(error.to_string().contains("conflicting node IDs"));
    }

    #[test]
    fn conflicting_node_id_and_endpoint_mappings_are_rejected() {
        let slots = parse_cluster_slots(
            vec![range(
                0,
                16383,
                vec![
                    node("primary", 6379, "p1"),
                    node("replica", 6379, "r1"),
                    node("replica", 6379, "p1"),
                ],
            )],
            &"bootstrap:6379".parse().unwrap(),
        )
        .unwrap();
        let error = map_cluster_slots(slots, "127.0.0.1:6380".parse().unwrap())
            .unwrap_err();
        assert!(error.to_string().contains("conflicts"));
    }

    #[test]
    fn parses_cluster_slots_response() {
        let frame = parse_frame(
            b"*1\r\n*3\r\n:0\r\n:16383\r\n*3\r\n$9\r\n127.0.0.1\r\n:7000\r\n$4\r\nnode\r\n",
        )
        .unwrap();
        let Frame::Array(Some(items)) = frame else {
            panic!("expected array");
        };

        let slots = parse_cluster_slots(
            items,
            &TcpEndpoint {
                host: "127.0.0.1".to_owned(),
                port: 6379,
            },
        )
        .unwrap();

        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].start, 0);
        assert_eq!(slots[0].end, 16383);
        assert_eq!(slots[0].primary.upstream.port, 7000);
        assert!(slots[0].replicas.is_empty());
    }

    #[test]
    fn local_slots_response_uses_local_proxy_endpoint() {
        let topology = Topology::Cluster {
            targets: vec![ProxyTarget {
                upstream: Endpoint::Tcp(TcpEndpoint {
                    host: "127.0.0.1".to_owned(),
                    port: 7000,
                }),
                listen: Endpoint::Tcp(TcpEndpoint {
                    host: "127.0.0.1".to_owned(),
                    port: 6380,
                }),
            }],
            slots: vec![LocalSlotRange {
                start: 0,
                end: 16_383,
                primary: LocalNode {
                    upstream: TcpEndpoint {
                        host: "127.0.0.1".to_owned(),
                        port: 7000,
                    },
                    local: "127.0.0.1:6380".parse().unwrap(),
                    node_id: Some(b"node".to_vec()),
                },
                replicas: Vec::new(),
            }],
        };

        let response = topology.local_slots_response().unwrap();

        assert_eq!(
            response.encode(),
            b"*1\r\n*3\r\n:0\r\n:16383\r\n*3\r\n$9\r\n127.0.0.1\r\n:6380\r\n$4\r\nnode\r\n"
        );
    }

    #[tokio::test]
    async fn unix_endpoints_use_standalone_topology_without_cluster_probe() {
        let proxy = Endpoint::Unix("/tmp/upstream.sock".into());
        let listen = Endpoint::Unix("/tmp/listen.sock".into());

        let topology = discover(proxy.clone(), listen.clone()).await.unwrap();

        let Topology::Standalone { target } = topology else {
            panic!("expected standalone topology");
        };
        assert_eq!(target.upstream, proxy);
        assert_eq!(target.listen, listen);
    }
}
