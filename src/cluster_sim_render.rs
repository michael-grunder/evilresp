//! Render a simulated node's view as the topology replies Redis and Valkey
//! emit: `CLUSTER SLOTS`, `SHARDS`, `NODES`, `INFO`, `MYID`, `MYSHARDID`.

use std::fmt::Write as _;
use std::net::SocketAddr;

use crate::cluster_sim_model::{ClusterState, SLOT_COUNT};
use crate::cluster_sim_timeline::{Flavor, Timeline};
use crate::resp::Frame;

pub(crate) struct RenderContext<'a> {
    pub timeline: &'a Timeline,
    pub addresses: &'a [SocketAddr],
    pub resp3: bool,
    pub stage: usize,
    /// The node answering the query.
    pub node: usize,
}

impl RenderContext<'_> {
    fn id(&self, node: usize) -> Frame {
        bulk(&self.timeline.node_ids[node])
    }

    fn map(&self, pairs: Vec<(Frame, Frame)>) -> Frame {
        if self.resp3 {
            Frame::Map(pairs)
        } else {
            Frame::Array(Some(
                pairs.into_iter().flat_map(|(k, v)| [k, v]).collect(),
            ))
        }
    }

    fn text(&self, text: String) -> Frame {
        if self.resp3 {
            let mut bytes = b"txt:".to_vec();
            bytes.extend(text.into_bytes());
            Frame::VerbatimString(bytes)
        } else {
            Frame::BulkString(Some(text.into_bytes()))
        }
    }

    fn ip(&self, node: usize) -> String {
        self.addresses[node].ip().to_string()
    }

    fn port(&self, node: usize) -> i64 {
        i64::from(self.addresses[node].port())
    }
}

fn bulk(value: &str) -> Frame {
    Frame::BulkString(Some(value.as_bytes().to_vec()))
}

/// `CLUSTER SLOTS`: failed replicas are omitted, a failed primary is not.
pub(crate) fn cluster_slots(
    view: &ClusterState,
    ctx: &RenderContext<'_>,
) -> Frame {
    let entry = |node: usize| {
        Frame::Array(Some(vec![
            bulk(&ctx.ip(node)),
            Frame::Integer(ctx.port(node)),
            ctx.id(node),
            ctx.map(Vec::new()),
        ]))
    };
    Frame::Array(Some(
        view.slots
            .iter()
            .map(|range| {
                let mut parts = vec![
                    Frame::Integer(i64::from(range.start)),
                    Frame::Integer(i64::from(range.end)),
                    entry(range.owner),
                ];
                parts.extend(
                    view.members()
                        .filter(|n| {
                            let node = &view.nodes[*n];
                            node.primary_of() == Some(range.owner) && !node.fail
                        })
                        .map(entry),
                );
                Frame::Array(Some(parts))
            })
            .collect(),
    ))
}

/// `CLUSTER SHARDS` in membership order, with Valkey's trailing shard `id`.
pub(crate) fn cluster_shards(
    view: &ClusterState,
    ctx: &RenderContext<'_>,
) -> Frame {
    Frame::Array(Some(
        view.shards()
            .into_iter()
            .map(|(shard, members)| {
                let slots = view
                    .shard_slot_source(&members)
                    .map(|source| view.ranges_of(source))
                    .unwrap_or_default()
                    .into_iter()
                    .flat_map(|(start, end)| {
                        [
                            Frame::Integer(i64::from(start)),
                            Frame::Integer(i64::from(end)),
                        ]
                    })
                    .collect();
                let nodes =
                    members.iter().map(|n| shard_node(view, *n, ctx)).collect();
                let mut pairs = vec![
                    (bulk("slots"), Frame::Array(Some(slots))),
                    (bulk("nodes"), Frame::Array(Some(nodes))),
                ];
                if ctx.timeline.config.flavor == Flavor::Valkey {
                    pairs.push((
                        bulk("id"),
                        bulk(&ctx.timeline.shard_ids[shard]),
                    ));
                }
                ctx.map(pairs)
            })
            .collect(),
    ))
}

fn shard_node(
    view: &ClusterState,
    node: usize,
    ctx: &RenderContext<'_>,
) -> Frame {
    let entry = &view.nodes[node];
    let health = if entry.fail {
        "fail"
    } else if entry.loading() {
        "loading"
    } else {
        "online"
    };
    ctx.map(vec![
        (bulk("id"), ctx.id(node)),
        (bulk("port"), Frame::Integer(ctx.port(node))),
        (bulk("ip"), bulk(&ctx.ip(node))),
        (bulk("endpoint"), bulk(&ctx.ip(node))),
        (
            bulk("role"),
            bulk(if entry.is_primary() {
                "master"
            } else {
                "replica"
            }),
        ),
        (
            bulk("replication-offset"),
            Frame::Integer(i64::try_from(entry.offset).unwrap_or(i64::MAX)),
        ),
        (bulk("health"), bulk(health)),
    ])
}

/// `CLUSTER NODES`. Only the answering node reports its own open
/// migrations, one bracketed entry per slot, as Redis does.
pub(crate) fn cluster_nodes(
    view: &ClusterState,
    ctx: &RenderContext<'_>,
) -> Frame {
    let ids = &ctx.timeline.node_ids;
    let pong = ctx.timeline.stage_start(ctx.stage);
    let mut text = String::new();
    for node in view.members() {
        let entry = &view.nodes[node];
        let mut flags = Vec::new();
        if node == ctx.node {
            flags.push("myself");
        }
        flags.push(if entry.is_primary() {
            "master"
        } else {
            "slave"
        });
        if entry.pfail {
            flags.push("fail?");
        }
        if entry.fail {
            flags.push("fail");
        }
        let master = entry
            .primary_of()
            .map_or_else(|| "-".to_owned(), |of| ids[of].clone());
        let port = ctx.addresses[node].port();
        let bus = u32::from(port) + 10_000;
        let link = if node != ctx.node && (entry.pfail || entry.fail) {
            "disconnected"
        } else {
            "connected"
        };
        let epoch = match entry.primary_of() {
            Some(of) => view.nodes[of].epoch,
            None => entry.epoch,
        };
        let _ = write!(
            text,
            "{} {}:{port}@{} {} {master} 0 {} {epoch} {link}",
            ids[node],
            ctx.ip(node),
            bus % 65_536,
            flags.join(","),
            if node == ctx.node { 0 } else { pong },
        );
        for (start, end) in view.ranges_of(node) {
            if start == end {
                let _ = write!(text, " {start}");
            } else {
                let _ = write!(text, " {start}-{end}");
            }
        }
        if node == ctx.node {
            for migration in &view.migrations {
                for slot in migration.start..=migration.end {
                    if migration.from == node {
                        let _ =
                            write!(text, " [{slot}->-{}]", ids[migration.to]);
                    } else if migration.to == node {
                        let _ =
                            write!(text, " [{slot}-<-{}]", ids[migration.from]);
                    }
                }
            }
        }
        text.push('\n');
    }
    ctx.text(text)
}

pub(crate) fn cluster_info(
    view: &ClusterState,
    ctx: &RenderContext<'_>,
) -> Frame {
    let full_coverage = ctx.timeline.config.full_coverage;
    let assigned = view.assigned_slots();
    let slots_where = |predicate: &dyn Fn(usize) -> bool| -> usize {
        view.slots
            .iter()
            .filter(|range| predicate(range.owner))
            .map(|range| usize::from(range.end - range.start) + 1)
            .sum()
    };
    let pfail = slots_where(&|owner| view.nodes[owner].pfail);
    let fail = slots_where(&|owner| view.nodes[owner].fail);
    let size = view
        .members()
        .filter(|n| !view.ranges_of(*n).is_empty())
        .count();
    let me = &view.nodes[ctx.node];
    let my_epoch = match me.primary_of() {
        Some(of) => view.nodes[of].epoch,
        None => me.epoch,
    };
    let state = if view.state_ok(full_coverage) {
        "ok"
    } else {
        "fail"
    };
    let text = format!(
        "cluster_enabled:1\r\n\
         cluster_state:{state}\r\n\
         cluster_slots_assigned:{assigned}\r\n\
         cluster_slots_ok:{}\r\n\
         cluster_slots_pfail:{pfail}\r\n\
         cluster_slots_fail:{fail}\r\n\
         cluster_known_nodes:{}\r\n\
         cluster_size:{size}\r\n\
         cluster_current_epoch:{}\r\n\
         cluster_my_epoch:{my_epoch}\r\n\
         cluster_stats_messages_sent:0\r\n\
         cluster_stats_messages_received:0\r\n\
         total_cluster_links_buffer_limit_exceeded:0\r\n",
        assigned - pfail - fail,
        view.members().count(),
        view.current_epoch,
    );
    debug_assert!(assigned <= SLOT_COUNT);
    ctx.text(text)
}

pub(crate) fn cluster_myid(ctx: &RenderContext<'_>) -> Frame {
    ctx.id(ctx.node)
}

pub(crate) fn cluster_myshardid(
    view: &ClusterState,
    ctx: &RenderContext<'_>,
) -> Frame {
    bulk(&ctx.timeline.shard_ids[view.nodes[ctx.node].shard])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_sim_timeline::SimConfig;

    fn timeline(args: &str, nodes: usize) -> Timeline {
        let args = args
            .split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        Timeline::build(SimConfig::parse(&args, 0).unwrap(), nodes, 2).unwrap()
    }

    fn addresses(count: usize) -> Vec<SocketAddr> {
        (0..count)
            .map(|i| SocketAddr::from(([127, 0, 0, 1], 7000 + i as u16)))
            .collect()
    }

    fn ctx<'a>(
        timeline: &'a Timeline,
        addresses: &'a [SocketAddr],
        resp3: bool,
        node: usize,
    ) -> RenderContext<'a> {
        RenderContext {
            timeline,
            addresses,
            resp3,
            stage: 0,
            node,
        }
    }

    #[test]
    fn stable_slots_and_shards_have_exact_shapes() {
        let timeline = timeline("STABLE SHARDS 1 REPLICAS 1", 2);
        let addresses = addresses(2);
        let ids = &timeline.node_ids;
        let view = timeline.view(0, 0);
        let slots = cluster_slots(&view, &ctx(&timeline, &addresses, false, 0));
        let expected = format!(
            "*1\r\n*4\r\n:0\r\n:16383\r\n*4\r\n$9\r\n127.0.0.1\r\n:7000\r\n$40\r\n{}\r\n*0\r\n*4\r\n$9\r\n127.0.0.1\r\n:7001\r\n$40\r\n{}\r\n*0\r\n",
            ids[0], ids[1]
        );
        assert_eq!(String::from_utf8(slots.encode()).unwrap(), expected);

        let shards =
            cluster_shards(&view, &ctx(&timeline, &addresses, true, 0));
        let encoded = String::from_utf8(shards.encode()).unwrap();
        assert!(encoded.starts_with("*1\r\n%2\r\n$5\r\nslots\r\n*2\r\n:0\r\n:16383\r\n$5\r\nnodes\r\n*2\r\n%7\r\n$2\r\nid\r\n"));
        assert!(encoded.contains("$4\r\nrole\r\n$6\r\nmaster\r\n"));
        assert!(encoded.contains("$4\r\nrole\r\n$7\r\nreplica\r\n"));
        assert!(encoded.contains("$6\r\nhealth\r\n$6\r\nonline\r\n"));
        let flat = cluster_shards(&view, &ctx(&timeline, &addresses, false, 0));
        assert!(flat.encode().starts_with(b"*1\r\n*4\r\n$5\r\nslots\r\n"));
    }

    #[test]
    fn valkey_flavor_appends_shard_id() {
        let timeline = timeline("STABLE SHARDS 1 FLAVOR VALKEY", 1);
        let addresses = addresses(1);
        let view = timeline.view(0, 0);
        let frame = cluster_shards(&view, &ctx(&timeline, &addresses, true, 0));
        let Frame::Array(Some(shards)) = frame else {
            panic!("array");
        };
        let Frame::Map(pairs) = &shards[0] else {
            panic!("map");
        };
        assert_eq!(pairs[2], (bulk("id"), bulk(&timeline.shard_ids[0])));
        assert_eq!(
            cluster_myshardid(&view, &ctx(&timeline, &addresses, true, 0)),
            bulk(&timeline.shard_ids[0])
        );
    }

    #[test]
    fn failover_views_render_fail_flags_health_and_loading() {
        let timeline = timeline("FAILOVER SEED 1 SHARDS 2 REPLICAS 1", 4);
        let addresses = addresses(4);
        let marked = timeline
            .stages
            .iter()
            .position(|s| s.label.contains("marked FAIL"))
            .unwrap();
        let auth = timeline.authoritative(marked);
        let failed = (0..4).find(|n| auth.nodes[*n].fail).unwrap();
        let observer = (0..4)
            .find(|n| {
                *n != failed
                    && timeline.stages[marked].views[*n]
                        == timeline.stages[marked].auth
            })
            .unwrap();
        let view = timeline.view(marked, observer);
        let mut context = ctx(&timeline, &addresses, false, observer);
        context.stage = marked;
        let Frame::BulkString(Some(nodes)) = cluster_nodes(&view, &context)
        else {
            panic!("bulk");
        };
        let nodes = String::from_utf8(nodes).unwrap();
        let failed_line = nodes
            .lines()
            .find(|line| line.starts_with(&timeline.node_ids[failed]))
            .unwrap();
        assert!(failed_line.contains(" master,fail "), "{failed_line}");
        assert!(failed_line.contains(" disconnected"));
        assert_eq!(nodes.lines().filter(|l| l.contains("myself")).count(), 1);
        let shards =
            String::from_utf8(cluster_shards(&view, &context).encode())
                .unwrap();
        assert!(shards.contains("$4\r\nfail\r\n"));
        let info = cluster_info(&view, &context);
        let Frame::BulkString(Some(info)) = info else {
            panic!("bulk");
        };
        let info = String::from_utf8(info).unwrap();
        assert!(info.contains("cluster_state:ok\r\n"), "{info}");
        assert!(info.contains("cluster_slots_fail:8192\r\n"), "{info}");

        let loading = timeline
            .stages
            .iter()
            .position(|s| s.label.contains("loading"))
            .unwrap();
        let view = timeline.view(loading, failed);
        let shards = String::from_utf8(
            cluster_shards(&view, &ctx(&timeline, &addresses, false, failed))
                .encode(),
        )
        .unwrap();
        assert!(shards.contains("$7\r\nloading\r\n"));
    }

    #[test]
    fn partial_view_reports_unassigned_slots_and_full_coverage_failure() {
        let timeline = timeline("PARTIAL SEED 5 FULL_COVERAGE YES", 4);
        let addresses = addresses(4);
        let view = timeline.view(0, 0);
        let Frame::VerbatimString(info) =
            cluster_info(&view, &ctx(&timeline, &addresses, true, 0))
        else {
            panic!("verbatim");
        };
        let info = String::from_utf8(info).unwrap();
        assert!(
            info.starts_with("txt:cluster_enabled:1\r\ncluster_state:fail\r\n")
        );
        let Frame::Array(Some(ranges)) =
            cluster_slots(&view, &ctx(&timeline, &addresses, false, 0))
        else {
            panic!("array");
        };
        let covered: i64 = ranges
            .iter()
            .map(|range| {
                let Frame::Array(Some(parts)) = range else {
                    panic!("range");
                };
                let (Frame::Integer(start), Frame::Integer(end)) =
                    (&parts[0], &parts[1])
                else {
                    panic!("bounds");
                };
                end - start + 1
            })
            .sum();
        assert_eq!(covered as usize, view.assigned_slots());
        assert!(covered < SLOT_COUNT as i64);
    }

    #[test]
    fn migrations_are_listed_only_by_the_participants() {
        let timeline = timeline("RESHARD SEED 3", 2);
        let addresses = addresses(2);
        let stage = timeline
            .stages
            .iter()
            .position(|s| s.label.contains("migrating"))
            .unwrap();
        let auth = timeline.authoritative(stage);
        let migration = auth.migrations[0];
        for node in 0..2 {
            let mut context = ctx(&timeline, &addresses, false, node);
            context.stage = stage;
            let Frame::BulkString(Some(text)) =
                cluster_nodes(&timeline.view(stage, node), &context)
            else {
                panic!("bulk");
            };
            let text = String::from_utf8(text).unwrap();
            let marker = if node == migration.from {
                format!(
                    "[{}->-{}]",
                    migration.start, timeline.node_ids[migration.to]
                )
            } else {
                format!(
                    "[{}-<-{}]",
                    migration.start, timeline.node_ids[migration.from]
                )
            };
            assert!(text.contains(&marker), "{text}");
        }
    }
}
