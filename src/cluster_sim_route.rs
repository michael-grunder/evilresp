//! Pure request routing for a simulated node, mirroring the order of
//! `getNodeByQuery()` and the loading check that follows it in
//! `processCommand()` on Redis and Valkey.

use std::net::SocketAddr;

use crate::cluster_sim_model::key_moved;
use crate::cluster_sim_timeline::Timeline;
use crate::topology_evil::redis_slot;

pub(crate) struct RouteRequest<'a> {
    /// Keys of the command, or of every queued command for `EXEC`.
    pub keys: &'a [Vec<u8>],
    pub write: bool,
    pub allowed_while_loading: bool,
    /// The connection sent `READONLY`.
    pub readonly: bool,
    /// The previous command on this connection was `ASKING`.
    pub asking: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Decision {
    /// Execute against the real cluster; `slot` is `None` for keyless
    /// commands.
    Serve { slot: Option<u16> },
    /// Reply with this error (without the leading `-`).
    Error(String),
    /// The simulated node is down: drop the connection without replying.
    Close,
}

pub(crate) const LOADING: &str =
    "LOADING Redis is loading the dataset in memory";

pub(crate) fn route(
    timeline: &Timeline,
    stage: usize,
    node: usize,
    addresses: &[SocketAddr],
    request: &RouteRequest<'_>,
) -> Decision {
    let auth = timeline.authoritative(stage);
    if auth.nodes[node].down {
        return Decision::Close;
    }
    let decision = redirect(timeline, stage, node, addresses, request);
    if matches!(decision, Decision::Serve { .. })
        && auth.nodes[node].loading()
        && !request.allowed_while_loading
    {
        return Decision::Error(LOADING.to_owned());
    }
    decision
}

fn redirect(
    timeline: &Timeline,
    stage: usize,
    node: usize,
    addresses: &[SocketAddr],
    request: &RouteRequest<'_>,
) -> Decision {
    let mut slot = None;
    for key in request.keys {
        // redis_slot returns 0..16384.
        let key_slot = redis_slot(key) as u16;
        if slot.is_some_and(|slot| slot != key_slot) {
            return Decision::Error(
                "CROSSSLOT Keys in request don't hash to the same slot"
                    .to_owned(),
            );
        }
        slot = Some(key_slot);
    }
    let Some(slot) = slot else {
        return Decision::Serve { slot: None };
    };
    let view = timeline.view(stage, node);
    let config = &timeline.config;
    let Some(owner) = view.owner(slot) else {
        return Decision::Error("CLUSTERDOWN Hash slot not served".to_owned());
    };
    if !view.state_ok(config.full_coverage) {
        if !config.reads_when_down {
            return Decision::Error(
                "CLUSTERDOWN The cluster is down".to_owned(),
            );
        }
        if request.write {
            return Decision::Error(
                "CLUSTERDOWN The cluster is down and only accepts read commands"
                    .to_owned(),
            );
        }
    }
    let moved = |keys: &[Vec<u8>], progress| {
        keys.iter()
            .filter(|key| key_moved(config.seed, key, progress))
            .count()
    };
    let address = |target: usize| {
        let address = addresses[target];
        format!("{}:{}", address.ip(), address.port())
    };
    if let Some(migration) = view.migration(slot) {
        let moved = moved(request.keys, migration.progress);
        if owner == node && migration.from == node {
            if moved == request.keys.len() {
                return Decision::Error(format!(
                    "ASK {slot} {}",
                    address(migration.to)
                ));
            }
            if moved > 0 {
                return Decision::Error(
                    "TRYAGAIN Multiple keys request during rehashing of slot"
                        .to_owned(),
                );
            }
        }
        if migration.to == node && request.asking {
            if request.keys.len() > 1 && moved != request.keys.len() {
                return Decision::Error(
                    "TRYAGAIN Multiple keys request during rehashing of slot"
                        .to_owned(),
                );
            }
            return Decision::Serve { slot: Some(slot) };
        }
    }
    if owner == node {
        return Decision::Serve { slot: Some(slot) };
    }
    if request.readonly
        && !request.write
        && view.nodes[node].primary_of() == Some(owner)
    {
        return Decision::Serve { slot: Some(slot) };
    }
    Decision::Error(format!("MOVED {slot} {}", address(owner)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_sim_timeline::SimConfig;

    fn timeline(args: &str, nodes: usize, primaries: usize) -> Timeline {
        let args = args
            .split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        Timeline::build(SimConfig::parse(&args, 0).unwrap(), nodes, primaries)
            .unwrap()
    }

    fn addresses(count: usize) -> Vec<SocketAddr> {
        (0..count)
            .map(|i| SocketAddr::from(([127, 0, 0, 1], 7000 + i as u16)))
            .collect()
    }

    fn key_in(slot_owner: impl Fn(u16) -> bool) -> Vec<u8> {
        (0..)
            .map(|i| format!("key:{i}").into_bytes())
            .find(|key| slot_owner(redis_slot(key) as u16))
            .unwrap()
    }

    fn request(keys: &[Vec<u8>]) -> RouteRequest<'_> {
        RouteRequest {
            keys,
            write: true,
            allowed_while_loading: false,
            readonly: false,
            asking: false,
        }
    }

    #[test]
    fn owner_serves_others_move_and_cross_slot_is_rejected() {
        let timeline = timeline("STABLE", 4, 2);
        let addresses = addresses(4);
        let view = timeline.view(0, 0);
        let key = key_in(|slot| view.owner(slot) == Some(1));
        let keys = [key.clone()];
        let slot = redis_slot(&key) as u16;
        assert_eq!(
            route(&timeline, 0, 1, &addresses, &request(&keys)),
            Decision::Serve { slot: Some(slot) }
        );
        assert_eq!(
            route(&timeline, 0, 0, &addresses, &request(&keys)),
            Decision::Error(format!("MOVED {slot} 127.0.0.1:7001"))
        );
        // Node 3 replicates node 1: READONLY reads are served locally,
        // writes and plain reads are redirected.
        let mut read = request(&keys);
        read.write = false;
        assert!(matches!(
            route(&timeline, 0, 3, &addresses, &read),
            Decision::Error(_)
        ));
        read.readonly = true;
        assert_eq!(
            route(&timeline, 0, 3, &addresses, &read),
            Decision::Serve { slot: Some(slot) }
        );
        let other = key_in(|s| s != slot);
        let cross = [key, other];
        assert_eq!(
            route(&timeline, 0, 1, &addresses, &request(&cross)),
            Decision::Error(
                "CROSSSLOT Keys in request don't hash to the same slot"
                    .to_owned()
            )
        );
        assert_eq!(
            route(&timeline, 0, 1, &addresses, &request(&[])),
            Decision::Serve { slot: None }
        );
    }

    #[test]
    fn unassigned_slots_are_not_served_and_stale_views_redirect() {
        let timeline = timeline("PARTIAL SEED 1", 6, 3);
        let addresses = addresses(6);
        let partial = timeline.authoritative(0);
        let hole = key_in(|slot| partial.owner(slot).is_none());
        let keys = [hole.clone()];
        for node in 0..6 {
            assert_eq!(
                route(&timeline, 0, node, &addresses, &request(&keys)),
                Decision::Error("CLUSTERDOWN Hash slot not served".to_owned())
            );
        }
        let last = timeline.stages.len() - 1;
        let owner = timeline
            .authoritative(last)
            .owner(redis_slot(&hole) as u16)
            .unwrap();
        let non_owner = (0..6)
            .find(|n| {
                *n != owner
                    && timeline.authoritative(last).nodes[*n].is_primary()
            })
            .unwrap();
        assert!(matches!(
            route(&timeline, last, non_owner, &addresses, &request(&keys)),
            Decision::Error(error) if error.starts_with("MOVED ")
        ));
    }

    #[test]
    fn lagging_observers_report_assigned_slots_as_unserved() {
        // Search seeds for a hole assignment observed late by a third node;
        // that node answers from its old map while fresh nodes redirect.
        let addresses = addresses(6);
        let found = (0..20).any(|seed| {
            let timeline = timeline(&format!("PARTIAL SEED {seed}"), 6, 3);
            (1..timeline.stages.len()).any(|stage| {
                let entry = &timeline.stages[stage];
                let auth = timeline.authoritative(stage);
                (0..6).any(|node| {
                    let view = &timeline.states[entry.views[node]];
                    let Some(slot) = (0..16_384_u16).find(|s| {
                        view.owner(*s).is_none() && auth.owner(*s).is_some()
                    }) else {
                        return false;
                    };
                    let key = key_in(|s| s == slot);
                    let keys = [key];
                    let owner = auth.owner(slot).unwrap();
                    let fresh = (0..6)
                        .find(|n| *n != owner && entry.views[*n] == entry.auth);
                    route(&timeline, stage, node, &addresses, &request(&keys))
                        == Decision::Error(
                            "CLUSTERDOWN Hash slot not served".to_owned(),
                        )
                        && fresh.is_some_and(|fresh| {
                            route(
                                &timeline,
                                stage,
                                fresh,
                                &addresses,
                                &request(&keys),
                            ) == Decision::Error(format!(
                                "MOVED {slot} 127.0.0.1:{}",
                                7000 + owner
                            ))
                        })
                })
            })
        });
        assert!(found);
    }

    #[test]
    fn full_coverage_and_reads_when_down_control_cluster_down_errors() {
        let addresses = addresses(4);
        for (options, write, expected) in [
            ("", true, "CLUSTERDOWN The cluster is down"),
            (
                "READS_WHEN_DOWN YES",
                true,
                "CLUSTERDOWN The cluster is down and only accepts read commands",
            ),
        ] {
            let timeline = timeline(
                &format!("PARTIAL SEED 1 FULL_COVERAGE YES {options}"),
                4,
                2,
            );
            let view = timeline.view(0, 0);
            let key = key_in(|slot| view.owner(slot) == Some(0));
            let keys = [key];
            let mut req = request(&keys);
            req.write = write;
            assert_eq!(
                route(&timeline, 0, 0, &addresses, &req),
                Decision::Error(expected.to_owned())
            );
        }
        let timeline = timeline(
            "PARTIAL SEED 1 FULL_COVERAGE YES READS_WHEN_DOWN YES",
            4,
            2,
        );
        let view = timeline.view(0, 0);
        let keys = [key_in(|slot| view.owner(slot) == Some(0))];
        let mut read = request(&keys);
        read.write = false;
        assert!(matches!(
            route(&timeline, 0, 0, &addresses, &read),
            Decision::Serve { .. }
        ));
    }

    #[test]
    fn down_nodes_close_and_loading_replicas_reject_data_commands() {
        let timeline = timeline("FAILOVER SEED 1 SHARDS 2 REPLICAS 1", 4, 2);
        let addresses = addresses(4);
        let unreachable = timeline
            .stages
            .iter()
            .position(|s| s.label.contains("PFAIL"))
            .unwrap();
        let down = (0..4)
            .find(|n| timeline.authoritative(unreachable).nodes[*n].down)
            .unwrap();
        assert_eq!(
            route(&timeline, unreachable, down, &addresses, &request(&[])),
            Decision::Close
        );
        let loading = timeline
            .stages
            .iter()
            .position(|s| s.label.contains("loading"))
            .unwrap();
        assert_eq!(
            route(&timeline, loading, down, &addresses, &request(&[])),
            Decision::Error(LOADING.to_owned())
        );
        let mut ping = request(&[]);
        ping.allowed_while_loading = true;
        assert_eq!(
            route(&timeline, loading, down, &addresses, &ping),
            Decision::Serve { slot: None }
        );
    }

    #[test]
    fn migrating_slots_ask_tryagain_and_accept_asking_at_the_target() {
        let timeline = timeline("RESHARD SEED 3", 2, 2);
        let addresses = addresses(2);
        let stage = timeline
            .stages
            .iter()
            .position(|s| s.label.contains("migrating"))
            .unwrap();
        let migration = timeline.authoritative(stage).migrations[0];
        let seed = timeline.config.seed;
        let in_range = |moved: bool| {
            (0..)
                .map(|i| format!("{{t{i}}}k").into_bytes())
                .find(|key| {
                    migration.contains(redis_slot(key) as u16)
                        && key_moved(seed, key, migration.progress) == moved
                })
                .unwrap()
        };
        let moved = in_range(true);
        let stayed = in_range(false);
        let slot = redis_slot(&moved) as u16;
        let target = format!("127.0.0.1:{}", 7000 + migration.to);
        let moved_keys = [moved.clone()];
        assert_eq!(
            route(
                &timeline,
                stage,
                migration.from,
                &addresses,
                &request(&moved_keys)
            ),
            Decision::Error(format!("ASK {slot} {target}"))
        );
        let stayed_keys = [stayed.clone()];
        assert!(matches!(
            route(
                &timeline,
                stage,
                migration.from,
                &addresses,
                &request(&stayed_keys)
            ),
            Decision::Serve { .. }
        ));
        // The target redirects back to the owner unless the client sent ASKING.
        assert!(matches!(
            route(&timeline, stage, migration.to, &addresses, &request(&moved_keys)),
            Decision::Error(error) if error.starts_with("MOVED ")
        ));
        let mut asking = request(&moved_keys);
        asking.asking = true;
        assert!(matches!(
            route(&timeline, stage, migration.to, &addresses, &asking),
            Decision::Serve { .. }
        ));
        // Same-slot multi-key with keys on both sides of the migration.
        let tag = |key: &[u8]| {
            let text = String::from_utf8(key.to_vec()).unwrap();
            text[1..text.find('}').unwrap()].to_owned()
        };
        let mixed_partner = (0..)
            .map(|i| format!("{{{}}}m{i}", tag(&moved)).into_bytes())
            .find(|key| !key_moved(seed, key, migration.progress))
            .unwrap();
        let mixed = [moved, mixed_partner];
        assert_eq!(
            route(
                &timeline,
                stage,
                migration.from,
                &addresses,
                &request(&mixed)
            ),
            Decision::Error(
                "TRYAGAIN Multiple keys request during rehashing of slot"
                    .to_owned()
            )
        );
        let mut asking = request(&mixed);
        asking.asking = true;
        assert_eq!(
            route(&timeline, stage, migration.to, &addresses, &asking),
            Decision::Error(
                "TRYAGAIN Multiple keys request during rehashing of slot"
                    .to_owned()
            )
        );
    }
}
