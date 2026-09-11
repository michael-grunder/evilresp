//! Legacy mixed topology mutation and focused, bounded redirection injection.

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

use crate::cli::TcpEndpoint;
use crate::cluster::ClusterRedirectionMap;
use crate::error::AppResult;
use crate::evil::{AppliedMutation, EvilConfig, MutationKind};
use crate::resp::{Frame, parse_frame};
use crate::topology_config::{
    RedirectKind, RedirectPhase, RedirectSlot, RedirectTarget,
};

const CLUSTER_SLOT_COUNT: i32 = 16_384;

#[derive(Clone, Debug)]
pub struct TopologyMutation {
    pub frame: Frame,
    pub mutations: Vec<AppliedMutation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RedirectionKind {
    Moved,
    Ask,
}

#[derive(Clone, Debug)]
struct Redirection {
    kind: RedirectionKind,
    slot: i32,
    server: String,
}

pub fn maybe_mutate_topology(
    config: &EvilConfig,
    command_index: u64,
    command_hash: &str,
    command: &Frame,
    upstream_bytes: Option<&[u8]>,
    local_slots: &Frame,
) -> AppResult<Option<TopologyMutation>> {
    if config.topology_probability <= 0.0 || config.topology_redirect.is_some()
    {
        return Ok(None);
    }

    let upstream_hash = upstream_bytes
        .map(crate::evil::deterministic_hash)
        .unwrap_or_default();
    let mut rng =
        topology_rng(config.seed, command_index, command_hash, &upstream_hash);
    let targets = redirection_targets(local_slots);
    if targets.is_empty() {
        return Ok(None);
    }

    let upstream = match upstream_bytes {
        Some(bytes) => parse_redirection(&parse_frame(bytes)?),
        None => None,
    };

    let (mut redirection, mut mutations) = match upstream {
        Some(redirection) => (redirection, Vec::new()),
        None => {
            if !should_apply(config.topology_probability, &mut rng) {
                return Ok(None);
            }

            (
                fake_redirection(command, &targets, &mut rng),
                vec![AppliedMutation {
                    path: "topology".to_owned(),
                    kind: MutationKind::TopologyFakeRedirection,
                    length: None,
                }],
            )
        }
    };

    apply_redirection_mutations(
        &mut redirection,
        &targets,
        config.topology_probability,
        &mut rng,
        &mut mutations,
    );

    if mutations.is_empty() {
        return Ok(None);
    }

    Ok(Some(TopologyMutation {
        frame: redirection.to_frame(),
        mutations,
    }))
}

pub(crate) struct RedirectContext<'a> {
    pub command_index: u64,
    pub command_hash: &'a str,
    pub command: &'a Frame,
    pub upstream_bytes: Option<&'a [u8]>,
    pub local_slots: &'a Frame,
    pub listener: Option<&'a TcpEndpoint>,
}

pub(crate) fn configured_redirection(
    config: &EvilConfig,
    context: RedirectContext<'_>,
) -> Option<TopologyMutation> {
    let redirect = config.topology_redirect.as_ref()?;
    if config.topology_probability <= 0.0
        || redirect
            .until
            .is_some_and(|end| context.command_index >= end)
        || (redirect.phase == RedirectPhase::Before)
            != context.upstream_bytes.is_none()
    {
        return None;
    }

    let upstream_hash = context
        .upstream_bytes
        .map(crate::evil::deterministic_hash)
        .unwrap_or_default();
    let mut rng = topology_rng(
        config.seed,
        context.command_index,
        context.command_hash,
        &upstream_hash,
    );
    if !should_apply(config.topology_probability, &mut rng) {
        return None;
    }

    let correct_slot = match redirect.slot {
        RedirectSlot::Fixed(slot) => i32::from(slot),
        _ => command_slot(context.command, redirect.key)?,
    };
    let nodes = RedirectNodes::from_slots(context.local_slots, correct_slot);
    let listener = context.listener.map(TcpEndpoint::connect_addr);
    let server = match &redirect.target {
        RedirectTarget::Endpoint(endpoint) => endpoint.connect_addr(),
        RedirectTarget::SelfNode => {
            let listener = listener?;
            if !nodes.all.contains(&listener) {
                return None;
            }
            listener
        }
        RedirectTarget::WrongNode => {
            wrong_server(nodes.owner.as_ref()?, &nodes.primaries, &mut rng)?
        }
        RedirectTarget::Replica => choose(&nodes.replicas, &mut rng)?,
        RedirectTarget::Random => choose(&nodes.primaries, &mut rng)?,
        RedirectTarget::Next => {
            let listener = listener?;
            if nodes.primaries.len() < 2 || !nodes.all.contains(&listener) {
                return None;
            }
            let next = nodes
                .primaries
                .iter()
                .position(|node| node == &listener)
                .map_or(0, |index| (index + 1) % nodes.primaries.len());
            nodes.primaries[next].clone()
        }
    };
    let slot = match redirect.slot {
        RedirectSlot::Correct | RedirectSlot::Fixed(_) => correct_slot,
        RedirectSlot::Wrong => wrong_valid_slot(correct_slot, &mut rng),
        RedirectSlot::Wild => {
            let value = rng.r#gen::<i32>();
            if (0..CLUSTER_SLOT_COUNT).contains(&value) {
                -1
            } else {
                value
            }
        }
    };
    let kind = match redirect.kind {
        RedirectKind::Moved => RedirectionKind::Moved,
        RedirectKind::Ask => RedirectionKind::Ask,
        RedirectKind::Random => {
            if rng.r#gen() {
                RedirectionKind::Moved
            } else {
                RedirectionKind::Ask
            }
        }
    };
    Some(TopologyMutation {
        frame: Redirection { kind, slot, server }.to_frame(),
        mutations: vec![AppliedMutation {
            path: "topology".to_owned(),
            kind: match redirect.phase {
                RedirectPhase::Before => MutationKind::TopologyRedirectBefore,
                RedirectPhase::After => MutationKind::TopologyRedirectAfter,
            },
            length: None,
        }],
    })
}

fn choose(targets: &[String], rng: &mut ChaCha20Rng) -> Option<String> {
    if targets.is_empty() {
        None
    } else {
        Some(targets[rng.gen_range(0..targets.len())].clone())
    }
}

fn command_slot(command: &Frame, key: usize) -> Option<i32> {
    let bytes = match command {
        Frame::Array(Some(items)) => match items.get(key)? {
            Frame::BulkString(Some(bytes)) | Frame::VerbatimString(bytes) => {
                bytes
            }
            Frame::SimpleString(value) => value.as_bytes(),
            _ => return None,
        },
        Frame::Inline(parts) => parts.get(key)?,
        _ => return None,
    };
    Some(redis_slot(bytes))
}

#[derive(Default)]
struct RedirectNodes {
    primaries: Vec<String>,
    all: Vec<String>,
    owner: Option<String>,
    replicas: Vec<String>,
}

impl RedirectNodes {
    fn from_slots(slots: &Frame, slot: i32) -> Self {
        let mut result = Self::default();
        let Frame::Array(Some(ranges)) = slots else {
            return result;
        };
        for range in ranges {
            let Frame::Array(Some(parts)) = range else {
                continue;
            };
            let [
                Frame::Integer(start),
                Frame::Integer(end),
                primary,
                replicas @ ..,
            ] = parts.as_slice()
            else {
                continue;
            };
            let Some(primary) = node_endpoint(primary) else {
                continue;
            };
            if !result.primaries.contains(&primary) {
                result.primaries.push(primary.clone());
            }
            let owns_slot = (*start..=*end).contains(&i64::from(slot));
            if owns_slot {
                result.owner = Some(primary.clone());
            }
            if !result.all.contains(&primary) {
                result.all.push(primary);
            }
            for replica in replicas.iter().filter_map(node_endpoint) {
                if owns_slot && !result.replicas.contains(&replica) {
                    result.replicas.push(replica.clone());
                }
                if !result.all.contains(&replica) {
                    result.all.push(replica);
                }
            }
        }
        result
    }
}

fn node_endpoint(node: &Frame) -> Option<String> {
    let Frame::Array(Some(parts)) = node else {
        return None;
    };
    let host = frame_string(parts.first()?)?;
    let Frame::Integer(port) = parts.get(1)? else {
        return None;
    };
    Some(
        TcpEndpoint {
            host,
            port: u16::try_from(*port).ok()?,
        }
        .connect_addr(),
    )
}

/// Rewrite a cluster redirection, or return a local error if its target has
/// no listener. Non-redirection replies return `None` and pass through.
pub fn normalize_redirection(
    frame: &Frame,
    redirection_map: &ClusterRedirectionMap,
) -> Option<Frame> {
    let mut redirection = parse_redirection(frame)?;
    let Some(server) = redirection_map.rewrite_server(&redirection.server)
    else {
        return Some(Frame::SimpleError(
            "ERR evilresp has no local listener for redirection target"
                .to_owned(),
        ));
    };
    redirection.server = server;
    Some(redirection.to_matching_frame(frame))
}

fn parse_redirection(frame: &Frame) -> Option<Redirection> {
    let value = match frame {
        Frame::SimpleError(value) => value.as_str(),
        Frame::BulkError(bytes) => std::str::from_utf8(bytes).ok()?,
        _ => return None,
    };
    let mut parts = value.split_whitespace();
    let kind = match parts.next()? {
        code if code.eq_ignore_ascii_case("MOVED") => RedirectionKind::Moved,
        code if code.eq_ignore_ascii_case("ASK")
            || code.eq_ignore_ascii_case("ASKING") =>
        {
            RedirectionKind::Ask
        }
        _ => return None,
    };
    let slot = parts.next()?.parse::<i32>().ok()?;
    let server = parts.next()?.to_owned();

    Some(Redirection { kind, slot, server })
}

fn fake_redirection(
    command: &Frame,
    targets: &[String],
    rng: &mut ChaCha20Rng,
) -> Redirection {
    let slot = command
        .argv_lossy()
        .get(1)
        .map(|key| redis_slot(key.as_bytes()))
        .unwrap_or_else(|| rng.gen_range(0..CLUSTER_SLOT_COUNT));
    let server = targets[rng.gen_range(0..targets.len())].clone();
    let kind = if rng.r#gen() {
        RedirectionKind::Moved
    } else {
        RedirectionKind::Ask
    };

    Redirection { kind, slot, server }
}

fn apply_redirection_mutations(
    redirection: &mut Redirection,
    targets: &[String],
    probability: f64,
    rng: &mut ChaCha20Rng,
    mutations: &mut Vec<AppliedMutation>,
) {
    if should_apply(probability, rng) {
        redirection.kind = match redirection.kind {
            RedirectionKind::Moved => RedirectionKind::Ask,
            RedirectionKind::Ask => RedirectionKind::Moved,
        };
        mutations.push(AppliedMutation {
            path: "topology.kind".to_owned(),
            kind: MutationKind::TopologyWrongRedirectionKind,
            length: None,
        });
    }

    if should_apply(probability, rng) {
        redirection.slot = wrong_valid_slot(redirection.slot, rng);
        mutations.push(AppliedMutation {
            path: "topology.slot".to_owned(),
            kind: MutationKind::TopologyWrongSlot,
            length: None,
        });
    }

    if should_apply(probability, rng)
        && let Some(server) = wrong_server(&redirection.server, targets, rng)
    {
        redirection.server = server;
        mutations.push(AppliedMutation {
            path: "topology.server".to_owned(),
            kind: MutationKind::TopologyWrongServer,
            length: None,
        });
    }

    if should_apply(probability, rng) {
        redirection.slot = rng.r#gen::<i32>();
        mutations.push(AppliedMutation {
            path: "topology.slot".to_owned(),
            kind: MutationKind::TopologyWildSlot,
            length: None,
        });
    }
}

fn wrong_valid_slot(current: i32, rng: &mut ChaCha20Rng) -> i32 {
    let mut slot = rng.gen_range(0..CLUSTER_SLOT_COUNT);
    if slot == current {
        slot = (slot + 1) % CLUSTER_SLOT_COUNT;
    }
    slot
}

fn wrong_server(
    current: &str,
    targets: &[String],
    rng: &mut ChaCha20Rng,
) -> Option<String> {
    let alternatives = targets
        .iter()
        .filter(|target| target.as_str() != current)
        .collect::<Vec<_>>();
    if !alternatives.is_empty() {
        return Some(
            alternatives[rng.gen_range(0..alternatives.len())].clone(),
        );
    }

    None
}

impl Redirection {
    fn to_frame(&self) -> Frame {
        Frame::SimpleError(self.to_string())
    }

    fn to_matching_frame(&self, original: &Frame) -> Frame {
        match original {
            Frame::BulkError(_) => Frame::BulkError(self.to_string().into()),
            _ => self.to_frame(),
        }
    }
}

impl std::fmt::Display for Redirection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} {} {}",
            self.kind.as_str(),
            self.slot,
            self.server
        )
    }
}

impl RedirectionKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Moved => "MOVED",
            Self::Ask => "ASK",
        }
    }
}

fn redirection_targets(slots: &Frame) -> Vec<String> {
    let Frame::Array(Some(ranges)) = slots else {
        return Vec::new();
    };

    ranges
        .iter()
        .filter_map(|range| {
            let Frame::Array(Some(parts)) = range else {
                return None;
            };
            let Frame::Array(Some(node)) = parts.get(2)? else {
                return None;
            };
            let host = frame_string(node.first()?)?;
            let port = match node.get(1)? {
                Frame::Integer(port) => u16::try_from(*port).ok()?,
                _ => return None,
            };
            Some(format!("{host}:{port}"))
        })
        .collect()
}

fn frame_string(frame: &Frame) -> Option<String> {
    match frame {
        Frame::BulkString(Some(bytes)) | Frame::VerbatimString(bytes) => {
            Some(String::from_utf8_lossy(bytes).into_owned())
        }
        Frame::SimpleString(value) => Some(value.clone()),
        _ => None,
    }
}

fn redis_slot(key: &[u8]) -> i32 {
    i32::from(crc16_xmodem(key_tag(key)) % CLUSTER_SLOT_COUNT as u16)
}

fn key_tag(key: &[u8]) -> &[u8] {
    let Some(open) = key.iter().position(|byte| *byte == b'{') else {
        return key;
    };
    let tag_start = open + 1;
    let Some(close_offset) =
        key[tag_start..].iter().position(|byte| *byte == b'}')
    else {
        return key;
    };
    if close_offset == 0 {
        return key;
    }
    &key[tag_start..tag_start + close_offset]
}

fn crc16_xmodem(bytes: &[u8]) -> u16 {
    let mut crc = 0_u16;
    for byte in bytes {
        crc ^= u16::from(*byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

fn should_apply(probability: f64, rng: &mut ChaCha20Rng) -> bool {
    probability > 0.0 && rng.gen_range(0.0..100.0) < probability
}

fn topology_rng(
    seed: u64,
    command_index: u64,
    command_hash: &str,
    upstream_hash: &str,
) -> ChaCha20Rng {
    let mut digest = Sha256::new();
    digest.update(b"evilresp-topology");
    digest.update(seed.to_le_bytes());
    digest.update(command_index.to_le_bytes());
    digest.update(command_hash.as_bytes());
    digest.update(upstream_hash.as_bytes());
    let bytes: [u8; 32] = digest.finalize().into();
    ChaCha20Rng::from_seed(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::TcpEndpoint;
    use crate::evil::EvilMode;

    fn focused_slots() -> Frame {
        fn node(host: &str, port: i64) -> Frame {
            Frame::Array(Some(vec![
                Frame::BulkString(Some(host.as_bytes().to_vec())),
                Frame::Integer(port),
            ]))
        }
        let first = Frame::Array(Some(vec![
            Frame::Integer(0),
            Frame::Integer(8191),
            node("127.0.0.1", 6380),
        ]));
        let second = Frame::Array(Some(vec![
            Frame::Integer(8192),
            Frame::Integer(16383),
            node("127.0.0.1", 6381),
            node("::1", 6382),
        ]));
        // Repeated range entries must not weight destination selection.
        Frame::Array(Some(vec![first, second.clone(), second]))
    }

    fn focused(
        options: &str,
        command: &Frame,
        index: u64,
        listener: &str,
        upstream: Option<&[u8]>,
    ) -> Option<TopologyMutation> {
        let mut config = EvilConfig::default();
        config.seed = 1234;
        config
            .apply_debug_command(
                &format!("DEBUG EVIL TOPOLOGY REDIRECT {options}")
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        configured_redirection(
            &config,
            RedirectContext {
                command_index: index,
                command_hash: &crate::evil::deterministic_hash(
                    &command.encode(),
                ),
                command,
                upstream_bytes: upstream,
                local_slots: &focused_slots(),
                listener: Some(&listener.parse().unwrap()),
            },
        )
    }

    #[test]
    fn focused_redirects_choose_exact_kind_slot_and_destination() {
        let command = parse_frame(b"GET foo\r\n").unwrap();
        for kind in ["MOVED", "ASK"] {
            for (target, destination) in [
                ("WRONG_NODE", "127.0.0.1:6380"),
                ("SELF", "127.0.0.1:6381"),
                ("NEXT", "127.0.0.1:6380"),
                ("REPLICA", "[::1]:6382"),
                ("unknown.invalid:7999", "unknown.invalid:7999"),
                ("[::2]:7999", "[::2]:7999"),
            ] {
                let options = format!("KIND {kind} TARGET {target}");
                let mutation =
                    focused(&options, &command, 9, "127.0.0.1:6381", None)
                        .unwrap();
                assert_eq!(
                    mutation.frame.encode(),
                    format!("-{kind} 12182 {destination}\r\n").as_bytes()
                );
                assert_eq!(mutation.mutations.len(), 1);
                assert_eq!(
                    mutation.mutations[0].kind,
                    MutationKind::TopologyRedirectBefore
                );
                assert_eq!(
                    focused(&options, &command, 9, "127.0.0.1:6381", None)
                        .unwrap()
                        .frame,
                    mutation.frame
                );
            }
        }
        let nodes = RedirectNodes::from_slots(&focused_slots(), 12182);
        assert_eq!(nodes.primaries, ["127.0.0.1:6380", "127.0.0.1:6381"]);
        assert_eq!(nodes.replicas, ["[::1]:6382"]);
    }

    #[test]
    fn focused_redirects_respect_phase_probability_cutoff_and_eligibility() {
        let command = parse_frame(b"GET foo\r\n").unwrap();
        for options in ["PROBABILITY 0", "UNTIL 9", "UNTIL 0", "PHASE AFTER"] {
            assert!(
                focused(options, &command, 9, "127.0.0.1:6381", None).is_none(),
                "{options}"
            );
        }
        assert!(
            focused("", &command, 9, "127.0.0.1:6381", Some(b"+OK\r\n"))
                .is_none()
        );
        let mutation = focused(
            "PHASE AFTER KIND ASK",
            &command,
            9,
            "127.0.0.1:6381",
            Some(b"-MOVED 12182 127.0.0.1:6381\r\n"),
        )
        .unwrap();
        assert_eq!(mutation.frame.encode(), b"-ASK 12182 127.0.0.1:6380\r\n");
        assert_eq!(
            mutation.mutations[0].kind,
            MutationKind::TopologyRedirectAfter
        );
        assert!(
            focused("UNTIL 10", &command, 9, "127.0.0.1:6381", None).is_some()
        );
        for options in ["TARGET SELF", "TARGET NEXT"] {
            assert!(
                focused(options, &command, 9, "127.0.0.1:7999", None).is_none()
            );
        }
        let command = parse_frame(b"PING\r\n").unwrap();
        assert!(focused("", &command, 9, "127.0.0.1:6381", None).is_none());
        assert_eq!(
            focused("SLOT 42", &command, 9, "127.0.0.1:6380", None)
                .unwrap()
                .frame
                .encode(),
            b"-MOVED 42 127.0.0.1:6381\r\n"
        );
        let command = parse_frame(b"GET bar\r\n").unwrap();
        // The shard containing bar has no replica: do not substitute a primary.
        assert!(
            focused("TARGET REPLICA", &command, 9, "127.0.0.1:6380", None)
                .is_none()
        );
    }

    #[test]
    fn correct_slots_use_binary_keys_and_explicit_argument_indexes() {
        for (key, slot) in [
            (b"\xff{foo}\x00".as_slice(), 12182),
            // CRC16/XMODEM over the raw bytes, including non-UTF-8 and NUL.
            (b"\xfffoo\x00".as_slice(), 2218),
        ] {
            let command = Frame::Array(Some(vec![
                Frame::BulkString(Some(b"GET".to_vec())),
                Frame::BulkString(Some(key.to_vec())),
            ]));
            assert_eq!(
                focused("TARGET SELF", &command, 9, "127.0.0.1:6381", None)
                    .unwrap()
                    .frame
                    .encode(),
                format!("-MOVED {slot} 127.0.0.1:6381\r\n").as_bytes()
            );
        }
        let command = parse_frame(b"EVAL script 1 foo\r\n").unwrap();
        assert_eq!(
            focused("KEY 3", &command, 9, "127.0.0.1:6381", None)
                .unwrap()
                .frame
                .encode(),
            b"-MOVED 12182 127.0.0.1:6380\r\n"
        );
        assert!(
            focused("KEY 4", &command, 9, "127.0.0.1:6381", None).is_none()
        );
    }

    #[test]
    fn random_kind_and_bad_slots_are_seeded_and_stay_in_their_categories() {
        let command = parse_frame(b"GET foo\r\n").unwrap();
        for options in ["KIND RANDOM TARGET RANDOM", "SLOT WRONG", "SLOT WILD"]
        {
            for index in 0..32 {
                let first =
                    focused(options, &command, index, "127.0.0.1:6381", None)
                        .unwrap();
                let second =
                    focused(options, &command, index, "127.0.0.1:6381", None)
                        .unwrap();
                assert_eq!(first.frame.encode(), second.frame.encode());
                let parsed = parse_redirection(&first.frame).unwrap();
                match options {
                    "SLOT WRONG" => {
                        assert!((0..16384).contains(&parsed.slot));
                        assert_ne!(parsed.slot, 12182);
                    }
                    "SLOT WILD" => assert!(!(0..16384).contains(&parsed.slot)),
                    _ => assert!(
                        ["127.0.0.1:6380", "127.0.0.1:6381"]
                            .contains(&parsed.server.as_str())
                    ),
                }
            }
        }
    }

    #[test]
    fn topology_mutation_can_fake_redirection_without_upstream() {
        let mut config = EvilConfig::default();
        config.seed = 1234;
        config.topology_probability = 100.0;
        let command = parse_frame(b"*2\r\n$3\r\nGET\r\n$3\r\nfoo\r\n").unwrap();
        let slots = parse_frame(
            b"*1\r\n*3\r\n:0\r\n:16383\r\n*2\r\n$9\r\n127.0.0.1\r\n:7000\r\n",
        )
        .unwrap();

        let mutated = maybe_mutate_topology(
            &config, 9, "command", &command, None, &slots,
        )
        .unwrap()
        .unwrap();

        let encoded = mutated.frame.encode();
        assert!(
            encoded.starts_with(b"-MOVED ") || encoded.starts_with(b"-ASK ")
        );
        assert!(
            mutated.mutations.iter().any(|mutation| mutation.kind
                == MutationKind::TopologyFakeRedirection)
        );
    }

    #[test]
    fn topology_mutation_rewrites_real_redirection() {
        let mut config = EvilConfig::default();
        config.seed = 1234;
        config.topology_probability = 100.0;
        config.mode = EvilMode::Off;
        let command = parse_frame(b"*2\r\n$3\r\nGET\r\n$3\r\nfoo\r\n").unwrap();
        let slots = parse_frame(
            b"*2\r\n*3\r\n:0\r\n:8191\r\n*2\r\n$9\r\n127.0.0.1\r\n:7000\r\n*3\r\n:8192\r\n:16383\r\n*2\r\n$9\r\n127.0.0.1\r\n:7001\r\n",
        )
        .unwrap();

        let mutated = maybe_mutate_topology(
            &config,
            9,
            "command",
            &command,
            Some(b"-MOVED 12182 127.0.0.1:7000\r\n"),
            &slots,
        )
        .unwrap()
        .unwrap();

        assert_ne!(mutated.frame.encode(), b"-MOVED 12182 127.0.0.1:7000\r\n");
        assert!(
            mutated
                .mutations
                .iter()
                .any(|mutation| mutation.kind == MutationKind::TopologyWildSlot)
        );
    }

    #[test]
    fn normalizes_upstream_redirection_to_local_proxy_endpoint() {
        let map = ClusterRedirectionMap::from_mappings([(
            TcpEndpoint {
                host: "127.0.0.1".to_owned(),
                port: 7002,
            },
            "127.0.0.1:6382".to_owned(),
        )]);
        let frame = parse_frame(b"-MOVED 12182 127.0.0.1:7002\r\n").unwrap();

        let normalized = normalize_redirection(&frame, &map).unwrap();

        assert_eq!(normalized.encode(), b"-MOVED 12182 127.0.0.1:6382\r\n");
    }

    #[test]
    fn normalizes_bulk_ask_and_rejects_unmapped_targets() {
        let map = ClusterRedirectionMap::from_mappings([(
            "127.0.0.1:7002".parse().unwrap(),
            "127.0.0.1:6382".to_owned(),
        )]);
        let frame = Frame::BulkError(b"ASK 12182 127.0.0.1:7002".to_vec());
        assert_eq!(
            normalize_redirection(&frame, &map),
            Some(Frame::BulkError(b"ASK 12182 127.0.0.1:6382".to_vec(),))
        );
        let frame = Frame::BulkError(b"ASK 12182 127.0.0.1:7999".to_vec());
        assert_eq!(
            normalize_redirection(&frame, &map),
            Some(Frame::SimpleError(
                "ERR evilresp has no local listener for redirection target"
                    .to_owned(),
            ))
        );
        assert!(
            normalize_redirection(
                &Frame::SimpleError("ERR example".to_owned()),
                &map
            )
            .is_none()
        );
    }

    #[test]
    fn redis_slot_honors_hash_tags() {
        assert_eq!(redis_slot(b"foo{bar}zap"), redis_slot(b"{bar}"));
        assert_ne!(redis_slot(b"foo{}{bar}"), redis_slot(b"{bar}"));
    }
}
