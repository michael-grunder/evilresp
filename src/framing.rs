//! Select length headers from typed frames and corrupt only their encoding.
//! Advertised lengths never control allocation or traversal of frame bodies.
//! `DEPTH INNER` weights `TARGET ANY` toward nested headers and halves the
//! automatic root fault's probability per nesting level of the reply.

use rand::Rng;
use rand_chacha::ChaCha20Rng;

use crate::error::{AppError, AppResult};
use crate::evil::{
    AppliedMutation, EvilConfig, EvilMode, LengthCorruption, LengthMutation,
    MutatedReply, MutationCount, MutationDepth, MutationKind,
    parse_probability,
};
use crate::resp::Frame;

#[derive(Clone, Debug)]
pub(crate) enum FramingConfig {
    Auto,
    Off,
    Length(LengthConfig),
}

#[derive(Clone, Debug)]
pub(crate) struct LengthConfig {
    probability: f64,
    target: Target,
    kind: Option<LengthCorruption>,
}

#[derive(Clone, Debug)]
enum Target {
    Any,
    Path(String),
}

impl Target {
    fn parse(value: &str) -> AppResult<Self> {
        if value.eq_ignore_ascii_case("ANY") {
            return Ok(Self::Any);
        }
        let mut parts = value.split('.');
        if !parts
            .next()
            .is_some_and(|part| part.eq_ignore_ascii_case("root"))
        {
            return Err(invalid("TARGET requires ANY or a root frame path"));
        }
        let mut path = "root".to_owned();
        let mut after_index = false;
        for part in parts {
            let part = part.to_ascii_lowercase();
            path.push('.');
            if after_index && matches!(part.as_str(), "key" | "value") {
                path.push_str(&part);
                after_index = false;
            } else if !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_digit())
            {
                let index = part
                    .parse::<usize>()
                    .map_err(|_| invalid("frame path index is too large"))?;
                path.push_str(&index.to_string());
                after_index = true;
            } else {
                return Err(invalid(
                    "invalid frame path: use root, numeric children, and .key/.value after a pair index",
                ));
            }
        }
        Ok(Self::Path(path))
    }

    fn as_str(&self) -> &str {
        match self {
            Self::Any => "ANY",
            Self::Path(path) => path,
        }
    }

    fn matches(&self, path: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Path(target) => target == path,
        }
    }
}

impl FramingConfig {
    pub(crate) fn parse(argv: &[String]) -> AppResult<Self> {
        let Some(mode) = argv.first() else {
            return Err(invalid("FRAMING requires AUTO, OFF, or LENGTH"));
        };
        match mode.to_ascii_uppercase().as_str() {
            "AUTO" | "OFF" if argv.len() != 1 => {
                Err(invalid("FRAMING AUTO and OFF do not accept options"))
            }
            "AUTO" => Ok(Self::Auto),
            "OFF" => Ok(Self::Off),
            "LENGTH" => {
                let mut config = LengthConfig {
                    probability: 100.0,
                    target: Target::Any,
                    kind: None,
                };
                let mut seen = [false; 3];
                let (options, remainder) = argv[1..].as_chunks::<2>();
                if !remainder.is_empty() {
                    return Err(invalid(
                        "FRAMING LENGTH options require a value",
                    ));
                }
                for option in options {
                    let index = match option[0].to_ascii_uppercase().as_str() {
                        "PROBABILITY" => {
                            config.probability = parse_probability(&option[1])?;
                            0
                        }
                        "TARGET" => {
                            config.target = Target::parse(&option[1])?;
                            1
                        }
                        "KIND" => {
                            config.kind = match option[1]
                                .to_ascii_uppercase()
                                .as_str()
                            {
                                "RANDOM" => None,
                                "SHORTER" => Some(LengthCorruption::Shorter),
                                "LONGER" => Some(LengthCorruption::Longer),
                                "NEGATIVE" => Some(LengthCorruption::Negative),
                                "BOUNDARY" => Some(LengthCorruption::Boundary),
                                "OVERFLOW" => Some(LengthCorruption::Overflow),
                                _ => {
                                    return Err(invalid(
                                        "KIND requires RANDOM, SHORTER, LONGER, NEGATIVE, BOUNDARY, or OVERFLOW",
                                    ));
                                }
                            };
                            2
                        }
                        _ => {
                            return Err(invalid(
                                "FRAMING LENGTH accepts PROBABILITY, TARGET, and KIND",
                            ));
                        }
                    };
                    if seen[index] {
                        return Err(invalid("duplicate FRAMING LENGTH option"));
                    }
                    seen[index] = true;
                }
                Ok(Self::Length(config))
            }
            _ => Err(invalid("FRAMING requires AUTO, OFF, or LENGTH")),
        }
    }

    pub(crate) fn status(&self) -> String {
        match self {
            Self::Auto => "framing=AUTO".to_owned(),
            Self::Off => "framing=OFF".to_owned(),
            Self::Length(config) => format!(
                "framing=LENGTH framing_probability={:.2} framing_target={} framing_kind={}",
                config.probability,
                config.target.as_str(),
                config.kind.map(kind_name).unwrap_or("RANDOM"),
            ),
        }
    }
}

fn invalid(message: &str) -> AppError {
    AppError::EvilConfig(message.to_owned())
}

fn kind_name(kind: LengthCorruption) -> &'static str {
    match kind {
        LengthCorruption::Shorter => "SHORTER",
        LengthCorruption::Longer => "LONGER",
        LengthCorruption::Negative => "NEGATIVE",
        LengthCorruption::Boundary => "BOUNDARY",
        LengthCorruption::Overflow => "OVERFLOW",
    }
}

struct Header {
    index: usize,
    path: String,
    original: i128,
}

pub(crate) fn mutate_length(
    frame: &Frame,
    config: &EvilConfig,
    rng: &mut ChaCha20Rng,
) -> Option<MutatedReply> {
    let (header, kind, replacement) = match &config.framing {
        FramingConfig::Off => return None,
        FramingConfig::Auto => {
            // Preserve the legacy draw order and root-only behavior. INNER
            // treats the root header like any other depth-weighted target.
            if config.mutation_count == MutationCount::One {
                return None;
            }
            let probability =
                config.depth.scale(config.probability, 0, tree_depth(frame));
            if !should_apply(probability, rng) {
                return None;
            }
            let original = frame.declared_length()?;
            let (kind, replacement) = if config.mode == EvilMode::Overflow {
                (LengthCorruption::Boundary, i64::MAX.to_string())
            } else {
                (LengthCorruption::Longer, (original + 1).to_string())
            };
            (
                Header {
                    index: 0,
                    path: "root".to_owned(),
                    original,
                },
                kind,
                replacement,
            )
        }
        FramingConfig::Length(options) => {
            if !should_apply(options.probability, rng) {
                return None;
            }
            let header =
                select_header(frame, &options.target, config.depth, rng)?;
            let kind = options.kind.unwrap_or_else(|| {
                const KINDS: [LengthCorruption; 5] = [
                    LengthCorruption::Shorter,
                    LengthCorruption::Longer,
                    LengthCorruption::Negative,
                    LengthCorruption::Boundary,
                    LengthCorruption::Overflow,
                ];
                KINDS[rng.gen_range(0..KINDS.len())]
            });
            let replacement = corrupt_length(header.original, kind, rng);
            (header, kind, replacement)
        }
    };
    Some(MutatedReply {
        bytes: frame.encode_with_length(header.index, &replacement),
        mutations: vec![AppliedMutation {
            path: header.path,
            kind: MutationKind::WrongLength,
            exec: None,
            length: Some(LengthMutation {
                kind,
                original: header.original.to_string(),
                replacement,
            }),
        }],
    })
}

fn should_apply(probability: f64, rng: &mut ChaCha20Rng) -> bool {
    probability > 0.0 && rng.gen_range(0.0..100.0) < probability
}

fn select_header(
    frame: &Frame,
    target: &Target,
    depth: MutationDepth,
    rng: &mut ChaCha20Rng,
) -> Option<Header> {
    if matches!(target, Target::Any) && depth == MutationDepth::Inner {
        return select_weighted_header(frame, depth, rng);
    }
    let mut index = 0;
    let mut candidates = 0_usize;
    let mut selected = None;
    visit(frame, "root", 0, &mut |frame, path, _| {
        if let Some(original) = frame.declared_length()
            && target.matches(path)
        {
            candidates += 1;
            // Reservoir selection uses constant candidate storage.
            if candidates == 1 || rng.gen_range(0..candidates) == 0 {
                selected = Some(Header {
                    index,
                    path: path.to_owned(),
                    original,
                });
            }
        }
        index += 1;
    });
    selected
}

/// Select any length header with probability proportional to its depth
/// weight, consuming one draw regardless of tree size.
fn select_weighted_header(
    frame: &Frame,
    depth: MutationDepth,
    rng: &mut ChaCha20Rng,
) -> Option<Header> {
    let mut total = 0_u128;
    visit(frame, "root", 0, &mut |frame, _, level| {
        if frame.declared_length().is_some() {
            total += depth.weight(level);
        }
    });
    if total == 0 {
        return None;
    }
    let mut remaining = rng.gen_range(0..total);
    let mut index = 0;
    let mut selected = None;
    visit(frame, "root", 0, &mut |frame, path, level| {
        if selected.is_none()
            && let Some(original) = frame.declared_length()
        {
            let weight = depth.weight(level);
            if remaining < weight {
                selected = Some(Header {
                    index,
                    path: path.to_owned(),
                    original,
                });
            } else {
                remaining -= weight;
            }
        }
        index += 1;
    });
    selected
}

/// Deepest nesting level of any frame in the reply (a scalar root is 0).
fn tree_depth(frame: &Frame) -> usize {
    let mut deepest = 0;
    visit(frame, "root", 0, &mut |_, _, level| {
        deepest = deepest.max(level)
    });
    deepest
}

fn visit(
    frame: &Frame,
    path: &str,
    depth: usize,
    visitor: &mut impl FnMut(&Frame, &str, usize),
) {
    visitor(frame, path, depth);
    match frame {
        Frame::Array(Some(items)) | Frame::Set(items) | Frame::Push(items) => {
            for (index, item) in items.iter().enumerate() {
                visit(item, &format!("{path}.{index}"), depth + 1, visitor);
            }
        }
        Frame::Map(items) | Frame::Attribute(items) => {
            for (index, (key, value)) in items.iter().enumerate() {
                visit(key, &format!("{path}.{index}.key"), depth + 1, visitor);
                visit(
                    value,
                    &format!("{path}.{index}.value"),
                    depth + 1,
                    visitor,
                );
            }
        }
        _ => {}
    }
}

fn corrupt_length(
    original: i128,
    kind: LengthCorruption,
    rng: &mut ChaCha20Rng,
) -> String {
    match kind {
        LengthCorruption::Shorter => (original - 1).to_string(),
        LengthCorruption::Longer => (original + 1).to_string(),
        LengthCorruption::Negative => {
            choose_different(original, &[-2, -3, i64::MIN as i128], rng)
        }
        LengthCorruption::Boundary => choose_different(
            original,
            &[
                0,
                1,
                i32::MAX as i128,
                i32::MAX as i128 + 1,
                u32::MAX as i128,
                u32::MAX as i128 + 1,
                i64::MAX as i128,
                u64::MAX as i128,
            ],
            rng,
        ),
        LengthCorruption::Overflow => {
            const VALUES: [&str; 4] = [
                "9223372036854775808",
                "18446744073709551616",
                "-9223372036854775809",
                "340282366920938463463374607431768211456",
            ];
            VALUES[rng.gen_range(0..VALUES.len())].to_owned()
        }
    }
}

fn choose_different(
    original: i128,
    values: &[i128],
    rng: &mut ChaCha20Rng,
) -> String {
    let index = rng.gen_range(0..values.len());
    let value = if values[index] == original {
        values[(index + 1) % values.len()]
    } else {
        values[index]
    };
    value.to_string()
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use serde_json::json;

    use super::*;
    use crate::mutation;
    use crate::repro::ReproRecord;
    use crate::resp::parse_frame;

    fn config(framing: &[&str]) -> EvilConfig {
        let mut config = EvilConfig::default();
        config
            .apply_debug_command(
                &["DEBUG", "EVIL", "MODE", "MUTATE", "PROBABILITY", "0"]
                    .map(str::to_owned),
            )
            .unwrap();
        let command = ["DEBUG", "EVIL", "FRAMING"]
            .into_iter()
            .chain(framing.iter().copied())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        config.apply_debug_command(&command).unwrap();
        config
    }

    fn run(bytes: &[u8], config: &EvilConfig) -> MutatedReply {
        mutation::mutate(
            &parse_frame(bytes).unwrap(),
            config,
            &mut ChaCha20Rng::seed_from_u64(7),
        )
    }

    #[test]
    fn each_header_type_can_be_corrupted_at_root_or_nested() {
        for (before, after) in [
            ("$3\r\nfoo\r\n", "$4\r\nfoo\r\n"),
            ("$-1\r\n", "$0\r\n"),
            ("*-1\r\n", "*0\r\n"),
            ("*0\r\n", "*1\r\n"),
            ("*1\r\n:1\r\n", "*2\r\n:1\r\n"),
            ("!3\r\nERR\r\n", "!4\r\nERR\r\n"),
            ("=7\r\ntxt:hey\r\n", "=8\r\ntxt:hey\r\n"),
            ("%1\r\n+k\r\n+v\r\n", "%2\r\n+k\r\n+v\r\n"),
            ("~1\r\n:1\r\n", "~2\r\n:1\r\n"),
            (">1\r\n+message\r\n", ">2\r\n+message\r\n"),
            ("|1\r\n+k\r\n+v\r\n", "|2\r\n+k\r\n+v\r\n"),
        ] {
            for (target, prefix, suffix) in [
                ("root", "", ""),
                ("root.1", "*3\r\n+before\r\n", "+after\r\n"),
            ] {
                let bytes = format!("{prefix}{before}{suffix}");
                let result = run(
                    bytes.as_bytes(),
                    &config(&["LENGTH", "TARGET", target, "KIND", "LONGER"]),
                );
                assert_eq!(
                    result.bytes,
                    format!("{prefix}{after}{suffix}").as_bytes(),
                    "{target} {before:?}"
                );
                assert_eq!(result.mutations.len(), 1);
                assert_eq!(result.mutations[0].path, target);
                assert_eq!(result.mutations[0].kind, MutationKind::WrongLength);
            }
        }
    }

    #[test]
    fn nested_fault_preserves_siblings_and_header_like_payload_bytes() {
        let bytes = b"*3\r\n$13\r\n*0\r\n$3\r\nfoo\r\n\r\n%1\r\n$1\r\nk\r\n~1\r\n$3\r\nabc\r\n#t\r\n";
        let result = run(
            bytes,
            &config(&[
                "LENGTH",
                "TARGET",
                "root.1.0.value.0",
                "KIND",
                "SHORTER",
            ]),
        );
        assert_eq!(result.bytes,
            b"*3\r\n$13\r\n*0\r\n$3\r\nfoo\r\n\r\n%1\r\n$1\r\nk\r\n~1\r\n$2\r\nabc\r\n#t\r\n");
        let record = ReproRecord::new(
            7,
            99,
            0,
            b"GET k\r\n",
            Some(bytes),
            &result.bytes,
            EvilMode::Mutate,
            result.mutations,
        );
        let json = serde_json::to_value(record).unwrap();
        assert_eq!(
            json["mutations"],
            json!([{
                "path": "root.1.0.value.0", "kind": "wrong_length",
                "length": {"kind": "shorter", "original": "3", "replacement": "2"},
            }])
        );
        assert_eq!(json["upstream_response_bytes_hex"], hex::encode(bytes));
        assert_eq!(
            json["mutated_response_bytes_hex"],
            hex::encode(&result.bytes)
        );
    }

    #[test]
    fn map_keys_and_attribute_values_use_pair_paths() {
        let original = b"|1\r\n%1\r\n$1\r\nk\r\n:1\r\n>1\r\n$0\r\n\r\n";
        for (path, expected) in [
            (
                "root.0.key.0.key",
                b"|1\r\n%1\r\n$0\r\nk\r\n:1\r\n>1\r\n$0\r\n\r\n".as_slice(),
            ),
            (
                "root.0.value.0",
                b"|1\r\n%1\r\n$1\r\nk\r\n:1\r\n>1\r\n$-1\r\n\r\n",
            ),
        ] {
            let result = run(
                original,
                &config(&["LENGTH", "TARGET", path, "KIND", "SHORTER"]),
            );
            assert_eq!(result.bytes, expected);
            assert_eq!(result.mutations[0].path, path);
        }
        let result = run(b"$-1\r\n", &config(&["LENGTH", "KIND", "SHORTER"]));
        assert_eq!(result.bytes, b"$-2\r\n");
    }

    #[test]
    fn ineligible_targets_leave_output_and_records_unchanged() {
        for (bytes, target) in [
            (b"+OK\r\n".as_slice(), "ANY"),
            (b"*1\r\n:1\r\n", "root.0"),
            (b"*1\r\n$1\r\nx\r\n", "root.9"),
            (b"%1\r\n$1\r\nk\r\n$1\r\nv\r\n", "root.0"),
            (b"$4\r\n*0\r\n\r\n", "root.0"),
        ] {
            for count in [MutationCount::One, MutationCount::Many] {
                let mut config = config(&["LENGTH", "TARGET", target]);
                config.mutation_count = count;
                let result = run(bytes, &config);
                assert_eq!(result.bytes, bytes);
                assert!(result.mutations.is_empty());
            }
        }
    }

    #[test]
    fn framing_can_be_disabled_while_values_are_mutated() {
        for settings in [&["OFF"][..], &["LENGTH", "PROBABILITY", "0"]] {
            let mut config = config(settings);
            config.probability = 100.0;
            let result = run(b"*1\r\n#t\r\n", &config);
            assert_eq!(result.bytes, b"*1\r\n#f\r\n");
            assert_eq!(
                serde_json::to_value(&result.mutations).unwrap(),
                json!([
                    {"path": "root.0", "kind": "random_value"},
                ])
            );
        }
    }

    #[test]
    fn one_framing_fault_uses_the_single_slot_with_value_fallback() {
        let mut config =
            config(&["LENGTH", "KIND", "LONGER", "TARGET", "root"]);
        config.probability = 100.0;
        config.mutation_count = MutationCount::One;
        let result = run(b"*1\r\n#t\r\n", &config);
        assert_eq!(result.bytes, b"*2\r\n#t\r\n");
        assert_eq!(result.mutations.len(), 1);
        assert_eq!(result.mutations[0].kind, MutationKind::WrongLength);

        // The scalar has no length header, so value mutation gets the slot.
        let result = run(b"#t\r\n", &config);
        assert_eq!(result.bytes, b"#f\r\n");
        assert_eq!(result.mutations.len(), 1);
        assert_eq!(result.mutations[0].kind, MutationKind::RandomValue);

        config.mutation_count = MutationCount::Many;
        let result = run(b"*1\r\n#t\r\n", &config);
        assert_eq!(result.bytes, b"*2\r\n#f\r\n");
        assert_eq!(result.mutations.len(), 2);
    }

    #[test]
    fn many_framing_uses_final_tree_and_skips_a_removed_target() {
        let mut config =
            config(&["LENGTH", "TARGET", "root.0", "KIND", "LONGER"]);
        config.probability = 100.0;
        config.mode = EvilMode::Overflow;
        config.strategy = crate::evil::MutationStrategy::Replace;
        let result = run(b"*1\r\n$1\r\nx\r\n", &config);
        assert_eq!(result.bytes, b":9223372036854775807\r\n");
        assert_eq!(result.mutations.len(), 1);
        assert_eq!(result.mutations[0].kind, MutationKind::OverflowValue);
    }

    #[test]
    fn extreme_headers_have_exact_seeded_bytes_and_small_payloads() {
        use crate::evil::{deterministic_hash, mutate_reply};
        let original =
            parse_frame(b"*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n").unwrap();
        let command_hash = deterministic_hash(b"MGET a b\r\n");
        let reply_hash = deterministic_hash(&original.encode());
        // These seeds exercise invalid negatives, 32/64-bit boundaries,
        // and decimal overflow, including a value beyond u128::MAX.
        for (kind, seed, expected) in [
            ("NEGATIVE", 0, "-9223372036854775808"),
            ("NEGATIVE", 2, "-2"),
            ("NEGATIVE", 5, "-3"),
            ("BOUNDARY", 0, "18446744073709551615"),
            ("BOUNDARY", 4, "4294967296"),
            ("OVERFLOW", 0, "-9223372036854775809"),
            ("OVERFLOW", 1, "340282366920938463463374607431768211456"),
            ("OVERFLOW", 2, "18446744073709551616"),
        ] {
            let mut config =
                config(&["LENGTH", "TARGET", "root.1", "KIND", kind]);
            config.seed = seed;
            let result =
                mutate_reply(&config, 9, &command_hash, &reply_hash, &original);
            assert_eq!(
                result.bytes,
                format!("*2\r\n$3\r\nfoo\r\n${expected}\r\nbar\r\n").as_bytes()
            );
            let length = result.mutations[0].length.as_ref().unwrap();
            assert_eq!(kind_name(length.kind), kind);
            assert_eq!(length.original, "3");
            assert_eq!(length.replacement, expected);
            assert!(result.bytes.len() < 80);
        }
    }

    #[test]
    fn any_target_and_random_kind_are_deterministic() {
        use crate::evil::{deterministic_hash, mutate_reply};
        let original =
            parse_frame(b"*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n").unwrap();
        let command_hash = deterministic_hash(b"MGET a b\r\n");
        let reply_hash = deterministic_hash(&original.encode());
        // Seeds 0, 1, and 3 select a root boundary, nested overflow,
        // and nested off-by-one respectively.
        for (seed, path, kind, expected) in [
            (
                0,
                "root",
                LengthCorruption::Boundary,
                "*1\r\n$3\r\nfoo\r\n$3\r\nbar\r\n",
            ),
            (
                1,
                "root.0",
                LengthCorruption::Overflow,
                "*2\r\n$18446744073709551616\r\nfoo\r\n$3\r\nbar\r\n",
            ),
            (
                3,
                "root.0",
                LengthCorruption::Longer,
                "*2\r\n$4\r\nfoo\r\n$3\r\nbar\r\n",
            ),
        ] {
            let mut config = config(&["LENGTH"]);
            config.seed = seed;
            config.depth = MutationDepth::Any;
            let result =
                mutate_reply(&config, 9, &command_hash, &reply_hash, &original);
            assert_eq!(result.bytes, expected.as_bytes());
            assert_eq!(result.mutations[0].path, path);
            assert_eq!(result.mutations[0].length.as_ref().unwrap().kind, kind);
            let repeated =
                mutate_reply(&config, 9, &command_hash, &reply_hash, &original);
            assert_eq!(result.bytes, repeated.bytes);
            assert_eq!(
                serde_json::to_value(&result.mutations).unwrap(),
                serde_json::to_value(&repeated.mutations).unwrap()
            );
        }
    }

    #[test]
    fn a_boundary_equal_to_the_original_length_is_not_a_no_op() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let proposed = corrupt_length(3, LengthCorruption::Boundary, &mut rng);
        let replacement = corrupt_length(
            proposed.parse().unwrap(),
            LengthCorruption::Boundary,
            &mut ChaCha20Rng::seed_from_u64(7),
        );
        assert_ne!(proposed, replacement);
    }

    #[test]
    fn inner_depth_weights_any_target_toward_nested_headers() {
        use crate::evil::mutate_reply;
        let original =
            parse_frame(b"*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n").unwrap();
        let run = |depth: MutationDepth, seed: u64| {
            let mut config = config(&["LENGTH", "KIND", "LONGER"]);
            config.seed = seed;
            config.depth = depth;
            mutate_reply(&config, 9, "command", "upstream", &original)
        };

        // Seed 2 still reaches the root; seed 3 lengthens the first bulk.
        let result = run(MutationDepth::Inner, 2);
        assert_eq!(result.bytes, b"*3\r\n$3\r\nfoo\r\n$3\r\nbar\r\n");
        assert_eq!(result.mutations[0].path, "root");
        let result = run(MutationDepth::Inner, 3);
        assert_eq!(result.bytes, b"*2\r\n$4\r\nfoo\r\n$3\r\nbar\r\n");
        assert_eq!(result.mutations[0].path, "root.0");
        assert_eq!(run(MutationDepth::Inner, 3).bytes, result.bytes);

        let root_count = |depth| {
            (0..100)
                .filter(|seed| {
                    let result = run(depth, *seed);
                    assert_eq!(result.mutations.len(), 1);
                    result.mutations[0].path == "root"
                })
                .count()
        };
        // Root weight 1 against two nested headers of weight 2 each.
        let inner = root_count(MutationDepth::Inner);
        let any = root_count(MutationDepth::Any);
        assert!(inner > 0 && (10..=30).contains(&inner), "{inner}");
        assert!(inner < any, "{inner} {any}");
    }

    #[test]
    fn inner_depth_halves_the_automatic_root_fault_per_nesting_level() {
        let run = |bytes: &[u8], depth: MutationDepth, seed: u64| {
            let mut config = config(&["AUTO"]);
            config.probability = 100.0;
            config.depth = depth;
            config.seed = seed;
            crate::evil::mutate_reply(
                &config,
                9,
                "command",
                "upstream",
                &parse_frame(bytes).unwrap(),
            )
        };
        let root_faults = |bytes: &[u8], depth| {
            (0..64)
                .filter(|seed| {
                    run(bytes, depth, *seed).mutations.iter().any(|m| {
                        m.path == "root" && m.kind == MutationKind::WrongLength
                    })
                })
                .count()
        };
        // Legacy AUTO always corrupts the root at full probability.
        assert_eq!(root_faults(b"*1\r\n:1\r\n", MutationDepth::Any), 64);
        // A scalar root has no nesting to protect.
        assert_eq!(root_faults(b"$3\r\nfoo\r\n", MutationDepth::Inner), 64);
        let one_level = root_faults(b"*1\r\n:1\r\n", MutationDepth::Inner);
        let two_levels =
            root_faults(b"*1\r\n*1\r\n:1\r\n", MutationDepth::Inner);
        assert!((20..=44).contains(&one_level), "{one_level}");
        assert!((6..=26).contains(&two_levels), "{two_levels}");
        assert!(two_levels < one_level);

        // Seed 0 keeps the outer shell valid while the leaf still changes.
        let result = run(b"*1\r\n*1\r\n:1\r\n", MutationDepth::Inner, 0);
        assert_eq!(result.bytes, b"*1\r\n*1\r\n:4294967295\r\n");
        assert_eq!(result.mutations.len(), 1);
        assert_eq!(result.mutations[0].path, "root.0.0");
    }
}
