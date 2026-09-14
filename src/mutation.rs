//! Apply RESP mutations to original reply trees. Replacement subtrees are
//! terminal: only original children participate in mutation selection.
//! `DEPTH INNER` weights every selection toward nested frames so the outer
//! shell of a reply usually stays valid.

use rand::Rng;
use rand_chacha::ChaCha20Rng;

use crate::evil::{
    AppliedMutation, EvilConfig, EvilMode, MutatedReply, MutationCount,
    MutationDepth, MutationKind, MutationStrategy,
};
use crate::framing::{FramingConfig, mutate_length};
use crate::resp::Frame;

pub(crate) fn mutate(
    upstream: &Frame,
    config: &EvilConfig,
    rng: &mut ChaCha20Rng,
) -> MutatedReply {
    let mut frame = upstream.clone();
    let mut mutations = Vec::new();
    if !matches!(config.mode, EvilMode::Mutate | EvilMode::Overflow) {
        return MutatedReply {
            bytes: frame.encode(),
            mutations,
        };
    }

    // An explicit framing fault has priority for the single mutation slot.
    // If it cannot apply, value mutation still gets its probability check.
    if config.mutation_count == MutationCount::One
        && matches!(config.framing, FramingConfig::Length(_))
        && let Some(reply) = mutate_length(&frame, config, rng)
    {
        return reply;
    }

    match config.mutation_count {
        MutationCount::One => {
            if should_apply(config.probability, rng)
                && let Some(mut remaining) = select_weight(&frame, config, rng)
            {
                mutate_selected(
                    &mut frame,
                    config,
                    rng,
                    "root",
                    0,
                    &mut remaining,
                    &mut mutations,
                );
            }
        }
        MutationCount::Many => {
            let max_depth = eligible_max_depth(&frame, config, 0).unwrap_or(0);
            mutate_frame(
                &mut frame,
                config,
                rng,
                "root",
                0,
                max_depth,
                &mut mutations,
            );
        }
    }

    // MANY applies framing to the final typed tree after value mutation.
    if config.mutation_count == MutationCount::Many
        && let Some(mut reply) = mutate_length(&frame, config, rng)
    {
        mutations.append(&mut reply.mutations);
        reply.mutations = mutations;
        return reply;
    }
    MutatedReply {
        bytes: frame.encode(),
        mutations,
    }
}

fn eligible(frame: &Frame, config: &EvilConfig) -> bool {
    if config.strategy == MutationStrategy::Replace {
        return true;
    }
    match frame {
        Frame::SimpleString(_)
        | Frame::SimpleError(_)
        | Frame::Integer(_)
        | Frame::BulkString(Some(_))
        | Frame::Double(_)
        | Frame::BigNumber(_)
        | Frame::BulkError(_)
        | Frame::VerbatimString(_) => true,
        Frame::Boolean(_) | Frame::Inline(_) => config.mode == EvilMode::Mutate,
        _ => false,
    }
}

/// Visit each direct child of an aggregate frame; scalars have none.
fn for_each_child(frame: &Frame, mut visitor: impl FnMut(&Frame)) {
    match frame {
        Frame::Array(Some(items)) | Frame::Set(items) | Frame::Push(items) => {
            items.iter().for_each(&mut visitor);
        }
        Frame::Map(items) | Frame::Attribute(items) => {
            for (key, value) in items {
                visitor(key);
                visitor(value);
            }
        }
        _ => {}
    }
}

/// Total selection weight of all eligible frames in the tree.
fn eligible_weight(frame: &Frame, config: &EvilConfig, depth: usize) -> u128 {
    let mut total = if eligible(frame, config) {
        config.depth.weight(depth)
    } else {
        0
    };
    for_each_child(frame, |child| {
        total += eligible_weight(child, config, depth + 1);
    });
    total
}

/// Deepest nesting level that holds an eligible frame, if any.
fn eligible_max_depth(
    frame: &Frame,
    config: &EvilConfig,
    depth: usize,
) -> Option<usize> {
    let mut deepest = eligible(frame, config).then_some(depth);
    for_each_child(frame, |child| {
        deepest = deepest.max(eligible_max_depth(child, config, depth + 1));
    });
    deepest
}

/// Draw the cumulative weight offset of the frame to mutate. `ANY` keeps the
/// legacy uniform integer draw so existing seeded output is unchanged.
fn select_weight(
    frame: &Frame,
    config: &EvilConfig,
    rng: &mut ChaCha20Rng,
) -> Option<u128> {
    let total = eligible_weight(frame, config, 0);
    if total == 0 {
        return None;
    }
    Some(match config.depth {
        // Every weight is one, so the total is an exact frame count.
        MutationDepth::Any => rng.gen_range(0..total as usize) as u128,
        MutationDepth::Inner => rng.gen_range(0..total),
    })
}

fn mutate_selected(
    frame: &mut Frame,
    config: &EvilConfig,
    rng: &mut ChaCha20Rng,
    path: &str,
    depth: usize,
    remaining: &mut u128,
    mutations: &mut Vec<AppliedMutation>,
) -> bool {
    if eligible(frame, config) {
        let weight = config.depth.weight(depth);
        if *remaining < weight {
            mutations.push(AppliedMutation {
                path: path.to_owned(),
                kind: mutate_one(frame, config, rng),
                length: None,
                exec: None,
            });
            return true;
        }
        *remaining -= weight;
    }
    match frame {
        Frame::Array(Some(items)) | Frame::Set(items) | Frame::Push(items) => {
            for (index, item) in items.iter_mut().enumerate() {
                if mutate_selected(
                    item,
                    config,
                    rng,
                    &format!("{path}.{index}"),
                    depth + 1,
                    remaining,
                    mutations,
                ) {
                    return true;
                }
            }
        }
        Frame::Map(items) | Frame::Attribute(items) => {
            for (index, (key, value)) in items.iter_mut().enumerate() {
                if mutate_selected(
                    key,
                    config,
                    rng,
                    &format!("{path}.{index}.key"),
                    depth + 1,
                    remaining,
                    mutations,
                ) || mutate_selected(
                    value,
                    config,
                    rng,
                    &format!("{path}.{index}.value"),
                    depth + 1,
                    remaining,
                    mutations,
                ) {
                    return true;
                }
            }
        }
        _ => {}
    }
    false
}

fn mutate_frame(
    frame: &mut Frame,
    config: &EvilConfig,
    rng: &mut ChaCha20Rng,
    path: &str,
    depth: usize,
    max_depth: usize,
    mutations: &mut Vec<AppliedMutation>,
) {
    if eligible(frame, config)
        && should_apply(
            config.depth.scale(config.probability, depth, max_depth),
            rng,
        )
    {
        let kind = mutate_one(frame, config, rng);
        mutations.push(AppliedMutation {
            path: path.to_owned(),
            kind,
            length: None,
            exec: None,
        });
        // Do not recursively mutate a replacement's generated descendants.
        return;
    }

    match frame {
        Frame::Array(Some(items)) | Frame::Set(items) | Frame::Push(items) => {
            for (index, item) in items.iter_mut().enumerate() {
                mutate_frame(
                    item,
                    config,
                    rng,
                    &format!("{path}.{index}"),
                    depth + 1,
                    max_depth,
                    mutations,
                );
            }
        }
        Frame::Map(items) | Frame::Attribute(items) => {
            for (index, (key, value)) in items.iter_mut().enumerate() {
                mutate_frame(
                    key,
                    config,
                    rng,
                    &format!("{path}.{index}.key"),
                    depth + 1,
                    max_depth,
                    mutations,
                );
                mutate_frame(
                    value,
                    config,
                    rng,
                    &format!("{path}.{index}.value"),
                    depth + 1,
                    max_depth,
                    mutations,
                );
            }
        }
        _ => {}
    }
}

fn should_apply(probability: f64, rng: &mut ChaCha20Rng) -> bool {
    probability > 0.0 && rng.gen_range(0.0..100.0) < probability
}

fn mutate_one(
    frame: &mut Frame,
    config: &EvilConfig,
    rng: &mut ChaCha20Rng,
) -> MutationKind {
    if config.mode == EvilMode::Overflow {
        if matches!(
            frame,
            Frame::Integer(_)
                | Frame::SimpleString(_)
                | Frame::SimpleError(_)
                | Frame::Double(_)
                | Frame::BigNumber(_)
                | Frame::BulkString(Some(_))
                | Frame::BulkError(_)
                | Frame::VerbatimString(_)
        ) {
            config.generator.mutate_scalar(frame, rng, true);
        } else {
            *frame = Frame::Integer(i64::MAX);
        }
        return MutationKind::OverflowValue;
    }

    match config.strategy {
        MutationStrategy::Preserve => {
            config.generator.mutate_scalar(frame, rng, false);
            MutationKind::RandomValue
        }
        MutationStrategy::Replace => {
            let replacement = config.generator.frame(rng);
            *frame = if *frame != replacement {
                replacement
            } else if matches!(frame, Frame::Integer(0)) {
                Frame::Integer(1)
            } else {
                Frame::Integer(0)
            };
            MutationKind::RandomFrame
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;

    use super::*;
    use crate::resp::parse_frame;

    /// Legacy uniform selection; INNER tests opt in with `inner`.
    fn config(mode: &str, count: &str, strategy: &str) -> EvilConfig {
        let mut config = EvilConfig::default();
        for args in [
            ["DEBUG", "EVIL", "MODE", mode],
            ["DEBUG", "EVIL", "MUTATIONS", count],
            ["DEBUG", "EVIL", "STRATEGY", strategy],
            ["DEBUG", "EVIL", "DEPTH", "ANY"],
        ] {
            config
                .apply_debug_command(&args.map(str::to_owned))
                .unwrap();
        }
        config
    }

    fn run(frame: &Frame, config: &EvilConfig) -> MutatedReply {
        mutate(frame, config, &mut ChaCha20Rng::seed_from_u64(7))
    }

    #[test]
    fn preserve_mutates_nested_values_without_replacing_containers() {
        let original = parse_frame(
            b"*2\r\n%1\r\n#t\r\n~2\r\n#f\r\n*2\r\n#t\r\n_\r\n$-1\r\n",
        )
        .unwrap();
        let result = run(&original, &config("MUTATE", "MANY", "PRESERVE"));
        // MANY retains its separate root length fault (*2 becomes *3).
        // Every original boolean flips and all container bodies survive.
        assert_eq!(
            result.bytes,
            b"*3\r\n%1\r\n#f\r\n~2\r\n#t\r\n*2\r\n#f\r\n_\r\n$-1\r\n"
        );
        assert_eq!(
            result
                .mutations
                .iter()
                .map(|m| (m.path.as_str(), m.kind))
                .collect::<Vec<_>>(),
            [
                ("root.0.0.key", MutationKind::RandomValue),
                ("root.0.0.value.0", MutationKind::RandomValue),
                ("root.0.0.value.1.0", MutationKind::RandomValue),
                ("root", MutationKind::WrongLength),
            ]
        );
    }

    #[test]
    fn overflow_reaches_original_nested_values_at_full_probability() {
        let original = parse_frame(
            b"*2\r\n%1\r\n+18446744073709551615\r\n~1\r\n:9223372036854775807\r\n#t\r\n",
        ).unwrap();
        let result = run(&original, &config("OVERFLOW", "MANY", "PRESERVE"));
        // Existing extreme values must switch to the other boundary,
        // independently of which boundary the RNG initially selects.
        assert_eq!(result.bytes,
            b"*9223372036854775807\r\n%1\r\n+9223372036854775807\r\n~1\r\n:-9223372036854775808\r\n#t\r\n");
        assert_eq!(
            result
                .mutations
                .iter()
                .map(|m| (m.path.as_str(), m.kind))
                .collect::<Vec<_>>(),
            [
                ("root.0.0.key", MutationKind::OverflowValue),
                ("root.0.0.value.0", MutationKind::OverflowValue),
                ("root", MutationKind::WrongLength),
            ]
        );
    }

    #[test]
    fn one_mutation_reaches_a_nested_leaf_without_a_length_fault() {
        for (mode, before, after) in [
            ("MUTATE", "#t", "#f"),
            ("OVERFLOW", ":9223372036854775807", ":-9223372036854775808"),
        ] {
            let original = parse_frame(
                format!("*2\r\n_\r\n%1\r\n_\r\n~2\r\n{before}\r\n_\r\n")
                    .as_bytes(),
            )
            .unwrap();
            let result = run(&original, &config(mode, "ONE", "PRESERVE"));
            assert_eq!(
                result.bytes,
                format!("*2\r\n_\r\n%1\r\n_\r\n~2\r\n{after}\r\n_\r\n")
                    .as_bytes()
            );
            assert_eq!(result.mutations.len(), 1);
            assert_eq!(result.mutations[0].path, "root.1.0.value.0");
            assert!(parse_frame(&result.bytes).is_ok());
        }
    }

    #[test]
    fn one_mutation_without_eligible_values_leaves_reply_unchanged() {
        for bytes in [
            b"_\r\n".as_slice(),
            b"$-1\r\n",
            b"*-1\r\n",
            b"*0\r\n",
            b"*2\r\n%1\r\n_\r\n~0\r\n*0\r\n",
        ] {
            for mode in ["MUTATE", "OVERFLOW"] {
                let result = run(
                    &parse_frame(bytes).unwrap(),
                    &config(mode, "ONE", "PRESERVE"),
                );
                assert_eq!(result.bytes, bytes);
                assert!(result.mutations.is_empty());
            }
        }
        let result = run(
            &Frame::Boolean(true),
            &config("OVERFLOW", "ONE", "PRESERVE"),
        );
        assert_eq!(result.bytes, b"#t\r\n");
        assert!(result.mutations.is_empty());
    }

    #[test]
    fn zero_probability_disables_both_values_and_framing() {
        let original =
            parse_frame(b"*2\r\n%1\r\n+k\r\n~1\r\n:42\r\n$3\r\nfoo\r\n")
                .unwrap();
        for mode in ["MUTATE", "OVERFLOW"] {
            for count in ["ONE", "MANY"] {
                for strategy in ["PRESERVE", "REPLACE"] {
                    let mut config = config(mode, count, strategy);
                    config.probability = 0.0;
                    let result = run(&original, &config);
                    assert_eq!(result.bytes, original.encode());
                    assert!(result.mutations.is_empty());
                }
            }
        }
    }

    #[test]
    fn replace_can_explicitly_collapse_an_entire_aggregate() {
        let original = parse_frame(b"*2\r\n:1\r\n~1\r\n:2\r\n").unwrap();
        let result = run(&original, &config("OVERFLOW", "MANY", "REPLACE"));
        assert_eq!(result.bytes, b":9223372036854775807\r\n");
        assert_eq!(result.mutations.len(), 1);
        assert_eq!(result.mutations[0].path, "root");
        assert_eq!(result.mutations[0].kind, MutationKind::OverflowValue);
    }

    #[test]
    fn selected_mutations_always_change_the_value() {
        for mode in ["MUTATE", "OVERFLOW"] {
            for strategy in ["PRESERVE", "REPLACE"] {
                let config = config(mode, "ONE", strategy);
                for original in [
                    Frame::Integer(i64::MAX),
                    Frame::Integer(i64::MIN),
                    Frame::SimpleString(String::new()),
                    Frame::BulkString(Some(Vec::new())),
                    Frame::SimpleString(i64::MAX.to_string()),
                    Frame::BulkString(Some(u64::MAX.to_string().into_bytes())),
                ] {
                    // Reusing the RNG state with the previous result forces
                    // an identical proposed value on the second mutation.
                    let mut first = original;
                    mutate_one(
                        &mut first,
                        &config,
                        &mut ChaCha20Rng::seed_from_u64(7),
                    );
                    let mut second = first.clone();
                    mutate_one(
                        &mut second,
                        &config,
                        &mut ChaCha20Rng::seed_from_u64(7),
                    );
                    assert_ne!(first, second, "{mode} {strategy}");
                }
            }
        }
    }

    fn inner(mut config: EvilConfig, framing: &str) -> EvilConfig {
        for args in [
            ["DEBUG", "EVIL", "DEPTH", "INNER"],
            ["DEBUG", "EVIL", "FRAMING", framing],
        ] {
            config
                .apply_debug_command(&args.map(str::to_owned))
                .unwrap();
        }
        config
    }

    fn seeded(config: &EvilConfig, seed: u64, frame: &Frame) -> MutatedReply {
        let mut config = config.clone();
        config.seed = seed;
        crate::evil::mutate_reply(&config, 9, "command", "upstream", frame)
    }

    #[test]
    fn inner_depth_weights_one_selection_toward_nested_frames() {
        // Two records of (member, score): root weight 1, each record 2,
        // each leaf 4, so the root holds 1/21 of the selection mass.
        let original = parse_frame(
            b"*2\r\n*2\r\n$1\r\na\r\n:1\r\n*2\r\n$1\r\nb\r\n:2\r\n",
        )
        .unwrap();
        let legacy = config("MUTATE", "ONE", "REPLACE");
        let weighted = inner(legacy.clone(), "OFF");

        // Seed 0 replaces the first record's score with a null bulk string
        // while both records and the outer array survive.
        let result = seeded(&weighted, 0, &original);
        assert_eq!(
            result.bytes,
            b"*2\r\n*2\r\n$1\r\na\r\n$-1\r\n*2\r\n$1\r\nb\r\n:2\r\n"
        );
        assert_eq!(result.mutations.len(), 1);
        assert_eq!(result.mutations[0].path, "root.0.1");
        assert_eq!(result.mutations[0].kind, MutationKind::RandomFrame);
        assert_eq!(seeded(&weighted, 0, &original).bytes, result.bytes);

        let count = |config: &EvilConfig, predicate: fn(&str) -> bool| {
            (0..200_u64)
                .filter(|seed| {
                    let result = seeded(config, *seed, &original);
                    assert_eq!(result.mutations.len(), 1);
                    predicate(&result.mutations[0].path)
                })
                .count()
        };
        let root = count(&weighted, |path| path == "root");
        let records = count(&weighted, |path| path.len() == "root.0".len());
        let leaves = count(&weighted, |path| path.len() == "root.0.0".len());
        assert_eq!(root + records + leaves, 200);
        // Every level remains reachable, but leaves dominate and the root is
        // selected far less often than under uniform legacy selection.
        assert!(root > 0 && (5..=25).contains(&root), "{root}");
        assert!(records > 0 && leaves >= 120, "{records} {leaves}");
        assert!(root < count(&legacy, |path| path == "root"));
    }

    #[test]
    fn inner_depth_scales_many_probability_per_level() {
        // The depth-two boolean keeps the full probability; the depth-one
        // boolean is mutated half as often under INNER and always under ANY.
        let original = parse_frame(b"*2\r\n#t\r\n*1\r\n#t\r\n").unwrap();
        let legacy = config("MUTATE", "MANY", "PRESERVE");
        let weighted = inner(legacy.clone(), "OFF");
        let legacy = {
            let mut legacy = legacy;
            legacy
                .apply_debug_command(
                    &["DEBUG", "EVIL", "FRAMING", "OFF"].map(str::to_owned),
                )
                .unwrap();
            legacy
        };

        // Seed 5 flips only the nested boolean; seed 0 flips both.
        assert_eq!(
            seeded(&weighted, 5, &original).bytes,
            b"*2\r\n#t\r\n*1\r\n#f\r\n"
        );
        assert_eq!(
            seeded(&weighted, 0, &original).bytes,
            b"*2\r\n#f\r\n*1\r\n#f\r\n"
        );

        let mut shallow = 0;
        for seed in 0..64 {
            let result = seeded(&weighted, seed, &original);
            let paths = result
                .mutations
                .iter()
                .map(|m| m.path.as_str())
                .collect::<Vec<_>>();
            assert!(paths.contains(&"root.1.0"), "seed {seed}: {paths:?}");
            assert!(parse_frame(&result.bytes).is_ok());
            shallow += usize::from(paths.contains(&"root.0"));
            assert_eq!(
                seeded(&legacy, seed, &original).bytes,
                b"*2\r\n#f\r\n*1\r\n#f\r\n"
            );
        }
        assert!((16..=48).contains(&shallow), "{shallow}");
    }

    #[test]
    fn scalar_roots_mutate_under_both_depths_with_distinct_seeded_values() {
        // A scalar reply has one candidate under both settings, yet INNER
        // draws a wider offset, so seeded values differ between settings.
        let original = parse_frame(b"$3\r\nfoo\r\n").unwrap();
        let legacy = config("MUTATE", "ONE", "PRESERVE");
        let weighted = inner(legacy.clone(), "AUTO");
        let mut distinct = 0;
        for seed in 0..8 {
            let inner = seeded(&weighted, seed, &original);
            let any = seeded(&legacy, seed, &original);
            assert_eq!(inner.mutations.len(), 1);
            assert_eq!(any.mutations.len(), 1);
            assert_eq!(inner.mutations[0].path, "root");
            assert_eq!(any.mutations[0].path, "root");
            assert_ne!(inner.bytes, original.encode());
            assert_ne!(any.bytes, original.encode());
            distinct += usize::from(inner.bytes != any.bytes);
        }
        assert!(distinct > 0);
        assert_eq!(EvilConfig::default().depth, MutationDepth::Inner);
    }
}
