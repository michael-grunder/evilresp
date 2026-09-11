//! Apply RESP mutations to original reply trees. Replacement subtrees are
//! terminal: only original children participate in mutation selection.

use rand::Rng;
use rand_chacha::ChaCha20Rng;

use crate::evil::{
    AppliedMutation, EvilConfig, EvilMode, MutatedReply, MutationCount,
    MutationKind, MutationStrategy,
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
            if should_apply(config.probability, rng) {
                let count = eligible_count(&frame, config);
                if count > 0 {
                    let mut selected = rng.gen_range(0..count);
                    mutate_selected(
                        &mut frame,
                        config,
                        rng,
                        "root",
                        &mut selected,
                        &mut mutations,
                    );
                }
            }
        }
        MutationCount::Many => {
            mutate_frame(&mut frame, config, rng, "root", &mut mutations);
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

fn eligible_count(frame: &Frame, config: &EvilConfig) -> usize {
    let children = match frame {
        Frame::Array(Some(items)) | Frame::Set(items) | Frame::Push(items) => {
            items.iter().map(|item| eligible_count(item, config)).sum()
        }
        Frame::Map(items) | Frame::Attribute(items) => items
            .iter()
            .map(|(key, value)| {
                eligible_count(key, config) + eligible_count(value, config)
            })
            .sum(),
        _ => 0,
    };
    usize::from(eligible(frame, config)) + children
}

fn mutate_selected(
    frame: &mut Frame,
    config: &EvilConfig,
    rng: &mut ChaCha20Rng,
    path: &str,
    selected: &mut usize,
    mutations: &mut Vec<AppliedMutation>,
) -> bool {
    if eligible(frame, config) {
        if *selected == 0 {
            mutations.push(AppliedMutation {
                path: path.to_owned(),
                kind: mutate_one(frame, config, rng),
                length: None,
                exec: None,
            });
            return true;
        }
        *selected -= 1;
    }
    match frame {
        Frame::Array(Some(items)) | Frame::Set(items) | Frame::Push(items) => {
            for (index, item) in items.iter_mut().enumerate() {
                if mutate_selected(
                    item,
                    config,
                    rng,
                    &format!("{path}.{index}"),
                    selected,
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
                    selected,
                    mutations,
                ) || mutate_selected(
                    value,
                    config,
                    rng,
                    &format!("{path}.{index}.value"),
                    selected,
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
    mutations: &mut Vec<AppliedMutation>,
) {
    if eligible(frame, config) && should_apply(config.probability, rng) {
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
                    mutations,
                );
                mutate_frame(
                    value,
                    config,
                    rng,
                    &format!("{path}.{index}.value"),
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

    fn config(mode: &str, count: &str, strategy: &str) -> EvilConfig {
        let mut config = EvilConfig::default();
        for args in [
            ["DEBUG", "EVIL", "MODE", mode],
            ["DEBUG", "EVIL", "MUTATIONS", count],
            ["DEBUG", "EVIL", "STRATEGY", strategy],
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
}
