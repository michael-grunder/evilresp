//! Focused, correctly framed edits to the outer EXEC result array. A selected
//! edit replaces generic RESP mutation so other result contents survive.

use rand::Rng;

use crate::error::{AppError, AppResult};
use crate::evil::{
    AppliedMutation, EvilConfig, EvilMode, ExecMutation, MutatedReply,
    MutationKind, parse_probability, rng_for,
};
use crate::resp::Frame;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ExecAction {
    #[default]
    Off,
    Random,
    Remove,
    Duplicate,
    Swap,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ExecConfig {
    action: ExecAction,
    probability: f64,
}

impl Default for ExecConfig {
    fn default() -> Self {
        Self {
            action: ExecAction::Off,
            probability: 100.0,
        }
    }
}

impl ExecConfig {
    pub(crate) fn parse(args: &[String]) -> AppResult<Self> {
        let Some(action) = args.first() else {
            return Err(invalid());
        };
        let action = match action.to_ascii_uppercase().as_str() {
            "OFF" => ExecAction::Off,
            "RANDOM" => ExecAction::Random,
            "REMOVE" => ExecAction::Remove,
            "DUPLICATE" => ExecAction::Duplicate,
            "SWAP" => ExecAction::Swap,
            _ => return Err(invalid()),
        };
        let probability = match args.len() {
            1 => 100.0,
            3 if action != ExecAction::Off
                && args[1].eq_ignore_ascii_case("PROBABILITY") =>
            {
                parse_probability(&args[2])?
            }
            _ => return Err(invalid()),
        };
        Ok(Self {
            action,
            probability,
        })
    }

    pub(crate) fn status(&self) -> String {
        let action = match self.action {
            ExecAction::Off => "OFF",
            ExecAction::Random => "RANDOM",
            ExecAction::Remove => "REMOVE",
            ExecAction::Duplicate => "DUPLICATE",
            ExecAction::Swap => "SWAP",
        };
        format!("exec={action} exec_probability={:.2}", self.probability)
    }
}

fn invalid() -> AppError {
    AppError::EvilConfig(
        "expected EXEC <OFF|RANDOM|REMOVE|DUPLICATE|SWAP> [PROBABILITY <0..100>]; OFF accepts no options"
            .to_owned(),
    )
}

pub(crate) fn mutate_reply(
    config: &EvilConfig,
    command_index: u64,
    command_hash: &str,
    upstream_hash: &str,
    upstream: &Frame,
) -> Option<MutatedReply> {
    if !matches!(config.mode, EvilMode::Mutate | EvilMode::Overflow)
        || config.exec.action == ExecAction::Off
        || config.exec.probability == 0.0
    {
        return None;
    }
    let Frame::Array(Some(items)) = upstream else {
        return None;
    };
    let first = items.first()?;
    // Comparing against one representative detects whether any unequal pair
    // exists in linear time, without building all possible pairs.
    let can_swap = items.iter().any(|item| item != first);
    if config.exec.action == ExecAction::Swap && !can_swap {
        return None;
    }

    // Domain separation keeps focused choices independent of generic value
    // and framing draws. Skipped edits leave the legacy RNG stream unchanged.
    let mut rng = rng_for(
        config.seed,
        command_index,
        &format!("exec:{command_hash}"),
        upstream_hash,
    );
    if rng.gen_range(0.0..100.0) >= config.exec.probability {
        return None;
    }
    let action = if config.exec.action == ExecAction::Random {
        let actions =
            [ExecAction::Remove, ExecAction::Duplicate, ExecAction::Swap];
        actions[rng.gen_range(0..if can_swap { 3 } else { 2 })]
    } else {
        config.exec.action
    };
    let index = rng.gen_range(0..items.len());
    let mut result = items.clone();
    let mut other_index = None;
    let kind = match action {
        ExecAction::Remove => {
            result.remove(index);
            MutationKind::ExecRemove
        }
        ExecAction::Duplicate => {
            result.insert(index + 1, items[index].clone());
            MutationKind::ExecDuplicate
        }
        ExecAction::Swap => {
            let mut candidates = items
                .iter()
                .enumerate()
                .filter(|(_, item)| **item != items[index]);
            let selected = rng.gen_range(0..candidates.clone().count());
            // can_swap guarantees a distinct partner for every first index.
            let (other, _) = candidates.nth(selected)?;
            result.swap(index, other);
            other_index = Some(other);
            MutationKind::ExecSwap
        }
        ExecAction::Off | ExecAction::Random => return None,
    };
    let detail = ExecMutation {
        original_count: items.len(),
        replacement_count: result.len(),
        index,
        other_index,
    };
    Some(MutatedReply {
        bytes: Frame::Array(Some(result)).encode(),
        mutations: vec![AppliedMutation {
            path: "root".to_owned(),
            kind,
            length: None,
            exec: Some(detail),
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evil::{deterministic_hash, mutate_command_reply};
    use crate::resp::parse_frame;

    fn apply(config: &mut EvilConfig, command: &str) -> AppResult<()> {
        config
            .apply_debug_command(
                &format!("DEBUG EVIL {command}")
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect::<Vec<_>>(),
            )
            .map(|_| ())
    }

    fn config(action: &str) -> EvilConfig {
        let mut config = EvilConfig::default();
        apply(&mut config, "MODE MUTATE").unwrap();
        apply(&mut config, &format!("EXEC {action}")).unwrap();
        config
    }

    fn run(config: &EvilConfig, bytes: &[u8]) -> MutatedReply {
        mutate_command_reply(
            config,
            9,
            Some("EXEC"),
            "command",
            &deterministic_hash(bytes),
            &parse_frame(bytes).unwrap(),
        )
    }

    #[test]
    fn configuration_is_atomic_local_and_preserved_by_mode_changes() {
        let mut config = EvilConfig::default();
        assert!(config.status().contains("exec=OFF exec_probability=100.00"));
        apply(&mut config, "exec swap probability 12.5").unwrap();
        assert!(config.status().contains("exec=SWAP exec_probability=12.50"));
        let before = config.status();
        for command in [
            "EXEC",
            "EXEC UNKNOWN",
            "EXEC SWAP EXTRA",
            "EXEC REMOVE PROBABILITY",
            "EXEC REMOVE PROBABILITY NaN",
            "EXEC REMOVE PROBABILITY inf",
            "EXEC REMOVE PROBABILITY -1",
            "EXEC REMOVE PROBABILITY 101",
            "EXEC REMOVE PROBABILITY 50 PROBABILITY 60",
            "EXEC OFF PROBABILITY 10",
            "EXEC SWAP UNKNOWN 10",
        ] {
            assert!(apply(&mut config, command).is_err(), "{command}");
            assert_eq!(config.status(), before, "{command}");
        }
        for mode in ["OFF", "RANDOM", "OVERFLOW", "MUTATE", "RESET"] {
            apply(&mut config, &format!("MODE {mode}")).unwrap();
            assert!(
                config.status().contains("exec=SWAP exec_probability=12.50")
            );
        }
        apply(&mut config, "EXEC DUPLICATE").unwrap();
        assert!(
            config
                .status()
                .contains("exec=DUPLICATE exec_probability=100.00")
        );
        apply(&mut config, "EXEC OFF").unwrap();
        assert_eq!(config.exec, EvilConfig::default().exec);
    }

    #[test]
    fn edits_have_exact_valid_framing_and_repro_details() {
        // A singleton forces index zero, making remove/duplicate exact without
        // relying on which random index was selected. SWAP has one partner.
        for (action, before, after, kind) in [
            ("REMOVE", "*1\r\n:42\r\n", "*0\r\n", "exec_remove"),
            (
                "DUPLICATE",
                "*1\r\n:42\r\n",
                "*2\r\n:42\r\n:42\r\n",
                "exec_duplicate",
            ),
            (
                "SWAP",
                "*2\r\n:42\r\n*1\r\n+OK\r\n",
                "*2\r\n*1\r\n+OK\r\n:42\r\n",
                "exec_swap",
            ),
        ] {
            let result = run(&config(action), before.as_bytes());
            assert_eq!(result.bytes, after.as_bytes());
            assert_eq!(
                parse_frame(&result.bytes).unwrap().encode(),
                result.bytes
            );
            assert_eq!(result.mutations.len(), 1);
            let record = serde_json::to_value(&result.mutations[0]).unwrap();
            assert_eq!(record["kind"], kind);
            assert_eq!(record["path"], "root");
            assert!(record.get("length").is_none());
            let original = parse_frame(before.as_bytes()).unwrap();
            let Frame::Array(Some(mut items)) = original else {
                unreachable!()
            };
            assert_eq!(record["exec"]["original_count"], items.len());
            let index = record["exec"]["index"].as_u64().unwrap() as usize;
            match action {
                "REMOVE" => {
                    items.remove(index);
                }
                "DUPLICATE" => items.insert(index + 1, items[index].clone()),
                _ => items.swap(
                    index,
                    record["exec"]["other_index"].as_u64().unwrap() as usize,
                ),
            }
            assert_eq!(record["exec"]["replacement_count"], items.len());
            assert_eq!(Frame::Array(Some(items)).encode(), result.bytes);
        }
    }

    #[test]
    fn ineligible_and_skipped_edits_preserve_generic_output() {
        for action in ["OFF", "REMOVE", "DUPLICATE", "SWAP", "RANDOM"] {
            let mut configured = config(action);
            for bytes in [
                b"*0\r\n".as_slice(),
                b"*-1\r\n",
                b"_\r\n",
                b"-EXECABORT aborted\r\n",
                b"+QUEUED\r\n",
            ] {
                let mut baseline = configured.clone();
                apply(&mut baseline, "EXEC OFF").unwrap();
                let original = run(&baseline, bytes);
                assert_eq!(run(&configured, bytes).bytes, original.bytes);
            }
            apply(&mut configured, &format!("EXEC {action}")).unwrap();
            let bytes = b"*2\r\n:1\r\n:2\r\n";
            let mut baseline = configured.clone();
            apply(&mut baseline, "EXEC OFF").unwrap();
            configured.exec.probability = 0.0;
            assert_eq!(
                run(&configured, bytes).bytes,
                run(&baseline, bytes).bytes
            );
        }
        for bytes in [b"*1\r\n:42\r\n".as_slice(), b"*2\r\n:42\r\n:42\r\n"] {
            let configured = config("SWAP");
            let mut baseline = configured.clone();
            apply(&mut baseline, "EXEC OFF").unwrap();
            assert_eq!(
                run(&configured, bytes).bytes,
                run(&baseline, bytes).bytes
            );
        }
    }

    #[test]
    fn focused_edits_override_generic_settings_only_in_mutation_modes() {
        let bytes = b"*1\r\n:42\r\n";
        for mode in ["MUTATE", "OVERFLOW"] {
            for count in ["ONE", "MANY"] {
                for strategy in ["PRESERVE", "REPLACE"] {
                    for probability in [0, 100] {
                        let mut configured = config("REMOVE");
                        apply(
                            &mut configured,
                            &format!("MODE {mode} PROBABILITY {probability}"),
                        )
                        .unwrap();
                        apply(&mut configured, &format!("MUTATIONS {count}"))
                            .unwrap();
                        apply(&mut configured, &format!("STRATEGY {strategy}"))
                            .unwrap();
                        apply(
                            &mut configured,
                            "FRAMING LENGTH TARGET root KIND OVERFLOW",
                        )
                        .unwrap();
                        let result = run(&configured, bytes);
                        assert_eq!(result.bytes, b"*0\r\n");
                        assert_eq!(result.mutations.len(), 1);
                    }
                }
            }
        }
        for mode in ["OFF", "RANDOM"] {
            let mut configured = config("REMOVE");
            apply(&mut configured, &format!("MODE {mode}")).unwrap();
            assert!(
                mutate_reply(
                    &configured,
                    0,
                    "command",
                    "upstream",
                    &parse_frame(bytes).unwrap()
                )
                .is_none()
            );
        }
        let configured = config("REMOVE");
        let frame = parse_frame(bytes).unwrap();
        let actual = mutate_command_reply(
            &configured,
            9,
            Some("MGET"),
            "command",
            "upstream",
            &frame,
        );
        let expected = crate::evil::mutate_reply(
            &configured,
            9,
            "command",
            "upstream",
            &frame,
        );
        assert_eq!(actual.bytes, expected.bytes);
    }

    #[test]
    fn random_chooses_only_applicable_edits_and_is_repeatable() {
        for bytes in [
            b"*1\r\n:42\r\n".as_slice(),
            b"*3\r\n:42\r\n:42\r\n*1\r\n+OK\r\n",
        ] {
            let mut seen = std::collections::BTreeSet::new();
            for seed in 0..64 {
                let mut configured = config("RANDOM");
                configured.seed = seed;
                let first = run(&configured, bytes);
                let second = run(&configured, bytes);
                assert_eq!(first.bytes, second.bytes);
                assert_ne!(first.bytes, bytes);
                assert_eq!(first.mutations.len(), 1);
                let record = serde_json::to_value(&first.mutations).unwrap();
                assert_eq!(
                    record,
                    serde_json::to_value(&second.mutations).unwrap()
                );
                seen.insert(record[0]["kind"].as_str().unwrap().to_owned());
            }
            assert!(seen.contains("exec_remove"));
            assert!(seen.contains("exec_duplicate"));
            assert_eq!(seen.contains("exec_swap"), bytes.starts_with(b"*3"));
        }
    }
}
