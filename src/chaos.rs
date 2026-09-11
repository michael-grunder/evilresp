//! Expand a temperature into ordinary evil settings, without another RNG or
//! persistent mode. Subsequent DEBUG EVIL commands can refine the preset.

use crate::error::{AppError, AppResult};
use crate::evil::{EvilConfig, EvilMode, MutationCount, MutationStrategy};
use crate::exec_mutation::ExecConfig;
use crate::framing::FramingConfig;
use crate::protocol_fingerprint::ProtocolHash;
use crate::transport::TransportConfig;

const USAGE: &str =
    "expected DEBUG CHAOS <0..100> [SEED <u64>] [HASH <BLAKE3|TLSH>]";

pub(crate) fn apply(
    config: &mut EvilConfig,
    argv: &[String],
) -> AppResult<ProtocolHash> {
    if argv.len() < 3
        || !argv[0].eq_ignore_ascii_case("DEBUG")
        || !argv[1].eq_ignore_ascii_case("CHAOS")
    {
        return Err(invalid(USAGE));
    }
    let temperature = argv[2].parse::<f64>().map_err(|_| {
        invalid("temperature must be a finite number in 0..100")
    })?;
    if !(0.0..=100.0).contains(&temperature) {
        return Err(invalid("temperature must be a finite number in 0..100"));
    }
    let mut seed = config.seed;
    let mut hash = ProtocolHash::Blake3;
    let (options, tail) = argv[3..].as_chunks::<2>();
    if !tail.is_empty() {
        return Err(invalid(USAGE));
    }
    let mut seen = [false; 2];
    for [key, value] in options {
        let index = match key.to_ascii_uppercase().as_str() {
            "SEED" => {
                seed = value.parse().map_err(|_| {
                    invalid("SEED requires an unsigned 64-bit integer")
                })?;
                0
            }
            "HASH" => {
                hash = value.parse()?;
                1
            }
            _ => return Err(invalid(USAGE)),
        };
        if seen[index] {
            return Err(invalid("duplicate DEBUG CHAOS option"));
        }
        seen[index] = true;
    }

    // Stage the complete preset so even a failed expansion changes nothing.
    let mut next = config.clone();
    next.seed = seed;
    next.mode = if temperature == 0.0 {
        EvilMode::Off
    } else {
        EvilMode::Mutate
    };
    next.probability = temperature;
    next.strategy = if temperature > 50.0 {
        MutationStrategy::Replace
    } else {
        MutationStrategy::Preserve
    };
    next.mutation_count = if temperature > 25.0 {
        MutationCount::Many
    } else {
        MutationCount::One
    };
    next.framing = FramingConfig::Off;
    next.exec = ExecConfig::default();
    next.transport = TransportConfig::default();
    next.topology_redirect = None;
    next.topology_probability = (temperature - 50.0).max(0.0) / 2.0;
    next.generator = next.generator.updated(&strings(&[
        "CORPUS",
        "BOUNDARY",
        "VIOLATIONS",
        if temperature > 75.0 { "ON" } else { "OFF" },
    ]))?;
    if temperature > 25.0 {
        next.exec = ExecConfig::parse(&strings(&[
            "RANDOM",
            "PROBABILITY",
            &((temperature - 25.0) / 3.0).to_string(),
        ]))?;
    }
    if temperature > 50.0 {
        next.framing = FramingConfig::parse(&strings(&[
            "LENGTH",
            "PROBABILITY",
            &((temperature - 50.0) * 2.0).to_string(),
            "TARGET",
            "ANY",
            "KIND",
            "RANDOM",
        ]))?;
    }
    if temperature > 75.0 {
        next.transport = next.transport.updated(&strings(&[
            "TRUNCATE",
            "RANDOM",
            "CHUNKS",
            "RANDOM",
            "PROBABILITY",
            &(temperature - 75.0).to_string(),
        ]))?;
    }
    *config = next;
    Ok(hash)
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn invalid(message: &str) -> AppError {
    AppError::EvilConfig(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chaos(config: &mut EvilConfig, args: &str) -> AppResult<ProtocolHash> {
        apply(
            config,
            &strings(
                &format!("DEBUG CHAOS {args}")
                    .split_whitespace()
                    .collect::<Vec<_>>(),
            ),
        )
    }

    #[test]
    fn invalid_commands_are_atomic() {
        let mut config = EvilConfig::default();
        chaos(&mut config, "90 SEED 42").unwrap();
        let before = config.status();
        for args in [
            "",
            "-1",
            "100.1",
            "NaN",
            "inf",
            "-inf",
            "hot",
            "20 SEED",
            "20 SEED -1",
            "20 SEED 18446744073709551616",
            "20 SEED 9 HASH SHA256",
            "20 SEED 9 seed 10",
            "20 HASH TLSH hash BLAKE3",
            "20 UNKNOWN 1",
            "20 HASH TLSH extra",
        ] {
            assert!(chaos(&mut config, args).is_err(), "{args}");
            assert_eq!(config.status(), before, "{args}");
        }
    }

    #[test]
    fn preset_preserves_context_and_can_be_refined() {
        let mut config = EvilConfig::default();
        for args in [
            "SEED 18446744073709551615",
            "INCLUDE GET EXEC",
            "EXCLUDE EXEC",
            "CANONICALIZE NONE",
            "GENERATOR PROTOCOL RESP3",
            "TOPOLOGY REDIRECT TARGET example.test:1234",
            "TRANSPORT FAULT STALL DURATION 42",
        ] {
            config
                .apply_debug_command(&strings(
                    &format!("DEBUG EVIL {args}")
                        .split_whitespace()
                        .collect::<Vec<_>>(),
                ))
                .unwrap();
        }
        assert_eq!(
            chaos(&mut config, "100 hash tlsh").unwrap(),
            ProtocolHash::Tlsh
        );
        assert_eq!(config.seed, u64::MAX);
        assert!(config.should_mutate_command(Some("GET")));
        assert!(!config.should_mutate_command(Some("SET")));
        assert!(!config.should_mutate_command(Some("EXEC")));
        assert!(config.status().contains("canonicalize=NONE"));
        assert!(config.generator.status().contains("RESP3"));
        assert!(config.topology_redirect.is_none());
        assert!(!config.transport.status().contains("STALL"));
        config
            .apply_debug_command(&strings(&["DEBUG", "EVIL", "FRAMING", "OFF"]))
            .unwrap();
        assert!(matches!(config.framing, FramingConfig::Off));
        assert_eq!(
            chaos(&mut config, "0 SEED 7").unwrap(),
            ProtocolHash::Blake3
        );
        assert_eq!(config.seed, 7);
        assert_eq!(config.mode, EvilMode::Off);
        assert_eq!(config.probability, 0.0);
        assert_eq!(config.topology_probability, 0.0);
        assert!(!config.transport.enabled());
        assert_eq!(config.exec, ExecConfig::default());
        assert!(matches!(config.framing, FramingConfig::Off));
    }

    #[test]
    fn temperature_boundaries_expand_to_documented_settings() {
        for t in [0.0, 0.01, 25.0, 25.01, 50.0, 50.01, 75.0, 75.01, 100.0] {
            let mut config = EvilConfig::default();
            chaos(&mut config, &t.to_string()).unwrap();
            assert_eq!(config.probability, t);
            assert_eq!(config.mode == EvilMode::Off, t == 0.0);
            assert_eq!(config.mutation_count == MutationCount::Many, t > 25.0);
            assert_eq!(config.strategy == MutationStrategy::Replace, t > 50.0);
            assert_eq!(
                matches!(config.framing, FramingConfig::Length(_)),
                t > 50.0
            );
            assert_eq!(config.exec != ExecConfig::default(), t > 25.0);
            assert_eq!(config.transport.enabled(), t > 75.0);
            assert_eq!(
                config.generator.status().contains("violations=ON"),
                t > 75.0
            );
            assert_eq!(config.topology_probability, (t - 50.0).max(0.0) / 2.0);
        }
    }
}
