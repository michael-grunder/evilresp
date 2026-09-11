//! Validated controls for focused cluster redirection faults.

use std::collections::BTreeSet;
use std::net::Ipv6Addr;

use crate::cli::TcpEndpoint;
use crate::error::{AppError, AppResult};
use crate::evil::parse_probability;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RedirectKind {
    Moved,
    Ask,
    Random,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RedirectPhase {
    Before,
    After,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RedirectTarget {
    WrongNode,
    SelfNode,
    Replica,
    Next,
    Random,
    Endpoint(TcpEndpoint),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RedirectSlot {
    Correct,
    Wrong,
    Wild,
    Fixed(u16),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RedirectConfig {
    pub kind: RedirectKind,
    pub target: RedirectTarget,
    pub slot: RedirectSlot,
    pub phase: RedirectPhase,
    pub key: usize,
    pub until: Option<u64>,
}

impl Default for RedirectConfig {
    fn default() -> Self {
        Self {
            kind: RedirectKind::Moved,
            target: RedirectTarget::WrongNode,
            slot: RedirectSlot::Correct,
            phase: RedirectPhase::Before,
            key: 1,
            until: None,
        }
    }
}

/// Return both settings so callers can commit an update atomically. The
/// probability-only form retains its historical mutation algorithm.
pub(crate) fn parse_topology(
    args: &[String],
) -> AppResult<(f64, Option<RedirectConfig>)> {
    let Some(first) = args.first() else {
        return Err(invalid("expected TOPOLOGY <probability|OFF|REDIRECT>"));
    };
    if !first.eq_ignore_ascii_case("REDIRECT") {
        if args.len() != 1 {
            return Err(invalid(
                "TOPOLOGY probability and OFF accept no options",
            ));
        }
        return Ok((
            if first.eq_ignore_ascii_case("OFF") {
                0.0
            } else {
                parse_probability(first)?
            },
            None,
        ));
    }

    let mut config = RedirectConfig::default();
    let mut probability = 100.0;
    let mut seen = BTreeSet::new();
    let (options, remainder) = args[1..].as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(invalid("TOPOLOGY REDIRECT expects option/value pairs"));
    }
    for pair in options {
        let option = pair[0].to_ascii_uppercase();
        let value = pair[1].as_str();
        if !seen.insert(option.clone()) {
            return Err(invalid(&format!(
                "duplicate topology option {option}"
            )));
        }
        match option.as_str() {
            "PROBABILITY" => probability = parse_probability(value)?,
            "KIND" => {
                config.kind = match value.to_ascii_uppercase().as_str() {
                    "MOVED" => RedirectKind::Moved,
                    "ASK" => RedirectKind::Ask,
                    "RANDOM" => RedirectKind::Random,
                    _ => return Err(invalid("KIND expects MOVED|ASK|RANDOM")),
                };
            }
            "TARGET" => {
                config.target = match value.to_ascii_uppercase().as_str() {
                    "WRONG_NODE" => RedirectTarget::WrongNode,
                    "SELF" => RedirectTarget::SelfNode,
                    "REPLICA" => RedirectTarget::Replica,
                    "NEXT" => RedirectTarget::Next,
                    "RANDOM" => RedirectTarget::Random,
                    _ => RedirectTarget::Endpoint(parse_target(value)?),
                };
            }
            "SLOT" => {
                config.slot =
                    match value.to_ascii_uppercase().as_str() {
                        "CORRECT" => RedirectSlot::Correct,
                        "WRONG" => RedirectSlot::Wrong,
                        "WILD" => RedirectSlot::Wild,
                        _ => {
                            let slot = value.parse::<u16>().ok()
                            .filter(|slot| *slot < 16_384)
                            .ok_or_else(|| invalid(
                                "SLOT expects CORRECT|WRONG|WILD|0..16383",
                            ))?;
                            RedirectSlot::Fixed(slot)
                        }
                    };
            }
            "PHASE" => {
                config.phase = match value.to_ascii_uppercase().as_str() {
                    "BEFORE" => RedirectPhase::Before,
                    "AFTER" => RedirectPhase::After,
                    _ => return Err(invalid("PHASE expects BEFORE|AFTER")),
                };
            }
            "KEY" => {
                config.key = value
                    .parse::<usize>()
                    .ok()
                    .filter(|index| *index > 0)
                    .ok_or_else(|| {
                        invalid("KEY expects a positive argument index")
                    })?;
            }
            "UNTIL" => {
                config.until =
                    if value.eq_ignore_ascii_case("OFF") {
                        None
                    } else {
                        Some(value.parse::<u64>().map_err(|_| invalid(
                        "UNTIL expects OFF or an unsigned command index",
                    ))?)
                    };
            }
            _ => {
                return Err(invalid(&format!(
                    "unknown topology option {option}"
                )));
            }
        }
    }
    Ok((probability, Some(config)))
}

fn parse_target(value: &str) -> AppResult<TcpEndpoint> {
    let endpoint: TcpEndpoint = value.parse().map_err(|_| {
        invalid("TARGET expects WRONG_NODE|SELF|REPLICA|NEXT|RANDOM|host:port")
    })?;
    // Literal targets must still form one valid RESP error argument. IPv6
    // addresses are normalized by TcpEndpoint when the reply is encoded.
    if !endpoint
        .host
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b".-_:".contains(&byte))
        || ((endpoint.host.contains(':') || value.starts_with('['))
            && endpoint.host.parse::<Ipv6Addr>().is_err())
    {
        return Err(invalid("invalid topology target host"));
    }
    Ok(endpoint)
}

fn invalid(message: &str) -> AppError {
    AppError::EvilConfig(message.to_owned())
}

impl RedirectConfig {
    pub(crate) fn status(&self) -> String {
        let kind = match self.kind {
            RedirectKind::Moved => "MOVED",
            RedirectKind::Ask => "ASK",
            RedirectKind::Random => "RANDOM",
        };
        let target = match &self.target {
            RedirectTarget::WrongNode => "WRONG_NODE".to_owned(),
            RedirectTarget::SelfNode => "SELF".to_owned(),
            RedirectTarget::Replica => "REPLICA".to_owned(),
            RedirectTarget::Next => "NEXT".to_owned(),
            RedirectTarget::Random => "RANDOM".to_owned(),
            RedirectTarget::Endpoint(endpoint) => endpoint.to_string(),
        };
        let slot = match self.slot {
            RedirectSlot::Correct => "CORRECT".to_owned(),
            RedirectSlot::Wrong => "WRONG".to_owned(),
            RedirectSlot::Wild => "WILD".to_owned(),
            RedirectSlot::Fixed(slot) => slot.to_string(),
        };
        let phase = match self.phase {
            RedirectPhase::Before => "BEFORE",
            RedirectPhase::After => "AFTER",
        };
        let until = self
            .until
            .map_or_else(|| "OFF".to_owned(), |n| n.to_string());
        format!(
            "topology=REDIRECT topology_kind={kind} topology_target={target} topology_slot={slot} topology_phase={phase} topology_key={} topology_until={until}",
            self.key,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evil::EvilConfig;

    fn apply(config: &mut EvilConfig, options: &str) -> AppResult<()> {
        let argv = format!("DEBUG EVIL {options}")
            .split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        config.apply_debug_command(&argv).map(|_| ())
    }

    #[test]
    fn defaults_updates_status_and_legacy_forms() {
        let mut config = EvilConfig::default();
        apply(&mut config, "TOPOLOGY REDIRECT").unwrap();
        assert_eq!(config.topology_probability, 100.0);
        assert_eq!(config.topology_redirect, Some(RedirectConfig::default()));
        apply(&mut config, "TOPOLOGY redirect kind ask target [::1]:7999 slot 42 phase after key 3 until 17 probability 12.5").unwrap();
        let configured = config.status();
        assert!(configured.contains("topology_probability=12.50"));
        assert!(configured.contains("topology=REDIRECT topology_kind=ASK topology_target=[::1]:7999 topology_slot=42 topology_phase=AFTER topology_key=3 topology_until=17"));
        let redirect = config.topology_redirect.clone();
        for mode in ["MUTATE", "RANDOM", "OFF", "RESET"] {
            apply(&mut config, &format!("MODE {mode}")).unwrap();
            assert_eq!(config.topology_redirect, redirect);
            assert_eq!(config.topology_probability, 12.5);
        }
        // Each REDIRECT command starts from defaults rather than retaining
        // a previous target, phase, or cutoff by accident.
        apply(&mut config, "TOPOLOGY REDIRECT KIND RANDOM").unwrap();
        assert_eq!(config.topology_redirect.as_ref().unwrap().until, None);
        assert_eq!(
            config.topology_redirect.as_ref().unwrap().phase,
            RedirectPhase::Before
        );
        apply(&mut config, "TOPOLOGY 12.5").unwrap();
        assert_eq!(config.topology_probability, 12.5);
        assert_eq!(config.topology_redirect, None);
        assert!(config.status().contains("topology=LEGACY"));
        apply(&mut config, "TOPOLOGY OFF").unwrap();
        assert_eq!(config.topology_probability, 0.0);
        assert_eq!(config.topology_redirect, None);
    }

    #[test]
    fn rejects_invalid_and_duplicate_options_atomically() {
        let mut config = EvilConfig::default();
        apply(
            &mut config,
            "TOPOLOGY REDIRECT KIND ASK PROBABILITY 12 UNTIL 9",
        )
        .unwrap();
        let before = config.status();
        for options in [
            "TOPOLOGY",
            "TOPOLOGY OFF EXTRA",
            "TOPOLOGY 10 EXTRA",
            "TOPOLOGY REDIRECT KIND",
            "TOPOLOGY REDIRECT UNKNOWN 1",
            "TOPOLOGY REDIRECT KIND ASKING",
            "TOPOLOGY REDIRECT KIND MOVED kind ASK",
            "TOPOLOGY REDIRECT TARGET UNKNOWN",
            "TOPOLOGY REDIRECT TARGET host:65536",
            "TOPOLOGY REDIRECT TARGET :6379",
            "TOPOLOGY REDIRECT TARGET [not-ipv6]:123",
            "TOPOLOGY REDIRECT SLOT -1",
            "TOPOLOGY REDIRECT SLOT 16384",
            "TOPOLOGY REDIRECT PHASE MIDDLE",
            "TOPOLOGY REDIRECT KEY 0",
            "TOPOLOGY REDIRECT KEY -1",
            "TOPOLOGY REDIRECT UNTIL -1",
            "TOPOLOGY REDIRECT UNTIL 18446744073709551616",
            "TOPOLOGY REDIRECT PROBABILITY NaN",
            "TOPOLOGY REDIRECT PROBABILITY 101",
            "TOPOLOGY REDIRECT PROBABILITY -0.1",
            "TOPOLOGY REDIRECT PROBABILITY inf",
        ] {
            assert!(apply(&mut config, options).is_err(), "{options}");
            assert_eq!(config.status(), before, "{options}");
        }
        for host in ["bad\r\nhost:6379", "bad host:6379", "bad\0host:6379"] {
            let argv =
                ["DEBUG", "EVIL", "TOPOLOGY", "REDIRECT", "TARGET", host]
                    .map(str::to_owned);
            assert!(config.apply_debug_command(&argv).is_err());
            assert_eq!(config.status(), before);
        }
    }
}
