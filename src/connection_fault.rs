//! Deterministic connection-fault configuration and plans; no socket I/O.

use rand::Rng;
use serde::Serialize;

use crate::error::{AppError, AppResult};
use crate::evil::rng_for;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultAction {
    #[default]
    Off,
    Close,
    Reset,
    Stall,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultPoint {
    Before,
    #[default]
    After,
    Reply,
    Random,
    Bytes(usize),
}

#[derive(Clone, Debug)]
pub(crate) struct FaultConfig {
    pub action: FaultAction,
    pub point: FaultPoint,
    pub duration_ms: u64,
}

impl Default for FaultConfig {
    fn default() -> Self {
        Self {
            action: FaultAction::Off,
            point: FaultPoint::After,
            duration_ms: 10_000,
        }
    }
}

impl FaultConfig {
    pub(crate) fn set_action(&mut self, value: &str) -> AppResult<()> {
        self.action = match value.to_ascii_uppercase().as_str() {
            "OFF" => FaultAction::Off,
            "CLOSE" => FaultAction::Close,
            "RESET" => FaultAction::Reset,
            "STALL" => FaultAction::Stall,
            _ => return Err(invalid("FAULT expects OFF|CLOSE|RESET|STALL")),
        };
        Ok(())
    }

    pub(crate) fn set_point(&mut self, value: &str) -> AppResult<()> {
        self.point = match value.to_ascii_uppercase().as_str() {
            "BEFORE" => FaultPoint::Before,
            "AFTER" => FaultPoint::After,
            "REPLY" => FaultPoint::Reply,
            "RANDOM" => FaultPoint::Random,
            _ => FaultPoint::Bytes(
                decimal(value)?
                    .try_into()
                    .map_err(|_| invalid("AT offset is too large"))?,
            ),
        };
        Ok(())
    }

    pub(crate) fn set_duration(&mut self, value: &str) -> AppResult<()> {
        let ms = decimal(value)?;
        if !(1..=3_600_000).contains(&ms) {
            return Err(invalid("DURATION expects 1..3600000 milliseconds"));
        }
        self.duration_ms = ms;
        Ok(())
    }

    pub(crate) fn status(&self) -> String {
        let action = match self.action {
            FaultAction::Off => "OFF",
            FaultAction::Close => "CLOSE",
            FaultAction::Reset => "RESET",
            FaultAction::Stall => "STALL",
        };
        let point = match self.point {
            FaultPoint::Before => "BEFORE".to_owned(),
            FaultPoint::After => "AFTER".to_owned(),
            FaultPoint::Reply => "REPLY".to_owned(),
            FaultPoint::Random => "RANDOM".to_owned(),
            FaultPoint::Bytes(n) => n.to_string(),
        };
        format!(
            "transport_fault={action} transport_at={point} transport_duration={}",
            self.duration_ms
        )
    }

    pub(crate) fn plan(
        &self,
        probability: f64,
        seed: u64,
        command_index: u64,
        command_hash: &str,
        response_len: usize,
    ) -> Option<ConnectionFaultPlan> {
        if self.action == FaultAction::Off || probability == 0.0 {
            return None;
        }
        // A separate domain, without a reply hash, allows BEFORE selection
        // without executing upstream and leaves legacy delivery RNG unchanged.
        let mut rng = rng_for(
            seed,
            command_index,
            &format!("connection-fault:v1:{command_hash}"),
            "",
        );
        if !rng.gen_bool(probability / 100.0) {
            return None;
        }
        let after_bytes = match self.point {
            FaultPoint::Before | FaultPoint::After => 0,
            FaultPoint::Reply => response_len,
            FaultPoint::Random if response_len > 0 => {
                rng.gen_range(0..response_len)
            }
            FaultPoint::Random => 0,
            FaultPoint::Bytes(n) if n <= response_len => n,
            FaultPoint::Bytes(_) => return None,
        };
        Some(ConnectionFaultPlan {
            action: self.action,
            point: self.point,
            after_bytes,
            duration_ms: (self.action == FaultAction::Stall)
                .then_some(self.duration_ms),
        })
    }
}

fn decimal(value: &str) -> AppResult<u64> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid(
            "fault offsets/durations must be unsigned decimal integers",
        ));
    }
    value
        .parse()
        .map_err(|_| invalid("fault offset/duration is too large"))
}

fn invalid(message: &str) -> AppError {
    AppError::EvilConfig(message.to_owned())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConnectionFaultPlan {
    pub action: FaultAction,
    pub point: FaultPoint,
    pub after_bytes: usize,
    pub duration_ms: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fault_actions_never_select_stalls_implicitly() {
        for action in [FaultAction::Off, FaultAction::Close, FaultAction::Reset]
        {
            let config = FaultConfig {
                action,
                point: FaultPoint::Random,
                ..FaultConfig::default()
            };
            for seed in 0..128 {
                let plan = config.plan(100.0, seed, 7, "command", 20);
                if let Some(plan) = plan {
                    assert_eq!(plan.action, action);
                    assert!(plan.duration_ms.is_none());
                    assert!(plan.after_bytes < 20);
                    assert_eq!(
                        Some(plan),
                        config.plan(100.0, seed, 7, "command", 20)
                    );
                } else {
                    assert_eq!(action, FaultAction::Off);
                }
            }
        }
    }

    #[test]
    fn explicit_points_and_stalls_have_exact_plans() {
        for (point, expected) in [
            (FaultPoint::Before, Some(0)),
            (FaultPoint::After, Some(0)),
            (FaultPoint::Reply, Some(8)),
            (FaultPoint::Bytes(3), Some(3)),
            (FaultPoint::Bytes(8), Some(8)),
            (FaultPoint::Bytes(9), None),
        ] {
            let config = FaultConfig {
                action: FaultAction::Stall,
                point,
                duration_ms: 1234,
            };
            let expected = expected.map(|after_bytes| ConnectionFaultPlan {
                action: FaultAction::Stall,
                point,
                after_bytes,
                duration_ms: Some(1234),
            });
            assert_eq!(config.plan(100.0, 42, 7, "command", 8), expected);
            assert_eq!(config.plan(0.0, 42, 7, "command", 8), None);
        }
    }
}
