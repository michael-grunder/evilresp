//! Deterministic delivery plans and byte-accounted execution. Chunk boundaries
//! describe writer calls, never TCP packets or the client's read boundaries.

use std::io::{self, ErrorKind};

use rand::Rng;
use serde::Serialize;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::error::{AppError, AppResult};
use crate::evil::{deterministic_hash, parse_probability, rng_for};
use crate::protocol_fingerprint::{ProtocolDirection, ProtocolFingerprints};

const EXTRA_REPLY: &[u8] = b"+EVILRESP\r\n";
const MAX_BOUNDARIES: usize = 64;

#[derive(Clone, Debug, Default)]
enum Cut {
    #[default]
    Off,
    Random,
    At(usize),
}

#[derive(Clone, Debug, Default)]
enum Chunks {
    #[default]
    Off,
    Random,
    At(Vec<usize>),
}

#[derive(Clone, Debug)]
pub(crate) struct TransportConfig {
    truncate: Cut,
    extra: usize,
    chunks: Chunks,
    probability: f64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            truncate: Cut::Off,
            extra: 0,
            chunks: Chunks::Off,
            probability: 100.0,
        }
    }
}

impl TransportConfig {
    pub(crate) fn enabled(&self) -> bool {
        !matches!(self.truncate, Cut::Off)
            || self.extra != 0
            || !matches!(self.chunks, Chunks::Off)
    }

    pub(crate) fn updated(&self, argv: &[String]) -> AppResult<Self> {
        if argv.len() == 1 && argv[0].eq_ignore_ascii_case("OFF") {
            return Ok(Self::default());
        }
        let (pairs, tail) = argv.as_chunks::<2>();
        if pairs.is_empty() || !tail.is_empty() {
            return Err(invalid(
                "TRANSPORT requires OFF or option/value pairs",
            ));
        }
        let mut config = self.clone();
        let mut seen = [false; 4];
        for [key, value] in pairs {
            let index = match key.to_ascii_uppercase().as_str() {
                "TRUNCATE" => {
                    config.truncate = match value.to_ascii_uppercase().as_str()
                    {
                        "OFF" => Cut::Off,
                        "RANDOM" => Cut::Random,
                        _ => Cut::At(offset(value)?),
                    };
                    0
                }
                "EXTRA" => {
                    config.extra = offset(value)?;
                    if config.extra > 16 {
                        return Err(invalid("TRANSPORT EXTRA requires 0..16"));
                    }
                    1
                }
                "CHUNKS" => {
                    config.chunks = match value.to_ascii_uppercase().as_str() {
                        "OFF" => Chunks::Off,
                        "RANDOM" => Chunks::Random,
                        _ => {
                            // Bound parsing and allocation even for hostile DEBUG input.
                            let mut offsets = Vec::new();
                            for part in value.split(',') {
                                let next = offset(part)?;
                                if offsets.len() == MAX_BOUNDARIES
                                    || next == 0
                                    || offsets
                                        .last()
                                        .is_some_and(|last| *last >= next)
                                {
                                    return Err(invalid(
                                        "CHUNKS requires at most 64 strictly increasing positive offsets",
                                    ));
                                }
                                offsets.push(next);
                            }
                            Chunks::At(offsets)
                        }
                    };
                    2
                }
                "PROBABILITY" => {
                    config.probability = parse_probability(value)?;
                    3
                }
                _ => {
                    return Err(invalid(
                        "TRANSPORT accepts TRUNCATE, EXTRA, CHUNKS, and PROBABILITY",
                    ));
                }
            };
            if seen[index] {
                return Err(invalid("duplicate TRANSPORT option"));
            }
            seen[index] = true;
        }
        Ok(config)
    }

    pub(crate) fn status(&self) -> String {
        let cut = match self.truncate {
            Cut::Off => "OFF".to_owned(),
            Cut::Random => "RANDOM".to_owned(),
            Cut::At(n) => n.to_string(),
        };
        let chunks = match &self.chunks {
            Chunks::Off => "OFF".to_owned(),
            Chunks::Random => "RANDOM".to_owned(),
            Chunks::At(offsets) => offsets
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(","),
        };
        format!(
            "transport={} transport_probability={:.2} transport_truncate={cut} transport_extra={} transport_chunks={chunks}",
            if self.enabled() { "ON" } else { "OFF" },
            self.probability,
            self.extra
        )
    }

    pub(crate) fn plan(
        &self,
        seed: u64,
        command_index: u64,
        command_hash: &str,
        reply_hash: &str,
        response_len: usize,
    ) -> DeliveryPlan {
        let mut plan = DeliveryPlan::plain(response_len);
        if !self.enabled() || self.probability == 0.0 {
            return plan;
        }
        // Domain separation keeps transport choices out of the RESP RNG stream.
        let mut rng = rng_for(
            seed,
            command_index,
            &format!("transport:v1:{command_hash}"),
            reply_hash,
        );
        if !rng.gen_bool(self.probability / 100.0) {
            return plan;
        }
        plan.extra_reply_count = self.extra;
        let total = response_len + self.extra * EXTRA_REPLY.len();
        plan.truncate_at = match self.truncate {
            Cut::At(n) if n < total => Some(n),
            Cut::Random if total > 0 => Some(rng.gen_range(0..total)),
            _ => None,
        };
        let len = plan.truncate_at.unwrap_or(total);
        let mut boundaries = match &self.chunks {
            Chunks::Off => Vec::new(),
            Chunks::At(offsets) => {
                offsets.iter().copied().filter(|n| *n < len).collect()
            }
            Chunks::Random if len > 1 => {
                let count = rng.gen_range(1..=MAX_BOUNDARIES.min(len - 1));
                // Bounded draws; duplicate offsets are coalesced deterministically.
                let mut offsets = (0..count)
                    .map(|_| rng.gen_range(1..len))
                    .collect::<Vec<_>>();
                offsets.sort_unstable();
                offsets.dedup();
                offsets
            }
            Chunks::Random => Vec::new(),
        };
        if len > 0 {
            boundaries.push(len);
        }
        plan.chunk_ends = boundaries;
        plan
    }
}

fn invalid(message: &str) -> AppError {
    AppError::EvilConfig(message.to_owned())
}

fn offset(value: &str) -> AppResult<usize> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid(
            "transport offsets/counts must be unsigned decimal integers",
        ));
    }
    value
        .parse()
        .map_err(|_| invalid("transport offset/count is too large"))
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DeliveryPlan {
    pub version: u8,
    pub extra_reply_count: usize,
    pub extra_reply_bytes_hex: String,
    pub truncate_at: Option<usize>,
    /// Exclusive offsets into the planned wire bytes, including the final end.
    pub chunk_ends: Vec<usize>,
}

impl DeliveryPlan {
    pub(crate) fn plain(len: usize) -> Self {
        Self {
            version: 1,
            extra_reply_count: 0,
            extra_reply_bytes_hex: hex::encode(EXTRA_REPLY),
            truncate_at: None,
            chunk_ends: if len == 0 { Vec::new() } else { vec![len] },
        }
    }

    pub(crate) fn is_fault(&self) -> bool {
        self.extra_reply_count != 0
            || self.truncate_at.is_some()
            || self.chunk_ends.len() > 1
    }

    pub(crate) fn wire_bytes(&self, mut response: Vec<u8>) -> Vec<u8> {
        for _ in 0..self.extra_reply_count {
            response.extend_from_slice(EXTRA_REPLY);
        }
        if let Some(at) = self.truncate_at {
            response.truncate(at);
        }
        response
    }
}

#[derive(Debug, Serialize)]
pub struct DeliveryOutcome {
    pub bytes_written: usize,
    pub written_bytes_hash: String,
    pub completed_chunks: usize,
    pub shutdown_completed: bool,
    pub error_stage: Option<&'static str>,
    pub error_kind: Option<String>,
}

/// Writes only within a planned chunk; short writes finish that chunk before
/// the next starts. Account immediately, so errors cannot hide accepted bytes.
pub(crate) async fn write_counted<W: AsyncWrite + Unpin>(
    writer: &mut W,
    fingerprints: &mut ProtocolFingerprints,
    bytes: &[u8],
    written: &mut usize,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        match writer.write(&bytes[offset..]).await {
            Ok(0) => {
                return Err(io::Error::new(
                    ErrorKind::WriteZero,
                    "client writer made no progress",
                ));
            }
            Ok(n) => {
                fingerprints
                    .update(ProtocolDirection::Out, &bytes[offset..offset + n]);
                offset += n;
                *written += n;
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub(crate) async fn deliver<W: AsyncWrite + Unpin>(
    writer: &mut W,
    fingerprints: &mut ProtocolFingerprints,
    bytes: &[u8],
    plan: &DeliveryPlan,
) -> (DeliveryOutcome, io::Result<()>) {
    let mut outcome = DeliveryOutcome {
        bytes_written: 0,
        written_bytes_hash: String::new(),
        completed_chunks: 0,
        shutdown_completed: false,
        error_stage: None,
        error_kind: None,
    };
    let result = async {
        let mut start = 0;
        for &end in &plan.chunk_ends {
            outcome.error_stage = Some("write");
            write_counted(
                writer,
                fingerprints,
                &bytes[start..end],
                &mut outcome.bytes_written,
            )
            .await?;
            outcome.error_stage = Some("flush");
            writer.flush().await?;
            outcome.completed_chunks += 1;
            start = end;
        }
        if plan.truncate_at.is_some() {
            outcome.error_stage = Some("shutdown");
            writer.shutdown().await?;
            outcome.shutdown_completed = true;
        }
        Ok::<_, io::Error>(())
    }
    .await;
    outcome.written_bytes_hash =
        deterministic_hash(&bytes[..outcome.bytes_written]);
    match &result {
        Ok(()) => outcome.error_stage = None,
        Err(error) => outcome.error_kind = Some(format!("{:?}", error.kind())),
    }
    (outcome, result)
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use super::*;
    use crate::evil::EvilConfig;
    use crate::protocol_fingerprint::ProtocolHash;

    fn config(args: &[&str]) -> TransportConfig {
        TransportConfig::default()
            .updated(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap()
    }

    fn plan(config: &TransportConfig, len: usize) -> DeliveryPlan {
        config.plan(17, 9, "command", "upstream", len)
    }

    #[test]
    fn configuration_is_atomic_and_survives_reset() {
        let mut evil = EvilConfig::default();
        let apply = |evil: &mut EvilConfig, args: &[&str]| {
            evil.apply_debug_command(
                &["DEBUG", "EVIL", "TRANSPORT"]
                    .into_iter()
                    .chain(args.iter().copied())
                    .map(str::to_owned)
                    .collect::<Vec<_>>(),
            )
        };
        apply(
            &mut evil,
            &[
                "truncate",
                "3",
                "extra",
                "2",
                "chunks",
                "1,2",
                "probability",
                "50",
            ],
        )
        .unwrap();
        let before = evil.transport.status();
        for args in [
            vec![],
            vec!["OFF", "EXTRA", "1"],
            vec!["TRUNCATE"],
            vec!["TRUNCATE", "-1"],
            vec!["TRUNCATE", "184467440737095516160"],
            vec!["EXTRA", "17"],
            vec!["EXTRA", "1", "EXTRA", "2"],
            vec!["CHUNKS", "0"],
            vec!["CHUNKS", "2,1"],
            vec!["CHUNKS", "1,1"],
            vec!["CHUNKS", "1,"],
            vec!["CHUNKS", "+1"],
            vec!["PROBABILITY", "NaN"],
            vec!["PROBABILITY", "101"],
            vec!["TRUNCATE", "1", "CHUNKS", "bad"],
            vec!["UNKNOWN", "OFF"],
        ] {
            assert!(apply(&mut evil, &args).is_err(), "{args:?}");
            assert_eq!(evil.transport.status(), before);
        }
        let too_many = (1..=65)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(",");
        assert!(apply(&mut evil, &["CHUNKS", &too_many]).is_err());
        for mode in ["RANDOM", "MUTATE", "OVERFLOW", "OFF", "RESET"] {
            evil.apply_debug_command(
                &["DEBUG", "EVIL", "MODE", mode].map(str::to_owned),
            )
            .unwrap();
            assert_eq!(evil.transport.status(), before);
        }
        apply(&mut evil, &["EXTRA", "0"]).unwrap();
        assert!(evil.status().contains(
            "transport_truncate=3 transport_extra=0 transport_chunks=1,2"
        ));
        apply(&mut evil, &["OFF"]).unwrap();
        assert_eq!(
            evil.transport.status(),
            TransportConfig::default().status()
        );
    }

    #[test]
    fn explicit_plan_orders_extra_truncation_and_chunks() {
        let plan = plan(
            &config(&["EXTRA", "2", "TRUNCATE", "8", "CHUNKS", "1,3,7,8,100"]),
            5,
        );
        assert_eq!(plan.truncate_at, Some(8));
        assert_eq!(plan.chunk_ends, [1, 3, 7, 8]);
        assert_eq!(plan.wire_bytes(b"+OK\r\n".to_vec()), b"+OK\r\n+EV");
        let zero = plan_for_zero();
        assert!(zero.wire_bytes(b"+OK\r\n".to_vec()).is_empty());
        assert!(zero.chunk_ends.is_empty());
        assert!(zero.is_fault());
    }

    fn plan_for_zero() -> DeliveryPlan {
        plan(&config(&["TRUNCATE", "0", "CHUNKS", "RANDOM"]), 5)
    }

    #[test]
    fn disabled_probability_and_ineligible_offsets_are_plain() {
        for args in [
            vec!["OFF"],
            vec![
                "TRUNCATE",
                "1",
                "EXTRA",
                "16",
                "CHUNKS",
                "RANDOM",
                "PROBABILITY",
                "0",
            ],
            vec!["TRUNCATE", "5", "CHUNKS", "5,6"],
            vec!["TRUNCATE", "999", "CHUNKS", "999"],
        ] {
            assert_eq!(plan(&config(&args), 5), DeliveryPlan::plain(5));
        }
        assert_eq!(
            plan(&config(&["TRUNCATE", "RANDOM", "CHUNKS", "RANDOM"]), 0),
            DeliveryPlan::plain(0)
        );
    }

    #[test]
    fn random_plans_are_seeded_and_bounded() {
        let config =
            config(&["TRUNCATE", "RANDOM", "EXTRA", "2", "CHUNKS", "RANDOM"]);
        let first = plan(&config, 17);
        assert_eq!(first, plan(&config, 17));
        // Fixed seed exercises random truncation and chunk boundary selection.
        // Seed 17 cuts after the first extra reply and splits the prefix ten ways.
        assert_eq!(first.truncate_at, Some(28));
        assert_eq!(first.chunk_ends, [2, 5, 12, 13, 15, 21, 23, 24, 25, 28]);
        for seed in 0..128 {
            let p = config.plan(seed, 9, "command", "upstream", 17);
            let bytes = p.wire_bytes(vec![b'x'; 17]);
            assert!(bytes.len() < 39);
            assert!(p.chunk_ends.len() <= MAX_BOUNDARIES + 1);
            assert!(p.chunk_ends.windows(2).all(|pair| pair[0] < pair[1]));
            assert_eq!(p.chunk_ends.last().copied().unwrap_or(0), bytes.len());
        }
        assert_ne!(first, config.plan(17, 10, "command", "upstream", 17));
    }

    #[test]
    fn transport_configuration_does_not_change_resp_mutations() {
        use crate::evil::{EvilMode, mutate_reply, random_reply};
        use crate::resp::parse_frame;
        let mut original = EvilConfig::default();
        original.seed = 17;
        original.probability = 100.0;
        let frame = parse_frame(b"*2\r\n:42\r\n$3\r\nfoo\r\n").unwrap();
        for mode in [EvilMode::Random, EvilMode::Mutate, EvilMode::Overflow] {
            original.mode = mode;
            let mut with_transport = original.clone();
            with_transport.transport = config(&[
                "TRUNCATE", "RANDOM", "EXTRA", "2", "CHUNKS", "RANDOM",
            ]);
            assert_eq!(
                random_reply(&original, 9, "command").bytes,
                random_reply(&with_transport, 9, "command").bytes
            );
            assert_eq!(
                mutate_reply(&original, 9, "command", "upstream", &frame).bytes,
                mutate_reply(&with_transport, 9, "command", "upstream", &frame)
                    .bytes
            );
        }
    }

    #[tokio::test]
    async fn recorded_plan_replays_bytes_and_boundaries_without_rng() {
        use crate::evil::EvilMode;
        use crate::repro::ReproRecord;
        let response = b"+OK\r\n";
        let plan = plan(
            &config(&["EXTRA", "1", "TRUNCATE", "8", "CHUNKS", "1,3,7"]),
            response.len(),
        );
        let bytes = plan.wire_bytes(response.to_vec());
        let mut writer = Writer::default();
        let (outcome, result) = deliver(
            &mut writer,
            &mut ProtocolFingerprints::new(),
            &bytes,
            &plan,
        )
        .await;
        result.unwrap();
        let mut record = ReproRecord::new(
            17,
            99,
            9,
            b"GET key\r\n",
            Some(response),
            response,
            EvilMode::Off,
            Vec::new(),
        );
        record.planned_wire_bytes_hex = Some(hex::encode(&bytes));
        record.delivery_plan = Some(plan);
        record.delivery_outcome = Some(outcome);
        let json = serde_json::to_value(record).unwrap();
        // An external replayer can reconstruct the stream from existing output
        // bytes and the versioned plan; neither upstream nor RNG is required.
        let p = &json["delivery_plan"];
        assert_eq!(p["version"], 1);
        let mut replay_bytes =
            hex::decode(json["mutated_response_bytes_hex"].as_str().unwrap())
                .unwrap();
        for _ in 0..p["extra_reply_count"].as_u64().unwrap() {
            replay_bytes.extend(
                hex::decode(p["extra_reply_bytes_hex"].as_str().unwrap())
                    .unwrap(),
            );
        }
        replay_bytes.truncate(p["truncate_at"].as_u64().unwrap() as usize);
        assert_eq!(hex::encode(&replay_bytes), json["planned_wire_bytes_hex"]);
        let mut replay = Writer::default();
        let mut start = 0;
        for end in p["chunk_ends"].as_array().unwrap() {
            let end = end.as_u64().unwrap() as usize;
            replay.write_all(&replay_bytes[start..end]).await.unwrap();
            replay.flush().await.unwrap();
            start = end;
        }
        replay.shutdown().await.unwrap();
        assert_eq!(writer.accepted, replay.accepted);
        assert_eq!(writer.offered, replay.offered);
        assert_eq!(writer.flushes, replay.flushes);
        assert!(replay.shutdown);
    }

    #[derive(Default)]
    struct Writer {
        accepted: Vec<u8>,
        offered: Vec<Vec<u8>>,
        flushes: usize,
        shutdown: bool,
        short: bool,
        interrupt: bool,
        fail_after: Option<usize>,
        zero: bool,
        fail_flush: bool,
        fail_shutdown: bool,
    }

    impl AsyncWrite for Writer {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.offered.push(bytes.to_vec());
            if self.interrupt {
                self.interrupt = false;
                return Poll::Ready(Err(ErrorKind::Interrupted.into()));
            }
            let remaining = self
                .fail_after
                .map(|at| at.saturating_sub(self.accepted.len()))
                .unwrap_or(usize::MAX);
            if remaining == 0 {
                return Poll::Ready(if self.zero {
                    Ok(0)
                } else {
                    Err(ErrorKind::BrokenPipe.into())
                });
            }
            let n = bytes.len().min(remaining).min(if self.short {
                2
            } else {
                usize::MAX
            });
            self.accepted.extend_from_slice(&bytes[..n]);
            Poll::Ready(Ok(n))
        }
        fn poll_flush(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            self.flushes += 1;
            Poll::Ready(if self.fail_flush {
                Err(ErrorKind::BrokenPipe.into())
            } else {
                Ok(())
            })
        }
        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            self.shutdown = true;
            Poll::Ready(if self.fail_shutdown {
                Err(ErrorKind::BrokenPipe.into())
            } else {
                Ok(())
            })
        }
    }

    fn assert_fingerprint(fps: &ProtocolFingerprints, bytes: &[u8]) {
        assert_eq!(
            fps.get(ProtocolDirection::Out, ProtocolHash::Blake3),
            blake3::hash(bytes).to_hex().to_string()
        );
    }

    #[tokio::test]
    async fn chunk_calls_and_short_writes_preserve_exact_stream() {
        let plan = plan(&config(&["CHUNKS", "1,4"]), 8);
        for short in [false, true] {
            let mut writer = Writer {
                short,
                interrupt: true,
                ..Writer::default()
            };
            let mut fps = ProtocolFingerprints::new();
            let (outcome, result) =
                deliver(&mut writer, &mut fps, b"$2\r\nhi\r\n", &plan).await;
            result.unwrap();
            assert_eq!(writer.accepted, b"$2\r\nhi\r\n");
            assert_eq!(writer.flushes, 3);
            assert!(!writer.shutdown);
            assert_eq!(outcome.bytes_written, 8);
            assert_eq!(outcome.completed_chunks, 3);
            assert_eq!(
                outcome.written_bytes_hash,
                deterministic_hash(b"$2\r\nhi\r\n")
            );
            assert_fingerprint(&fps, b"$2\r\nhi\r\n");
            if !short {
                assert_eq!(
                    writer.offered,
                    [
                        b"$".to_vec(),
                        b"$".to_vec(),
                        b"2\r\n".to_vec(),
                        b"hi\r\n".to_vec()
                    ]
                );
            } else {
                assert_eq!(
                    writer.offered,
                    [
                        b"$".to_vec(),
                        b"$".to_vec(),
                        b"2\r\n".to_vec(),
                        b"\n".to_vec(),
                        b"hi\r\n".to_vec(),
                        b"\r\n".to_vec()
                    ]
                );
            }
        }
    }

    #[tokio::test]
    async fn partial_write_and_write_zero_record_only_accepted_prefix() {
        for zero in [false, true] {
            let plan = plan(&config(&["TRUNCATE", "7", "CHUNKS", "1,4"]), 8);
            let mut writer = Writer {
                short: true,
                fail_after: Some(3),
                zero,
                ..Writer::default()
            };
            let mut fps = ProtocolFingerprints::new();
            let (outcome, result) =
                deliver(&mut writer, &mut fps, b"$2\r\nhi\r", &plan).await;
            assert_eq!(
                result.unwrap_err().kind(),
                if zero {
                    ErrorKind::WriteZero
                } else {
                    ErrorKind::BrokenPipe
                }
            );
            assert_eq!(outcome.bytes_written, 3);
            assert_eq!(outcome.completed_chunks, 1);
            assert_eq!(outcome.error_stage, Some("write"));
            assert_eq!(
                outcome.error_kind.as_deref(),
                Some(if zero { "WriteZero" } else { "BrokenPipe" })
            );
            assert!(!outcome.shutdown_completed);
            assert!(!writer.shutdown);
            assert_eq!(writer.accepted, b"$2\r");
            assert_eq!(outcome.written_bytes_hash, deterministic_hash(b"$2\r"));
            assert_fingerprint(&fps, b"$2\r");
        }
    }

    #[tokio::test]
    async fn flush_and_shutdown_failures_keep_written_byte_accounting() {
        for fail_flush in [false, true] {
            let plan = plan(&config(&["TRUNCATE", "4"]), 5);
            let mut writer = Writer {
                fail_flush,
                fail_shutdown: !fail_flush,
                ..Writer::default()
            };
            let mut fps = ProtocolFingerprints::new();
            let (outcome, result) =
                deliver(&mut writer, &mut fps, b"+OK\r", &plan).await;
            assert!(result.is_err());
            assert_eq!(outcome.bytes_written, 4);
            assert_eq!(
                outcome.error_stage,
                Some(if fail_flush { "flush" } else { "shutdown" })
            );
            assert!(!outcome.shutdown_completed);
            assert_fingerprint(&fps, b"+OK\r");
        }
    }

    #[tokio::test]
    async fn zero_truncation_shuts_down_without_writing_or_hashing() {
        let mut writer = Writer::default();
        let mut fps = ProtocolFingerprints::new();
        let (outcome, result) =
            deliver(&mut writer, &mut fps, b"", &plan_for_zero()).await;
        result.unwrap();
        assert!(writer.shutdown);
        assert!(writer.offered.is_empty());
        assert_eq!(outcome.bytes_written, 0);
        assert!(outcome.shutdown_completed);
        assert_fingerprint(&fps, b"");
    }
}
