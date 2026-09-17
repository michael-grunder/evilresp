//! Explicit mutation and delivery of unsolicited upstream events.
//! Event indexes are per client and never consume ordinary command indexes.

use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;
use tokio::io::AsyncWrite;
use tracing::warn;

use crate::error::{AppError, AppResult};
use crate::evil::{
    EvilConfig, EvilMode, MutatedReply, deterministic_hash, mutate_reply,
    parse_probability,
};
use crate::framing::FramingConfig;
use crate::protocol_fingerprint::ProtocolFingerprints;
use crate::pubsub::string;
use crate::repro::{ReproRecord, ReproWriter};
use crate::resp::{Frame, parse_frame};
use crate::transport::{self, DeliveryPlan};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum PushTarget {
    #[default]
    Off,
    Payload,
    Frame,
}

impl PushTarget {
    fn as_str(self) -> &'static str {
        match self {
            Self::Off => "OFF",
            Self::Payload => "PAYLOAD",
            Self::Frame => "FRAME",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct PushConfig {
    target: PushTarget,
    probability: f64,
}

impl Default for PushConfig {
    fn default() -> Self {
        Self {
            target: PushTarget::Off,
            probability: 100.0,
        }
    }
}

impl PushConfig {
    pub(crate) fn parse(args: &[String]) -> AppResult<Self> {
        let invalid = || {
            AppError::EvilConfig(
            "PUSH requires OFF, PAYLOAD, or FRAME, with optional PROBABILITY <0..100> for PAYLOAD/FRAME".to_owned()
        )
        };
        let target =
            match args.first().map(|arg| arg.to_ascii_uppercase()).as_deref() {
                Some("OFF") => PushTarget::Off,
                Some("PAYLOAD") => PushTarget::Payload,
                Some("FRAME") => PushTarget::Frame,
                _ => return Err(invalid()),
            };
        let probability = match args.len() {
            1 => 100.0,
            3 if target != PushTarget::Off
                && args[1].eq_ignore_ascii_case("PROBABILITY") =>
            {
                parse_probability(&args[2])?
            }
            _ => return Err(invalid()),
        };
        Ok(Self {
            target,
            probability,
        })
    }

    pub(crate) fn status(&self) -> String {
        format!(
            "push={} push_probability={:.2}",
            self.target.as_str(),
            self.probability
        )
    }
}

#[derive(Debug, Serialize)]
pub struct PushRecord {
    pub index: u64,
    pub kind: Option<String>,
    pub(crate) target: PushTarget,
}

fn items(frame: &Frame) -> Option<&[Frame]> {
    match frame {
        Frame::Push(items) | Frame::Array(Some(items)) => Some(items),
        _ => None,
    }
}

fn kind(frame: &Frame) -> Option<&[u8]> {
    items(frame)?.first().and_then(string)
}

fn mutate(config: &EvilConfig, index: u64, bytes: &[u8]) -> MutatedReply {
    let plain = || MutatedReply {
        bytes: bytes.to_vec(),
        mutations: Vec::new(),
    };
    if config.push.target == PushTarget::Off
        || !matches!(config.mode, EvilMode::Mutate | EvilMode::Overflow)
    {
        return plain();
    }
    let Ok(frame) = parse_frame(bytes) else {
        return plain();
    };
    let mut settings = config.clone();
    settings.probability = config.push.probability;
    // Domain separation and original bytes: no command, connection identity,
    // canonicalization, or arrival timing enters this RNG.
    let domain = deterministic_hash(b"evilresp:push:v1");
    let hash = deterministic_hash(bytes);
    if config.push.target == PushTarget::Frame {
        let reply = mutate_reply(&settings, index, &domain, &hash, &frame);
        return if reply.mutations.is_empty() {
            plain()
        } else {
            reply
        };
    }
    let payload = match kind(&frame) {
        Some(b"invalidate")
            if items(&frame).is_some_and(|items| items.len() == 2) =>
        {
            1
        }
        Some(b"message" | b"smessage")
            if items(&frame).is_some_and(|items| items.len() == 3) =>
        {
            2
        }
        Some(b"pmessage")
            if items(&frame).is_some_and(|items| items.len() == 4) =>
        {
            3
        }
        _ => return plain(),
    };
    let (Frame::Push(items) | Frame::Array(Some(items))) = &frame else {
        return plain();
    };
    // PAYLOAD keeps the outer event correctly framed even with framing faults
    // configured for command replies. FRAME explicitly opts into those faults.
    settings.framing = FramingConfig::Off;
    let mut reply =
        mutate_reply(&settings, index, &domain, &hash, &items[payload]);
    if reply.mutations.is_empty() {
        return plain();
    }
    // Splice encoded output directly, including deliberate generator violations.
    let prefix = if bytes.first() == Some(&b'>') {
        '>'
    } else {
        '*'
    };
    let mut out = format!("{prefix}{}\r\n", items.len()).into_bytes();
    for (position, item) in items.iter().enumerate() {
        if position == payload {
            out.extend_from_slice(&reply.bytes);
        } else {
            out.extend(item.encode());
        }
    }
    reply.bytes = out;
    for mutation in &mut reply.mutations {
        mutation.path =
            mutation
                .path
                .replacen("root", &format!("root.{payload}"), 1);
    }
    reply
}

pub(crate) struct PushDelivery<'a, W> {
    pub writer: &'a mut W,
    pub fingerprints: &'a mut ProtocolFingerprints,
    pub config: &'a EvilConfig,
    pub index: &'a mut u64,
    pub connection_id: u64,
    pub epoch: u64,
    pub current_epoch: &'a AtomicU64,
    pub repro: Option<&'a ReproWriter>,
}

impl<W: AsyncWrite + Unpin> PushDelivery<'_, W> {
    pub(crate) async fn deliver(&mut self, bytes: Vec<u8>) -> AppResult<()> {
        if self.epoch != self.current_epoch.load(Ordering::SeqCst) {
            return Err(AppError::Proxy(
                "stale client after evil reset".to_owned(),
            ));
        }
        let index = *self.index;
        *self.index = index.checked_add(1).ok_or_else(|| {
            AppError::Proxy("push index exhausted".to_owned())
        })?;
        let response = mutate(self.config, index, &bytes);
        let plan = DeliveryPlan::plain(response.bytes.len());
        let (outcome, result) = transport::deliver(
            self.writer,
            self.fingerprints,
            &response.bytes,
            &plan,
        )
        .await;
        if (!response.mutations.is_empty() || result.is_err())
            && let Some(repro) = self.repro
        {
            // Command fields are empty/zero for an explicitly tagged push event.
            let mut record = ReproRecord::new(
                self.config.seed,
                self.connection_id,
                0,
                &[],
                Some(&bytes),
                &response.bytes,
                self.config.mode,
                response.mutations,
            );
            record.push = Some(PushRecord {
                index,
                kind: parse_frame(&bytes)
                    .ok()
                    .as_ref()
                    .and_then(kind)
                    .map(|kind| String::from_utf8_lossy(kind).into_owned()),
                target: self.config.push.target,
            });
            record.planned_wire_bytes_hex = Some(hex::encode(&response.bytes));
            record.delivery_plan = Some(plan);
            record.delivery_outcome = Some(outcome);
            if let Err(error) = repro.append(record).await {
                warn!(%error, "failed to write push repro record");
            }
        }
        result.map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::pin::Pin;
    use std::sync::atomic::AtomicUsize;
    use std::task::{Context, Poll};

    use super::*;
    use crate::protocol_fingerprint::{ProtocolDirection, ProtocolHash};

    fn configure(config: &mut EvilConfig, args: &str) -> AppResult<()> {
        config
            .apply_debug_command(
                &format!("DEBUG EVIL {args}")
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect::<Vec<_>>(),
            )
            .map(|_| ())
    }

    fn config() -> EvilConfig {
        let mut config = EvilConfig::default();
        for command in [
            "SEED 42",
            "MODE MUTATE PROBABILITY 0",
            "PUSH PAYLOAD",
            "DEPTH ANY",
        ] {
            configure(&mut config, command).unwrap();
        }
        config
    }

    #[test]
    fn push_configuration_is_atomic_and_survives_mode_reset() {
        let mut config = config();
        configure(&mut config, "PUSH frame probability 25").unwrap();
        assert!(
            config
                .status()
                .contains("push=FRAME push_probability=25.00")
        );
        let before = config.status();
        for bad in [
            "PUSH",
            "PUSH ON",
            "PUSH OFF PROBABILITY 1",
            "PUSH FRAME PROBABILITY",
            "PUSH FRAME EXTRA 1",
            "PUSH PAYLOAD PROBABILITY NaN",
            "PUSH FRAME PROBABILITY 101",
            "PUSH FRAME PROBABILITY -1",
            "PUSH FRAME PROBABILITY 1 extra",
            "PUSH FRAME PROBABILITY inf",
        ] {
            assert!(configure(&mut config, bad).is_err(), "{bad}");
            assert_eq!(config.status(), before);
        }
        configure(&mut config, "MODE RESET").unwrap();
        assert!(
            config
                .status()
                .contains("push=FRAME push_probability=25.00")
        );
        assert_eq!(config.mode, EvilMode::Off);
        configure(&mut config, "PUSH OFF").unwrap();
        assert!(config.status().contains("push=OFF"));
    }

    #[test]
    fn payload_preserves_envelopes_and_acks_despite_filters_and_framing() {
        let mut config = config();
        configure(&mut config, "INCLUDE GET").unwrap();
        configure(&mut config, "EXCLUDE GET").unwrap();
        configure(&mut config, "FRAMING LENGTH TARGET root KIND SHORTER")
            .unwrap();
        configure(&mut config, "CANONICALIZE ALL").unwrap();
        // Boolean payloads give an exact scalar mutation (false -> true),
        // independent of corpus selection, with seed 42 and probability 100.
        for (before, after, path) in [
            (
                ">3\r\n+message\r\n+channel\r\n#f\r\n",
                ">3\r\n+message\r\n+channel\r\n#t\r\n",
                "root.2",
            ),
            (
                ">4\r\n+pmessage\r\n+pattern\r\n+channel\r\n#f\r\n",
                ">4\r\n+pmessage\r\n+pattern\r\n+channel\r\n#t\r\n",
                "root.3",
            ),
            (
                ">3\r\n+smessage\r\n+channel\r\n#f\r\n",
                ">3\r\n+smessage\r\n+channel\r\n#t\r\n",
                "root.2",
            ),
            (
                ">2\r\n+invalidate\r\n*1\r\n#f\r\n",
                ">2\r\n+invalidate\r\n*1\r\n#t\r\n",
                "root.1.0",
            ),
        ] {
            let reply = mutate(&config, 0, before.as_bytes());
            assert_eq!(reply.bytes, after.as_bytes());
            assert_eq!(reply.mutations.len(), 1);
            assert_eq!(reply.mutations[0].path, path);
        }
        for bytes in [
            b">3\r\n+subscribe\r\n+channel\r\n:1\r\n".as_slice(),
            b">1\r\n+unknown\r\n",
            b">2\r\n+invalidate\r\n_\r\n",
            b">2\r\n+invalidate\r\n+\xff\r\n",
        ] {
            let reply = mutate(&config, 0, bytes);
            assert_eq!(reply.bytes, bytes);
            assert!(reply.mutations.is_empty());
        }
    }

    #[test]
    fn whole_frame_mutation_explicitly_allows_ack_and_length_corruption() {
        let mut config = config();
        configure(&mut config, "PUSH FRAME PROBABILITY 0").unwrap();
        configure(&mut config, "FRAMING LENGTH TARGET root KIND SHORTER")
            .unwrap();
        let bytes = b">3\r\n+subscribe\r\n+channel\r\n:1\r\n";
        let reply = mutate(&config, 0, bytes);
        assert_eq!(reply.bytes, b">2\r\n+subscribe\r\n+channel\r\n:1\r\n");
        assert_eq!(reply.mutations.len(), 1);
        assert_eq!(reply.mutations[0].path, "root");
    }

    #[test]
    fn disabled_and_zero_probability_events_keep_original_encoding() {
        let mut config = config();
        let bytes = b">02\r\n+invalidate\r\n*01\r\n$03\r\nkey\r\n";
        for command in [
            "PUSH OFF",
            "PUSH PAYLOAD PROBABILITY 0",
            "PUSH FRAME PROBABILITY 0",
        ] {
            configure(&mut config, command).unwrap();
            configure(&mut config, "FRAMING OFF").unwrap();
            assert_eq!(mutate(&config, 0, bytes).bytes, bytes);
        }
        configure(&mut config, "PUSH FRAME").unwrap();
        for mode in ["MODE OFF", "MODE RANDOM", "MODE RESET"] {
            configure(&mut config, mode).unwrap();
            assert_eq!(mutate(&config, 0, bytes).bytes, bytes);
        }
    }

    struct FailingWriter {
        accepted: Vec<u8>,
    }

    impl AsyncWrite for FailingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.accepted.len() == 5 {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            let count = (5 - self.accepted.len()).min(bytes.len());
            self.accepted.extend_from_slice(&bytes[..count]);
            Poll::Ready(Ok(count))
        }
        fn poll_flush(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn partial_event_delivery_is_fingerprinted_and_recorded_without_command_attribution()
     {
        static FILE_ID: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "evilresp-push-record-{}-{}.jsonl",
            std::process::id(),
            FILE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let repro = ReproWriter::open(&path).await.unwrap();
        let mut writer = FailingWriter {
            accepted: Vec::new(),
        };
        let mut fingerprints = ProtocolFingerprints::new();
        let mut index = 7;
        let epoch = AtomicU64::new(0);
        let config = config();
        let bytes = b">3\r\n+message\r\n+channel\r\n#f\r\n";
        let result = PushDelivery {
            writer: &mut writer,
            fingerprints: &mut fingerprints,
            config: &config,
            index: &mut index,
            connection_id: 999,
            epoch: 0,
            current_epoch: &epoch,
            repro: Some(&repro),
        }
        .deliver(bytes.to_vec())
        .await;
        assert!(result.is_err());
        assert_eq!(index, 8);
        assert_eq!(writer.accepted, b">3\r\n+");
        assert_eq!(
            fingerprints.get(ProtocolDirection::Out, ProtocolHash::Blake3),
            blake3::hash(&writer.accepted).to_hex().to_string()
        );
        let record: serde_json::Value = serde_json::from_str(
            &tokio::fs::read_to_string(&path).await.unwrap(),
        )
        .unwrap();
        assert_eq!(record["push"]["index"], 7);
        assert_eq!(record["push"]["kind"], "message");
        assert_eq!(record["push"]["target"], "PAYLOAD");
        assert_eq!(record["command_bytes_hex"], "");
        assert_eq!(record["delivery_outcome"]["bytes_written"], 5);
        assert_eq!(record["upstream_response_bytes_hex"], hex::encode(bytes));
        assert_eq!(
            record["mutated_response_bytes_hex"],
            hex::encode(b">3\r\n+message\r\n+channel\r\n#t\r\n")
        );
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn stale_connections_cannot_deliver_or_consume_event_indexes() {
        let mut writer = Vec::new();
        let mut fingerprints = ProtocolFingerprints::new();
        let mut index = 7;
        let epoch = AtomicU64::new(2);
        let config = config();
        assert!(
            PushDelivery {
                writer: &mut writer,
                fingerprints: &mut fingerprints,
                config: &config,
                index: &mut index,
                connection_id: 999,
                epoch: 1,
                current_epoch: &epoch,
                repro: None,
            }
            .deliver(b">1\r\n+test\r\n".to_vec())
            .await
            .is_err()
        );
        assert_eq!(index, 7);
        assert!(writer.is_empty());
    }
}
