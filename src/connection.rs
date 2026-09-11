//! Socket-specific termination and bounded stalls for established clients.

use std::io;
use std::time::Duration;

use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadHalf,
    WriteHalf,
};
use tokio::net::{TcpStream, UnixStream};

use crate::connection_fault::{ConnectionFaultPlan, FaultAction};
use crate::protocol_fingerprint::{ProtocolDirection, ProtocolFingerprints};
use crate::transport::DeliveryOutcome;

pub(crate) trait ProxyIo: AsyncRead + AsyncWrite + Unpin + Send {
    fn supports_reset(&self) -> bool {
        false
    }
    fn prepare_reset(&self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TCP reset requires a TCP client socket",
        ))
    }
}

impl ProxyIo for UnixStream {}
impl ProxyIo for TcpStream {
    fn supports_reset(&self) -> bool {
        true
    }
    fn prepare_reset(&self) -> io::Result<()> {
        self.set_zero_linger()
    }
}

pub(crate) type ProxyStream = Box<dyn ProxyIo>;

pub(crate) async fn finish_fault(
    mut reader: BufReader<ReadHalf<ProxyStream>>,
    mut writer: WriteHalf<ProxyStream>,
    fingerprints: &mut ProtocolFingerprints,
    plan: &ConnectionFaultPlan,
    outcome: &mut DeliveryOutcome,
) -> io::Result<()> {
    let result = async {
        if let Some(ms) = plan.duration_ms {
            outcome.error_stage = Some("stall");
            outcome.stall_end = Some(
                stall(&mut reader, fingerprints, Duration::from_millis(ms))
                    .await?,
            );
        }
        if plan.action != FaultAction::Reset {
            outcome.error_stage = Some("shutdown");
            writer.shutdown().await?;
            outcome.shutdown_completed = true;
        }
        Ok::<_, io::Error>(())
    }
    .await;
    // Reunite both halves and close before awaiting a repro-file write.
    let socket = reader.into_inner().unsplit(writer);
    let result = result.and_then(|()| {
        if plan.action == FaultAction::Reset {
            outcome.error_stage = Some("reset");
            socket.prepare_reset()?;
        }
        Ok(())
    });
    drop(socket);
    outcome.fault_completed = Some(result.is_ok());
    match &result {
        Ok(()) => outcome.error_stage = None,
        Err(error) => outcome.error_kind = Some(format!("{:?}", error.kind())),
    }
    result
}

async fn stall<R: AsyncRead + Unpin>(
    reader: &mut R,
    fingerprints: &mut ProtocolFingerprints,
    duration: Duration,
) -> io::Result<&'static str> {
    let deadline = tokio::time::sleep(duration);
    tokio::pin!(deadline);
    let mut discarded = [0; 8192];
    loop {
        tokio::select! {
            biased;
            _ = &mut deadline => return Ok("duration_elapsed"),
            read = reader.read(&mut discarded) => match read {
                Ok(0) => return Ok("peer_closed"),
                Ok(n) => fingerprints.update(ProtocolDirection::In, &discarded[..n]),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {},
                Err(error) => return Err(error),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn stall_drains_input_without_reply_and_stops_at_deadline() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let task = tokio::spawn(async move {
            let mut fingerprints = ProtocolFingerprints::new();
            let result =
                stall(&mut server, &mut fingerprints, Duration::from_secs(5))
                    .await;
            (result, fingerprints)
        });
        client.write_all(b"pipelined commands").await.unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(4)).await;
        assert!(!task.is_finished());
        tokio::time::advance(Duration::from_secs(1)).await;
        let (result, fingerprints) = task.await.unwrap();
        assert_eq!(result.unwrap(), "duration_elapsed");
        assert_eq!(
            fingerprints.get(
                ProtocolDirection::In,
                crate::protocol_fingerprint::ProtocolHash::Blake3
            ),
            blake3::hash(b"pipelined commands").to_hex().to_string()
        );
        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes).await.unwrap();
        assert!(bytes.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn stall_ends_early_on_peer_eof_or_read_failure() {
        let (client, mut server) = tokio::io::duplex(64);
        let start = tokio::time::Instant::now();
        drop(client);
        assert_eq!(
            stall(
                &mut server,
                &mut ProtocolFingerprints::new(),
                Duration::from_secs(10)
            )
            .await
            .unwrap(),
            "peer_closed"
        );
        assert_eq!(tokio::time::Instant::now(), start);
        struct FailedReader;
        impl AsyncRead for FailedReader {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                _: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                std::task::Poll::Ready(Err(
                    io::ErrorKind::ConnectionReset.into()
                ))
            }
        }
        assert_eq!(
            stall(
                &mut FailedReader,
                &mut ProtocolFingerprints::new(),
                Duration::from_secs(10)
            )
            .await
            .unwrap_err()
            .kind(),
            io::ErrorKind::ConnectionReset
        );
    }
}
