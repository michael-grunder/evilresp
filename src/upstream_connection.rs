//! Replace failed upstream sessions at the next forwarding boundary.
//! Never retry a command: a missing reply does not imply it did not execute.

use tokio::io::{AsyncWriteExt, BufReader, ReadHalf, WriteHalf};
use tokio::net::{TcpStream, UnixStream};
use tracing::{info, warn};

use crate::cli::Endpoint;
use crate::connection::ProxyStream;
use crate::error::AppResult;
use crate::resp::read_raw_frame;
use crate::upstream_identity::UpstreamIdentity;

pub(crate) const UNAVAILABLE_REPLY: &[u8] =
    b"-ERR evilresp upstream unavailable; command outcome unknown; upstream session reset; retry on next command\r\n";

struct Session {
    read: BufReader<ReadHalf<ProxyStream>>,
    write: WriteHalf<ProxyStream>,
    identity: UpstreamIdentity,
}

impl Session {
    async fn connect(endpoint: &Endpoint) -> AppResult<Self> {
        let stream: ProxyStream = match endpoint {
            Endpoint::Tcp(endpoint) => {
                Box::new(TcpStream::connect(endpoint.connect_addr()).await?)
            }
            Endpoint::Unix(path) => Box::new(UnixStream::connect(path).await?),
        };
        let (read, write) = tokio::io::split(stream);
        let mut session = Self {
            read: BufReader::new(read),
            write,
            identity: UpstreamIdentity::default(),
        };
        session
            .identity
            .apply(&mut session.read, &mut session.write)
            .await?;
        Ok(session)
    }

    async fn exchange(
        &mut self,
        command: &[u8],
        argv: &[String],
    ) -> AppResult<Vec<u8>> {
        self.write.write_all(command).await?;
        self.write.flush().await?;
        let reply = read_raw_frame(&mut self.read).await?;
        if self.identity.retry_after(argv, &reply) {
            self.identity.apply(&mut self.read, &mut self.write).await?;
        }
        Ok(reply)
    }
}

pub(crate) struct UpstreamConnection {
    endpoint: Endpoint,
    connection_id: u64,
    session: Option<Session>,
}

impl UpstreamConnection {
    pub(crate) async fn new(endpoint: Endpoint, connection_id: u64) -> Self {
        let session = match Session::connect(&endpoint).await {
            Ok(session) => Some(session),
            Err(error) => {
                warn!(connection_id, upstream = %endpoint, %error,
                    "upstream connection failed; retrying on next forwarded command");
                None
            }
        };
        Self {
            endpoint,
            connection_id,
            session,
        }
    }

    pub(crate) async fn exchange(
        &mut self,
        command: &[u8],
        argv: &[String],
    ) -> AppResult<Vec<u8>> {
        if self.session.is_none() {
            match Session::connect(&self.endpoint).await {
                Ok(session) => {
                    self.session = Some(session);
                    info!(connection_id = self.connection_id,
                        upstream = %self.endpoint, "upstream reconnected");
                }
                Err(error) => {
                    warn!(connection_id = self.connection_id,
                        upstream = %self.endpoint, %error,
                        "upstream reconnect failed; retrying on next forwarded command");
                    return Err(error);
                }
            }
        }
        // The initial session or the successful reconnect is present here.
        let result = self
            .session
            .as_mut()
            .expect("connected upstream")
            .exchange(command, argv)
            .await;
        if let Err(error) = &result {
            // Drop both halves and any partial reply before another command.
            self.session = None;
            warn!(connection_id = self.connection_id,
                upstream = %self.endpoint, %error,
                "upstream connection lost; retrying on next forwarded command");
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::net::{TcpListener, UnixListener};

    use super::*;
    use crate::cli::TcpEndpoint;
    use crate::connection::ProxyIo;
    use crate::error::AppError;
    use crate::upstream_identity::accept_identity;

    const PING: &[u8] = b"*1\r\n$4\r\nPING\r\n";

    #[tokio::test]
    async fn tcp_eof_reconnects_without_replaying_failed_command() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(accept_identity(stream).await);
            assert_eq!(read_raw_frame(&mut stream).await.unwrap(), PING);
            drop(stream);
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(accept_identity(stream).await);
            assert_eq!(
                read_raw_frame(&mut stream).await.unwrap(),
                b"*1\r\n$4\r\nNEXT\r\n"
            );
            stream.get_mut().write_all(b"+OK\r\n").await.unwrap();
        });
        let mut upstream = UpstreamConnection::new(
            Endpoint::Tcp(TcpEndpoint {
                host: address.ip().to_string(),
                port: address.port(),
            }),
            0,
        )
        .await;
        assert!(upstream.exchange(PING, &[]).await.is_err());
        assert!(upstream.session.is_none());
        assert_eq!(
            upstream
                .exchange(b"*1\r\n$4\r\nNEXT\r\n", &[])
                .await
                .unwrap(),
            b"+OK\r\n"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn failed_connect_and_identification_can_recover_on_later_command() {
        let path = std::env::temp_dir().join(format!(
            "evilresp-upstream-recovery-{}.sock",
            std::process::id()
        ));
        let mut upstream =
            UpstreamConnection::new(Endpoint::Unix(path.clone()), 0).await;
        assert!(upstream.session.is_none());
        // An unavailable endpoint fails once per call, without looping.
        for _ in 0..2 {
            assert!(upstream.exchange(PING, &[]).await.is_err());
            assert!(upstream.session.is_none());
        }
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            // A malformed identification reply poisons only this attempt.
            for _ in 0..3 {
                read_raw_frame(&mut stream).await.unwrap();
            }
            stream.get_mut().write_all(b":1\r\n").await.unwrap();
            drop(stream);
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(accept_identity(stream).await);
            assert_eq!(read_raw_frame(&mut stream).await.unwrap(), PING);
            stream.get_mut().write_all(b"+PONG\r\n").await.unwrap();
        });
        assert!(upstream.exchange(PING, &[]).await.is_err());
        assert!(upstream.session.is_none());
        assert_eq!(upstream.exchange(PING, &[]).await.unwrap(), b"+PONG\r\n");
        server.await.unwrap();
        std::fs::remove_file(path).unwrap();
    }

    #[derive(Clone, Copy)]
    enum FailureStage {
        Read,
        Write,
        Flush,
    }

    struct FailingStream {
        stage: FailureStage,
        kind: io::ErrorKind,
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl ProxyIo for FailingStream {}

    impl AsyncRead for FailingStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::from(self.kind)))
        }
    }

    impl AsyncWrite for FailingStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            let mut written = self.written.lock().unwrap();
            let count = if matches!(self.stage, FailureStage::Write) {
                if !written.is_empty() {
                    return Poll::Ready(Err(io::Error::from(self.kind)));
                }
                2.min(bytes.len())
            } else {
                bytes.len()
            };
            written.extend_from_slice(&bytes[..count]);
            Poll::Ready(Ok(count))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(if matches!(self.stage, FailureStage::Flush) {
                Err(io::Error::from(self.kind))
            } else {
                Ok(())
            })
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn io_failures_discard_session_without_retrying_partial_writes() {
        for (stage, kind) in [
            (FailureStage::Read, io::ErrorKind::TimedOut),
            (FailureStage::Read, io::ErrorKind::ConnectionReset),
            (FailureStage::Write, io::ErrorKind::BrokenPipe),
            (FailureStage::Flush, io::ErrorKind::ConnectionReset),
        ] {
            let written = Arc::new(Mutex::new(Vec::new()));
            let stream: ProxyStream = Box::new(FailingStream {
                stage,
                kind,
                written: written.clone(),
            });
            let (read, write) = tokio::io::split(stream);
            let mut upstream = UpstreamConnection {
                endpoint: Endpoint::Unix("/unused".into()),
                connection_id: 0,
                session: Some(Session {
                    read: BufReader::new(read),
                    write,
                    identity: UpstreamIdentity::default(),
                }),
            };
            let error = upstream.exchange(PING, &[]).await.unwrap_err();
            assert!(
                matches!(error, AppError::Io(error) if error.kind() == kind)
            );
            assert!(upstream.session.is_none());
            assert_eq!(
                *written.lock().unwrap(),
                if matches!(stage, FailureStage::Write) {
                    &PING[..2]
                } else {
                    PING
                }
            );
        }
    }
}
