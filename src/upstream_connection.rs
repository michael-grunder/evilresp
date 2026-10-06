//! Replace failed upstream sessions at the next forwarding boundary.
//! Read unsolicited events independently without replaying failed commands.

use std::collections::VecDeque;
use std::future::pending;

use tokio::io::{AsyncWrite, AsyncWriteExt, BufReader, WriteHalf};
use tokio::net::{TcpStream, UnixStream};
use tracing::{info, warn};

use crate::cli::Endpoint;
use crate::connection::ProxyStream;
use crate::error::{AppError, AppResult};
use crate::pubsub::Subscriptions;
use crate::push::PushDelivery;
use crate::upstream_identity::UpstreamIdentity;
use crate::upstream_reader::UpstreamReader;

pub(crate) const UNAVAILABLE_REPLY: &[u8] =
    b"-ERR evilresp upstream unavailable; command outcome unknown; upstream session reset; retry on next command\r\n";

pub(crate) enum Exchange {
    Reply(Vec<u8>),
    Subscription,
    Unavailable(AppError),
}

struct Session {
    read: UpstreamReader,
    write: WriteHalf<ProxyStream>,
    identity: UpstreamIdentity,
    subscriptions: Subscriptions,
    held: Option<AppResult<Vec<u8>>>,
    pending_identity: VecDeque<usize>,
}

impl Session {
    async fn connect(endpoint: &Endpoint) -> AppResult<Self> {
        let stream: ProxyStream = match endpoint {
            Endpoint::Tcp(endpoint) => {
                Box::new(TcpStream::connect(endpoint.connect_addr()).await?)
            }
            Endpoint::Unix(path) => Box::new(UnixStream::connect(path).await?),
        };
        let (read, mut write) = tokio::io::split(stream);
        let mut read = BufReader::new(read);
        let mut identity = UpstreamIdentity::default();
        identity.apply(&mut read, &mut write).await?;
        Ok(Self {
            read: UpstreamReader::new(read),
            write,
            identity,
            subscriptions: Subscriptions::default(),
            held: None,
            pending_identity: VecDeque::new(),
        })
    }

    async fn next(&mut self) -> AppResult<Vec<u8>> {
        Ok(match self.held.take() {
            Some(frame) => frame?,
            None => self.read.next().await?,
        })
    }

    async fn identity_step(&mut self) -> AppResult<Option<Vec<u8>>> {
        let bytes = self.next().await?;
        if !self.subscriptions.is_event(&bytes, None)
            && let Some(index) = self.pending_identity.pop_front()
        {
            self.identity.observe(index, &bytes)?;
            return Ok(None);
        }
        Ok(Some(bytes))
    }
}

pub(crate) struct UpstreamConnection {
    endpoint: Endpoint,
    connection_id: u64,
    session: Option<Session>,
}

impl UpstreamConnection {
    pub(crate) async fn check(endpoint: &Endpoint) -> AppResult<()> {
        Session::connect(endpoint).await.map(|_| ())
    }

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

    async fn send(&mut self, command: &[u8]) -> AppResult<()> {
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
        let session = self.connected();
        session.write.write_all(command).await?;
        session.write.flush().await?;
        Ok(())
    }

    fn connected(&mut self) -> &mut Session {
        // Used only after a successful send and before discarding the session.
        self.session.as_mut().expect("connected upstream")
    }

    fn discard(&mut self, error: &AppError) {
        self.session = None;
        warn!(connection_id = self.connection_id,
            upstream = %self.endpoint, %error,
            "upstream connection lost; retrying on next forwarded command");
    }

    /// Cancellation-safe. Ordinary frames and EOF stay held for the next
    /// exchange, preserving recovery at forwarding boundaries without emitting
    /// an unsolicited command error or reconnecting an idle client.
    pub(crate) async fn next_push(&mut self) -> Vec<u8> {
        let Some(session) = &mut self.session else {
            return pending().await;
        };
        loop {
            if session.held.is_none() {
                match session.identity_step().await {
                    Ok(None) => continue,
                    Ok(Some(bytes)) => session.held = Some(Ok(bytes)),
                    Err(error) => session.held = Some(Err(error)),
                }
            }
            if let Some(Ok(bytes)) = &session.held
                && session.subscriptions.is_event(bytes, None)
            {
                session.subscriptions.observe(bytes, None);
                // The event was just checked above.
                return session.held.take().unwrap().unwrap();
            }
            return pending().await;
        }
    }

    /// Upstream failures become Unavailable; event-delivery failures propagate
    /// to close the client rather than masquerading as an upstream failure.
    pub(crate) async fn forward<W: AsyncWrite + Unpin>(
        &mut self,
        command: &[u8],
        argv: &[String],
        push: &mut PushDelivery<'_, W>,
    ) -> AppResult<Exchange> {
        // Finish metadata retries after the preceding client reply has been
        // delivered, preserving PUSH ordering without buffering events.
        while let Some(session) = &mut self.session {
            if session.held.as_ref().is_some_and(Result::is_err) {
                // The held frame was just checked to be an error.
                let error = session.held.take().unwrap().unwrap_err();
                self.discard(&error);
                return Ok(Exchange::Unavailable(error));
            }
            if session.pending_identity.is_empty() {
                break;
            }
            match session.identity_step().await {
                Ok(Some(bytes)) => {
                    session.subscriptions.observe(&bytes, None);
                    push.deliver(bytes).await?;
                }
                Ok(None) => {}
                Err(error) => {
                    self.discard(&error);
                    return Ok(Exchange::Unavailable(error));
                }
            }
        }
        if let Err(error) = self.send(command).await {
            self.discard(&error);
            return Ok(Exchange::Unavailable(error));
        }
        let mut subscription = self.connected().subscriptions.pending(argv);
        let reply = loop {
            let bytes = match self.connected().next().await {
                Ok(bytes) => bytes,
                Err(error) => {
                    self.discard(&error);
                    return Ok(Exchange::Unavailable(error));
                }
            };
            if self
                .connected()
                .subscriptions
                .is_event(&bytes, subscription.as_ref())
            {
                let completed = self
                    .connected()
                    .subscriptions
                    .observe(&bytes, subscription.as_mut());
                push.deliver(bytes).await?;
                if completed {
                    return Ok(Exchange::Subscription);
                }
            } else {
                break bytes;
            }
        };
        self.connected().subscriptions.observe_reply(argv, &reply);
        if self.connected().identity.retry_after(argv, &reply) {
            let commands = self.connected().identity.pending_commands();
            for (_, command) in &commands {
                if let Err(error) = self.send(&command.encode()).await {
                    self.discard(&error);
                    return Ok(Exchange::Unavailable(error));
                }
            }
            self.connected().pending_identity =
                commands.into_iter().map(|(index, _)| index).collect();
        }
        Ok(Exchange::Reply(reply))
    }

    #[cfg(test)]
    async fn exchange(
        &mut self,
        command: &[u8],
        argv: &[String],
    ) -> AppResult<Vec<u8>> {
        let mut writer = Vec::new();
        let mut fingerprints =
            crate::protocol_fingerprint::ProtocolFingerprints::new();
        let config = crate::evil::EvilConfig::default();
        let mut index = 0;
        let epoch = std::sync::atomic::AtomicU64::new(0);
        match self
            .forward(
                command,
                argv,
                &mut PushDelivery {
                    writer: &mut writer,
                    fingerprints: &mut fingerprints,
                    config: &config,
                    index: &mut index,
                    connection_id: 0,
                    epoch: 0,
                    current_epoch: &epoch,
                    repro: None,
                },
            )
            .await?
        {
            Exchange::Reply(bytes) => Ok(bytes),
            Exchange::Unavailable(error) => Err(error),
            Exchange::Subscription => {
                Err(AppError::Proxy("expected ordinary reply".to_owned()))
            }
        }
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
    use crate::resp::read_raw_frame;
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
                    read: UpstreamReader::new(read),
                    write,
                    identity: UpstreamIdentity::default(),
                    subscriptions: Subscriptions::default(),
                    held: None,
                    pending_identity: VecDeque::new(),
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
