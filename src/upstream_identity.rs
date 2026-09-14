//! Best-effort upstream identification, outside client traffic and mutation.

use tokio::io::{AsyncBufRead, AsyncWrite, AsyncWriteExt};
use tracing::debug;

use crate::error::{AppError, AppResult};
use crate::resp::{Frame, parse_frame, read_raw_frame};

pub(crate) struct UpstreamIdentity {
    pending: [bool; 3],
}

impl Default for UpstreamIdentity {
    fn default() -> Self {
        Self { pending: [true; 3] }
    }
}

fn commands() -> [Frame; 3] {
    [
        vec!["CLIENT", "SETNAME", "evilresp"],
        vec!["CLIENT", "SETINFO", "LIB-NAME", "evilresp"],
        vec!["CLIENT", "SETINFO", "LIB-VER", env!("CARGO_PKG_VERSION")],
    ]
    .map(|argv| {
        Frame::Array(Some(
            argv.into_iter()
                .map(|arg| Frame::BulkString(Some(arg.as_bytes().to_vec())))
                .collect(),
        ))
    })
}

impl UpstreamIdentity {
    pub(crate) async fn apply<R, W>(
        &mut self,
        read: &mut R,
        write: &mut W,
    ) -> AppResult<()>
    where
        R: AsyncBufRead + Unpin + Send,
        W: AsyncWrite + Unpin,
    {
        let commands = commands();
        for (pending, command) in self.pending.iter().zip(&commands) {
            if *pending {
                write.write_all(&command.encode()).await?;
            }
        }
        write.flush().await?;
        for (pending, command) in self.pending.iter_mut().zip(&commands) {
            if !*pending {
                continue;
            }
            match parse_frame(&read_raw_frame(read).await?)? {
                Frame::SimpleString(reply) if reply == "OK" => *pending = false,
                Frame::SimpleError(error) => {
                    debug!(?command, %error, "upstream identification rejected");
                }
                Frame::BulkError(error) => {
                    debug!(
                        ?command,
                        ?error,
                        "upstream identification rejected"
                    );
                }
                reply => {
                    return Err(AppError::Proxy(format!(
                        "upstream identification returned unexpected frame {reply:?}"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Retry rejected fields after authentication, using the real reply.
    /// Never inject commands following a queued or failed handshake.
    pub(crate) fn retry_after(
        &mut self,
        argv: &[String],
        reply: &[u8],
    ) -> bool {
        let Some(command) = argv.first() else {
            return false;
        };
        let authenticated =
            command.eq_ignore_ascii_case("AUTH") && reply == b"+OK\r\n";
        let hello = command.eq_ignore_ascii_case("HELLO")
            && matches!(reply.first(), Some(b'*' | b'%'));
        if hello {
            // HELLO's SETNAME follows the protocol and optional AUTH pair.
            let name_index = if argv
                .get(2)
                .is_some_and(|arg| arg.eq_ignore_ascii_case("AUTH"))
            {
                5
            } else {
                2
            };
            if argv
                .get(name_index)
                .is_some_and(|arg| arg.eq_ignore_ascii_case("SETNAME"))
            {
                self.pending[0] = false;
            }
        }
        (authenticated || hello) && self.pending.iter().any(|pending| *pending)
    }
}

#[cfg(test)]
pub(crate) async fn accept_identity<S>(stream: S) -> S
where
    S: tokio::io::AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut stream = tokio::io::BufReader::new(stream);
    for command in commands() {
        assert_eq!(
            read_raw_frame(&mut stream).await.unwrap(),
            command.encode()
        );
        stream.get_mut().write_all(b"+OK\r\n").await.unwrap();
    }
    assert!(stream.buffer().is_empty());
    stream.into_inner()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pipelines_exact_identity_and_consumes_only_its_replies() {
        let mut read = &b"+OK\r\n+OK\r\n+OK\r\n+PONG\r\n"[..];
        let mut write = Vec::new();
        let mut identity = UpstreamIdentity::default();
        identity.apply(&mut read, &mut write).await.unwrap();
        let version = env!("CARGO_PKG_VERSION");
        assert_eq!(write, format!(
            "*3\r\n$6\r\nCLIENT\r\n$7\r\nSETNAME\r\n$8\r\nevilresp\r\n\
             *4\r\n$6\r\nCLIENT\r\n$7\r\nSETINFO\r\n$8\r\nLIB-NAME\r\n$8\r\nevilresp\r\n\
             *4\r\n$6\r\nCLIENT\r\n$7\r\nSETINFO\r\n$7\r\nLIB-VER\r\n${}\r\n{version}\r\n",
            version.len()
        ).as_bytes());
        assert_eq!(read, b"+PONG\r\n");
        assert_eq!(identity.pending, [false; 3]);
    }

    #[tokio::test]
    async fn server_errors_are_tolerated_and_only_failed_fields_are_retried() {
        for error in [
            "-ERR unknown subcommand 'SETINFO'\r\n",
            "-NOPERM permission denied\r\n",
            "-NOAUTH Authentication required\r\n",
            "!6\r\nDENIED\r\n",
        ] {
            let replies = format!("+OK\r\n{error}{error}+PONG\r\n");
            let mut read = replies.as_bytes();
            let mut identity = UpstreamIdentity::default();
            identity.apply(&mut read, &mut Vec::new()).await.unwrap();
            assert_eq!(read, b"+PONG\r\n");
            assert_eq!(identity.pending, [false, true, true]);
            let auth = vec!["auth".to_owned(), "secret".to_owned()];
            assert!(
                !identity.retry_after(&auth, b"-WRONGPASS bad password\r\n")
            );
            assert!(!identity.retry_after(&auth, b"+QUEUED\r\n"));
            assert!(identity.retry_after(&auth, b"+OK\r\n"));
            let mut write = Vec::new();
            identity
                .apply(&mut &b"+OK\r\n+OK\r\n"[..], &mut write)
                .await
                .unwrap();
            assert_eq!(
                write,
                commands()[1..]
                    .iter()
                    .flat_map(Frame::encode)
                    .collect::<Vec<_>>()
            );
            assert!(!identity.retry_after(&auth, b"+OK\r\n"));
        }
    }

    #[tokio::test]
    async fn broken_identification_streams_fail() {
        for reply in
            [&b"+OK\r\n"[..], b"?invalid\r\n", b"+QUEUED\r\n", b":1\r\n"]
        {
            assert!(
                UpstreamIdentity::default()
                    .apply(&mut &reply[..], &mut Vec::new())
                    .await
                    .is_err()
            );
        }
    }

    #[test]
    fn hello_keeps_explicit_names_and_ignores_auth_credentials() {
        for (argv, pending_name) in [
            (vec!["HELLO", "3", "SETNAME", "app"], false),
            (
                vec!["hello", "3", "auth", "user", "pass", "setname", "app"],
                false,
            ),
            (vec!["HELLO", "2", "AUTH", "SETNAME", "SETNAME"], true),
            (vec!["HELLO"], true),
        ] {
            let argv = argv.into_iter().map(str::to_owned).collect::<Vec<_>>();
            for reply in [&b"%0\r\n"[..], b"*0\r\n"] {
                let mut identity = UpstreamIdentity::default();
                assert!(
                    !identity
                        .retry_after(&argv, b"-WRONGPASS bad password\r\n")
                );
                assert!(!identity.retry_after(&argv, b"+QUEUED\r\n"));
                assert_eq!(identity.pending, [true; 3]);
                assert!(identity.retry_after(&argv, reply));
                assert_eq!(identity.pending, [pending_name, true, true]);
            }
        }
    }
}
