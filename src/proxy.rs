use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::sync::RwLock;
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};

use crate::cli::{Cli, Endpoint};
use crate::cluster::{ProxyTarget, Topology, discover};
use crate::error::{AppError, AppResult};
use crate::evil::{
    DebugAction, DebugResult, EvilConfig, EvilMode, deterministic_hash,
    mutate_reply, random_reply,
};
use crate::protocol_fingerprint::{
    ProtocolDirection, ProtocolFingerprints, parse_debug_protocol,
};
use crate::repro::{ReproRecord, ReproWriter};
use crate::resp::{Frame, parse_frame, read_raw_frame};

trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

type ProxyStream = Box<dyn AsyncReadWrite>;

enum ProxyListener {
    Tcp(TcpListener),
    Unix {
        listener: UnixListener,
        path: PathBuf,
    },
}

impl ProxyListener {
    async fn bind(endpoint: &Endpoint) -> AppResult<Self> {
        match endpoint {
            Endpoint::Tcp(endpoint) => {
                Ok(Self::Tcp(TcpListener::bind(endpoint.connect_addr()).await?))
            }
            Endpoint::Unix(path) => Ok(Self::Unix {
                listener: UnixListener::bind(path)?,
                path: path.clone(),
            }),
        }
    }

    fn local_endpoint(&self) -> AppResult<String> {
        match self {
            Self::Tcp(listener) => Ok(listener.local_addr()?.to_string()),
            Self::Unix { path, .. } => Ok(format!("unix:{}", path.display())),
        }
    }

    async fn accept(&self) -> AppResult<(ProxyStream, String)> {
        match self {
            Self::Tcp(listener) => {
                let (stream, peer) = listener.accept().await?;
                Ok((Box::new(stream), peer.to_string()))
            }
            Self::Unix { listener, .. } => {
                let (stream, peer) = listener.accept().await?;
                let peer = peer
                    .as_pathname()
                    .map(|path| format!("unix:{}", path.display()))
                    .unwrap_or_else(|| "unix:<unnamed>".to_owned());
                Ok((Box::new(stream), peer))
            }
        }
    }
}

impl Drop for ProxyListener {
    fn drop(&mut self) {
        if let Self::Unix { path, .. } = self
            && let Err(error) = std::fs::remove_file(&*path)
            && error.kind() != ErrorKind::NotFound
        {
            warn!(path = %path.display(), %error, "failed to remove Unix listener socket");
        }
    }
}

#[derive(Clone)]
struct SharedState {
    evil: Arc<RwLock<EvilConfig>>,
    repro: Option<ReproWriter>,
    connection_ids: Arc<AtomicU64>,
    local_slots: Option<Frame>,
}

pub async fn run(cli: Cli) -> AppResult<()> {
    let repro = match &cli.repro_file {
        Some(path) => Some(ReproWriter::open(path).await?),
        None => None,
    };
    let topology = discover(cli.proxy.clone(), cli.listen).await?;
    let state = SharedState {
        evil: Arc::new(RwLock::new(EvilConfig::default())),
        repro,
        connection_ids: Arc::new(AtomicU64::new(0)),
        local_slots: topology.local_slots_response(),
    };

    serve_topology(topology, state).await
}

async fn serve_topology(
    topology: Topology,
    state: SharedState,
) -> AppResult<()> {
    let mut listeners = JoinSet::new();
    for target in topology.targets() {
        let listener = ProxyListener::bind(&target.listen).await?;
        let local_endpoint = listener.local_endpoint()?;
        info!(
            listen = %local_endpoint,
            upstream = %target.upstream,
            "listening for RESP clients"
        );
        listeners.spawn(serve_listener(
            listener,
            target.clone(),
            state.clone(),
        ));
    }

    tokio::select! {
        signal = tokio::signal::ctrl_c() => {
            signal?;
            info!("shutdown signal received");
            Ok(())
        }
        result = listeners.join_next() => {
            match result {
                Some(Ok(Ok(()))) => Ok(()),
                Some(Ok(Err(error))) => Err(error),
                Some(Err(error)) => {
                    Err(AppError::Proxy(format!("listener task failed: {error}")))
                }
                None => Ok(()),
            }
        }
    }
}

async fn serve_listener(
    listener: ProxyListener,
    target: ProxyTarget,
    state: SharedState,
) -> AppResult<()> {
    loop {
        let (client, peer) = listener.accept().await?;
        let connection_id =
            state.connection_ids.fetch_add(1, Ordering::Relaxed);
        debug!(%peer, connection_id, upstream = %target.upstream, "accepted client");

        tokio::spawn(handle_connection(
            client,
            target.clone(),
            state.clone(),
            connection_id,
        ));
    }
}

async fn handle_connection(
    client: ProxyStream,
    target: ProxyTarget,
    state: SharedState,
    connection_id: u64,
) {
    if let Err(error) =
        proxy_connection(client, target, state, connection_id).await
    {
        debug!(connection_id, %error, "client connection closed");
    }
}

async fn proxy_connection(
    client: ProxyStream,
    target: ProxyTarget,
    state: SharedState,
    mut connection_id: u64,
) -> AppResult<()> {
    let upstream = connect_upstream(&target.upstream).await?;
    let (client_read, mut client_write) = tokio::io::split(client);
    let (upstream_read, mut upstream_write) = tokio::io::split(upstream);
    let mut client_read = BufReader::new(client_read);
    let mut upstream_read = BufReader::new(upstream_read);
    let mut command_index = 0_u64;
    let mut fingerprints = ProtocolFingerprints::new();

    loop {
        let command_bytes = match read_raw_frame(&mut client_read).await {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => {
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        let command_frame = parse_frame(&command_bytes)?;
        let argv = command_frame.argv_lossy();
        let command_name = command_frame.command_name();

        if is_debug_protocol(&argv) {
            let response = apply_debug_protocol(&fingerprints, &argv);
            client_write.write_all(&response.encode()).await?;
            continue;
        }

        fingerprints.update(ProtocolDirection::In, &command_bytes);

        if is_debug_evil(&argv) {
            let result = apply_debug_evil(&state, &argv).await;
            let response = result.frame.encode();
            client_write.write_all(&response).await?;
            if result.action == DebugAction::ResetIncrementingState {
                reset_incrementing_state(
                    &state,
                    &mut connection_id,
                    &mut command_index,
                );
                fingerprints.reset();
            } else {
                fingerprints.update(ProtocolDirection::Out, &response);
                command_index += 1;
            }
            continue;
        }

        if is_cluster_slots(&argv)
            && let Some(response) = &state.local_slots
        {
            write_client_frame(&mut client_write, &mut fingerprints, response)
                .await?;
            command_index += 1;
            continue;
        }

        let config = state.evil.read().await.clone();
        let should_mutate =
            config.should_mutate_command(command_name.as_deref());
        let command_hash = deterministic_hash(&command_bytes);

        if config.mode == EvilMode::Random && should_mutate {
            let mutated = random_reply(
                &config,
                connection_id,
                command_index,
                &command_hash,
            );
            write_repro(
                &state,
                ReproRecord::new(
                    config.seed,
                    connection_id,
                    command_index,
                    &command_bytes,
                    None,
                    &mutated.bytes,
                    config.mode,
                    mutated.mutations,
                ),
            )
            .await;
            write_client_bytes(
                &mut client_write,
                &mut fingerprints,
                &mutated.bytes,
            )
            .await?;
            command_index += 1;
            continue;
        }

        upstream_write.write_all(&command_bytes).await?;
        upstream_write.flush().await?;

        let upstream_bytes = read_raw_frame(&mut upstream_read).await?;
        let response_bytes = if should_mutate
            && matches!(config.mode, EvilMode::Mutate | EvilMode::Overflow)
        {
            let upstream_frame = parse_frame(&upstream_bytes)?;
            let upstream_hash = deterministic_hash(&upstream_bytes);
            let mutated = mutate_reply(
                &config,
                connection_id,
                command_index,
                &command_hash,
                &upstream_hash,
                &upstream_frame,
            );
            if !mutated.mutations.is_empty() {
                write_repro(
                    &state,
                    ReproRecord::new(
                        config.seed,
                        connection_id,
                        command_index,
                        &command_bytes,
                        Some(&upstream_bytes),
                        &mutated.bytes,
                        config.mode,
                        mutated.mutations,
                    ),
                )
                .await;
            }
            mutated.bytes
        } else {
            upstream_bytes
        };

        write_client_bytes(
            &mut client_write,
            &mut fingerprints,
            &response_bytes,
        )
        .await?;
        command_index += 1;
    }
}

async fn connect_upstream(endpoint: &Endpoint) -> AppResult<ProxyStream> {
    match endpoint {
        Endpoint::Tcp(endpoint) => {
            Ok(Box::new(TcpStream::connect(endpoint.connect_addr()).await?))
        }
        Endpoint::Unix(path) => Ok(Box::new(UnixStream::connect(path).await?)),
    }
}

async fn apply_debug_evil(state: &SharedState, argv: &[String]) -> DebugResult {
    let mut config = state.evil.write().await;
    match config.apply_debug_command(argv) {
        Ok(result) => {
            info!(status = %config.status(), "updated evil configuration");
            result
        }
        Err(error) => {
            warn!(%error, "rejected DEBUG EVIL command");
            DebugResult {
                frame: Frame::SimpleError(format!("ERR {error}")),
                action: DebugAction::None,
            }
        }
    }
}

fn apply_debug_protocol(
    fingerprints: &ProtocolFingerprints,
    argv: &[String],
) -> Frame {
    match parse_debug_protocol(argv) {
        Ok((direction, algorithm)) => Frame::BulkString(Some(
            fingerprints.get(direction, algorithm).into_bytes(),
        )),
        Err(error) => {
            warn!(%error, "rejected DEBUG PROTOCOL command");
            Frame::SimpleError(format!("ERR {error}"))
        }
    }
}

async fn write_repro(state: &SharedState, record: ReproRecord) {
    if let Some(writer) = &state.repro
        && let Err(error) = writer.append(record).await
    {
        error!(%error, "failed to append repro record");
    }
}

async fn write_client_frame<W>(
    writer: &mut W,
    fingerprints: &mut ProtocolFingerprints,
    frame: &Frame,
) -> AppResult<()>
where
    W: AsyncWrite + Unpin,
{
    write_client_bytes(writer, fingerprints, &frame.encode()).await
}

async fn write_client_bytes<W>(
    writer: &mut W,
    fingerprints: &mut ProtocolFingerprints,
    bytes: &[u8],
) -> AppResult<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(bytes).await?;
    fingerprints.update(ProtocolDirection::Out, bytes);
    Ok(())
}

fn reset_incrementing_state(
    state: &SharedState,
    connection_id: &mut u64,
    command_index: &mut u64,
) {
    *connection_id = 0;
    state.connection_ids.store(1, Ordering::Relaxed);
    *command_index = 0;
}

fn is_debug_evil(argv: &[String]) -> bool {
    argv.len() >= 2
        && argv[0].eq_ignore_ascii_case("DEBUG")
        && argv[1].eq_ignore_ascii_case("EVIL")
}

fn is_debug_protocol(argv: &[String]) -> bool {
    argv.len() >= 2
        && argv[0].eq_ignore_ascii_case("DEBUG")
        && argv[1].eq_ignore_ascii_case("PROTOCOL")
}

fn is_cluster_slots(argv: &[String]) -> bool {
    argv.len() >= 2
        && argv[0].eq_ignore_ascii_case("CLUSTER")
        && argv[1].eq_ignore_ascii_case("SLOTS")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    static SOCKET_ID: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn detects_local_commands_case_insensitively() {
        assert!(is_debug_evil(&["debug".to_owned(), "evil".to_owned()]));
        assert!(is_cluster_slots(&[
            "cluster".to_owned(),
            "slots".to_owned()
        ]));
    }

    #[tokio::test]
    async fn accepts_client_on_unix_listener() {
        let path = unique_socket_path("listen");
        let endpoint = Endpoint::Unix(path.clone());
        let listener = ProxyListener::bind(&endpoint).await.unwrap();

        let client = UnixStream::connect(&path).await.unwrap();
        let (server, peer) = listener.accept().await.unwrap();

        assert_eq!(peer, "unix:<unnamed>");
        drop(client);
        drop(server);
        drop(listener);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn proxies_commands_to_unix_upstream() {
        let path = unique_socket_path("upstream");
        let upstream_listener = UnixListener::bind(&path).unwrap();
        let upstream = tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let (read, mut write) = tokio::io::split(stream);
            let mut read = BufReader::new(read);
            let command = read_raw_frame(&mut read).await.unwrap();
            assert_eq!(command, b"*1\r\n$4\r\nPING\r\n");
            write
                .write_all(&Frame::SimpleString("PONG".to_owned()).encode())
                .await
                .unwrap();
        });

        let (mut client, server) = UnixStream::pair().unwrap();
        let target = ProxyTarget {
            upstream: Endpoint::Unix(path.clone()),
            listen: Endpoint::Unix(unique_socket_path("unused-listen")),
        };
        let state = SharedState {
            evil: Arc::new(RwLock::new(EvilConfig::default())),
            repro: None,
            connection_ids: Arc::new(AtomicU64::new(0)),
            local_slots: None,
        };
        let proxy =
            tokio::spawn(proxy_connection(Box::new(server), target, state, 0));

        client.write_all(b"*1\r\n$4\r\nPING\r\n").await.unwrap();
        let mut read = BufReader::new(client);
        let response = read_raw_frame(&mut read).await.unwrap();

        assert_eq!(response, b"+PONG\r\n");
        drop(read);
        proxy.await.unwrap().unwrap();
        upstream.await.unwrap();
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn debug_protocol_reports_per_connection_blake3_fingerprints() {
        let command = b"*1\r\n$4\r\nPING\r\n";
        let response = b"+PONG\r\n";
        let debug_in =
            b"*4\r\n$5\r\nDEBUG\r\n$8\r\nPROTOCOL\r\n$2\r\nIN\r\n$6\r\nBLAKE3\r\n";
        let debug_out =
            b"*4\r\n$5\r\nDEBUG\r\n$8\r\nPROTOCOL\r\n$3\r\nOUT\r\n$6\r\nBLAKE3\r\n";

        let mut read =
            run_proxy_client_with_single_upstream_response(command, response)
                .await;

        read.get_mut().write_all(debug_in).await.unwrap();
        read.get_mut().write_all(debug_out).await.unwrap();

        assert_eq!(read_raw_frame(&mut read).await.unwrap(), response);
        assert_eq!(
            read_bulk_string(&mut read).await,
            blake3_hex(command).into_bytes()
        );
        assert_eq!(
            read_bulk_string(&mut read).await,
            blake3_hex(response).into_bytes()
        );
    }

    #[tokio::test]
    async fn debug_evil_reset_zeroes_protocol_fingerprints() {
        let command = b"*1\r\n$4\r\nPING\r\n";
        let response = b"+PONG\r\n";
        let reset =
            b"*4\r\n$5\r\nDEBUG\r\n$4\r\nEVIL\r\n$4\r\nMODE\r\n$5\r\nRESET\r\n";
        let debug_in =
            b"*4\r\n$5\r\nDEBUG\r\n$8\r\nPROTOCOL\r\n$2\r\nIN\r\n$6\r\nBLAKE3\r\n";
        let debug_out =
            b"*4\r\n$5\r\nDEBUG\r\n$8\r\nPROTOCOL\r\n$3\r\nOUT\r\n$6\r\nBLAKE3\r\n";

        let mut read =
            run_proxy_client_with_single_upstream_response(command, response)
                .await;

        read.get_mut().write_all(reset).await.unwrap();
        read.get_mut().write_all(debug_in).await.unwrap();
        read.get_mut().write_all(debug_out).await.unwrap();

        assert_eq!(read_raw_frame(&mut read).await.unwrap(), response);
        assert_eq!(read_raw_frame(&mut read).await.unwrap(), b"+OK\r\n");
        assert_eq!(
            read_bulk_string(&mut read).await,
            blake3_hex(b"").into_bytes()
        );
        assert_eq!(
            read_bulk_string(&mut read).await,
            blake3_hex(b"").into_bytes()
        );
    }

    async fn run_proxy_client_with_single_upstream_response(
        command: &'static [u8],
        response: &'static [u8],
    ) -> BufReader<UnixStream> {
        let path = unique_socket_path("upstream-fingerprint");
        let upstream_listener = UnixListener::bind(&path).unwrap();
        let upstream = tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let (read, mut write) = tokio::io::split(stream);
            let mut read = BufReader::new(read);
            assert_eq!(read_raw_frame(&mut read).await.unwrap(), command);
            write.write_all(response).await.unwrap();
        });

        let (mut client, server) = UnixStream::pair().unwrap();
        let target = ProxyTarget {
            upstream: Endpoint::Unix(path.clone()),
            listen: Endpoint::Unix(unique_socket_path("unused-listen")),
        };
        let state = SharedState {
            evil: Arc::new(RwLock::new(EvilConfig::default())),
            repro: None,
            connection_ids: Arc::new(AtomicU64::new(0)),
            local_slots: None,
        };
        let proxy =
            tokio::spawn(proxy_connection(Box::new(server), target, state, 0));

        client.write_all(command).await.unwrap();

        tokio::spawn(async move {
            proxy.await.unwrap().unwrap();
            upstream.await.unwrap();
            std::fs::remove_file(path).unwrap();
        });

        BufReader::new(client)
    }

    async fn read_bulk_string<R>(read: &mut R) -> Vec<u8>
    where
        R: tokio::io::AsyncBufRead + Unpin + Send,
    {
        let bytes = read_raw_frame(read).await.unwrap();
        match parse_frame(&bytes).unwrap() {
            Frame::BulkString(Some(bytes)) => bytes,
            other => panic!("expected bulk string, got {other:?}"),
        }
    }

    fn blake3_hex(bytes: &[u8]) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(bytes);
        hasher.finalize().to_hex().to_string()
    }

    fn unique_socket_path(name: &str) -> PathBuf {
        let id = SOCKET_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!("evilresp-{name}-{}-{id}.sock", std::process::id()))
    }

    #[tokio::test]
    async fn debug_evil_reset_zeroes_incrementing_state() {
        let mut config = EvilConfig::default();
        config.mode = EvilMode::Mutate;
        config.probability = 100.0;

        let state = SharedState {
            evil: Arc::new(RwLock::new(config)),
            repro: None,
            connection_ids: Arc::new(AtomicU64::new(17)),
            local_slots: None,
        };

        let result = apply_debug_evil(
            &state,
            &[
                "DEBUG".to_owned(),
                "EVIL".to_owned(),
                "MODE".to_owned(),
                "RESET".to_owned(),
            ],
        )
        .await;

        if result.action == DebugAction::ResetIncrementingState {
            let mut connection_id = 19;
            let mut command_index = 23;
            reset_incrementing_state(
                &state,
                &mut connection_id,
                &mut command_index,
            );
            assert_eq!(connection_id, 0);
            assert_eq!(command_index, 0);
        }

        assert_eq!(result.action, DebugAction::ResetIncrementingState);
        assert_eq!(state.connection_ids.load(Ordering::Relaxed), 1);
        let config = state.evil.read().await;
        assert_eq!(config.mode, EvilMode::Off);
        assert_eq!(config.probability, 0.0);
    }

    #[tokio::test]
    async fn debug_evil_reset_makes_repeated_client_runs_identical() {
        let first = run_mutating_client_after_reset(
            17,
            b"*2\r\n$3\r\nGET\r\n$1\r\na\r\n",
        )
        .await;
        let second = run_mutating_client_after_reset(
            42,
            b"*2\r\n$3\r\nGET\r\n$1\r\na\r\n",
        )
        .await;

        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn repeated_clients_with_same_evil_config_have_identical_protocol_output()
     {
        for mode in ["RANDOM", "MUTATE", "OVERFLOW"] {
            let first =
                run_protocol_fingerprint_client_after_reset(17, mode).await;
            let second =
                run_protocol_fingerprint_client_after_reset(42, mode).await;

            assert_eq!(first, second, "mode {mode}");
            assert!(!first.out_blake3.is_empty(), "mode {mode}");
            assert!(!first.out_tlsh.is_empty(), "mode {mode}");
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct ProtocolOutputRun {
        output: Vec<u8>,
        out_blake3: Vec<u8>,
        out_tlsh: Vec<u8>,
    }

    async fn run_protocol_fingerprint_client_after_reset(
        initial_connection_id: u64,
        mode: &str,
    ) -> ProtocolOutputRun {
        let path = unique_socket_path("upstream-protocol-determinism");
        let upstream_listener = UnixListener::bind(&path).unwrap();
        let upstream = tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let (read, mut write) = tokio::io::split(stream);
            let mut read = BufReader::new(read);

            loop {
                match read_raw_frame(&mut read).await {
                    Ok(command) => {
                        write
                            .write_all(&deterministic_upstream_response(
                                &command,
                            ))
                            .await
                            .unwrap();
                    }
                    Err(error) if error.kind() == ErrorKind::UnexpectedEof => {
                        break;
                    }
                    Err(error) => {
                        panic!("failed to read upstream command: {error}")
                    }
                }
            }
        });

        let (mut client, server) = UnixStream::pair().unwrap();
        let target = ProxyTarget {
            upstream: Endpoint::Unix(path.clone()),
            listen: Endpoint::Unix(unique_socket_path("unused-listen")),
        };
        let state = SharedState {
            evil: Arc::new(RwLock::new(EvilConfig::default())),
            repro: None,
            connection_ids: Arc::new(AtomicU64::new(initial_connection_id + 1)),
            local_slots: None,
        };
        let proxy = tokio::spawn(proxy_connection(
            Box::new(server),
            target,
            state,
            initial_connection_id,
        ));

        client
            .write_all(&resp_command(&["DEBUG", "EVIL", "MODE", "RESET"]))
            .await
            .unwrap();
        client
            .write_all(&resp_command(&["DEBUG", "EVIL", "SEED", "98765"]))
            .await
            .unwrap();
        client
            .write_all(&resp_command(&[
                "DEBUG",
                "EVIL",
                "MODE",
                mode,
                "PROBABILITY",
                "100.0",
            ]))
            .await
            .unwrap();

        let mut read = BufReader::new(client);
        let mut output = Vec::new();
        for _ in 0..3 {
            output.extend(read_raw_frame(&mut read).await.unwrap());
        }

        for command in deterministic_protocol_commands() {
            read.get_mut().write_all(&command).await.unwrap();
            output.extend(read_available_response_bytes(&mut read).await);
        }

        read.get_mut()
            .write_all(&resp_command(&["DEBUG", "PROTOCOL", "OUT", "BLAKE3"]))
            .await
            .unwrap();
        let out_blake3 = read_bulk_string(&mut read).await;

        read.get_mut()
            .write_all(&resp_command(&["DEBUG", "PROTOCOL", "OUT", "TLSH"]))
            .await
            .unwrap();
        let out_tlsh = read_bulk_string(&mut read).await;

        drop(read);
        proxy.await.unwrap().unwrap();
        upstream.await.unwrap();
        std::fs::remove_file(path).unwrap();

        ProtocolOutputRun {
            output,
            out_blake3,
            out_tlsh,
        }
    }

    fn deterministic_protocol_commands() -> Vec<Vec<u8>> {
        (0..12)
            .map(|index| resp_command(&["GET", &format!("key:{index:02}")]))
            .collect()
    }

    fn deterministic_upstream_response(command: &[u8]) -> Vec<u8> {
        let body = format!("value:{}", blake3_hex(command));
        Frame::BulkString(Some(body.into_bytes())).encode()
    }

    fn resp_command(args: &[&str]) -> Vec<u8> {
        Frame::Array(Some(
            args.iter()
                .map(|arg| Frame::BulkString(Some(arg.as_bytes().to_vec())))
                .collect(),
        ))
        .encode()
    }

    async fn run_mutating_client_after_reset(
        initial_connection_id: u64,
        command: &'static [u8],
    ) -> Vec<u8> {
        let path = unique_socket_path("upstream-reset");
        let upstream_listener = UnixListener::bind(&path).unwrap();
        let upstream_command = command.to_vec();
        let upstream = tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let (read, mut write) = tokio::io::split(stream);
            let mut read = BufReader::new(read);

            let command = read_raw_frame(&mut read).await.unwrap();
            write
                .write_all(upstream_response_for(&upstream_command, &command))
                .await
                .unwrap();
        });

        let (mut client, server) = UnixStream::pair().unwrap();
        let target = ProxyTarget {
            upstream: Endpoint::Unix(path.clone()),
            listen: Endpoint::Unix(unique_socket_path("unused-listen")),
        };
        let state = SharedState {
            evil: Arc::new(RwLock::new(EvilConfig::default())),
            repro: None,
            connection_ids: Arc::new(AtomicU64::new(initial_connection_id + 1)),
            local_slots: None,
        };
        let proxy = tokio::spawn(proxy_connection(
            Box::new(server),
            target,
            state,
            initial_connection_id,
        ));

        client
            .write_all(
                b"*4\r\n$5\r\nDEBUG\r\n$4\r\nEVIL\r\n$4\r\nMODE\r\n$5\r\nRESET\r\n",
            )
            .await
            .unwrap();
        client
            .write_all(b"*4\r\n$5\r\nDEBUG\r\n$4\r\nEVIL\r\n$4\r\nSEED\r\n$4\r\n1234\r\n")
            .await
            .unwrap();
        client
            .write_all(
                b"*6\r\n$5\r\nDEBUG\r\n$4\r\nEVIL\r\n$4\r\nMODE\r\n$6\r\nMUTATE\r\n$11\r\nPROBABILITY\r\n$5\r\n100.0\r\n",
            )
            .await
            .unwrap();
        client.write_all(command).await.unwrap();

        let mut read = BufReader::new(client);
        assert_eq!(read_raw_frame(&mut read).await.unwrap(), b"+OK\r\n");
        assert_eq!(read_raw_frame(&mut read).await.unwrap(), b"+OK\r\n");
        assert_eq!(read_raw_frame(&mut read).await.unwrap(), b"+OK\r\n");
        let response = read_available_response_bytes(&mut read).await;

        drop(read);
        proxy.await.unwrap().unwrap();
        upstream.await.unwrap();
        std::fs::remove_file(path).unwrap();

        response
    }

    async fn read_available_response_bytes<R>(read: &mut R) -> Vec<u8>
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        let mut response = Vec::new();
        let mut chunk = [0_u8; 1024];

        loop {
            match tokio::time::timeout(
                Duration::from_millis(25),
                tokio::io::AsyncReadExt::read(read, &mut chunk),
            )
            .await
            {
                Ok(Ok(0)) => break,
                Ok(Ok(count)) => response.extend_from_slice(&chunk[..count]),
                Ok(Err(error)) => panic!("failed to read response: {error}"),
                Err(_) if !response.is_empty() => break,
                Err(_) => panic!("timed out waiting for response"),
            }
        }

        response
    }

    fn upstream_response_for<'a>(
        fuzz_command: &[u8],
        command: &'a [u8],
    ) -> &'a [u8] {
        if command == fuzz_command {
            b"$5\r\nvalue\r\n"
        } else {
            b"+OK\r\n"
        }
    }
}
