use std::fmt::Write as _;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::sync::{RwLock, broadcast};
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};

use crate::cli::{Cli, Endpoint};
use crate::cluster::{ClusterRedirectionMap, ProxyTarget, Topology, discover};
use crate::error::{AppError, AppResult};
use crate::evil::{
    DebugAction, DebugResult, EvilConfig, EvilMode, canonicalize_reply,
    canonicalize_transaction_reply, deterministic_hash, mutate_reply,
    random_reply,
};
use crate::protocol_fingerprint::{
    ProtocolDirection, ProtocolFingerprints, parse_debug_protocol,
};
use crate::repro::{ReproRecord, ReproWriter};
use crate::resp::{Frame, parse_frame, read_raw_frame};
use crate::topology_evil::{maybe_mutate_topology, normalize_redirection};

trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

const MONITOR_BUFFER: usize = 1024;

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
    repro: Option<ReproWriter>,
    monitor: broadcast::Sender<String>,
    reset_barrier: Arc<RwLock<()>>,
    reset_epoch: Arc<AtomicU64>,
    connection_ids: Arc<AtomicU64>,
    command_ids: Arc<AtomicU64>,
    local_slots: Option<Frame>,
    redirection_map: ClusterRedirectionMap,
}

pub async fn run(cli: Cli) -> AppResult<()> {
    let repro = match &cli.repro_file {
        Some(path) => Some(ReproWriter::open(path).await?),
        None => None,
    };
    let (monitor, _) = broadcast::channel(MONITOR_BUFFER);
    let topology = discover(cli.proxy.clone(), cli.listen).await?;
    let state = SharedState {
        repro,
        monitor,
        reset_barrier: Arc::new(RwLock::new(())),
        reset_epoch: Arc::new(AtomicU64::new(0)),
        connection_ids: Arc::new(AtomicU64::new(0)),
        command_ids: Arc::new(AtomicU64::new(0)),
        local_slots: topology.local_slots_response(),
        redirection_map: topology.local_redirection_map(),
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
        let reset_epoch = state.reset_epoch.load(Ordering::SeqCst);
        let connection_id = state.connection_ids.fetch_add(1, Ordering::SeqCst);
        debug!(%peer, reset_epoch, connection_id, upstream = %target.upstream, "accepted client");

        tokio::spawn(handle_connection(
            client,
            target.clone(),
            state.clone(),
            connection_id,
            reset_epoch,
        ));
    }
}

async fn handle_connection(
    client: ProxyStream,
    target: ProxyTarget,
    state: SharedState,
    connection_id: u64,
    reset_epoch: u64,
) {
    if let Err(error) =
        proxy_connection(client, target, state, connection_id, reset_epoch)
            .await
    {
        debug!(connection_id, %error, "client connection closed");
    }
}

async fn proxy_connection(
    client: ProxyStream,
    target: ProxyTarget,
    state: SharedState,
    connection_id: u64,
    mut reset_epoch: u64,
) -> AppResult<()> {
    let upstream = connect_upstream(&target.upstream).await?;
    let (client_read, mut client_write) = tokio::io::split(client);
    let (upstream_read, mut upstream_write) = tokio::io::split(upstream);
    let mut client_read = BufReader::new(client_read);
    let mut upstream_read = BufReader::new(upstream_read);
    let mut fingerprints = ProtocolFingerprints::new();
    let mut transaction_commands = Option::<Vec<String>>::None;
    let mut config = EvilConfig::default();

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

        if reset_epoch != state.reset_epoch.load(Ordering::SeqCst) {
            debug!(
                connection_id,
                reset_epoch, "closing stale client connection after evil reset"
            );
            return Ok(());
        }

        if is_debug_protocol(&argv) {
            let response = apply_debug_protocol(&fingerprints, &argv);
            client_write.write_all(&response.encode()).await?;
            continue;
        }

        fingerprints.update(ProtocolDirection::In, &command_bytes);

        if is_monitor(command_name.as_deref()) {
            if argv.len() != 1 {
                write_client_frame(
                    &mut client_write,
                    &mut fingerprints,
                    &Frame::SimpleError(
                        "ERR wrong number of arguments for 'monitor' command"
                            .to_owned(),
                    ),
                )
                .await?;
                continue;
            }

            stream_monitor(
                &mut client_write,
                &mut fingerprints,
                state.monitor.subscribe(),
                connection_id,
            )
            .await?;
            return Ok(());
        }

        if is_debug_evil(&argv) {
            publish_monitor_command(&state, connection_id, &command_frame);
            let result = apply_debug_evil(&mut config, &argv);
            let response = result.frame.encode();
            if result.action == DebugAction::ResetIncrementingState {
                reset_incrementing_state(&state, &mut reset_epoch).await;
                client_write.write_all(&response).await?;
                fingerprints.reset();
            } else {
                client_write.write_all(&response).await?;
                fingerprints.update(ProtocolDirection::Out, &response);
            }
            continue;
        }

        if is_cluster_slots(&argv)
            && let Some(response) = &state.local_slots
        {
            publish_monitor_command(&state, connection_id, &command_frame);
            write_client_frame(&mut client_write, &mut fingerprints, response)
                .await?;
            continue;
        }

        let (
            command_id,
            should_mutate,
            command_hash,
            exec_transaction_commands,
        ) = {
            let _reset_guard = state.reset_barrier.read().await;
            if reset_epoch != state.reset_epoch.load(Ordering::SeqCst) {
                debug!(
                    connection_id,
                    reset_epoch,
                    "closing stale client connection after waiting for evil reset"
                );
                return Ok(());
            }

            let command_id = state.command_ids.fetch_add(1, Ordering::SeqCst);
            let should_mutate =
                config.should_mutate_command(command_name.as_deref());
            let command_hash = deterministic_hash(&command_bytes);
            let exec_transaction_commands = if is_exec(command_name.as_deref())
            {
                transaction_commands.take()
            } else {
                None
            };

            (
                command_id,
                should_mutate,
                command_hash,
                exec_transaction_commands,
            )
        };

        publish_monitor_command(&state, connection_id, &command_frame);

        if config.mode == EvilMode::Random && should_mutate {
            if let Some(local_slots) = &state.local_slots
                && let Some(mutated) = maybe_mutate_topology(
                    &config,
                    command_id,
                    &command_hash,
                    &command_frame,
                    None,
                    local_slots,
                )?
            {
                let bytes = mutated.frame.encode();
                write_repro(
                    &state,
                    ReproRecord::new(
                        config.seed,
                        connection_id,
                        command_id,
                        &command_bytes,
                        None,
                        &bytes,
                        config.mode,
                        mutated.mutations,
                    ),
                )
                .await;
                write_client_bytes(
                    &mut client_write,
                    &mut fingerprints,
                    &bytes,
                )
                .await?;
                continue;
            }

            let mutated = random_reply(&config, command_id, &command_hash);
            write_repro(
                &state,
                ReproRecord::new(
                    config.seed,
                    connection_id,
                    command_id,
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
            continue;
        }

        upstream_write.write_all(&command_bytes).await?;
        upstream_write.flush().await?;

        let upstream_bytes = read_raw_frame(&mut upstream_read).await?;
        update_transaction_commands(
            &mut transaction_commands,
            command_name.as_deref(),
        );
        let relay_upstream_bytes =
            normalize_cluster_redirection(&upstream_bytes, &state)?;
        let mut applied_mutations = Vec::new();
        let response_frame = if should_mutate
            && let Some(local_slots) = &state.local_slots
            && let Some(mutated) = maybe_mutate_topology(
                &config,
                command_id,
                &command_hash,
                &command_frame,
                Some(&relay_upstream_bytes),
                local_slots,
            )? {
            applied_mutations = mutated.mutations;
            Some(mutated.frame)
        } else {
            None
        };
        let base_response_bytes = response_frame
            .as_ref()
            .map(Frame::encode)
            .unwrap_or_else(|| relay_upstream_bytes.clone());
        let response_bytes = if should_mutate
            && matches!(config.mode, EvilMode::Mutate | EvilMode::Overflow)
        {
            let upstream_frame = match &response_frame {
                Some(frame) => frame.clone(),
                None => parse_frame(&upstream_bytes)?,
            };
            let mutation_frame = match exec_transaction_commands {
                Some(commands) => canonicalize_transaction_reply(
                    config.canonicalization,
                    &commands,
                    &upstream_frame,
                ),
                None => canonicalize_reply(
                    config.canonicalization,
                    command_name.as_deref(),
                    &upstream_frame,
                ),
            };
            let upstream_hash = deterministic_hash(&mutation_frame.encode());
            let mutated = mutate_reply(
                &config,
                command_id,
                &command_hash,
                &upstream_hash,
                &mutation_frame,
            );
            applied_mutations.extend(mutated.mutations);
            if !applied_mutations.is_empty() {
                write_repro(
                    &state,
                    ReproRecord::new(
                        config.seed,
                        connection_id,
                        command_id,
                        &command_bytes,
                        Some(&upstream_bytes),
                        &mutated.bytes,
                        config.mode,
                        applied_mutations,
                    ),
                )
                .await;
            }
            mutated.bytes
        } else {
            if !applied_mutations.is_empty() {
                write_repro(
                    &state,
                    ReproRecord::new(
                        config.seed,
                        connection_id,
                        command_id,
                        &command_bytes,
                        Some(&upstream_bytes),
                        &base_response_bytes,
                        config.mode,
                        applied_mutations,
                    ),
                )
                .await;
            }
            base_response_bytes
        };

        write_client_bytes(
            &mut client_write,
            &mut fingerprints,
            &response_bytes,
        )
        .await?;
    }
}

fn normalize_cluster_redirection(
    upstream_bytes: &[u8],
    state: &SharedState,
) -> AppResult<Vec<u8>> {
    if !matches!(upstream_bytes.first(), Some(b'-' | b'!')) {
        return Ok(upstream_bytes.to_vec());
    }

    let upstream_frame = parse_frame(upstream_bytes)?;
    Ok(
        normalize_redirection(&upstream_frame, &state.redirection_map)
            .map(|frame| frame.encode())
            .unwrap_or_else(|| upstream_bytes.to_vec()),
    )
}

async fn connect_upstream(endpoint: &Endpoint) -> AppResult<ProxyStream> {
    match endpoint {
        Endpoint::Tcp(endpoint) => {
            Ok(Box::new(TcpStream::connect(endpoint.connect_addr()).await?))
        }
        Endpoint::Unix(path) => Ok(Box::new(UnixStream::connect(path).await?)),
    }
}

fn apply_debug_evil(config: &mut EvilConfig, argv: &[String]) -> DebugResult {
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

async fn stream_monitor<W>(
    writer: &mut W,
    fingerprints: &mut ProtocolFingerprints,
    mut receiver: broadcast::Receiver<String>,
    connection_id: u64,
) -> AppResult<()>
where
    W: AsyncWrite + Unpin,
{
    write_client_frame(
        writer,
        fingerprints,
        &Frame::SimpleString("OK".to_owned()),
    )
    .await?;

    loop {
        match receiver.recv().await {
            Ok(line) => {
                write_client_frame(
                    writer,
                    fingerprints,
                    &Frame::SimpleString(line),
                )
                .await?;
            }
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                warn!(
                    connection_id,
                    skipped, "monitor client lagged behind command stream"
                );
            }
            Err(broadcast::error::RecvError::Closed) => return Ok(()),
        }
    }
}

fn publish_monitor_command(
    state: &SharedState,
    connection_id: u64,
    command: &Frame,
) {
    if state.monitor.receiver_count() == 0 {
        return;
    }

    let argv = monitor_argv(command);
    if argv.is_empty() {
        return;
    }

    let line = format_monitor_line(connection_id, &argv);
    let _ = state.monitor.send(line);
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

async fn reset_incrementing_state(state: &SharedState, reset_epoch: &mut u64) {
    let _reset_guard = state.reset_barrier.write().await;
    *reset_epoch = state.reset_epoch.fetch_add(1, Ordering::SeqCst) + 1;
    state.command_ids.store(0, Ordering::SeqCst);
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

fn is_monitor(command: Option<&str>) -> bool {
    command.is_some_and(|command| command.eq_ignore_ascii_case("MONITOR"))
}

fn is_cluster_slots(argv: &[String]) -> bool {
    argv.len() >= 2
        && argv[0].eq_ignore_ascii_case("CLUSTER")
        && argv[1].eq_ignore_ascii_case("SLOTS")
}

fn is_exec(command: Option<&str>) -> bool {
    command.is_some_and(|command| command.eq_ignore_ascii_case("EXEC"))
}

fn update_transaction_commands(
    transaction_commands: &mut Option<Vec<String>>,
    command: Option<&str>,
) {
    let Some(command) = command else {
        return;
    };
    let command = command.to_ascii_uppercase();

    match command.as_str() {
        "EXEC" | "DISCARD" => *transaction_commands = None,
        "MULTI" if transaction_commands.is_none() => {
            *transaction_commands = Some(Vec::new());
        }
        _ => {
            if let Some(commands) = transaction_commands {
                commands.push(command);
            }
        }
    }
}

fn monitor_argv(command: &Frame) -> Vec<Vec<u8>> {
    match command {
        Frame::Array(Some(items)) => items
            .iter()
            .filter_map(|item| match item {
                Frame::BulkString(Some(bytes)) => Some(bytes.clone()),
                Frame::SimpleString(value) => Some(value.as_bytes().to_vec()),
                Frame::VerbatimString(bytes) => Some(bytes.clone()),
                _ => None,
            })
            .collect(),
        Frame::Inline(parts) => parts.clone(),
        _ => Vec::new(),
    }
}

fn format_monitor_line(connection_id: u64, argv: &[Vec<u8>]) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let mut line = format!(
        "{}.{:06} [0 unix:evilresp:{}]",
        now.as_secs(),
        now.subsec_micros(),
        connection_id
    );

    for arg in argv {
        line.push(' ');
        push_monitor_arg(&mut line, arg);
    }

    line
}

fn push_monitor_arg(line: &mut String, arg: &[u8]) {
    line.push('"');
    for byte in arg {
        match byte {
            b'\\' => line.push_str("\\\\"),
            b'"' => line.push_str("\\\""),
            b'\n' => line.push_str("\\n"),
            b'\r' => line.push_str("\\r"),
            b'\t' => line.push_str("\\t"),
            0x20..=0x7e => line.push(char::from(*byte)),
            _ => {
                let _ = write!(line, "\\x{byte:02x}");
            }
        }
    }
    line.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::TcpEndpoint;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    static SOCKET_ID: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn detects_local_commands_case_insensitively() {
        assert!(is_debug_evil(&["debug".to_owned(), "evil".to_owned()]));
        assert!(is_monitor(Some("monitor")));
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
            repro: None,
            monitor: monitor_sender(),
            reset_barrier: Arc::new(RwLock::new(())),
            reset_epoch: Arc::new(AtomicU64::new(0)),
            connection_ids: Arc::new(AtomicU64::new(0)),
            command_ids: Arc::new(AtomicU64::new(0)),
            local_slots: None,
            redirection_map: ClusterRedirectionMap::default(),
        };
        let proxy = tokio::spawn(proxy_connection(
            Box::new(server),
            target,
            state,
            0,
            0,
        ));

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
    async fn monitor_streams_commands_from_connected_clients() {
        let path = unique_socket_path("upstream-monitor");
        let upstream_listener = UnixListener::bind(&path).unwrap();
        let upstream = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = upstream_listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let (read, mut write) = tokio::io::split(stream);
                    let mut read = BufReader::new(read);
                    loop {
                        match read_raw_frame(&mut read).await {
                            Ok(_) => {
                                write.write_all(b"+OK\r\n").await.unwrap();
                            }
                            Err(error)
                                if error.kind() == ErrorKind::UnexpectedEof =>
                            {
                                break;
                            }
                            Err(error) => {
                                panic!(
                                    "failed to read upstream command: {error}"
                                );
                            }
                        }
                    }
                });
            }
        });

        let target = ProxyTarget {
            upstream: Endpoint::Unix(path.clone()),
            listen: Endpoint::Unix(unique_socket_path("unused-listen")),
        };
        let state = SharedState {
            repro: None,
            monitor: monitor_sender(),
            reset_barrier: Arc::new(RwLock::new(())),
            reset_epoch: Arc::new(AtomicU64::new(0)),
            connection_ids: Arc::new(AtomicU64::new(0)),
            command_ids: Arc::new(AtomicU64::new(0)),
            local_slots: None,
            redirection_map: ClusterRedirectionMap::default(),
        };

        let mut monitor = spawn_proxy_client(target.clone(), state.clone(), 0);
        monitor
            .get_mut()
            .write_all(&resp_command(&["MONITOR"]))
            .await
            .unwrap();
        assert_eq!(read_raw_frame(&mut monitor).await.unwrap(), b"+OK\r\n");

        let mut client = spawn_proxy_client(target, state, 1);
        client
            .get_mut()
            .write_all(&resp_command(&["SET", "watched", "value\n\""]))
            .await
            .unwrap();
        assert_eq!(read_raw_frame(&mut client).await.unwrap(), b"+OK\r\n");

        let line = read_simple_string(&mut monitor).await;
        assert!(line.contains("[0 unix:evilresp:1]"));
        assert!(line.contains("\"SET\""));
        assert!(line.contains("\"watched\""));
        assert!(line.contains("\"value\\n\\\"\""));

        drop(monitor);
        drop(client);
        upstream.abort();
        let _ = upstream.await;
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
            repro: None,
            monitor: monitor_sender(),
            reset_barrier: Arc::new(RwLock::new(())),
            reset_epoch: Arc::new(AtomicU64::new(0)),
            connection_ids: Arc::new(AtomicU64::new(0)),
            command_ids: Arc::new(AtomicU64::new(0)),
            local_slots: None,
            redirection_map: ClusterRedirectionMap::default(),
        };
        let proxy = tokio::spawn(proxy_connection(
            Box::new(server),
            target,
            state,
            0,
            0,
        ));

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

    async fn read_simple_string<R>(read: &mut R) -> String
    where
        R: tokio::io::AsyncBufRead + Unpin + Send,
    {
        let bytes = read_raw_frame(read).await.unwrap();
        match parse_frame(&bytes).unwrap() {
            Frame::SimpleString(value) => value,
            other => panic!("expected simple string, got {other:?}"),
        }
    }

    async fn read_simple_error<R>(read: &mut R) -> String
    where
        R: tokio::io::AsyncBufRead + Unpin + Send,
    {
        let bytes = read_raw_frame(read).await.unwrap();
        match parse_frame(&bytes).unwrap() {
            Frame::SimpleError(value) => value,
            other => panic!("expected simple error, got {other:?}"),
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

    fn monitor_sender() -> broadcast::Sender<String> {
        let (sender, _) = broadcast::channel(MONITOR_BUFFER);
        sender
    }

    #[tokio::test]
    async fn debug_evil_reset_zeroes_incrementing_state() {
        let mut config = EvilConfig::default();
        config.mode = EvilMode::Mutate;
        config.probability = 100.0;

        let state = SharedState {
            repro: None,
            monitor: monitor_sender(),
            reset_barrier: Arc::new(RwLock::new(())),
            reset_epoch: Arc::new(AtomicU64::new(3)),
            connection_ids: Arc::new(AtomicU64::new(17)),
            command_ids: Arc::new(AtomicU64::new(23)),
            local_slots: None,
            redirection_map: ClusterRedirectionMap::default(),
        };

        let result = apply_debug_evil(
            &mut config,
            &[
                "DEBUG".to_owned(),
                "EVIL".to_owned(),
                "MODE".to_owned(),
                "RESET".to_owned(),
            ],
        );

        if result.action == DebugAction::ResetIncrementingState {
            let mut reset_epoch = 3;
            reset_incrementing_state(&state, &mut reset_epoch).await;
            assert_eq!(reset_epoch, 4);
        }

        assert_eq!(result.action, DebugAction::ResetIncrementingState);
        assert_eq!(state.reset_epoch.load(Ordering::SeqCst), 4);
        assert_eq!(state.connection_ids.load(Ordering::SeqCst), 17);
        assert_eq!(state.command_ids.load(Ordering::SeqCst), 0);
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

    #[tokio::test]
    async fn unordered_redis_replies_mutate_identically_across_upstreams() {
        let canonical =
            run_unordered_reply_proxy_session(ReplyOrder::Canonical).await;
        let scrambled =
            run_unordered_reply_proxy_session(ReplyOrder::Scrambled).await;

        assert_eq!(canonical, scrambled);
        assert_eq!(canonical.len(), unordered_redis_commands().len());
    }

    #[tokio::test]
    async fn transaction_unordered_replies_mutate_identically_across_upstreams()
    {
        let canonical =
            run_transaction_reply_proxy_session(ReplyOrder::Canonical).await;
        let scrambled =
            run_transaction_reply_proxy_session(ReplyOrder::Scrambled).await;

        assert_eq!(canonical, scrambled);
        assert_eq!(canonical.len(), transaction_redis_commands().len());
    }

    #[tokio::test]
    async fn reconnect_starts_with_default_evil_config() {
        let single = run_two_command_sequence(false).await;
        let reconnected = run_two_command_sequence(true).await;

        assert_ne!(single, reconnected);
    }

    #[tokio::test]
    async fn new_connections_do_not_inherit_evil_config() {
        let path = unique_socket_path("upstream-per-connection-config");
        let upstream_listener = UnixListener::bind(&path).unwrap();
        let upstream = tokio::spawn(async move {
            loop {
                if upstream_listener.accept().await.is_err() {
                    break;
                }
            }
        });

        let target = ProxyTarget {
            upstream: Endpoint::Unix(path.clone()),
            listen: Endpoint::Unix(unique_socket_path("unused-listen")),
        };
        let state = SharedState {
            repro: None,
            monitor: monitor_sender(),
            reset_barrier: Arc::new(RwLock::new(())),
            reset_epoch: Arc::new(AtomicU64::new(0)),
            connection_ids: Arc::new(AtomicU64::new(0)),
            command_ids: Arc::new(AtomicU64::new(0)),
            local_slots: None,
            redirection_map: ClusterRedirectionMap::default(),
        };

        let mut first = spawn_proxy_client(target.clone(), state.clone(), 0);
        first
            .get_mut()
            .write_all(&resp_command(&["DEBUG", "EVIL", "MODE", "RANDOM"]))
            .await
            .unwrap();
        first
            .get_mut()
            .write_all(&resp_command(&["DEBUG", "EVIL", "STATUS"]))
            .await
            .unwrap();

        assert_eq!(read_raw_frame(&mut first).await.unwrap(), b"+OK\r\n");
        let first_status =
            String::from_utf8(read_bulk_string(&mut first).await).unwrap();
        assert!(first_status.contains("mode=RANDOM"));

        let mut second = spawn_proxy_client(target, state, 1);
        second
            .get_mut()
            .write_all(&resp_command(&["DEBUG", "EVIL", "STATUS"]))
            .await
            .unwrap();

        let second_status =
            String::from_utf8(read_bulk_string(&mut second).await).unwrap();
        assert!(second_status.contains("mode=OFF"));
        assert!(second_status.contains("seed=0"));

        drop(first);
        drop(second);
        upstream.abort();
        let _ = upstream.await;
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn topology_evil_can_fake_redirection_with_resp_mode_off() {
        let path = unique_socket_path("upstream-topology-redirection");
        let upstream_listener = UnixListener::bind(&path).unwrap();
        let upstream = tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let (read, mut write) = tokio::io::split(stream);
            let mut read = BufReader::new(read);
            assert_eq!(
                read_raw_frame(&mut read).await.unwrap(),
                resp_command(&["GET", "foo"])
            );
            write
                .write_all(&bulk_string("value").encode())
                .await
                .unwrap();
        });

        let target = ProxyTarget {
            upstream: Endpoint::Unix(path.clone()),
            listen: Endpoint::Unix(unique_socket_path("unused-listen")),
        };
        let state = SharedState {
            repro: None,
            monitor: monitor_sender(),
            reset_barrier: Arc::new(RwLock::new(())),
            reset_epoch: Arc::new(AtomicU64::new(0)),
            connection_ids: Arc::new(AtomicU64::new(1)),
            command_ids: Arc::new(AtomicU64::new(0)),
            local_slots: Some(cluster_slots_frame()),
            redirection_map: ClusterRedirectionMap::default(),
        };
        let mut client = spawn_proxy_client(target, state, 0);

        client
            .get_mut()
            .write_all(&resp_command(&["DEBUG", "EVIL", "TOPOLOGY", "100"]))
            .await
            .unwrap();
        assert_eq!(read_raw_frame(&mut client).await.unwrap(), b"+OK\r\n");

        client
            .get_mut()
            .write_all(&resp_command(&["GET", "foo"]))
            .await
            .unwrap();
        let response = read_simple_error(&mut client).await;

        assert!(response.starts_with("MOVED ") || response.starts_with("ASK "));

        drop(client);
        upstream.await.unwrap();
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn upstream_redirections_are_rewritten_to_proxy_ports() {
        let path = unique_socket_path("upstream-real-redirection");
        let upstream_listener = UnixListener::bind(&path).unwrap();
        let upstream = tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let (read, mut write) = tokio::io::split(stream);
            let mut read = BufReader::new(read);
            assert_eq!(
                read_raw_frame(&mut read).await.unwrap(),
                resp_command(&["GET", "foo"])
            );
            write
                .write_all(b"-MOVED 12182 127.0.0.1:7002\r\n")
                .await
                .unwrap();
        });

        let target = ProxyTarget {
            upstream: Endpoint::Unix(path.clone()),
            listen: Endpoint::Unix(unique_socket_path("unused-listen")),
        };
        let state = SharedState {
            repro: None,
            monitor: monitor_sender(),
            reset_barrier: Arc::new(RwLock::new(())),
            reset_epoch: Arc::new(AtomicU64::new(0)),
            connection_ids: Arc::new(AtomicU64::new(1)),
            command_ids: Arc::new(AtomicU64::new(0)),
            local_slots: Some(cluster_slots_frame()),
            redirection_map: ClusterRedirectionMap::from_mappings([(
                TcpEndpoint {
                    host: "127.0.0.1".to_owned(),
                    port: 7002,
                },
                "127.0.0.1:6382".to_owned(),
            )]),
        };
        let mut client = spawn_proxy_client(target, state, 0);

        client
            .get_mut()
            .write_all(&resp_command(&["GET", "foo"]))
            .await
            .unwrap();

        assert_eq!(
            read_simple_error(&mut client).await,
            "MOVED 12182 127.0.0.1:6382"
        );

        drop(client);
        upstream.await.unwrap();
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn stale_connections_after_reset_do_not_consume_command_ids() {
        let path = unique_socket_path("upstream-stale-reset");
        let upstream_listener = UnixListener::bind(&path).unwrap();
        let upstream = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = upstream_listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let (read, mut write) = tokio::io::split(stream);
                    let mut read = BufReader::new(read);
                    loop {
                        match read_raw_frame(&mut read).await {
                            Ok(command) => {
                                write
                                    .write_all(
                                        &deterministic_upstream_response(
                                            &command,
                                        ),
                                    )
                                    .await
                                    .unwrap();
                            }
                            Err(error)
                                if error.kind() == ErrorKind::UnexpectedEof =>
                            {
                                break;
                            }
                            Err(error) => {
                                panic!(
                                    "failed to read upstream command: {error}"
                                )
                            }
                        }
                    }
                });
            }
        });

        let target = ProxyTarget {
            upstream: Endpoint::Unix(path.clone()),
            listen: Endpoint::Unix(unique_socket_path("unused-listen")),
        };
        let state = SharedState {
            repro: None,
            monitor: monitor_sender(),
            reset_barrier: Arc::new(RwLock::new(())),
            reset_epoch: Arc::new(AtomicU64::new(0)),
            connection_ids: Arc::new(AtomicU64::new(2)),
            command_ids: Arc::new(AtomicU64::new(0)),
            local_slots: None,
            redirection_map: ClusterRedirectionMap::default(),
        };

        let mut stale = spawn_proxy_client(target.clone(), state.clone(), 0);
        let mut current = spawn_proxy_client(target, state.clone(), 1);

        current
            .get_mut()
            .write_all(&resp_command(&["DEBUG", "EVIL", "MODE", "RESET"]))
            .await
            .unwrap();
        assert_eq!(read_raw_frame(&mut current).await.unwrap(), b"+OK\r\n");

        stale
            .get_mut()
            .write_all(&resp_command(&["GET", "key:00"]))
            .await
            .unwrap();
        let stale_read = read_raw_frame(&mut stale).await;

        assert!(matches!(
            stale_read,
            Err(error) if error.kind() == ErrorKind::UnexpectedEof
        ));
        assert_eq!(state.command_ids.load(Ordering::SeqCst), 0);

        drop(stale);
        drop(current);
        upstream.abort();
        let _ = upstream.await;
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn reset_does_not_wait_for_in_flight_upstream_replies() {
        let path = unique_socket_path("upstream-reset-blocked-command");
        let upstream_listener = UnixListener::bind(&path).unwrap();
        let (command_seen_tx, command_seen_rx) =
            tokio::sync::oneshot::channel();
        let upstream = tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (read, _write) = tokio::io::split(stream);
                let mut read = BufReader::new(read);
                read_raw_frame(&mut read).await.unwrap();
                let _ = command_seen_tx.send(());
                std::future::pending::<()>().await;
            });

            loop {
                if upstream_listener.accept().await.is_err() {
                    break;
                }
            }
        });

        let target = ProxyTarget {
            upstream: Endpoint::Unix(path.clone()),
            listen: Endpoint::Unix(unique_socket_path("unused-listen")),
        };
        let state = SharedState {
            repro: None,
            monitor: monitor_sender(),
            reset_barrier: Arc::new(RwLock::new(())),
            reset_epoch: Arc::new(AtomicU64::new(0)),
            connection_ids: Arc::new(AtomicU64::new(0)),
            command_ids: Arc::new(AtomicU64::new(0)),
            local_slots: None,
            redirection_map: ClusterRedirectionMap::default(),
        };

        let mut blocked = spawn_proxy_client(target.clone(), state.clone(), 0);
        blocked
            .get_mut()
            .write_all(&resp_command(&["GET", "blocked"]))
            .await
            .unwrap();
        command_seen_rx.await.unwrap();

        let mut reset_client = spawn_proxy_client(target, state, 1);
        reset_client
            .get_mut()
            .write_all(&resp_command(&["DEBUG", "EVIL", "MODE", "RESET"]))
            .await
            .unwrap();
        let response = tokio::time::timeout(
            Duration::from_secs(1),
            read_raw_frame(&mut reset_client),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(response, b"+OK\r\n");

        drop(blocked);
        drop(reset_client);
        upstream.abort();
        let _ = upstream.await;
        std::fs::remove_file(path).unwrap();
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
            repro: None,
            monitor: monitor_sender(),
            reset_barrier: Arc::new(RwLock::new(())),
            reset_epoch: Arc::new(AtomicU64::new(0)),
            connection_ids: Arc::new(AtomicU64::new(initial_connection_id + 1)),
            command_ids: Arc::new(AtomicU64::new(0)),
            local_slots: None,
            redirection_map: ClusterRedirectionMap::default(),
        };
        let proxy = tokio::spawn(proxy_connection(
            Box::new(server),
            target,
            state,
            initial_connection_id,
            0,
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

    async fn run_two_command_sequence(reconnect: bool) -> Vec<Vec<u8>> {
        let path = unique_socket_path("upstream-reconnect-sequence");
        let upstream_listener = UnixListener::bind(&path).unwrap();
        let upstream = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = upstream_listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let (read, mut write) = tokio::io::split(stream);
                    let mut read = BufReader::new(read);
                    loop {
                        match read_raw_frame(&mut read).await {
                            Ok(command) => {
                                write
                                    .write_all(
                                        &deterministic_upstream_response(
                                            &command,
                                        ),
                                    )
                                    .await
                                    .unwrap();
                            }
                            Err(error)
                                if error.kind() == ErrorKind::UnexpectedEof =>
                            {
                                break;
                            }
                            Err(error) => {
                                panic!(
                                    "failed to read upstream command: {error}"
                                )
                            }
                        }
                    }
                });
            }
        });

        let target = ProxyTarget {
            upstream: Endpoint::Unix(path.clone()),
            listen: Endpoint::Unix(unique_socket_path("unused-listen")),
        };
        let state = SharedState {
            repro: None,
            monitor: monitor_sender(),
            reset_barrier: Arc::new(RwLock::new(())),
            reset_epoch: Arc::new(AtomicU64::new(0)),
            connection_ids: Arc::new(AtomicU64::new(0)),
            command_ids: Arc::new(AtomicU64::new(0)),
            local_slots: None,
            redirection_map: ClusterRedirectionMap::default(),
        };

        let mut first = spawn_proxy_client(target.clone(), state.clone(), 0);
        write_evil_setup(first.get_mut()).await;
        let mut responses = Vec::new();
        responses.push(read_raw_frame(&mut first).await.unwrap());
        responses.push(read_raw_frame(&mut first).await.unwrap());
        responses.push(read_raw_frame(&mut first).await.unwrap());

        first
            .get_mut()
            .write_all(&resp_command(&["GET", "key:00"]))
            .await
            .unwrap();
        responses.push(read_available_response_bytes(&mut first).await);

        if reconnect {
            drop(first);
            let mut second = spawn_proxy_client(target, state, 1);
            second
                .get_mut()
                .write_all(&resp_command(&["GET", "key:01"]))
                .await
                .unwrap();
            responses.push(read_available_response_bytes(&mut second).await);
            drop(second);
        } else {
            first
                .get_mut()
                .write_all(&resp_command(&["GET", "key:01"]))
                .await
                .unwrap();
            responses.push(read_available_response_bytes(&mut first).await);
            drop(first);
        }

        upstream.abort();
        let _ = upstream.await;
        std::fs::remove_file(path).unwrap();

        responses
    }

    async fn run_transaction_reply_proxy_session(
        order: ReplyOrder,
    ) -> Vec<Vec<u8>> {
        let path = unique_socket_path("upstream-transaction-replies");
        let upstream_listener = UnixListener::bind(&path).unwrap();
        let upstream = tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let (read, mut write) = tokio::io::split(stream);
            let mut read = BufReader::new(read);
            let mut queued_commands = Vec::<String>::new();

            loop {
                match read_raw_frame(&mut read).await {
                    Ok(command) => {
                        let command = parse_frame(&command).unwrap();
                        let argv = command.argv_lossy();
                        let response = transaction_upstream_reply(
                            &argv,
                            &mut queued_commands,
                            order,
                        );
                        write.write_all(&response.encode()).await.unwrap();
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

        let target = ProxyTarget {
            upstream: Endpoint::Unix(path.clone()),
            listen: Endpoint::Unix(unique_socket_path("unused-listen")),
        };
        let state = SharedState {
            repro: None,
            monitor: monitor_sender(),
            reset_barrier: Arc::new(RwLock::new(())),
            reset_epoch: Arc::new(AtomicU64::new(0)),
            connection_ids: Arc::new(AtomicU64::new(1)),
            command_ids: Arc::new(AtomicU64::new(0)),
            local_slots: None,
            redirection_map: ClusterRedirectionMap::default(),
        };
        let mut client = spawn_proxy_client(target, state, 0);
        write_evil_setup(client.get_mut()).await;

        for _ in 0..3 {
            assert_eq!(read_raw_frame(&mut client).await.unwrap(), b"+OK\r\n");
        }

        let mut responses = Vec::new();
        for command in transaction_redis_commands() {
            client.get_mut().write_all(&command).await.unwrap();
            responses.push(read_available_response_bytes(&mut client).await);
        }

        drop(client);
        upstream.abort();
        let _ = upstream.await;
        std::fs::remove_file(path).unwrap();

        responses
    }

    #[derive(Clone, Copy)]
    enum ReplyOrder {
        Canonical,
        Scrambled,
    }

    async fn run_unordered_reply_proxy_session(
        order: ReplyOrder,
    ) -> Vec<Vec<u8>> {
        let path = unique_socket_path("upstream-unordered-replies");
        let upstream_listener = UnixListener::bind(&path).unwrap();
        let upstream = tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let (read, mut write) = tokio::io::split(stream);
            let mut read = BufReader::new(read);

            loop {
                match read_raw_frame(&mut read).await {
                    Ok(command) => {
                        let command = parse_frame(&command).unwrap();
                        let argv = command.argv_lossy();
                        write
                            .write_all(
                                &unordered_redis_reply(&argv, order).encode(),
                            )
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

        let target = ProxyTarget {
            upstream: Endpoint::Unix(path.clone()),
            listen: Endpoint::Unix(unique_socket_path("unused-listen")),
        };
        let state = SharedState {
            repro: None,
            monitor: monitor_sender(),
            reset_barrier: Arc::new(RwLock::new(())),
            reset_epoch: Arc::new(AtomicU64::new(0)),
            connection_ids: Arc::new(AtomicU64::new(1)),
            command_ids: Arc::new(AtomicU64::new(0)),
            local_slots: None,
            redirection_map: ClusterRedirectionMap::default(),
        };
        let mut client = spawn_proxy_client(target, state, 0);
        write_evil_setup(client.get_mut()).await;

        for _ in 0..3 {
            assert_eq!(read_raw_frame(&mut client).await.unwrap(), b"+OK\r\n");
        }

        let mut responses = Vec::new();
        for command in unordered_redis_commands() {
            client.get_mut().write_all(&command).await.unwrap();
            responses.push(read_available_response_bytes(&mut client).await);
        }

        drop(client);
        upstream.abort();
        let _ = upstream.await;
        std::fs::remove_file(path).unwrap();

        responses
    }

    fn unordered_redis_commands() -> Vec<Vec<u8>> {
        vec![
            resp_command(&["HGETALL", "hash:key"]),
            resp_command(&["HKEYS", "hash:key"]),
            resp_command(&["HVALS", "hash:key"]),
            resp_command(&["HGET", "hash:key", "field:alpha"]),
            resp_command(&["HEXISTS", "hash:key", "field:beta"]),
            resp_command(&["SMEMBERS", "set:key"]),
            resp_command(&["SINTER", "set:left", "set:right"]),
            resp_command(&["SUNION", "set:left", "set:right"]),
            resp_command(&["SDIFF", "set:left", "set:right"]),
            resp_command(&["SCARD", "set:key"]),
        ]
    }

    fn transaction_redis_commands() -> Vec<Vec<u8>> {
        vec![
            resp_command(&["MULTI"]),
            resp_command(&["SMEMBERS", "set:key"]),
            resp_command(&["HGETALL", "hash:key"]),
            resp_command(&["HKEYS", "hash:key"]),
            resp_command(&["HVALS", "hash:key"]),
            resp_command(&["SINTER", "set:left", "set:right"]),
            resp_command(&["EXEC"]),
        ]
    }

    fn transaction_upstream_reply(
        argv: &[String],
        queued_commands: &mut Vec<String>,
        order: ReplyOrder,
    ) -> Frame {
        match argv[0].to_ascii_uppercase().as_str() {
            "MULTI" => {
                queued_commands.clear();
                Frame::SimpleString("OK".to_owned())
            }
            "EXEC" => {
                let replies = queued_commands
                    .iter()
                    .map(|command| {
                        unordered_redis_reply(
                            std::slice::from_ref(command),
                            order,
                        )
                    })
                    .collect();
                queued_commands.clear();
                Frame::Array(Some(replies))
            }
            command => {
                queued_commands.push(command.to_owned());
                Frame::SimpleString("QUEUED".to_owned())
            }
        }
    }

    fn unordered_redis_reply(argv: &[String], order: ReplyOrder) -> Frame {
        match argv[0].to_ascii_uppercase().as_str() {
            "HGETALL" => {
                let pairs = ordered_values(
                    order,
                    &[
                        ("field:alpha", "value:one"),
                        ("field:beta", "value:two"),
                        ("field:gamma", "value:three"),
                    ],
                );
                let items = pairs
                    .into_iter()
                    .flat_map(|(key, value)| {
                        [bulk_string(key), bulk_string(value)]
                    })
                    .collect();
                Frame::Array(Some(items))
            }
            "HKEYS" => array_reply(ordered_values(
                order,
                &["field:alpha", "field:beta", "field:gamma"],
            )),
            "HVALS" => array_reply(ordered_values(
                order,
                &["value:one", "value:two", "value:three"],
            )),
            "HGET" => bulk_string("value:one"),
            "HEXISTS" => Frame::Integer(1),
            "SMEMBERS" | "SINTER" | "SUNION" | "SDIFF" => {
                array_reply(ordered_values(
                    order,
                    &["member:alpha", "member:beta", "member:gamma"],
                ))
            }
            "SCARD" => Frame::Integer(3),
            command => panic!("unexpected command {command}"),
        }
    }

    fn ordered_values<T: Copy>(order: ReplyOrder, values: &[T; 3]) -> Vec<T> {
        match order {
            ReplyOrder::Canonical => values.to_vec(),
            ReplyOrder::Scrambled => vec![values[2], values[0], values[1]],
        }
    }

    fn array_reply(values: Vec<&str>) -> Frame {
        Frame::Array(Some(values.into_iter().map(bulk_string).collect()))
    }

    fn bulk_string(value: &str) -> Frame {
        Frame::BulkString(Some(value.as_bytes().to_vec()))
    }

    fn cluster_slots_frame() -> Frame {
        parse_frame(
            b"*1\r\n*3\r\n:0\r\n:16383\r\n*2\r\n$9\r\n127.0.0.1\r\n:7000\r\n",
        )
        .unwrap()
    }

    fn spawn_proxy_client(
        target: ProxyTarget,
        state: SharedState,
        connection_id: u64,
    ) -> BufReader<UnixStream> {
        let (client, server) = UnixStream::pair().unwrap();
        let reset_epoch = state.reset_epoch.load(Ordering::SeqCst);
        tokio::spawn(proxy_connection(
            Box::new(server),
            target,
            state,
            connection_id,
            reset_epoch,
        ));

        BufReader::new(client)
    }

    async fn write_evil_setup(client: &mut UnixStream) {
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
                "MUTATE",
                "PROBABILITY",
                "100.0",
            ]))
            .await
            .unwrap();
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
            repro: None,
            monitor: monitor_sender(),
            reset_barrier: Arc::new(RwLock::new(())),
            reset_epoch: Arc::new(AtomicU64::new(0)),
            connection_ids: Arc::new(AtomicU64::new(initial_connection_id + 1)),
            command_ids: Arc::new(AtomicU64::new(0)),
            local_slots: None,
            redirection_map: ClusterRedirectionMap::default(),
        };
        let proxy = tokio::spawn(proxy_connection(
            Box::new(server),
            target,
            state,
            initial_connection_id,
            0,
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
