use std::fmt::Write as _;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::sync::{RwLock, broadcast};
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};

use crate::cli::{Cli, Endpoint};
use crate::cluster::{ClusterRedirectionMap, ProxyTarget, Topology, discover};
use crate::cluster_rewrite::{
    is_cluster_nodes, is_cluster_shards, rewrite_cluster_nodes,
    rewrite_cluster_shards,
};
use crate::connection::{ProxyStream, finish_fault};
use crate::error::{AppError, AppResult};
use crate::evil::{
    DebugAction, DebugResult, EvilConfig, EvilMode, MutatedReply,
    canonicalize_reply, canonicalize_transaction_reply, deterministic_hash,
    mutate_reply, random_reply,
};
use crate::protocol_fingerprint::{
    ProtocolDirection, ProtocolFingerprints, parse_debug_protocol,
};
use crate::repro::{ReproRecord, ReproWriter};
use crate::resp::{Frame, parse_frame, read_raw_frame};
use crate::stats::Stats;
use crate::topology_evil::{
    RedirectContext, configured_redirection, maybe_mutate_topology,
    normalize_redirection,
};
use crate::transaction::TransactionCommands;
use crate::transport::{self, DeliveryPlan};

const MONITOR_BUFFER: usize = 1024;

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
    stats: Arc<Stats>,
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
        stats: Arc::new(Stats::default()),
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
        _ = state.stats.report() => Ok(()),
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

        let connection = state.stats.client_connected();
        let target = target.clone();
        let state = state.clone();
        tokio::spawn(async move {
            let _connection = connection;
            handle_connection(
                client,
                target,
                state,
                connection_id,
                reset_epoch,
            )
            .await;
        });
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
    let reset_supported = client.supports_reset();
    let upstream = connect_upstream(&target.upstream).await?;
    let (client_read, mut client_write) = tokio::io::split(client);
    let (upstream_read, mut upstream_write) = tokio::io::split(upstream);
    let mut client_read = BufReader::new(client_read);
    let mut upstream_read = BufReader::new(upstream_read);
    let mut fingerprints = ProtocolFingerprints::new();
    let mut transaction_commands = TransactionCommands::default();
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
            let result = apply_debug_evil(
                &mut config,
                &argv,
                &state.stats,
                reset_supported,
            );
            let response = result.frame.encode();
            if result.action == DebugAction::ResetIncrementingState {
                reset_incrementing_state(&state, &mut reset_epoch).await;
                client_write.write_all(&response).await?;
                fingerprints.reset();
            } else {
                write_client_bytes(
                    &mut client_write,
                    &mut fingerprints,
                    &response,
                )
                .await?;
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

        /* Like CLUSTER SLOTS, the other topology queries name upstream
        nodes; they are answered by the upstream and rewritten to the
        local listeners, outside the mutation pipeline so a client can
        always bootstrap. */
        if state.local_slots.is_some()
            && (is_cluster_shards(&argv) || is_cluster_nodes(&argv))
        {
            publish_monitor_command(&state, connection_id, &command_frame);
            upstream_write.write_all(&command_bytes).await?;
            upstream_write.flush().await?;
            let upstream_frame =
                parse_frame(&read_raw_frame(&mut upstream_read).await?)?;
            let response = if is_cluster_shards(&argv) {
                rewrite_cluster_shards(&upstream_frame, &state.redirection_map)
            } else {
                rewrite_cluster_nodes(&upstream_frame, &state.redirection_map)
            };
            write_client_frame(&mut client_write, &mut fingerprints, &response)
                .await?;
            continue;
        }

        let (command_id, should_mutate, command_hash) = {
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
            (command_id, should_mutate, command_hash)
        };

        publish_monitor_command(&state, connection_id, &command_frame);

        let pre_topology =
            if should_mutate && let Some(local_slots) = &state.local_slots {
                configured_redirection(
                    &config,
                    RedirectContext {
                        command_index: command_id,
                        command_hash: &command_hash,
                        command: &command_frame,
                        upstream_bytes: None,
                        local_slots,
                        listener: target.listen.as_tcp(),
                    },
                )
            } else {
                None
            };
        let transport_enabled = should_mutate && config.transport.enabled();
        let before_plan = if transport_enabled {
            config
                .transport
                .before_plan(config.seed, command_id, &command_hash)
        } else {
            None
        };
        let (upstream_bytes, response, delivery_seed_hash) = if before_plan
            .is_some()
        {
            (
                None,
                MutatedReply {
                    bytes: Vec::new(),
                    mutations: Vec::new(),
                },
                String::new(),
            )
        } else if config.mode == EvilMode::Random && should_mutate {
            let topology = if pre_topology.is_some() {
                pre_topology
            } else if let Some(local_slots) = &state.local_slots {
                maybe_mutate_topology(
                    &config,
                    command_id,
                    &command_hash,
                    &command_frame,
                    None,
                    local_slots,
                )?
            } else {
                None
            };
            let response = match topology {
                Some(mutated) => MutatedReply {
                    bytes: mutated.frame.encode(),
                    mutations: mutated.mutations,
                },
                None => random_reply(&config, command_id, &command_hash),
            };
            (None, response, String::new())
        } else {
            let (upstream_bytes, exec_commands, relay_bytes, topology) =
                if let Some(topology) = pre_topology {
                    (None, None, Vec::new(), Some(topology))
                } else {
                    upstream_write.write_all(&command_bytes).await?;
                    upstream_write.flush().await?;
                    let upstream_bytes =
                        read_raw_frame(&mut upstream_read).await?;
                    let exec_commands =
                        transaction_commands.observe(&argv, &upstream_bytes);
                    let relay_bytes =
                        normalize_cluster_redirection(&upstream_bytes, &state)?;
                    let topology = if should_mutate
                        && let Some(local_slots) = &state.local_slots
                    {
                        if config.topology_redirect.is_some() {
                            configured_redirection(
                                &config,
                                RedirectContext {
                                    command_index: command_id,
                                    command_hash: &command_hash,
                                    command: &command_frame,
                                    upstream_bytes: Some(&relay_bytes),
                                    local_slots,
                                    listener: target.listen.as_tcp(),
                                },
                            )
                        } else {
                            maybe_mutate_topology(
                                &config,
                                command_id,
                                &command_hash,
                                &command_frame,
                                Some(&relay_bytes),
                                local_slots,
                            )?
                        }
                    } else {
                        None
                    };
                    (Some(upstream_bytes), exec_commands, relay_bytes, topology)
                };
            let (base_bytes, mut mutations) = match topology {
                Some(mutated) => (mutated.frame.encode(), mutated.mutations),
                None => (relay_bytes, Vec::new()),
            };
            let mutate_values = should_mutate
                && matches!(config.mode, EvilMode::Mutate | EvilMode::Overflow);
            // Transport uses the same canonical input as RESP mutation,
            // even when it runs alone with MODE OFF. Relay bytes stay intact.
            let canonical = if mutate_values || transport_enabled {
                let frame = parse_frame(&base_bytes)?;
                Some(match exec_commands {
                    Some(commands) => canonicalize_transaction_reply(
                        config.canonicalization,
                        &commands,
                        &frame,
                    ),
                    None => canonicalize_reply(
                        config.canonicalization,
                        command_name.as_deref(),
                        &frame,
                    ),
                })
            } else {
                None
            };
            let seed_hash = canonical
                .as_ref()
                .map(|frame| deterministic_hash(&frame.encode()))
                .unwrap_or_default();
            let bytes = if mutate_values {
                // mutate_values always prepares a canonical frame above.
                let frame =
                    canonical.as_ref().expect("canonical mutation input");
                let mutated = mutate_reply(
                    &config,
                    command_id,
                    &command_hash,
                    &seed_hash,
                    frame,
                );
                mutations.extend(mutated.mutations);
                mutated.bytes
            } else {
                base_bytes
            };
            (upstream_bytes, MutatedReply { bytes, mutations }, seed_hash)
        };

        let plan = if let Some(plan) = before_plan {
            plan
        } else if transport_enabled {
            config.transport.plan(
                config.seed,
                command_id,
                &command_hash,
                &delivery_seed_hash,
                response.bytes.len(),
            )
        } else {
            DeliveryPlan::plain(response.bytes.len())
        };
        let record_needed = !response.mutations.is_empty() || plan.is_fault();
        // Keep the pre-transport response fields unchanged for existing readers.
        let mut record = state.repro.as_ref().map(|_| {
            ReproRecord::new(
                config.seed,
                connection_id,
                command_id,
                &command_bytes,
                upstream_bytes.as_deref(),
                &response.bytes,
                config.mode,
                response.mutations,
            )
        });
        let wire_bytes = plan.wire_bytes(response.bytes);
        let (mut outcome, mut result) = transport::deliver(
            &mut client_write,
            &mut fingerprints,
            &wire_bytes,
            &plan,
        )
        .await;
        if let Some(fault) = &plan.connection_fault {
            if result.is_ok() {
                result = finish_fault(
                    client_read,
                    client_write,
                    &mut fingerprints,
                    fault,
                    &mut outcome,
                )
                .await;
            } else {
                drop(client_read);
                drop(client_write);
            }
            record_delivery(&state, record.take(), &plan, &wire_bytes, outcome)
                .await;
            return result.map_err(Into::into);
        }
        // Persist successful delivery and partial failures before consuming
        // another command index.
        if record_needed || result.is_err() {
            record_delivery(&state, record.take(), &plan, &wire_bytes, outcome)
                .await;
        }
        result?;
        if plan.truncate_at.is_some() {
            return Ok(());
        }
    }
}

fn normalize_cluster_redirection(
    upstream_bytes: &[u8],
    state: &SharedState,
) -> AppResult<Vec<u8>> {
    if state.local_slots.is_none()
        || !matches!(upstream_bytes.first(), Some(b'-' | b'!'))
    {
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

fn apply_debug_evil(
    config: &mut EvilConfig,
    argv: &[String],
    stats: &Stats,
    reset_supported: bool,
) -> DebugResult {
    let previous_transport = config.transport.clone();
    let result = config.apply_debug_command(argv).and_then(|result| {
        if config.transport.requires_tcp() && !reset_supported {
            config.transport = previous_transport;
            Err(AppError::EvilConfig(
                "FAULT RESET requires a TCP client connection".to_owned(),
            ))
        } else {
            Ok(result)
        }
    });
    match result {
        Ok(result) => {
            // Successful parsing guarantees a subcommand is present.
            if argv[2].eq_ignore_ascii_case("STATUS") {
                stats.status_read();
            } else {
                stats.configuration_updated();
                if result.action == DebugAction::ResetIncrementingState {
                    stats.reset();
                } else if argv[2].eq_ignore_ascii_case("MODE") {
                    stats.mode_selected(config.mode);
                }
                debug!(status = %config.status(), "updated evil configuration");
            }
            result
        }
        Err(error) => {
            stats.command_rejected();
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
            debug!(?argv, "rejected DEBUG PROTOCOL command arguments");
            Frame::SimpleError(format!("ERR {error}"))
        }
    }
}

async fn record_delivery(
    state: &SharedState,
    record: Option<ReproRecord>,
    plan: &DeliveryPlan,
    wire_bytes: &[u8],
    outcome: transport::DeliveryOutcome,
) {
    if let Some(mut record) = record {
        record.planned_wire_bytes_hex = Some(hex::encode(wire_bytes));
        record.delivery_plan = Some(plan.clone());
        record.delivery_outcome = Some(outcome);
        write_repro(state, record).await;
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
    transport::write_counted(writer, fingerprints, bytes, &mut 0).await?;
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
    use tokio::io::AsyncRead;

    static SOCKET_ID: AtomicUsize = AtomicUsize::new(0);

    #[derive(Clone, Default)]
    struct LogBuffer(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for LogBuffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn evil_configuration_updates_are_logged_only_when_verbose() {
        for level in [tracing::Level::INFO, tracing::Level::DEBUG] {
            let buffer = LogBuffer::default();
            let writer = buffer.clone();
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(level)
                .without_time()
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish();
            tracing::subscriber::with_default(subscriber, || {
                let mut config = EvilConfig::default();
                let stats = Stats::default();
                let argv =
                    ["DEBUG", "EVIL", "MODE", "MUTATE"].map(str::to_owned);
                let result = apply_debug_evil(&mut config, &argv, &stats, true);
                assert_eq!(result.frame.encode(), b"+OK\r\n");
                let log = String::from_utf8(buffer.0.lock().unwrap().clone())
                    .unwrap();
                if level == tracing::Level::INFO {
                    assert!(log.is_empty(), "{log}");
                } else {
                    assert!(log.contains("updated evil configuration"));
                    assert!(log.contains("status=mode=MUTATE"));
                }

                buffer.0.lock().unwrap().clear();
                let argv = ["DEBUG", "EVIL", "STATUS"].map(str::to_owned);
                apply_debug_evil(&mut config, &argv, &stats, true);
                assert!(buffer.0.lock().unwrap().is_empty());
            });
        }
    }

    #[tokio::test(start_paused = true)]
    async fn periodic_stats_count_updates_modes_and_rejections_across_reset() {
        use std::future::Future;
        use std::task::{Context, Waker};

        let state = SharedState {
            stats: Arc::new(Stats::default()),
            repro: None,
            monitor: monitor_sender(),
            reset_barrier: Arc::new(RwLock::new(())),
            reset_epoch: Arc::new(AtomicU64::new(0)),
            connection_ids: Arc::new(AtomicU64::new(2)),
            command_ids: Arc::new(AtomicU64::new(23)),
            local_slots: None,
            redirection_map: ClusterRedirectionMap::default(),
        };
        let buffer = LogBuffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .with_max_level(tracing::Level::INFO)
            .without_time()
            .with_writer(move || writer.clone())
            .finish();
        let dispatch = tracing::Dispatch::new(subscriber);
        let connection = state.stats.client_connected();
        drop(state.stats.client_connected());

        let mut config = EvilConfig::default();
        let mut epoch = 0;
        for args in [
            "MODE OFF",
            "mode random",
            "MODE MUTATE",
            "MODE MUTATE",
            "MODE OVERFLOW",
            "SEED 42",
            "SEED 42",
            "STATUS",
            "status",
            "MODE INVALID",
            "MODE MUTATE PROBABILITY 101",
            "STATUS EXTRA",
            "MODE RESET",
        ] {
            let argv = format!("DEBUG EVIL {args}")
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            let result = tracing::dispatcher::with_default(&dispatch, || {
                apply_debug_evil(&mut config, &argv, &state.stats, true)
            });
            if args == "MODE RESET" {
                assert_eq!(result.action, DebugAction::ResetIncrementingState);
                reset_incrementing_state(&state, &mut epoch).await;
            }
        }
        assert_eq!(epoch, 1);
        assert_eq!(state.command_ids.load(Ordering::SeqCst), 0);
        assert_eq!(config.mode, EvilMode::Off);
        let logs = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        assert_eq!(logs.lines().count(), 3);
        assert!(logs.lines().all(|line| {
            let event: serde_json::Value = serde_json::from_str(line).unwrap();
            event["level"] == "WARN"
                && event["message"] == "rejected DEBUG EVIL command"
        }));
        buffer.0.lock().unwrap().clear();

        let mut report = std::pin::pin!(state.stats.report());
        let mut poll_report = || {
            tracing::dispatcher::with_default(&dispatch, || {
                assert!(
                    report
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
            });
        };
        poll_report();
        tokio::time::advance(Duration::from_millis(999)).await;
        poll_report();
        assert!(buffer.0.lock().unwrap().is_empty());
        tokio::time::advance(Duration::from_millis(1)).await;
        poll_report();

        let logs = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        assert_eq!(logs.lines().count(), 1);
        let event: serde_json::Value =
            serde_json::from_str(logs.trim()).unwrap();
        assert_eq!(event["level"], "INFO");
        assert_eq!(event["message"], "proxy statistics");
        for (field, expected) in [
            ("clients_total", 2),
            ("clients_active", 1),
            ("evil_updates", 8),
            ("evil_status_reads", 2),
            ("evil_rejected", 3),
            ("evil_resets", 1),
            ("mode_off", 1),
            ("mode_random", 1),
            ("mode_mutate", 2),
            ("mode_overflow", 1),
        ] {
            assert_eq!(event[field], expected, "{field}");
        }

        // A delayed reporter emits one summary, without catch-up bursts.
        drop(connection);
        tokio::time::advance(Duration::from_secs(5)).await;
        poll_report();
        poll_report();
        let logs = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        assert_eq!(logs.lines().count(), 2);
        let event: serde_json::Value =
            serde_json::from_str(logs.lines().last().unwrap()).unwrap();
        assert_eq!(event["clients_total"], 2);
        assert_eq!(event["clients_active"], 0);
        assert_eq!(event["evil_updates"], 8);
    }

    #[test]
    fn rejected_debug_protocol_logs_full_arguments_only_when_verbose() {
        for level in [
            tracing::Level::INFO,
            tracing::Level::DEBUG,
            tracing::Level::TRACE,
        ] {
            for (args, error_detail) in [
                (
                    vec!["DEBUG", "PROTOCOL"],
                    Some("missing protocol direction"),
                ),
                (
                    vec!["DEBUG", "PROTOCOL", "IN"],
                    Some("missing protocol hash"),
                ),
                (
                    vec!["DEBUG", "PROTOCOL", "SIDEWAYS"],
                    Some(
                        "unknown protocol direction \"SIDEWAYS\"; expected <IN|OUT>",
                    ),
                ),
                (
                    vec!["DEBUG", "PROTOCOL", "IN", "SHA256"],
                    Some(
                        "unknown protocol hash \"SHA256\"; expected <BLAKE3|TLSH>",
                    ),
                ),
                (
                    vec!["DEBUG", "PROTOCOL", "IN", "BLAKE3", "", "a\n\"b"],
                    Some("unexpected argument \"\""),
                ),
                (vec!["DEBUG", "PROTOCOL", "IN", "BLAKE3"], None),
            ] {
                let argv: Vec<String> =
                    args.into_iter().map(str::to_owned).collect();
                let buffer = LogBuffer::default();
                let writer = buffer.clone();
                let subscriber = tracing_subscriber::fmt()
                    .with_max_level(level)
                    .without_time()
                    .with_ansi(false)
                    .with_writer(move || writer.clone())
                    .finish();
                let response =
                    tracing::subscriber::with_default(subscriber, || {
                        apply_debug_protocol(
                            &ProtocolFingerprints::new(),
                            &argv,
                        )
                    });
                let log = String::from_utf8(buffer.0.lock().unwrap().clone())
                    .unwrap();
                if let Some(error_detail) = error_detail {
                    let Frame::SimpleError(error) = response else {
                        panic!("expected an error response");
                    };
                    assert!(error.contains(error_detail), "{error}");
                    assert!(log.contains(error_detail), "{log}");
                    assert!(log.contains("rejected DEBUG PROTOCOL command"));
                    if level == tracing::Level::INFO {
                        assert!(!log.contains("argv="));
                        assert!(!log.contains("a\\n\\\"b"));
                    } else {
                        assert!(log.contains(&format!("argv={argv:?}")));
                    }
                } else {
                    assert_eq!(
                        response,
                        Frame::BulkString(Some(blake3_hex(b"").into_bytes()))
                    );
                    assert!(log.is_empty());
                }
            }
        }
    }

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
            stats: Arc::new(Stats::default()),
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
            stats: Arc::new(Stats::default()),
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
            stats: Arc::new(Stats::default()),
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
            stats: Arc::new(Stats::default()),
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
            &state.stats,
            true,
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
            stats: Arc::new(Stats::default()),
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
        for args in [
            ["DEBUG", "EVIL", "STRATEGY", "REPLACE"],
            ["DEBUG", "EVIL", "MUTATIONS", "ONE"],
            ["DEBUG", "EVIL", "FRAMING", "OFF"],
        ] {
            first
                .get_mut()
                .write_all(&resp_command(&args))
                .await
                .unwrap();
            assert_eq!(read_raw_frame(&mut first).await.unwrap(), b"+OK\r\n");
        }
        first
            .get_mut()
            .write_all(&resp_command(&[
                "DEBUG",
                "EVIL",
                "GENERATOR",
                "PROTOCOL",
                "RESP3",
                "CORPUS",
                "RANDOM",
                "VIOLATIONS",
                "ON",
            ]))
            .await
            .unwrap();
        assert_eq!(read_raw_frame(&mut first).await.unwrap(), b"+OK\r\n");
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
        assert!(first_status.contains("strategy=REPLACE mutations=ONE"));
        assert!(first_status.contains("framing=OFF"));
        assert!(first_status.contains("generator_protocol=RESP3 generator_corpus=RANDOM generator_violations=ON"));

        transport_setup(
            &mut first,
            &["DEBUG", "EVIL", "TRANSPORT", "TRUNCATE", "0"],
        )
        .await;
        first
            .get_mut()
            .write_all(&resp_command(&["DEBUG", "EVIL", "STATUS"]))
            .await
            .unwrap();
        let status =
            String::from_utf8(read_raw_frame(&mut first).await.unwrap())
                .unwrap();
        assert!(status.contains("transport=ON"));

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
        assert!(second_status.contains("strategy=PRESERVE mutations=MANY"));
        assert!(second_status.contains("framing=AUTO"));
        assert!(second_status.contains("transport=OFF"));
        assert!(second_status.contains("generator_protocol=RESP2 generator_corpus=BOUNDARY generator_violations=OFF"));

        drop(first);
        drop(second);
        upstream.abort();
        let _ = upstream.await;
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn single_mutation_preserves_nested_wire_reply_and_next_command() {
        let path = unique_socket_path("upstream-single-mutation");
        let listener = UnixListener::bind(&path).unwrap();
        let upstream = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = tokio::io::split(stream);
            let mut read = BufReader::new(read);
            // Local mutation controls must never arrive upstream.
            assert_eq!(
                read_raw_frame(&mut read).await.unwrap(),
                resp_command(&["LRANGE", "key", "0", "-1"])
            );
            write
                .write_all(b"*2\r\n_\r\n*1\r\n:9223372036854775807\r\n")
                .await
                .unwrap();
            assert_eq!(
                read_raw_frame(&mut read).await.unwrap(),
                resp_command(&["PING"])
            );
            write.write_all(b"+PONG\r\n").await.unwrap();
        });
        let (client, server) = UnixStream::pair().unwrap();
        let target = ProxyTarget {
            upstream: Endpoint::Unix(path.clone()),
            listen: Endpoint::Unix(unique_socket_path("unused-listen")),
        };
        let state = SharedState {
            stats: Arc::new(Stats::default()),
            repro: None,
            monitor: monitor_sender(),
            reset_barrier: Arc::new(RwLock::new(())),
            reset_epoch: Arc::new(AtomicU64::new(0)),
            connection_ids: Arc::new(AtomicU64::new(0)),
            command_ids: Arc::new(AtomicU64::new(0)),
            local_slots: None,
            redirection_map: ClusterRedirectionMap::default(),
        };
        let command_ids = state.command_ids.clone();
        let proxy = tokio::spawn(proxy_connection(
            Box::new(server),
            target,
            state,
            0,
            0,
        ));
        let mut client = BufReader::new(client);
        for args in [
            ["DEBUG", "EVIL", "MODE", "OVERFLOW"],
            ["DEBUG", "EVIL", "STRATEGY", "PRESERVE"],
            ["DEBUG", "EVIL", "MUTATIONS", "ONE"],
        ] {
            client
                .get_mut()
                .write_all(&resp_command(&args))
                .await
                .unwrap();
            assert_eq!(read_raw_frame(&mut client).await.unwrap(), b"+OK\r\n");
        }
        assert_eq!(command_ids.load(Ordering::SeqCst), 0);
        client
            .get_mut()
            .write_all(&resp_command(&["LRANGE", "key", "0", "-1"]))
            .await
            .unwrap();
        assert_eq!(
            read_raw_frame(&mut client).await.unwrap(),
            b"*2\r\n_\r\n*1\r\n:-9223372036854775808\r\n"
        );
        client
            .get_mut()
            .write_all(&resp_command(&["DEBUG", "EVIL", "MODE", "OFF"]))
            .await
            .unwrap();
        assert_eq!(read_raw_frame(&mut client).await.unwrap(), b"+OK\r\n");
        client
            .get_mut()
            .write_all(&resp_command(&["PING"]))
            .await
            .unwrap();
        assert_eq!(read_raw_frame(&mut client).await.unwrap(), b"+PONG\r\n");
        assert_eq!(command_ids.load(Ordering::SeqCst), 2);
        drop(client);
        proxy.await.unwrap().unwrap();
        upstream.await.unwrap();
        std::fs::remove_file(path).unwrap();
    }

    fn transport_test_state(repro: ReproWriter) -> SharedState {
        SharedState {
            stats: Arc::new(Stats::default()),
            repro: Some(repro),
            monitor: monitor_sender(),
            reset_barrier: Arc::new(RwLock::new(())),
            reset_epoch: Arc::new(AtomicU64::new(0)),
            connection_ids: Arc::new(AtomicU64::new(0)),
            command_ids: Arc::new(AtomicU64::new(0)),
            local_slots: None,
            redirection_map: ClusterRedirectionMap::default(),
        }
    }

    async fn transport_setup(
        client: &mut BufReader<UnixStream>,
        args: &[&str],
    ) {
        client
            .get_mut()
            .write_all(&resp_command(args))
            .await
            .unwrap();
        assert_eq!(read_raw_frame(client).await.unwrap(), b"+OK\r\n");
    }

    #[tokio::test]
    async fn transport_truncation_records_repeatable_eof_and_stops_pipeline() {
        use tokio::io::AsyncReadExt;
        let path = unique_socket_path("transport-truncate");
        let repro_path = path.with_extension("jsonl");
        let listener = UnixListener::bind(&path).unwrap();
        let upstream = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                assert_eq!(
                    read_raw_frame(&mut stream).await.unwrap(),
                    resp_command(&["GET", "one"])
                );
                stream.get_mut().write_all(b"$3\r\nfoo\r\n").await.unwrap();
                // The second pipelined command must never be forwarded.
                assert_eq!(
                    stream.read_u8().await.unwrap_err().kind(),
                    ErrorKind::UnexpectedEof
                );
            }
        });
        for connection_id in [7, 99] {
            let state = transport_test_state(
                ReproWriter::open(&repro_path).await.unwrap(),
            );
            let ids = state.command_ids.clone();
            let (client, server) = UnixStream::pair().unwrap();
            let proxy = tokio::spawn(proxy_connection(
                Box::new(server),
                ProxyTarget {
                    upstream: Endpoint::Unix(path.clone()),
                    listen: Endpoint::Unix(unique_socket_path("unused")),
                },
                state,
                connection_id,
                0,
            ));
            let mut client = BufReader::new(client);
            transport_setup(
                &mut client,
                &[
                    "DEBUG",
                    "EVIL",
                    "TRANSPORT",
                    "TRUNCATE",
                    "6",
                    "CHUNKS",
                    "RANDOM",
                ],
            )
            .await;
            // RESET preserves the plan, and local replies cannot be truncated.
            transport_setup(&mut client, &["DEBUG", "EVIL", "MODE", "RESET"])
                .await;
            assert_eq!(ids.load(Ordering::SeqCst), 0);
            let pipeline =
                [resp_command(&["GET", "one"]), resp_command(&["GET", "two"])]
                    .concat();
            client.get_mut().write_all(&pipeline).await.unwrap();
            let mut bytes = Vec::new();
            // EOF must arrive from the proxy without a client-side shutdown.
            client.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, b"$3\r\nfo");
            proxy.await.unwrap().unwrap();
            assert_eq!(ids.load(Ordering::SeqCst), 1);
        }
        upstream.await.unwrap();
        let records = std::fs::read_to_string(&repro_path)
            .unwrap()
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["delivery_plan"], records[1]["delivery_plan"]);
        assert_eq!(
            records[0]["delivery_outcome"],
            records[1]["delivery_outcome"]
        );
        for record in records {
            assert_eq!(
                record["mutated_response_bytes_hex"],
                hex::encode(b"$3\r\nfoo\r\n")
            );
            assert_eq!(
                record["planned_wire_bytes_hex"],
                hex::encode(b"$3\r\nfo")
            );
            assert_eq!(record["delivery_plan"]["truncate_at"], 6);
            assert_eq!(record["delivery_outcome"]["bytes_written"], 6);
            assert_eq!(record["delivery_outcome"]["shutdown_completed"], true);
            assert_eq!(
                record["delivery_outcome"]["written_bytes_hash"],
                deterministic_hash(b"$3\r\nfo")
            );
            assert_eq!(
                record["delivery_outcome"]["error_kind"],
                serde_json::Value::Null
            );
            assert_eq!(record["mutations"], serde_json::json!([]));
        }
        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(repro_path).unwrap();
    }

    #[tokio::test]
    async fn transport_extra_replies_keep_connection_and_fingerprints_consistent()
     {
        let path = unique_socket_path("transport-extra");
        let repro_path = path.with_extension("jsonl");
        let listener = UnixListener::bind(&path).unwrap();
        let upstream = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            for (command, response) in [
                (&["GET", "one"][..], &b"+OK\r\n"[..]),
                (&["GET", "two"][..], &b"+OK\r\n"[..]),
                (&["PING"][..], &b"+PONG\r\n"[..]),
                (&["HELLO"][..], &b"+OK\r\n"[..]),
            ] {
                assert_eq!(
                    read_raw_frame(&mut stream).await.unwrap(),
                    resp_command(command)
                );
                stream.get_mut().write_all(response).await.unwrap();
            }
        });
        let state =
            transport_test_state(ReproWriter::open(&repro_path).await.unwrap());
        let ids = state.command_ids.clone();
        let (client, server) = UnixStream::pair().unwrap();
        let proxy = tokio::spawn(proxy_connection(
            Box::new(server),
            ProxyTarget {
                upstream: Endpoint::Unix(path.clone()),
                listen: Endpoint::Unix(unique_socket_path("unused")),
            },
            state,
            3,
            0,
        ));
        let mut client = BufReader::new(client);
        transport_setup(
            &mut client,
            &["DEBUG", "EVIL", "INCLUDE", "GET", "HELLO"],
        )
        .await;
        transport_setup(
            &mut client,
            &["DEBUG", "EVIL", "TRANSPORT", "EXTRA", "2", "CHUNKS", "1,3"],
        )
        .await;
        let mut output = b"+OK\r\n+OK\r\n".to_vec();
        for key in ["one", "two"] {
            client
                .get_mut()
                .write_all(&resp_command(&["GET", key]))
                .await
                .unwrap();
            for expected in
                [b"+OK\r\n".as_slice(), b"+EVILRESP\r\n", b"+EVILRESP\r\n"]
            {
                let bytes = read_raw_frame(&mut client).await.unwrap();
                assert_eq!(bytes, expected);
                output.extend(bytes);
            }
        }
        // Include and default exclude filters both protect non-target traffic.
        for (args, expected) in [
            (&["PING"][..], b"+PONG\r\n".as_slice()),
            (&["HELLO"][..], b"+OK\r\n"),
        ] {
            client
                .get_mut()
                .write_all(&resp_command(args))
                .await
                .unwrap();
            let bytes = read_raw_frame(&mut client).await.unwrap();
            assert_eq!(bytes, expected);
            output.extend(bytes);
        }
        client
            .get_mut()
            .write_all(&resp_command(&["DEBUG", "PROTOCOL", "OUT", "BLAKE3"]))
            .await
            .unwrap();
        assert_eq!(
            parse_frame(&read_raw_frame(&mut client).await.unwrap()).unwrap(),
            Frame::BulkString(Some(blake3_hex(&output).into_bytes()))
        );
        drop(client);
        proxy.await.unwrap().unwrap();
        upstream.await.unwrap();
        assert_eq!(ids.load(Ordering::SeqCst), 4);
        let records = std::fs::read_to_string(&repro_path)
            .unwrap()
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 2);
        for record in records {
            assert_eq!(record["delivery_plan"]["extra_reply_count"], 2);
            assert_eq!(
                record["delivery_plan"]["chunk_ends"],
                serde_json::json!([1, 3, 27])
            );
            assert_eq!(
                record["planned_wire_bytes_hex"],
                hex::encode(b"+OK\r\n+EVILRESP\r\n+EVILRESP\r\n")
            );
            assert_eq!(record["delivery_outcome"]["bytes_written"], 27);
            assert_eq!(record["delivery_outcome"]["shutdown_completed"], false);
        }
        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(repro_path).unwrap();
    }

    #[tokio::test]
    async fn framing_only_mutation_records_exact_wire_bytes_across_connections()
    {
        let path = unique_socket_path("upstream-framing-only");
        let repro_path = path.with_extension("jsonl");
        let listener = UnixListener::bind(&path).unwrap();
        let upstream = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                let (read, mut write) = tokio::io::split(stream);
                let mut read = BufReader::new(read);
                // All DEBUG settings stay local and the command is unchanged.
                assert_eq!(
                    read_raw_frame(&mut read).await.unwrap(),
                    resp_command(&["LRANGE", "key", "0", "-1"])
                );
                write
                    .write_all(b"*2\r\n+before\r\n*1\r\n$3\r\nfoo\r\n")
                    .await
                    .unwrap();
            }
        });
        let expected = b"*2\r\n+before\r\n*1\r\n$2\r\nfoo\r\n";
        for connection_id in [7, 99] {
            let (client, server) = UnixStream::pair().unwrap();
            let target = ProxyTarget {
                upstream: Endpoint::Unix(path.clone()),
                listen: Endpoint::Unix(unique_socket_path("unused-listen")),
            };
            let state = SharedState {
                stats: Arc::new(Stats::default()),
                repro: Some(ReproWriter::open(&repro_path).await.unwrap()),
                monitor: monitor_sender(),
                reset_barrier: Arc::new(RwLock::new(())),
                reset_epoch: Arc::new(AtomicU64::new(0)),
                connection_ids: Arc::new(AtomicU64::new(0)),
                command_ids: Arc::new(AtomicU64::new(0)),
                local_slots: None,
                redirection_map: ClusterRedirectionMap::default(),
            };
            let command_ids = state.command_ids.clone();
            let proxy = tokio::spawn(proxy_connection(
                Box::new(server),
                target,
                state,
                connection_id,
                0,
            ));
            let mut client = BufReader::new(client);
            for args in [
                &["DEBUG", "EVIL", "MODE", "MUTATE", "PROBABILITY", "0"][..],
                &["DEBUG", "EVIL", "MUTATIONS", "ONE"],
                &[
                    "DEBUG",
                    "EVIL",
                    "FRAMING",
                    "LENGTH",
                    "TARGET",
                    "root.1.0",
                    "KIND",
                    "SHORTER",
                    "PROBABILITY",
                    "100",
                ],
            ] {
                client
                    .get_mut()
                    .write_all(&resp_command(args))
                    .await
                    .unwrap();
                assert_eq!(
                    read_raw_frame(&mut client).await.unwrap(),
                    b"+OK\r\n"
                );
            }
            assert_eq!(command_ids.load(Ordering::SeqCst), 0);
            client
                .get_mut()
                .write_all(&resp_command(&["LRANGE", "key", "0", "-1"]))
                .await
                .unwrap();
            client.get_mut().shutdown().await.unwrap();
            // Read malformed output as raw bytes through EOF, without timing.
            let mut response = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut client, &mut response)
                .await
                .unwrap();
            assert_eq!(response, expected);
            proxy.await.unwrap().unwrap();
            assert_eq!(command_ids.load(Ordering::SeqCst), 1);
        }
        upstream.await.unwrap();
        let records = std::fs::read_to_string(&repro_path).unwrap();
        let records = records
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 2);
        for (record, connection_id) in records.iter().zip([7, 99]) {
            assert_eq!(record["connection_id"], connection_id);
            assert_eq!(record["command_index"], 0);
            assert_eq!(
                record["mutated_response_bytes_hex"],
                hex::encode(expected)
            );
            assert_eq!(
                record["mutations"],
                serde_json::json!([{
                    "path": "root.1.0", "kind": "wrong_length",
                    "length": {"kind": "shorter", "original": "3", "replacement": "2"},
                }])
            );
        }
        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(repro_path).unwrap();
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
            stats: Arc::new(Stats::default()),
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

    async fn topology_request<S>(
        client: &mut BufReader<S>,
        args: &[&str],
    ) -> Vec<u8>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        client
            .get_mut()
            .write_all(&resp_command(args))
            .await
            .unwrap();
        read_raw_frame(client).await.unwrap()
    }

    #[tokio::test]
    async fn connection_failures_control_execution_reset_and_stop_pipelines() {
        use tokio::io::AsyncReadExt;

        const REPLY: &[u8] = b"$5\r\nvalue\r\n";
        for action in ["CLOSE", "RESET"] {
            for point in ["BEFORE", "AFTER", "REPLY", "3", "RANDOM"] {
                let path = unique_socket_path("connection-fault");
                let repro_path = unique_socket_path("connection-fault-repro");
                let upstream_listener = UnixListener::bind(&path).unwrap();
                let upstream = tokio::spawn(async move {
                    let (stream, _) = upstream_listener.accept().await.unwrap();
                    let (read, mut write) = tokio::io::split(stream);
                    let mut read = BufReader::new(read);
                    let mut commands = 0;
                    while let Ok(bytes) = read_raw_frame(&mut read).await {
                        assert_eq!(bytes, resp_command(&["GET", "foo"]));
                        commands += 1;
                        write.write_all(REPLY).await.unwrap();
                    }
                    commands
                });
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let socket = TcpStream::connect(listener.local_addr().unwrap())
                    .await
                    .unwrap();
                let (server, _) = listener.accept().await.unwrap();
                let target = ProxyTarget {
                    upstream: Endpoint::Unix(path.clone()),
                    listen: Endpoint::Tcp(
                        listener
                            .local_addr()
                            .unwrap()
                            .to_string()
                            .parse()
                            .unwrap(),
                    ),
                };
                let state = transport_test_state(
                    ReproWriter::open(&repro_path).await.unwrap(),
                );
                let indexes = state.command_ids.clone();
                let proxy = tokio::spawn(proxy_connection(
                    Box::new(server),
                    target,
                    state,
                    99,
                    0,
                ));
                let mut client = BufReader::new(socket);
                assert_eq!(
                    topology_request(
                        &mut client,
                        &[
                            "DEBUG",
                            "EVIL",
                            "TRANSPORT",
                            "FAULT",
                            action,
                            "AT",
                            point,
                        ]
                    )
                    .await,
                    b"+OK\r\n"
                );
                client
                    .get_mut()
                    .write_all(
                        &[
                            resp_command(&["GET", "foo"]),
                            resp_command(&["GET", "foo"]),
                        ]
                        .concat(),
                    )
                    .await
                    .unwrap();
                let mut received = Vec::new();
                let result = client.read_to_end(&mut received).await;
                if action == "RESET" {
                    assert_eq!(
                        result.unwrap_err().kind(),
                        ErrorKind::ConnectionReset
                    );
                } else {
                    result.unwrap();
                }
                proxy.await.unwrap().unwrap();
                assert_eq!(
                    upstream.await.unwrap(),
                    usize::from(point != "BEFORE")
                );
                assert_eq!(indexes.load(Ordering::SeqCst), 1);
                let records = std::fs::read_to_string(&repro_path).unwrap();
                assert_eq!(records.lines().count(), 1);
                let record: serde_json::Value =
                    serde_json::from_str(records.trim()).unwrap();
                let fault = &record["delivery_plan"]["connection_fault"];
                assert_eq!(record["delivery_plan"]["version"], 2);
                assert_eq!(fault["action"], action.to_ascii_lowercase());
                assert!(fault["duration_ms"].is_null());
                let after_bytes =
                    fault["after_bytes"].as_u64().unwrap() as usize;
                match point {
                    "BEFORE" | "AFTER" => assert_eq!(after_bytes, 0),
                    "REPLY" => assert_eq!(after_bytes, REPLY.len()),
                    "3" => assert_eq!(after_bytes, 3),
                    _ => assert!(after_bytes < REPLY.len()),
                }
                let planned = &REPLY[..after_bytes];
                assert!(planned.starts_with(&received));
                if action == "CLOSE" {
                    assert_eq!(received, planned);
                }
                assert_eq!(
                    record["planned_wire_bytes_hex"],
                    hex::encode(planned)
                );
                assert_eq!(
                    record["delivery_outcome"]["bytes_written"],
                    after_bytes
                );
                assert_eq!(
                    record["delivery_outcome"]["written_bytes_hash"],
                    deterministic_hash(planned)
                );
                assert_eq!(record["delivery_outcome"]["fault_completed"], true);
                assert_eq!(
                    record["delivery_outcome"]["shutdown_completed"],
                    action == "CLOSE"
                );
                assert!(record["delivery_outcome"]["error_stage"].is_null());
                assert_eq!(
                    record["upstream_response_bytes_hex"].is_null(),
                    point == "BEFORE"
                );
                assert_eq!(
                    record["mutated_response_bytes_hex"],
                    hex::encode(if point == "BEFORE" { b"" } else { REPLY })
                );
                std::fs::remove_file(path).unwrap();
                std::fs::remove_file(repro_path).unwrap();
            }
        }
    }

    #[test]
    fn reset_fault_is_rejected_atomically_on_unix_connections() {
        let mut config = EvilConfig::default();
        let stats = Stats::default();
        let before = config.status();
        let result = apply_debug_evil(
            &mut config,
            &[
                "DEBUG",
                "EVIL",
                "TRANSPORT",
                "FAULT",
                "RESET",
                "AT",
                "BEFORE",
            ]
            .map(str::to_owned),
            &stats,
            false,
        );
        assert_eq!(result.frame.encode(), b"-ERR invalid evil configuration: FAULT RESET requires a TCP client connection\r\n");
        assert_eq!(config.status(), before);
    }

    #[tokio::test]
    async fn opted_in_stall_records_peer_close_and_never_processes_pipeline() {
        for point in ["BEFORE", "AFTER"] {
            let path = unique_socket_path("stall");
            let repro_path = unique_socket_path("stall-repro");
            let listener = UnixListener::bind(&path).unwrap();
            let upstream = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let (read, mut write) = tokio::io::split(stream);
                let mut read = BufReader::new(read);
                let mut commands = 0;
                while let Ok(bytes) = read_raw_frame(&mut read).await {
                    assert_eq!(bytes, resp_command(&["GET", "foo"]));
                    commands += 1;
                    write.write_all(b"+OK\r\n").await.unwrap();
                }
                commands
            });
            let target = ProxyTarget {
                upstream: Endpoint::Unix(path.clone()),
                listen: Endpoint::Unix(unique_socket_path("unused")),
            };
            let state = transport_test_state(
                ReproWriter::open(&repro_path).await.unwrap(),
            );
            let indexes = state.command_ids.clone();
            let (client, server) = UnixStream::pair().unwrap();
            let proxy = tokio::spawn(proxy_connection(
                Box::new(server),
                target,
                state,
                1,
                0,
            ));
            let mut client = BufReader::new(client);
            assert_eq!(
                topology_request(
                    &mut client,
                    &[
                        "DEBUG",
                        "EVIL",
                        "TRANSPORT",
                        "FAULT",
                        "STALL",
                        "AT",
                        point,
                        "DURATION",
                        "3600000",
                    ]
                )
                .await,
                b"+OK\r\n"
            );
            client
                .get_mut()
                .write_all(
                    &[
                        resp_command(&["GET", "foo"]),
                        resp_command(&["GET", "foo"]),
                    ]
                    .concat(),
                )
                .await
                .unwrap();
            // EOF terminates the stall without waiting for its deadline.
            drop(client);
            proxy.await.unwrap().unwrap();
            assert_eq!(upstream.await.unwrap(), usize::from(point == "AFTER"));
            assert_eq!(indexes.load(Ordering::SeqCst), 1);
            let text = std::fs::read_to_string(&repro_path).unwrap();
            assert_eq!(text.lines().count(), 1);
            let record: serde_json::Value =
                serde_json::from_str(text.trim()).unwrap();
            assert_eq!(
                record["delivery_plan"]["connection_fault"]["action"],
                "stall"
            );
            assert_eq!(
                record["delivery_plan"]["connection_fault"]["duration_ms"],
                3_600_000
            );
            assert_eq!(record["delivery_outcome"]["stall_end"], "peer_closed");
            assert_eq!(record["delivery_outcome"]["fault_completed"], true);
            assert_eq!(record["delivery_outcome"]["bytes_written"], 0);
            assert_eq!(record["planned_wire_bytes_hex"], "");
            std::fs::remove_file(path).unwrap();
            std::fs::remove_file(repro_path).unwrap();
        }
    }

    #[tokio::test]
    async fn focused_topology_phases_control_execution_and_repro_records() {
        for phase in ["BEFORE", "AFTER"] {
            let path = unique_socket_path("topology-phase");
            let repro_path = unique_socket_path("topology-phase-repro");
            let listener = UnixListener::bind(&path).unwrap();
            let upstream = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let (read, mut write) = tokio::io::split(stream);
                let mut read = BufReader::new(read);
                let mut writes = 0;
                while let Ok(bytes) = read_raw_frame(&mut read).await {
                    // Local configuration must never leak upstream.
                    assert_eq!(bytes, resp_command(&["INCR", "foo"]));
                    writes += 1;
                    write.write_all(b":1\r\n").await.unwrap();
                }
                writes
            });
            let target = ProxyTarget {
                upstream: Endpoint::Unix(path.clone()),
                listen: Endpoint::Unix(unique_socket_path("unused")),
            };
            let mut state = transport_test_state(
                ReproWriter::open(&repro_path).await.unwrap(),
            );
            state.local_slots = Some(cluster_slots_frame());
            let (client, server) = UnixStream::pair().unwrap();
            let proxy = tokio::spawn(proxy_connection(
                Box::new(server),
                target,
                state,
                1,
                0,
            ));
            let mut client = BufReader::new(client);
            assert_eq!(
                topology_request(
                    &mut client,
                    &[
                        "DEBUG",
                        "EVIL",
                        "TOPOLOGY",
                        "REDIRECT",
                        "KIND",
                        "ASK",
                        "TARGET",
                        "missing.invalid:7999",
                        "PHASE",
                        phase,
                    ]
                )
                .await,
                b"+OK\r\n"
            );
            assert_eq!(
                topology_request(&mut client, &["INCR", "foo"]).await,
                b"-ASK 12182 missing.invalid:7999\r\n"
            );

            // A rejected update must leave the configured fault in place.
            assert!(
                topology_request(
                    &mut client,
                    &[
                        "DEBUG", "EVIL", "TOPOLOGY", "REDIRECT", "KIND",
                        "INVALID",
                    ]
                )
                .await
                .starts_with(b"-ERR ")
            );
            assert_eq!(
                topology_request(&mut client, &["INCR", "foo"]).await,
                b"-ASK 12182 missing.invalid:7999\r\n"
            );
            assert_eq!(
                topology_request(
                    &mut client,
                    &["DEBUG", "EVIL", "TOPOLOGY", "OFF"]
                )
                .await,
                b"+OK\r\n"
            );
            assert_eq!(
                topology_request(&mut client, &["INCR", "foo"]).await,
                b":1\r\n"
            );
            drop(client);
            proxy.await.unwrap().unwrap();
            assert_eq!(
                upstream.await.unwrap(),
                if phase == "BEFORE" { 1 } else { 3 }
            );
            let records = std::fs::read_to_string(&repro_path).unwrap();
            let records: Vec<serde_json::Value> = records
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            assert_eq!(records.len(), 2);
            for (index, record) in records.iter().enumerate() {
                assert_eq!(record["command_index"], index);
                assert_eq!(record["selected_evil_mode"], "OFF");
                assert_eq!(
                    record["mutations"][0]["kind"],
                    format!("topology_redirect_{}", phase.to_ascii_lowercase())
                );
                assert_eq!(
                    record["mutated_response_bytes_hex"],
                    hex::encode(b"-ASK 12182 missing.invalid:7999\r\n")
                );
                assert_eq!(
                    record["upstream_response_bytes_hex"].is_null(),
                    phase == "BEFORE"
                );
                if phase == "AFTER" {
                    assert_eq!(
                        record["upstream_response_bytes_hex"],
                        hex::encode(b":1\r\n")
                    );
                }
            }
            std::fs::remove_file(path).unwrap();
            std::fs::remove_file(repro_path).unwrap();
        }
    }

    #[tokio::test]
    async fn topology_bounces_across_listeners_recovers_and_replays_after_reset()
     {
        let upstream_path = unique_socket_path("topology-bounce");
        let upstream_listener = UnixListener::bind(&upstream_path).unwrap();
        let (seen, mut requests) = tokio::sync::mpsc::unbounded_channel();
        let upstream = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            // Two connections per run, with two replay runs.
            for _ in 0..4 {
                let (stream, _) = upstream_listener.accept().await.unwrap();
                let seen = seen.clone();
                connections.spawn(async move {
                    let (read, mut write) = tokio::io::split(stream);
                    let mut read = BufReader::new(read);
                    while let Ok(bytes) = read_raw_frame(&mut read).await {
                        seen.send(bytes).unwrap();
                        write.write_all(b":1\r\n").await.unwrap();
                    }
                });
            }
            while let Some(result) = connections.join_next().await {
                result.unwrap();
            }
        });
        let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addresses =
            [first.local_addr().unwrap(), second.local_addr().unwrap()];
        let node = |address: std::net::SocketAddr| {
            Frame::Array(Some(vec![
                bulk_string(&address.ip().to_string()),
                Frame::Integer(i64::from(address.port())),
            ]))
        };
        let slots = Frame::Array(Some(vec![
            Frame::Array(Some(vec![
                Frame::Integer(0),
                Frame::Integer(8191),
                node(addresses[0]),
            ])),
            Frame::Array(Some(vec![
                Frame::Integer(8192),
                Frame::Integer(16383),
                node(addresses[1]),
            ])),
        ]));
        let state = SharedState {
            stats: Arc::new(Stats::default()),
            repro: None,
            monitor: monitor_sender(),
            reset_barrier: Arc::new(RwLock::new(())),
            reset_epoch: Arc::new(AtomicU64::new(0)),
            connection_ids: Arc::new(AtomicU64::new(0)),
            command_ids: Arc::new(AtomicU64::new(0)),
            local_slots: Some(slots.clone()),
            redirection_map: ClusterRedirectionMap::default(),
        };
        let mut listeners = JoinSet::new();
        for (index, listener) in [first, second].into_iter().enumerate() {
            listeners.spawn(serve_listener(
                ProxyListener::Tcp(listener),
                ProxyTarget {
                    listen: Endpoint::Tcp(
                        addresses[index].to_string().parse().unwrap(),
                    ),
                    upstream: Endpoint::Unix(upstream_path.clone()),
                },
                state.clone(),
            ));
        }
        let mut previous = None;
        for _ in 0..2 {
            let mut first =
                BufReader::new(TcpStream::connect(addresses[0]).await.unwrap());
            assert_eq!(
                topology_request(
                    &mut first,
                    &["DEBUG", "EVIL", "MODE", "RESET"]
                )
                .await,
                b"+OK\r\n"
            );
            let second =
                BufReader::new(TcpStream::connect(addresses[1]).await.unwrap());
            let mut clients = [first, second];
            for client in &mut clients {
                assert_eq!(
                    topology_request(
                        client,
                        &[
                            "DEBUG", "EVIL", "TOPOLOGY", "REDIRECT", "TARGET",
                            "NEXT", "UNTIL", "3",
                        ]
                    )
                    .await,
                    b"+OK\r\n"
                );
                assert_eq!(
                    topology_request(client, &["CLUSTER", "SLOTS"]).await,
                    slots.encode()
                );
            }
            assert_eq!(state.command_ids.load(Ordering::SeqCst), 0);
            let mut output = Vec::new();
            for index in 0..4 {
                let response =
                    topology_request(&mut clients[index % 2], &["INCR", "foo"])
                        .await;
                if index < 3 {
                    assert_eq!(
                        response,
                        format!(
                            "-MOVED 12182 {}\r\n",
                            addresses[(index + 1) % 2]
                        )
                        .as_bytes()
                    );
                    assert!(requests.try_recv().is_err());
                } else {
                    assert_eq!(response, b":1\r\n");
                    assert_eq!(
                        requests.recv().await.unwrap(),
                        resp_command(&["INCR", "foo"])
                    );
                }
                output.extend(response);
            }
            assert_eq!(state.command_ids.load(Ordering::SeqCst), 4);
            if let Some(previous) = &previous {
                assert_eq!(&output, previous);
            }
            previous = Some(output);
        }
        upstream.await.unwrap();
        listeners.abort_all();
        while let Some(result) = listeners.join_next().await {
            assert!(result.unwrap_err().is_cancelled());
        }
        std::fs::remove_file(upstream_path).unwrap();
    }

    #[tokio::test]
    async fn upstream_redirections_are_rewritten_to_proxy_ports() {
        assert_redirection_reply(
            "OFF",
            "7002",
            b"-MOVED 12182 127.0.0.1:6382\r\n",
        )
        .await;
    }

    #[tokio::test]
    async fn zero_probability_mutation_preserves_rewritten_redirections() {
        for mode in ["MUTATE", "OVERFLOW"] {
            assert_redirection_reply(
                mode,
                "7002",
                b"-MOVED 12182 127.0.0.1:6382\r\n",
            )
            .await;
        }
    }

    #[tokio::test]
    async fn unmapped_redirections_do_not_expose_upstream_endpoints() {
        assert_redirection_reply(
            "OFF",
            "7999",
            b"-ERR evilresp has no local listener for redirection target\r\n",
        )
        .await;
    }

    async fn assert_redirection_reply(
        mode: &str,
        upstream_port: &str,
        expected: &[u8],
    ) {
        let path = unique_socket_path("upstream-real-redirection");
        let upstream_listener = UnixListener::bind(&path).unwrap();
        let reply = format!("-MOVED 12182 127.0.0.1:{upstream_port}\r\n");
        let upstream = tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let (read, mut write) = tokio::io::split(stream);
            let mut read = BufReader::new(read);
            assert_eq!(
                read_raw_frame(&mut read).await.unwrap(),
                resp_command(&["GET", "foo"])
            );
            write.write_all(reply.as_bytes()).await.unwrap();
        });

        let target = ProxyTarget {
            upstream: Endpoint::Unix(path.clone()),
            listen: Endpoint::Unix(unique_socket_path("unused-listen")),
        };
        let state = SharedState {
            stats: Arc::new(Stats::default()),
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
            .write_all(&resp_command(&[
                "DEBUG",
                "EVIL",
                "MODE",
                mode,
                "PROBABILITY",
                "0",
            ]))
            .await
            .unwrap();
        assert_eq!(read_raw_frame(&mut client).await.unwrap(), b"+OK\r\n");
        client
            .get_mut()
            .write_all(&resp_command(&["GET", "foo"]))
            .await
            .unwrap();

        assert_eq!(read_raw_frame(&mut client).await.unwrap(), expected);

        drop(client);
        upstream.await.unwrap();
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn discovered_replica_listener_proxies_reads_and_topology() {
        let primary = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let replica = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_replica = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let primary_addr = primary.local_addr().unwrap();
        let replica_addr = replica.local_addr().unwrap();
        let local_replica_addr = local_replica.local_addr().unwrap();
        // Reserve the replica listener before discovery; only its preceding
        // port is used for the primary mapping, with no fixed ports or rebind.
        let mut local_primary_addr = local_replica_addr;
        local_primary_addr.set_port(local_replica_addr.port() - 1);
        let slots = Frame::Array(Some(vec![Frame::Array(Some(vec![
            Frame::Integer(0),
            Frame::Integer(16383),
            Frame::Array(Some(vec![
                bulk_string("127.0.0.1"),
                Frame::Integer(i64::from(primary_addr.port())),
                bulk_string("primary"),
            ])),
            Frame::Array(Some(vec![
                bulk_string("127.0.0.1"),
                Frame::Integer(i64::from(replica_addr.port())),
                bulk_string("replica"),
            ])),
        ]))]));
        let probe = tokio::spawn(async move {
            let (stream, _) = primary.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            assert_eq!(
                read_raw_frame(&mut stream).await.unwrap(),
                resp_command(&["CLUSTER", "SLOTS"])
            );
            stream.get_mut().write_all(&slots.encode()).await.unwrap();
        });
        let topology = discover(
            primary_addr.to_string().parse().unwrap(),
            local_primary_addr.to_string().parse().unwrap(),
        )
        .await
        .unwrap();
        probe.await.unwrap();
        assert_eq!(topology.targets().len(), 2);
        let target = topology.targets()[1].clone();
        assert_eq!(target.upstream.to_string(), replica_addr.to_string());
        assert_eq!(target.listen.to_string(), local_replica_addr.to_string());

        let shard_reply = |port| {
            Frame::Array(Some(vec![Frame::Map(vec![
                (
                    bulk_string("slots"),
                    Frame::Array(Some(vec![
                        Frame::Integer(0),
                        Frame::Integer(16383),
                    ])),
                ),
                (
                    bulk_string("nodes"),
                    Frame::Array(Some(vec![Frame::Map(vec![
                        (bulk_string("id"), bulk_string("replica")),
                        (bulk_string("ip"), bulk_string("127.0.0.1")),
                        (bulk_string("port"), Frame::Integer(i64::from(port))),
                        (bulk_string("role"), bulk_string("replica")),
                    ])])),
                ),
            ])]))
        };
        let upstream_shards = shard_reply(replica_addr.port());
        let local_shards = shard_reply(local_replica_addr.port());
        let nodes_reply = |addr| {
            bulk_string(&format!(
                "replica {addr}@16379 myself,slave primary 0 0 1 connected\n"
            ))
        };
        let upstream_nodes = nodes_reply(replica_addr);
        let local_nodes = nodes_reply(local_replica_addr);
        let upstream = tokio::spawn(async move {
            let (stream, _) = replica.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            for (command, response) in [
                (vec!["CLUSTER", "SHARDS"], upstream_shards),
                (vec!["CLUSTER", "NODES"], upstream_nodes),
                (vec!["READONLY"], Frame::SimpleString("OK".to_owned())),
                (vec!["GET", "foo"], bulk_string("replica-value")),
                (vec!["READWRITE"], Frame::SimpleString("OK".to_owned())),
                (
                    vec!["GET", "foo"],
                    Frame::SimpleError(format!("MOVED 12182 {primary_addr}")),
                ),
            ] {
                assert_eq!(
                    read_raw_frame(&mut stream).await.unwrap(),
                    resp_command(&command)
                );
                stream
                    .get_mut()
                    .write_all(&response.encode())
                    .await
                    .unwrap();
            }
        });
        let state = SharedState {
            stats: Arc::new(Stats::default()),
            repro: None,
            monitor: monitor_sender(),
            reset_barrier: Arc::new(RwLock::new(())),
            reset_epoch: Arc::new(AtomicU64::new(0)),
            connection_ids: Arc::new(AtomicU64::new(0)),
            command_ids: Arc::new(AtomicU64::new(0)),
            local_slots: topology.local_slots_response(),
            redirection_map: topology.local_redirection_map(),
        };
        let server = tokio::spawn(serve_listener(
            ProxyListener::Tcp(local_replica),
            target,
            state.clone(),
        ));
        let mut client = BufReader::new(
            TcpStream::connect(local_replica_addr).await.unwrap(),
        );
        client
            .get_mut()
            .write_all(&resp_command(&["DEBUG", "EVIL", "MODE", "RANDOM"]))
            .await
            .unwrap();
        assert_eq!(read_raw_frame(&mut client).await.unwrap(), b"+OK\r\n");
        for (subcommand, expected) in [
            ("SLOTS", state.local_slots.clone().unwrap()),
            ("SHARDS", local_shards),
            ("NODES", local_nodes),
        ] {
            client
                .get_mut()
                .write_all(&resp_command(&["CLUSTER", subcommand]))
                .await
                .unwrap();
            assert_eq!(
                read_raw_frame(&mut client).await.unwrap(),
                expected.encode()
            );
        }
        assert_eq!(state.command_ids.load(Ordering::SeqCst), 0);
        client
            .get_mut()
            .write_all(&resp_command(&["DEBUG", "EVIL", "MODE", "OFF"]))
            .await
            .unwrap();
        assert_eq!(read_raw_frame(&mut client).await.unwrap(), b"+OK\r\n");
        for (command, expected) in [
            (vec!["READONLY"], b"+OK\r\n".to_vec()),
            (vec!["GET", "foo"], bulk_string("replica-value").encode()),
            (vec!["READWRITE"], b"+OK\r\n".to_vec()),
            (
                vec!["GET", "foo"],
                format!("-MOVED 12182 {local_primary_addr}\r\n").into_bytes(),
            ),
        ] {
            client
                .get_mut()
                .write_all(&resp_command(&command))
                .await
                .unwrap();
            assert_eq!(read_raw_frame(&mut client).await.unwrap(), expected);
        }
        assert_eq!(state.command_ids.load(Ordering::SeqCst), 4);
        drop(client);
        upstream.await.unwrap();
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn cluster_shards_replies_are_rewritten_to_proxy_ports() {
        let path = unique_socket_path("upstream-cluster-shards");
        let upstream_listener = UnixListener::bind(&path).unwrap();
        let upstream = tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let (read, mut write) = tokio::io::split(stream);
            let mut read = BufReader::new(read);
            assert_eq!(
                read_raw_frame(&mut read).await.unwrap(),
                resp_command(&["CLUSTER", "SHARDS"])
            );
            /* One shard, RESP3 shape: a primary with a local listener and a
            replica without one. */
            write
                .write_all(
                    b"*1\r\n%2\r\n$5\r\nslots\r\n*2\r\n:0\r\n:16383\r\n$5\r\nnodes\r\n*2\r\n\
                      %4\r\n$2\r\nid\r\n$1\r\na\r\n$4\r\nport\r\n:7002\r\n$2\r\nip\r\n$9\r\n127.0.0.1\r\n$4\r\nrole\r\n$6\r\nmaster\r\n\
                      %4\r\n$2\r\nid\r\n$1\r\nb\r\n$4\r\nport\r\n:7003\r\n$2\r\nip\r\n$9\r\n127.0.0.1\r\n$4\r\nrole\r\n$7\r\nreplica\r\n",
                )
                .await
                .unwrap();
            /* The command that follows must still reach the upstream: the
            topology query consumed no command id and left the connection
            in step. */
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
            stats: Arc::new(Stats::default()),
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
        let mut client = spawn_proxy_client(target, state.clone(), 0);
        transport_setup(
            &mut client,
            &["DEBUG", "EVIL", "TRANSPORT", "TRUNCATE", "0"],
        )
        .await;
        client
            .get_mut()
            .write_all(&resp_command(&["CLUSTER", "SLOTS"]))
            .await
            .unwrap();
        assert_eq!(
            read_raw_frame(&mut client).await.unwrap(),
            cluster_slots_frame().encode()
        );

        client
            .get_mut()
            .write_all(&resp_command(&["CLUSTER", "SHARDS"]))
            .await
            .unwrap();
        assert_eq!(
            read_raw_frame(&mut client).await.unwrap(),
            b"*1\r\n%2\r\n$5\r\nslots\r\n*2\r\n:0\r\n:16383\r\n$5\r\nnodes\r\n*1\r\n\
              %4\r\n$2\r\nid\r\n$1\r\na\r\n$4\r\nport\r\n:6382\r\n$2\r\nip\r\n$9\r\n127.0.0.1\r\n$4\r\nrole\r\n$6\r\nmaster\r\n"
        );
        assert_eq!(state.command_ids.load(Ordering::SeqCst), 0);
        transport_setup(&mut client, &["DEBUG", "EVIL", "TRANSPORT", "OFF"])
            .await;

        client
            .get_mut()
            .write_all(&resp_command(&["GET", "foo"]))
            .await
            .unwrap();
        assert_eq!(
            read_raw_frame(&mut client).await.unwrap(),
            bulk_string("value").encode()
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
            stats: Arc::new(Stats::default()),
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
            stats: Arc::new(Stats::default()),
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
            stats: Arc::new(Stats::default()),
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
            stats: Arc::new(Stats::default()),
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
            stats: Arc::new(Stats::default()),
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
            stats: Arc::new(Stats::default()),
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
            stats: Arc::new(Stats::default()),
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
