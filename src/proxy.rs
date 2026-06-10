use std::io::ErrorKind;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};

use crate::cli::Cli;
use crate::cluster::{ProxyTarget, Topology, discover};
use crate::error::{AppError, AppResult};
use crate::evil::{
    EvilConfig, EvilMode, deterministic_hash, mutate_reply, random_reply,
};
use crate::repro::{ReproRecord, ReproWriter};
use crate::resp::{Frame, parse_frame, read_raw_frame};

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
        let listener = TcpListener::bind(target.listen).await?;
        let local_addr = listener.local_addr()?;
        info!(
            listen = %local_addr,
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
    listener: TcpListener,
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
    client: TcpStream,
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
    client: TcpStream,
    target: ProxyTarget,
    state: SharedState,
    connection_id: u64,
) -> AppResult<()> {
    let upstream = TcpStream::connect(target.upstream.connect_addr()).await?;
    let (client_read, mut client_write) = client.into_split();
    let (upstream_read, mut upstream_write) = upstream.into_split();
    let mut client_read = BufReader::new(client_read);
    let mut upstream_read = BufReader::new(upstream_read);
    let mut command_index = 0_u64;

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

        if is_debug_evil(&argv) {
            let response = apply_debug_evil(&state, &argv).await;
            client_write.write_all(&response.encode()).await?;
            command_index += 1;
            continue;
        }

        if is_cluster_slots(&argv)
            && let Some(response) = &state.local_slots
        {
            client_write.write_all(&response.encode()).await?;
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
            client_write.write_all(&mutated.bytes).await?;
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

        client_write.write_all(&response_bytes).await?;
        command_index += 1;
    }
}

async fn apply_debug_evil(state: &SharedState, argv: &[String]) -> Frame {
    let mut config = state.evil.write().await;
    match config.apply_debug_command(argv) {
        Ok(frame) => {
            info!(status = %config.status(), "updated evil configuration");
            frame
        }
        Err(error) => {
            warn!(%error, "rejected DEBUG EVIL command");
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

fn is_debug_evil(argv: &[String]) -> bool {
    argv.len() >= 2
        && argv[0].eq_ignore_ascii_case("DEBUG")
        && argv[1].eq_ignore_ascii_case("EVIL")
}

fn is_cluster_slots(argv: &[String]) -> bool {
    argv.len() >= 2
        && argv[0].eq_ignore_ascii_case("CLUSTER")
        && argv[1].eq_ignore_ascii_case("SLOTS")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_local_commands_case_insensitively() {
        assert!(is_debug_evil(&["debug".to_owned(), "evil".to_owned()]));
        assert!(is_cluster_slots(&[
            "cluster".to_owned(),
            "slots".to_owned()
        ]));
    }
}
