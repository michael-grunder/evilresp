//! Runtime for `DEBUG EVIL CLUSTER`: the process-wide simulated topology
//! and each client connection's view of it.
//!
//! Unlike other evil settings, the active scenario is global: a cluster
//! client opens its own connections to every listener, and they must all
//! agree on one topology. The scenario's stage is selected by the shared
//! command index, so it restarts after `DEBUG EVIL MODE RESET`.
//!
//! Commands a simulated node accepts execute on the real upstream primary
//! that owns the key's slot, whichever listener received them.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use tokio::io::AsyncWrite;
use tracing::{debug, info};

use crate::cli::{Endpoint, TcpEndpoint};
use crate::cluster_sim_render::{
    RenderContext, cluster_info, cluster_myid, cluster_myshardid,
    cluster_nodes, cluster_shards, cluster_slots,
};
use crate::cluster_sim_route::{Decision, RouteRequest, route};
use crate::cluster_sim_timeline::{SimConfig, Timeline};
use crate::command_keys::{CommandInfo, CommandTable, Keys, parse_getkeys};
use crate::error::{AppError, AppResult};
use crate::push::PushDelivery;
use crate::resp::{Frame, parse_frame};
use crate::upstream_connection::{
    Exchange, UNAVAILABLE_REPLY, UpstreamConnection,
};

const REAL_OWNER_UNAVAILABLE: &[u8] =
    b"-ERR evilresp cluster simulation could not reach the real slot owner\r\n";
const MAX_REAL_REDIRECTS: usize = 2;

/// Real upstream ownership of one slot range, from startup discovery.
#[derive(Clone, Debug)]
pub(crate) struct RealRange {
    pub start: u16,
    pub end: u16,
    pub primary: TcpEndpoint,
}

struct Active {
    timeline: Timeline,
    commands: Arc<CommandTable>,
}

pub(crate) struct ClusterSim {
    /// Listener address of each virtual node, in listener order.
    addresses: Vec<SocketAddr>,
    real_primaries: usize,
    real_ranges: Vec<RealRange>,
    active: RwLock<Option<Arc<Active>>>,
    commands: Mutex<Option<Arc<CommandTable>>>,
    logged_stage: AtomicUsize,
}

impl ClusterSim {
    pub(crate) fn new(
        addresses: Vec<SocketAddr>,
        real_primaries: usize,
        mut real_ranges: Vec<RealRange>,
    ) -> Self {
        real_ranges.sort_by_key(|range| range.start);
        Self {
            addresses,
            real_primaries,
            real_ranges,
            active: RwLock::new(None),
            commands: Mutex::new(None),
            logged_stage: AtomicUsize::new(usize::MAX),
        }
    }

    pub(crate) fn node_for(&self, listen: &Endpoint) -> Option<usize> {
        let listen =
            listen.as_tcp()?.connect_addr().parse::<SocketAddr>().ok()?;
        self.addresses.iter().position(|address| *address == listen)
    }

    fn active(&self) -> Option<Arc<Active>> {
        // A poisoned lock only means another task panicked mid-update.
        self.active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn set_active(&self, active: Option<Arc<Active>>) {
        *self
            .active
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = active;
        self.logged_stage.store(usize::MAX, Ordering::SeqCst);
    }

    fn stage(&self, active: &Active, command_index: u64) -> usize {
        let stage = active.timeline.stage_index(command_index);
        if self.logged_stage.swap(stage, Ordering::SeqCst) != stage {
            info!(
                stage,
                command_index,
                label = %active.timeline.stages[stage].label,
                "cluster simulation stage"
            );
        }
        stage
    }

    fn real_owner(&self, slot: u16) -> Option<&TcpEndpoint> {
        let index = self.real_ranges.partition_point(|r| r.end < slot);
        self.real_ranges
            .get(index)
            .filter(|range| range.start <= slot)
            .map(|range| &range.primary)
    }

    /// Handle `DEBUG EVIL CLUSTER ...`. The command table is loaded once
    /// through the configuring connection's upstream.
    pub(crate) async fn apply_debug<W: AsyncWrite + Unpin>(
        &self,
        argv: &[String],
        default_seed: u64,
        next_index: u64,
        upstream: &mut UpstreamConnection,
        push: &mut PushDelivery<'_, W>,
    ) -> AppResult<Frame> {
        let Some(subcommand) = argv.get(3) else {
            return Err(invalid("CLUSTER expects OFF|STATUS|SCENARIO"));
        };
        match subcommand.to_ascii_uppercase().as_str() {
            "OFF" if argv.len() == 4 => {
                self.set_active(None);
                Ok(ok())
            }
            "STATUS" if argv.len() == 4 => Ok(Frame::BulkString(Some(
                self.status(next_index).into_bytes(),
            ))),
            "SCENARIO" => {
                let config = SimConfig::parse(&argv[4..], default_seed)?;
                let timeline = Timeline::build(
                    config,
                    self.addresses.len(),
                    self.real_primaries,
                )?;
                let commands = self.command_table(upstream, push).await?;
                self.set_active(Some(Arc::new(Active { timeline, commands })));
                Ok(ok())
            }
            "OFF" | "STATUS" => Err(invalid(&format!(
                "CLUSTER {subcommand} accepts no options"
            ))),
            _ => Err(invalid("CLUSTER expects OFF|STATUS|SCENARIO")),
        }
    }

    async fn command_table<W: AsyncWrite + Unpin>(
        &self,
        upstream: &mut UpstreamConnection,
        push: &mut PushDelivery<'_, W>,
    ) -> AppResult<Arc<CommandTable>> {
        if let Some(table) = self.cached_commands() {
            return Ok(table);
        }
        let command = encode_command(&[b"COMMAND".to_vec()]);
        let table =
            exchange_reply(upstream, &command, &["COMMAND".to_owned()], push)
                .await?
                .and_then(|bytes| parse_frame(&bytes).ok())
                .and_then(|frame| CommandTable::parse(&frame));
        let Some(table) = table else {
            debug!(
                "COMMAND unavailable; cluster simulation uses COMMAND GETKEYS"
            );
            return Ok(Arc::new(CommandTable::default()));
        };
        let table = Arc::new(table);
        *self
            .commands
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some(table.clone());
        Ok(table)
    }

    fn cached_commands(&self) -> Option<Arc<CommandTable>> {
        self.commands
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn status(&self, next_index: u64) -> String {
        let Some(active) = self.active() else {
            return "cluster=OFF".to_owned();
        };
        let timeline = &active.timeline;
        let stage = timeline.stage_index(next_index);
        let next = if stage + 1 < timeline.stages.len() {
            timeline.stage_start(stage + 1).to_string()
        } else {
            "OFF".to_owned()
        };
        format!(
            "{} cluster_nodes={} cluster_stage={stage} cluster_stages={} cluster_next_stage_index={next} cluster_stage_label=\"{}\"",
            timeline.config.status(&timeline.layout),
            timeline.layout.nodes,
            timeline.stages.len(),
            timeline.stages[stage].label,
        )
    }
}

fn ok() -> Frame {
    Frame::SimpleString("OK".to_owned())
}

fn invalid(message: &str) -> AppError {
    AppError::EvilConfig(message.to_owned())
}

fn encode_command(argv: &[Vec<u8>]) -> Vec<u8> {
    Frame::Array(Some(
        argv.iter()
            .map(|arg| Frame::BulkString(Some(arg.clone())))
            .collect(),
    ))
    .encode()
}

/// Binary-safe argument vector; `None` for non-command frames.
fn raw_argv(frame: &Frame) -> Option<Vec<Vec<u8>>> {
    match frame {
        Frame::Array(Some(items)) => items
            .iter()
            .map(|item| match item {
                Frame::BulkString(Some(bytes))
                | Frame::VerbatimString(bytes) => Some(bytes.clone()),
                Frame::SimpleString(value) => Some(value.as_bytes().to_vec()),
                _ => None,
            })
            .collect(),
        Frame::Inline(parts) => Some(parts.clone()),
        _ => None,
    }
}

fn error_bytes(message: &str) -> Vec<u8> {
    Frame::SimpleError(message.to_owned()).encode()
}

/// What the proxy does with a command after the simulation saw it.
pub(crate) enum SimOutcome {
    Reply(Vec<u8>),
    /// The simulated node is down: close without replying.
    Close,
}

struct Queued {
    bytes: Vec<u8>,
    argv: Vec<String>,
    keys: Vec<Vec<u8>>,
    write: bool,
    loading: bool,
}

struct Transaction {
    queued: Vec<Queued>,
    dirty: bool,
}

pub(crate) struct SimConnection {
    node: Option<usize>,
    connection_id: u64,
    readonly: bool,
    asking: bool,
    resp3: bool,
    transaction: Option<Transaction>,
    /// Upstream sessions to real slot owners other than this listener's.
    backing: BTreeMap<String, UpstreamConnection>,
    /// Successful `AUTH`/`HELLO` commands, replayed on new backing sessions.
    prelude: Vec<Vec<u8>>,
}

pub(crate) struct ExchangeContext<'a, 'p, W> {
    pub sim: &'a ClusterSim,
    pub own_upstream: &'a Endpoint,
    pub upstream: &'a mut UpstreamConnection,
    pub command_index: u64,
    pub push: &'a mut PushDelivery<'p, W>,
}

impl SimConnection {
    pub(crate) fn new(
        sim: Option<&ClusterSim>,
        listen: &Endpoint,
        connection_id: u64,
    ) -> Self {
        Self {
            node: sim.and_then(|sim| sim.node_for(listen)),
            connection_id,
            readonly: false,
            asking: false,
            resp3: false,
            transaction: None,
            backing: BTreeMap::new(),
            prelude: Vec::new(),
        }
    }

    /// Answer a topology query from the simulated view. `None` means the
    /// simulation is inactive or the command is not a simulated query.
    pub(crate) fn topology_reply(
        &self,
        sim: &ClusterSim,
        argv: &[String],
        next_index: u64,
    ) -> Option<SimOutcome> {
        let node = self.node?;
        if argv.len() != 2 || !argv[0].eq_ignore_ascii_case("CLUSTER") {
            return None;
        }
        let active = sim.active()?;
        let subcommand = argv[1].to_ascii_uppercase();
        if !matches!(
            subcommand.as_str(),
            "SLOTS" | "SHARDS" | "NODES" | "INFO" | "MYID" | "MYSHARDID"
        ) {
            return None;
        }
        let stage = sim.stage(&active, next_index);
        if active.timeline.authoritative(stage).nodes[node].down {
            return Some(SimOutcome::Close);
        }
        let view = active.timeline.view(stage, node);
        let ctx = RenderContext {
            timeline: &active.timeline,
            addresses: &sim.addresses,
            resp3: self.resp3,
            stage,
            node,
        };
        let frame = match subcommand.as_str() {
            "SLOTS" => cluster_slots(&view, &ctx),
            "SHARDS" => cluster_shards(&view, &ctx),
            "NODES" => cluster_nodes(&view, &ctx),
            "INFO" => cluster_info(&view, &ctx),
            "MYID" => cluster_myid(&ctx),
            _ => cluster_myshardid(&view, &ctx),
        };
        Some(SimOutcome::Reply(frame.encode()))
    }

    /// Run one ordinary command through the simulation. `None` means the
    /// simulation is inactive and the caller forwards normally.
    pub(crate) async fn exchange<W: AsyncWrite + Unpin>(
        &mut self,
        mut ctx: ExchangeContext<'_, '_, W>,
        frame: &Frame,
        bytes: &[u8],
        argv: &[String],
    ) -> Option<AppResult<SimOutcome>> {
        let node = self.node?;
        let Some(active) = ctx.sim.active() else {
            // Leaving simulation discards simulated transaction state.
            self.transaction = None;
            self.asking = false;
            return None;
        };
        let stage = ctx.sim.stage(&active, ctx.command_index);
        let raw = raw_argv(frame).unwrap_or_default();
        let name = argv
            .first()
            .map(|name| name.to_ascii_uppercase())
            .unwrap_or_default();
        let asking = std::mem::take(&mut self.asking);
        let local = |reply: &str| {
            Some(Ok(SimOutcome::Reply(reply.as_bytes().to_vec())))
        };
        if active.timeline.authoritative(stage).nodes[node].down {
            return Some(Ok(SimOutcome::Close));
        }
        match (name.as_str(), self.transaction.is_some()) {
            ("READONLY", false) => {
                self.readonly = true;
                return local("+OK\r\n");
            }
            ("READWRITE", false) => {
                self.readonly = false;
                return local("+OK\r\n");
            }
            ("ASKING", _) => {
                self.asking = true;
                return local("+OK\r\n");
            }
            ("MULTI", true) => {
                return local("-ERR MULTI calls can not be nested\r\n");
            }
            ("MULTI", false) => {
                self.transaction = Some(Transaction {
                    queued: Vec::new(),
                    dirty: false,
                });
                return local("+OK\r\n");
            }
            ("DISCARD", true) => {
                self.transaction = None;
                return local("+OK\r\n");
            }
            ("EXEC", true) => {
                let transaction = self.transaction.take()?;
                return Some(
                    self.exec(&mut ctx, &active, stage, node, transaction)
                        .await,
                );
            }
            _ => {}
        }

        let info = active.commands.lookup(&raw).cloned();
        if info.as_ref().is_some_and(|info| info.pubsub) {
            return None;
        }
        let keys = match self.keys(&mut ctx, info.as_ref(), &raw).await {
            Ok(Some(keys)) => keys,
            Ok(None) => {
                return Some(Ok(SimOutcome::Reply(UNAVAILABLE_REPLY.to_vec())));
            }
            Err(error) => return Some(Err(error)),
        };
        let write = info.as_ref().is_none_or(|info| info.write);
        let loading = info.as_ref().is_some_and(|info| info.loading);
        let request = RouteRequest {
            keys: &keys,
            write,
            allowed_while_loading: loading,
            readonly: self.readonly,
            asking,
        };
        let decision =
            route(&active.timeline, stage, node, &ctx.sim.addresses, &request);

        if let Some(transaction) = &mut self.transaction {
            return Some(Ok(match decision {
                Decision::Close => SimOutcome::Close,
                Decision::Error(error) => {
                    transaction.dirty = true;
                    SimOutcome::Reply(error_bytes(&error))
                }
                Decision::Serve { .. } => {
                    transaction.queued.push(Queued {
                        bytes: bytes.to_vec(),
                        argv: argv.to_vec(),
                        keys,
                        write,
                        loading,
                    });
                    SimOutcome::Reply(b"+QUEUED\r\n".to_vec())
                }
            }));
        }

        Some(match decision {
            Decision::Close => Ok(SimOutcome::Close),
            Decision::Error(error) => {
                Ok(SimOutcome::Reply(error_bytes(&error)))
            }
            Decision::Serve { slot } => {
                let reply = self.forward(&mut ctx, slot, bytes, argv).await;
                if let Ok(SimOutcome::Reply(reply)) = &reply {
                    self.observe_session(&name, argv, bytes, reply);
                }
                reply
            }
        })
    }

    async fn keys<W: AsyncWrite + Unpin>(
        &mut self,
        ctx: &mut ExchangeContext<'_, '_, W>,
        info: Option<&CommandInfo>,
        raw: &[Vec<u8>],
    ) -> AppResult<Option<Vec<Vec<u8>>>> {
        match info.map(|info| info.keys(raw)) {
            Some(Keys::Known(keys)) => return Ok(Some(keys)),
            Some(Keys::Lookup) | None if raw.is_empty() => {
                return Ok(Some(Vec::new()));
            }
            _ => {}
        }
        let mut argv = vec![b"COMMAND".to_vec(), b"GETKEYS".to_vec()];
        argv.extend(raw.iter().cloned());
        let names = ["COMMAND".to_owned(), "GETKEYS".to_owned()];
        let reply = exchange_reply(
            ctx.upstream,
            &encode_command(&argv),
            &names,
            ctx.push,
        )
        .await?;
        Ok(reply.map(|reply| {
            parse_frame(&reply)
                .map(|frame| parse_getkeys(&frame))
                .unwrap_or_default()
        }))
    }

    async fn exec<W: AsyncWrite + Unpin>(
        &mut self,
        ctx: &mut ExchangeContext<'_, '_, W>,
        active: &Active,
        stage: usize,
        node: usize,
        transaction: Transaction,
    ) -> AppResult<SimOutcome> {
        if transaction.dirty {
            return Ok(SimOutcome::Reply(
                b"-EXECABORT Transaction discarded because of previous errors.\r\n"
                    .to_vec(),
            ));
        }
        let keys = transaction
            .queued
            .iter()
            .flat_map(|queued| queued.keys.iter().cloned())
            .collect::<Vec<_>>();
        let request = RouteRequest {
            keys: &keys,
            write: transaction.queued.iter().any(|queued| queued.write),
            allowed_while_loading: transaction.queued.iter().all(|q| q.loading),
            readonly: self.readonly,
            asking: false,
        };
        let slot = match route(
            &active.timeline,
            stage,
            node,
            &ctx.sim.addresses,
            &request,
        ) {
            Decision::Close => return Ok(SimOutcome::Close),
            Decision::Error(error) => {
                return Ok(SimOutcome::Reply(error_bytes(&error)));
            }
            Decision::Serve { slot } => slot,
        };
        let target = slot.and_then(|slot| ctx.sim.real_owner(slot)).cloned();
        let multi = encode_command(&[b"MULTI".to_vec()]);
        let exec = encode_command(&[b"EXEC".to_vec()]);
        let mut commands = vec![(multi, vec!["MULTI".to_owned()])];
        commands.extend(
            transaction
                .queued
                .into_iter()
                .map(|queued| (queued.bytes, queued.argv)),
        );
        commands.push((exec, vec!["EXEC".to_owned()]));
        let mut last = Vec::new();
        for (bytes, argv) in commands {
            let Some(reply) =
                self.send(ctx, target.as_ref(), &bytes, &argv).await?
            else {
                return Ok(SimOutcome::Reply(UNAVAILABLE_REPLY.to_vec()));
            };
            last = reply;
        }
        Ok(SimOutcome::Reply(last))
    }

    /// Execute on the real owner of `slot`, following real redirections a
    /// bounded number of times so real resharding never leaks to clients.
    async fn forward<W: AsyncWrite + Unpin>(
        &mut self,
        ctx: &mut ExchangeContext<'_, '_, W>,
        slot: Option<u16>,
        bytes: &[u8],
        argv: &[String],
    ) -> AppResult<SimOutcome> {
        let mut target =
            slot.and_then(|slot| ctx.sim.real_owner(slot)).cloned();
        let mut asking = false;
        for _ in 0..=MAX_REAL_REDIRECTS {
            if asking {
                let command = encode_command(&[b"ASKING".to_vec()]);
                if self
                    .send(
                        ctx,
                        target.as_ref(),
                        &command,
                        &["ASKING".to_owned()],
                    )
                    .await?
                    .is_none()
                {
                    return Ok(SimOutcome::Reply(UNAVAILABLE_REPLY.to_vec()));
                }
            }
            let Some(reply) =
                self.send(ctx, target.as_ref(), bytes, argv).await?
            else {
                return Ok(SimOutcome::Reply(UNAVAILABLE_REPLY.to_vec()));
            };
            match real_redirection(&reply) {
                Some((ask, endpoint)) => {
                    asking = ask;
                    target = Some(endpoint);
                }
                None => return Ok(SimOutcome::Reply(reply)),
            }
        }
        Ok(SimOutcome::Reply(REAL_OWNER_UNAVAILABLE.to_vec()))
    }

    async fn send<W: AsyncWrite + Unpin>(
        &mut self,
        ctx: &mut ExchangeContext<'_, '_, W>,
        target: Option<&TcpEndpoint>,
        bytes: &[u8],
        argv: &[String],
    ) -> AppResult<Option<Vec<u8>>> {
        let own = ctx.own_upstream.as_tcp().map(TcpEndpoint::connect_addr);
        let Some(target) = target.filter(|t| Some(t.connect_addr()) != own)
        else {
            return exchange_reply(ctx.upstream, bytes, argv, ctx.push).await;
        };
        let key = target.connect_addr();
        if !self.backing.contains_key(&key) {
            let mut session = UpstreamConnection::new(
                Endpoint::Tcp(target.clone()),
                self.connection_id,
            )
            .await;
            for command in &self.prelude {
                let names = parse_frame(command)
                    .map(|frame| frame.argv_lossy())
                    .unwrap_or_default();
                if exchange_reply(&mut session, command, &names, ctx.push)
                    .await?
                    .is_none()
                {
                    return Ok(None);
                }
            }
            self.backing.insert(key.clone(), session);
        }
        let session = self.backing.get_mut(&key).expect("inserted above");
        let result = exchange_reply(session, bytes, argv, ctx.push).await;
        if !matches!(&result, Ok(Some(_))) {
            // Recreate with the prelude rather than reconnect without it.
            self.backing.remove(&key);
        }
        result
    }

    fn observe_session(
        &mut self,
        name: &str,
        argv: &[String],
        bytes: &[u8],
        reply: &[u8],
    ) {
        if matches!(reply.first(), Some(b'-' | b'!')) {
            return;
        }
        match name {
            "HELLO" => {
                if let Some(version) = argv.get(1) {
                    self.resp3 = version == "3";
                }
            }
            "AUTH" => {}
            "RESET" => {
                self.readonly = false;
                self.resp3 = false;
                self.prelude.clear();
                self.backing.clear();
                return;
            }
            _ => return,
        }
        self.prelude.push(bytes.to_vec());
        // Existing backing sessions lack the new state; reopen lazily.
        self.backing.clear();
    }
}

async fn exchange_reply<W: AsyncWrite + Unpin>(
    upstream: &mut UpstreamConnection,
    bytes: &[u8],
    argv: &[String],
    push: &mut PushDelivery<'_, W>,
) -> AppResult<Option<Vec<u8>>> {
    match upstream.forward(bytes, argv, push).await? {
        Exchange::Reply(reply) => Ok(Some(reply)),
        Exchange::Unavailable(_) => Ok(None),
        Exchange::Subscription => {
            Err(AppError::Proxy("expected ordinary reply".to_owned()))
        }
    }
}

/// A real `MOVED`/`ASK` from the backing cluster: `(is_ask, endpoint)`.
fn real_redirection(reply: &[u8]) -> Option<(bool, TcpEndpoint)> {
    if reply.first() != Some(&b'-') {
        return None;
    }
    let text = std::str::from_utf8(reply).ok()?.trim_end();
    let mut parts = text[1..].split_whitespace();
    let ask = match parts.next()? {
        "MOVED" => false,
        "ASK" => true,
        _ => return None,
    };
    parts.next()?.parse::<u16>().ok()?;
    let endpoint = parts.next()?.parse::<TcpEndpoint>().ok()?;
    Some((ask, endpoint))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    use crate::evil::EvilConfig;
    use crate::protocol_fingerprint::ProtocolFingerprints;
    use crate::resp::read_raw_frame;

    #[tokio::test]
    async fn simulation_exchange_preserves_events_and_distinguishes_failures() {
        const EVENT: &[u8] = b">1\r\n+notice\r\n";
        for (upstream_fails, client_fails) in
            [(false, false), (true, false), (false, true)]
        {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = Endpoint::Tcp(
                listener.local_addr().unwrap().to_string().parse().unwrap(),
            );
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let stream =
                    crate::upstream_identity::accept_identity(stream).await;
                let mut stream = BufReader::new(stream);
                assert_eq!(
                    read_raw_frame(&mut stream).await.unwrap(),
                    b"*1\r\n$4\r\nPING\r\n"
                );
                if !upstream_fails {
                    stream.get_mut().write_all(EVENT).await.unwrap();
                    stream.get_mut().write_all(b"+OK\r\n").await.unwrap();
                }
            });
            let mut upstream = UpstreamConnection::new(endpoint, 0).await;
            let (mut writer, reader) = tokio::io::duplex(1024);
            let mut reader = Some(reader);
            if client_fails {
                drop(reader.take());
            }
            let mut fingerprints = ProtocolFingerprints::new();
            let config = EvilConfig::default();
            let mut index = 0;
            let epoch = AtomicU64::new(0);
            let result = exchange_reply(
                &mut upstream,
                b"*1\r\n$4\r\nPING\r\n",
                &["PING".to_owned()],
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
            .await;
            if client_fails {
                assert!(result.is_err());
            } else if upstream_fails {
                assert_eq!(result.unwrap(), None);
                assert_eq!(index, 0);
            } else {
                assert_eq!(result.unwrap(), Some(b"+OK\r\n".to_vec()));
                let mut event = vec![0; EVENT.len()];
                reader
                    .as_mut()
                    .unwrap()
                    .read_exact(&mut event)
                    .await
                    .unwrap();
                assert_eq!(event, EVENT);
                assert_eq!(index, 1);
            }
            server.await.unwrap();
        }
    }
}
