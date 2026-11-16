//! `DEBUG EVIL CLUSTER` scenario options and deterministic timelines.
//!
//! A timeline is a pure function of the scenario options, seed, and number
//! of local listeners. Each stage lasts `EVERY` shared command indexes and
//! holds an authoritative state plus the view each node reports. Nodes
//! involved in an event always see its result; a seeded subset of the
//! others may still report the previous state for one stage.

use std::collections::BTreeSet;

use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

use crate::cluster_sim_model::{
    ClusterState, Migration, Role, SLOT_COUNT, SimNode,
};
use crate::error::{AppError, AppResult};

const MAX_STEPS: usize = 256;
const DEFAULT_STEPS: usize = 8;
const DEFAULT_EVERY: u64 = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Scenario {
    Stable,
    Partial,
    Failover,
    ManualFailover,
    Replicas,
    Reshard,
    Random,
}

impl Scenario {
    fn parse(value: &str) -> AppResult<Self> {
        Ok(match value.to_ascii_uppercase().as_str() {
            "STABLE" => Self::Stable,
            "PARTIAL" => Self::Partial,
            "FAILOVER" => Self::Failover,
            "MANUAL_FAILOVER" => Self::ManualFailover,
            "REPLICAS" => Self::Replicas,
            "RESHARD" => Self::Reshard,
            "RANDOM" => Self::Random,
            _ => {
                return Err(invalid(
                    "SCENARIO expects STABLE|PARTIAL|FAILOVER|MANUAL_FAILOVER|REPLICAS|RESHARD|RANDOM",
                ));
            }
        })
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "STABLE",
            Self::Partial => "PARTIAL",
            Self::Failover => "FAILOVER",
            Self::ManualFailover => "MANUAL_FAILOVER",
            Self::Replicas => "REPLICAS",
            Self::Reshard => "RESHARD",
            Self::Random => "RANDOM",
        }
    }
}

/// Which server's `CLUSTER SHARDS` dialect to emit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Flavor {
    Redis,
    Valkey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SimConfig {
    pub scenario: Scenario,
    pub seed: u64,
    pub every: u64,
    pub start: u64,
    pub shards: Option<usize>,
    pub replicas: Option<usize>,
    pub steps: usize,
    pub full_coverage: bool,
    pub reads_when_down: bool,
    pub flavor: Flavor,
}

impl SimConfig {
    /// Parse `SCENARIO <name> [option value]...`, starting after `SCENARIO`.
    pub(crate) fn parse(args: &[String], default_seed: u64) -> AppResult<Self> {
        let Some(name) = args.first() else {
            return Err(invalid("SCENARIO requires a scenario name"));
        };
        let mut config = Self {
            scenario: Scenario::parse(name)?,
            seed: default_seed,
            every: DEFAULT_EVERY,
            start: 0,
            shards: None,
            replicas: None,
            steps: DEFAULT_STEPS,
            full_coverage: false,
            reads_when_down: false,
            flavor: Flavor::Redis,
        };
        let (pairs, remainder) = args[1..].as_chunks::<2>();
        if !remainder.is_empty() {
            return Err(invalid("SCENARIO expects option/value pairs"));
        }
        let mut seen = BTreeSet::new();
        for [option, value] in pairs {
            let option = option.to_ascii_uppercase();
            if !seen.insert(option.clone()) {
                return Err(invalid(&format!("duplicate option {option}")));
            }
            match option.as_str() {
                "SEED" => config.seed = number(value, "SEED")?,
                "EVERY" => {
                    config.every = number(value, "EVERY")?;
                    if config.every == 0 {
                        return Err(invalid("EVERY must be positive"));
                    }
                }
                "START" => config.start = number(value, "START")?,
                "SHARDS" => {
                    let shards = number::<usize>(value, "SHARDS")?;
                    if shards == 0 {
                        return Err(invalid("SHARDS must be positive"));
                    }
                    config.shards = Some(shards);
                }
                "REPLICAS" => {
                    config.replicas = Some(number(value, "REPLICAS")?)
                }
                "STEPS" => {
                    config.steps = number(value, "STEPS")?;
                    if config.steps > MAX_STEPS {
                        return Err(invalid("STEPS must be at most 256"));
                    }
                }
                "FULL_COVERAGE" => config.full_coverage = yes_no(value)?,
                "READS_WHEN_DOWN" => config.reads_when_down = yes_no(value)?,
                "FLAVOR" => {
                    config.flavor = match value.to_ascii_uppercase().as_str() {
                        "REDIS" => Flavor::Redis,
                        "VALKEY" => Flavor::Valkey,
                        _ => {
                            return Err(invalid("FLAVOR expects REDIS|VALKEY"));
                        }
                    };
                }
                _ => return Err(invalid(&format!("unknown option {option}"))),
            }
        }
        Ok(config)
    }

    pub(crate) fn status(&self, layout: &Layout) -> String {
        let flag = |value: bool| if value { "YES" } else { "NO" };
        format!(
            "cluster={} cluster_seed={} cluster_every={} cluster_start={} cluster_shards={} cluster_replicas={} cluster_steps={} cluster_full_coverage={} cluster_reads_when_down={} cluster_flavor={}",
            self.scenario.as_str(),
            self.seed,
            self.every,
            self.start,
            layout.shards,
            layout.replicas,
            self.steps,
            flag(self.full_coverage),
            flag(self.reads_when_down),
            match self.flavor {
                Flavor::Redis => "REDIS",
                Flavor::Valkey => "VALKEY",
            },
        )
    }
}

fn number<T: std::str::FromStr>(value: &str, name: &str) -> AppResult<T> {
    value
        .parse()
        .map_err(|_| invalid(&format!("{name} expects an unsigned integer")))
}

fn yes_no(value: &str) -> AppResult<bool> {
    match value.to_ascii_uppercase().as_str() {
        "YES" => Ok(true),
        "NO" => Ok(false),
        _ => Err(invalid("expected YES|NO")),
    }
}

fn invalid(message: &str) -> AppError {
    AppError::EvilConfig(message.to_owned())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Layout {
    pub nodes: usize,
    pub shards: usize,
    pub replicas: usize,
}

impl Layout {
    pub(crate) fn resolve(
        config: &SimConfig,
        nodes: usize,
        real_primaries: usize,
    ) -> AppResult<Self> {
        if nodes == 0 {
            return Err(invalid("cluster simulation requires listeners"));
        }
        let shards = config
            .shards
            .unwrap_or_else(|| real_primaries.clamp(1, nodes));
        if shards > nodes {
            return Err(invalid(&format!(
                "SHARDS {shards} exceeds the {nodes} local listeners"
            )));
        }
        let replicas = config.replicas.unwrap_or((nodes - shards) / shards);
        if shards * (1 + replicas) > nodes {
            return Err(invalid(&format!(
                "{shards} shards with {replicas} replicas need more than the {nodes} local listeners"
            )));
        }
        Ok(Self {
            nodes,
            shards,
            replicas,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Stage {
    pub auth: usize,
    /// State index each node reports and routes with.
    pub views: Vec<usize>,
    pub label: String,
}

#[derive(Clone, Debug)]
pub(crate) struct Timeline {
    pub config: SimConfig,
    pub layout: Layout,
    pub states: Vec<ClusterState>,
    pub stages: Vec<Stage>,
    pub node_ids: Vec<String>,
    pub shard_ids: Vec<String>,
}

impl Timeline {
    pub(crate) fn build(
        config: SimConfig,
        nodes: usize,
        real_primaries: usize,
    ) -> AppResult<Self> {
        let layout = Layout::resolve(&config, nodes, real_primaries)?;
        let mut builder = Builder::new(&config, &layout);
        match config.scenario {
            Scenario::Stable => {}
            Scenario::Partial => {
                let holes = builder.punch_holes();
                for hole in holes {
                    builder.assign_hole(hole);
                }
                builder.converge("full coverage");
            }
            Scenario::Failover => {
                if !builder.failover(false) {
                    return Err(invalid(
                        "FAILOVER requires a shard whose primary has an online replica",
                    ));
                }
            }
            Scenario::ManualFailover => {
                if !builder.failover(true) {
                    return Err(invalid(
                        "MANUAL_FAILOVER requires a shard whose primary has an online replica",
                    ));
                }
            }
            Scenario::Replicas => {
                if !builder.replica_churn() {
                    return Err(invalid(
                        "REPLICAS requires a replica or a spare listener",
                    ));
                }
            }
            Scenario::Reshard => {
                if !builder.reshard() {
                    return Err(invalid(
                        "RESHARD requires at least two shards",
                    ));
                }
            }
            Scenario::Random => builder.random_walk(config.steps),
        }
        let Builder { states, stages, .. } = builder;
        for (index, state) in states.iter().enumerate() {
            state.validate_structure().map_err(|error| {
                AppError::EvilConfig(format!("internal state {index}: {error}"))
            })?;
        }
        for stage in &stages {
            states[stage.auth]
                .validate_authoritative()
                .map_err(|error| {
                    AppError::EvilConfig(format!("internal stage: {error}"))
                })?;
        }
        Ok(Self {
            node_ids: ids(b"evilresp-cluster-node", config.seed, nodes),
            shard_ids: ids(b"evilresp-cluster-shard", config.seed, nodes * 2),
            config,
            layout,
            states,
            stages,
        })
    }

    /// The stage active at a shared command index.
    pub(crate) fn stage_index(&self, command_index: u64) -> usize {
        let elapsed = command_index.saturating_sub(self.config.start);
        let stage = elapsed / self.config.every;
        usize::try_from(stage)
            .unwrap_or(usize::MAX)
            .min(self.stages.len() - 1)
    }

    pub(crate) fn stage_start(&self, stage: usize) -> u64 {
        self.config
            .start
            .saturating_add((stage as u64).saturating_mul(self.config.every))
    }

    pub(crate) fn authoritative(&self, stage: usize) -> &ClusterState {
        &self.states[self.stages[stage].auth]
    }

    /// The view `node` holds at `stage`: its own (solo) view when it is not
    /// part of the cluster, else the stage's per-node state.
    pub(crate) fn view(&self, stage: usize, node: usize) -> ClusterState {
        let auth = self.authoritative(stage);
        if !auth.nodes[node].in_cluster {
            return auth.solo(node);
        }
        self.states[self.stages[stage].views[node]].clone()
    }
}

fn ids(domain: &[u8], seed: u64, count: usize) -> Vec<String> {
    (0..count)
        .map(|index| {
            let mut hasher = Sha256::new();
            hasher.update(domain);
            hasher.update(seed.to_be_bytes());
            hasher.update((index as u64).to_be_bytes());
            hex::encode(hasher.finalize())[..40].to_owned()
        })
        .collect()
}

#[derive(Clone, Copy, Debug)]
struct Hole {
    start: u16,
    end: u16,
    shard: usize,
}

struct Builder {
    states: Vec<ClusterState>,
    stages: Vec<Stage>,
    rng: ChaCha20Rng,
    holes: Vec<Hole>,
}

impl Builder {
    fn new(config: &SimConfig, layout: &Layout) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"evilresp-cluster-timeline");
        hasher.update(config.seed.to_be_bytes());
        hasher.update(config.scenario.as_str().as_bytes());
        for value in
            [layout.nodes, layout.shards, layout.replicas, config.steps]
        {
            hasher.update((value as u64).to_be_bytes());
        }
        let rng = ChaCha20Rng::from_seed(hasher.finalize().into());
        let mut builder = Self {
            states: Vec::new(),
            stages: Vec::new(),
            rng,
            holes: Vec::new(),
        };
        builder.push(initial_state(layout), "stable", &[], Vec::new());
        builder
    }

    fn auth(&self) -> ClusterState {
        let stage = self.stages.last().expect("builder starts with a stage");
        self.states[stage.auth].clone()
    }

    /// Append a stage. Uninvolved members may report one of `stale` views.
    fn push(
        &mut self,
        mut auth: ClusterState,
        label: &str,
        involved: &[usize],
        stale: Vec<ClusterState>,
    ) {
        let offset = (self.stages.len() as u64 + 1) * 1024;
        for node in &mut auth.nodes {
            if node.in_cluster
                && !node.down
                && (node.is_primary() || node.offset > 0)
            {
                node.offset = offset;
            }
        }
        let auth_index = self.states.len();
        self.states.push(auth.clone());
        let mut views = vec![auth_index; auth.nodes.len()];
        let mut candidates = auth
            .members()
            .filter(|node| {
                !involved.contains(node)
                    && stale.iter().all(|view| view.nodes[*node].in_cluster)
            })
            .collect::<Vec<_>>();
        if !stale.is_empty() && !candidates.is_empty() {
            candidates.shuffle(&mut self.rng);
            let count = self.rng.gen_range(1..=candidates.len().div_ceil(2));
            let first_stale = self.states.len();
            self.states.extend(stale.iter().cloned());
            for node in candidates.into_iter().take(count) {
                views[node] = first_stale + self.rng.gen_range(0..stale.len());
            }
        }
        self.stages.push(Stage {
            auth: auth_index,
            views,
            label: label.to_owned(),
        });
    }

    fn converge(&mut self, label: &str) {
        let auth = self.auth();
        let stage = self.stages.last().expect("builder starts with a stage");
        if stage.views.iter().all(|view| *view == stage.auth) {
            return;
        }
        self.push(auth, label, &[], Vec::new());
    }

    /// Remove seeded ranges at the first slot, an interior slot, and/or the
    /// last slot, then report the partial map from every node.
    fn punch_holes(&mut self) -> Vec<Hole> {
        let mut state = self.auth();
        let shards = state.shards().len().max(1);
        let max_len = (SLOT_COUNT / (shards * 4)).clamp(1, 512) as u16;
        let mask = self.rng.gen_range(1_u8..8);
        let mut holes = Vec::new();
        if mask & 1 != 0 {
            let len = self.rng.gen_range(1..=max_len);
            holes.push((0, len - 1));
        }
        if mask & 2 != 0 {
            let len = self.rng.gen_range(1..=max_len);
            let start = self.rng.gen_range(4096..12_288 - len);
            holes.push((start, start + len - 1));
        }
        if mask & 4 != 0 {
            let len = self.rng.gen_range(1..=max_len);
            let last = (SLOT_COUNT - 1) as u16;
            holes.push((last + 1 - len, last));
        }
        let holes = holes
            .into_iter()
            .map(|(start, end)| {
                let owner = state.owner(start).expect("initial full coverage");
                state.assign(start, end, None);
                Hole {
                    start,
                    end,
                    shard: state.nodes[owner].shard,
                }
            })
            .collect::<Vec<_>>();
        let missing = SLOT_COUNT - state.assigned_slots();
        // A scenario that starts partial replaces the initial full stage.
        if self.stages.len() == 1 {
            self.stages.clear();
        }
        self.push(
            state,
            &format!("partial coverage: {missing} slots unassigned"),
            &[],
            Vec::new(),
        );
        self.holes.extend(holes.iter().copied());
        holes
    }

    fn assign_hole(&mut self, hole: Hole) {
        self.holes.retain(|h| h.start != hole.start);
        let previous = self.auth();
        let mut state = previous.clone();
        let live = |node: &SimNode| {
            node.in_cluster && node.is_primary() && !node.fail && !node.down
        };
        let owner = (0..state.nodes.len())
            .find(|n| {
                live(&state.nodes[*n]) && state.nodes[*n].shard == hole.shard
            })
            .or_else(|| {
                (0..state.nodes.len()).find(|n| live(&state.nodes[*n]))
            });
        let Some(owner) = owner else {
            return;
        };
        state.assign(hole.start, hole.end, Some(owner));
        self.push(
            state,
            &format!(
                "CLUSTER ADDSLOTSRANGE {} {} on node {owner}",
                hole.start, hole.end
            ),
            &[owner],
            vec![previous],
        );
    }

    /// Fail over a shard whose primary owns slots and has an online replica.
    fn failover(&mut self, manual: bool) -> bool {
        let state = self.auth();
        let mut choices = Vec::new();
        for primary in state.members() {
            let node = &state.nodes[primary];
            if !node.is_primary()
                || node.fail
                || node.down
                || state.ranges_of(primary).is_empty()
            {
                continue;
            }
            for replica in state.members() {
                let candidate = &state.nodes[replica];
                if candidate.primary_of() == Some(primary)
                    && !candidate.loading()
                    && !candidate.down
                    && !candidate.fail
                {
                    choices.push((primary, replica));
                }
            }
        }
        let Some(&(primary, replica)) = choices.choose(&mut self.rng) else {
            return false;
        };
        if manual {
            self.manual_failover(state, primary, replica);
        } else {
            self.automatic_failover(state, primary, replica);
        }
        true
    }

    fn automatic_failover(
        &mut self,
        healthy: ClusterState,
        primary: usize,
        replica: usize,
    ) {
        let mut unreachable = healthy.clone();
        unreachable.nodes[primary].down = true;
        unreachable.nodes[primary].pfail = true;
        self.push(
            unreachable.clone(),
            &format!("node {primary} unreachable (PFAIL)"),
            &[primary],
            vec![healthy],
        );

        let mut failed = unreachable.clone();
        failed.nodes[primary].pfail = false;
        failed.nodes[primary].fail = true;
        self.push(
            failed.clone(),
            &format!("node {primary} marked FAIL"),
            &[primary],
            vec![unreachable],
        );

        let promoted = promote(&failed, primary, replica);
        self.push(
            promoted.clone(),
            &format!(
                "replica {replica} promoted; failed primary {primary} still listed"
            ),
            &shard_members(&failed, primary),
            vec![failed],
        );
        self.converge(&format!("failover of node {primary} converged"));

        let mut rejoined = promoted.clone();
        let node = &mut rejoined.nodes[primary];
        node.down = false;
        node.fail = false;
        node.role = Role::Replica { of: replica };
        node.offset = 0;
        self.push(
            rejoined.clone(),
            &format!(
                "node {primary} restarted as replica of {replica} (loading)"
            ),
            &[primary, replica],
            vec![promoted],
        );

        let mut synced = rejoined.clone();
        synced.nodes[primary].offset = 1;
        self.push(
            synced,
            &format!("node {primary} replica synced"),
            &[primary],
            vec![rejoined],
        );
        self.converge("failover complete");
    }

    fn manual_failover(
        &mut self,
        before: ClusterState,
        primary: usize,
        replica: usize,
    ) {
        // Promotion is visible before the old primary's demotion: some
        // observers briefly report two online primaries in one shard.
        let mut both = before.clone();
        both.current_epoch += 1;
        both.nodes[replica].role = Role::Primary;
        both.nodes[replica].epoch = both.current_epoch;
        reassign(&mut both, primary, replica);
        let mut after = both.clone();
        demote_and_relink(&mut after, primary, replica);
        let involved = shard_members(&before, primary);
        self.push(
            after,
            &format!(
                "CLUSTER FAILOVER: replica {replica} replaced primary {primary}"
            ),
            &involved,
            vec![before, both],
        );
        self.converge("manual failover converged");
    }

    /// Forget an existing replica and re-add it, or add a spare listener,
    /// as a loading replica that later synchronizes.
    fn replica_churn(&mut self) -> bool {
        let state = self.auth();
        let replicas = state
            .members()
            .filter(|n| {
                let node = &state.nodes[*n];
                !node.is_primary() && !node.down && !node.fail
            })
            .collect::<Vec<_>>();
        let spares = (0..state.nodes.len())
            .filter(|n| !state.nodes[*n].in_cluster)
            .collect::<Vec<_>>();
        if replicas.is_empty() && spares.is_empty() {
            return false;
        }
        let node = if !spares.is_empty()
            && (replicas.is_empty() || self.rng.gen_bool(0.5))
        {
            spares[self.rng.gen_range(0..spares.len())]
        } else {
            let node = replicas[self.rng.gen_range(0..replicas.len())];
            let previous = self.auth();
            let mut forgotten = previous.clone();
            let entry = &mut forgotten.nodes[node];
            entry.in_cluster = false;
            entry.shard = previous.nodes.len() + node;
            entry.role = Role::Primary;
            self.push(
                forgotten,
                &format!("CLUSTER FORGET replica {node}"),
                &[node],
                vec![previous],
            );
            self.converge(&format!("replica {node} forgotten"));
            node
        };
        self.join_replica(node)
    }

    fn join_replica(&mut self, node: usize) -> bool {
        let previous = self.auth();
        let primaries = previous
            .members()
            .filter(|n| {
                let entry = &previous.nodes[*n];
                entry.is_primary() && !entry.fail && !entry.down
            })
            .collect::<Vec<_>>();
        let Some(&primary) = primaries.choose(&mut self.rng) else {
            return false;
        };
        let mut joined = previous.clone();
        let entry = &mut joined.nodes[node];
        entry.in_cluster = true;
        entry.shard = previous.nodes[primary].shard;
        entry.role = Role::Replica { of: primary };
        entry.down = false;
        entry.offset = 0;
        self.push(
            joined.clone(),
            &format!("node {node} joined as replica of {primary} (loading)"),
            &[node, primary],
            vec![previous],
        );
        let mut synced = joined.clone();
        synced.nodes[node].offset = 1;
        self.push(
            synced,
            &format!("replica {node} synced"),
            &[node],
            vec![joined],
        );
        self.converge(&format!("replica {node} converged"));
        true
    }

    /// Migrate a seeded slot range between two live primaries, with ASK
    /// redirections while it is open and MOVED afterwards.
    fn reshard(&mut self) -> bool {
        let state = self.auth();
        let live = state
            .members()
            .filter(|n| {
                let node = &state.nodes[*n];
                node.is_primary() && !node.fail && !node.down
            })
            .collect::<Vec<_>>();
        let sources = live
            .iter()
            .copied()
            .filter(|n| !state.ranges_of(*n).is_empty())
            .collect::<Vec<_>>();
        if live.len() < 2 || sources.is_empty() {
            return false;
        }
        let from = sources[self.rng.gen_range(0..sources.len())];
        let targets = live
            .iter()
            .copied()
            .filter(|n| state.nodes[*n].shard != state.nodes[from].shard)
            .collect::<Vec<_>>();
        let Some(&to) = targets.choose(&mut self.rng) else {
            return false;
        };
        let ranges = state.ranges_of(from);
        let (range_start, range_end) =
            ranges[self.rng.gen_range(0..ranges.len())];
        let span = range_end - range_start + 1;
        let len = self.rng.gen_range(1..=span.min(1024));
        let start = range_start + self.rng.gen_range(0..=span - len);
        let end = start + len - 1;

        let mut migrating = state;
        migrating.migrations.push(Migration {
            start,
            end,
            from,
            to,
            progress: 30,
        });
        self.push(
            migrating.clone(),
            &format!("slots {start}-{end} migrating from {from} to {to}"),
            &[from, to],
            Vec::new(),
        );
        let mut later = migrating;
        later.migrations.last_mut().expect("just pushed").progress = 70;
        self.push(
            later.clone(),
            &format!("slots {start}-{end} mostly migrated"),
            &[from, to],
            Vec::new(),
        );
        let mut done = later.clone();
        done.migrations.pop();
        done.assign(start, end, Some(to));
        done.current_epoch += 1;
        done.nodes[to].epoch = done.current_epoch;
        self.push(
            done,
            &format!("CLUSTER SETSLOT {start}-{end} NODE {to}"),
            &[from, to],
            vec![later],
        );
        self.converge("migration converged");
        true
    }

    /// A seeded sequence of valid operations that always settles back to a
    /// fully covered, converged cluster.
    fn random_walk(&mut self, steps: usize) {
        if steps > 0 && self.rng.gen_bool(0.5) {
            self.punch_holes();
        }
        for _ in 0..steps {
            let mut events = [0_u8, 1, 2, 3, 4];
            events.shuffle(&mut self.rng);
            for event in events {
                let applied = match event {
                    0 => match self.holes.first().copied() {
                        Some(hole) => {
                            self.assign_hole(hole);
                            true
                        }
                        None => false,
                    },
                    1 => self.failover(false),
                    2 => self.failover(true),
                    3 => self.replica_churn(),
                    _ => self.reshard(),
                };
                if applied {
                    break;
                }
            }
        }
        while let Some(hole) = self.holes.first().copied() {
            self.assign_hole(hole);
        }
        self.converge("settled");
    }
}

fn shard_members(state: &ClusterState, node: usize) -> Vec<usize> {
    let shard = state.nodes[node].shard;
    state
        .members()
        .filter(|member| state.nodes[*member].shard == shard)
        .collect()
}

fn promote(
    failed: &ClusterState,
    primary: usize,
    replica: usize,
) -> ClusterState {
    let mut state = failed.clone();
    state.current_epoch += 1;
    state.nodes[replica].role = Role::Primary;
    state.nodes[replica].epoch = state.current_epoch;
    reassign(&mut state, primary, replica);
    for node in 0..state.nodes.len() {
        if node != replica && state.nodes[node].primary_of() == Some(primary) {
            state.nodes[node].role = Role::Replica { of: replica };
        }
    }
    state
}

fn reassign(state: &mut ClusterState, from: usize, to: usize) {
    for range in &mut state.slots {
        if range.owner == from {
            range.owner = to;
        }
    }
    // Open migrations from the old owner are abandoned by a failover.
    state.migrations.retain(|m| m.from != from && m.to != from);
    let table = state.owner_table();
    state.set_owner_table(&table);
}

fn demote_and_relink(state: &mut ClusterState, primary: usize, replica: usize) {
    for node in 0..state.nodes.len() {
        if node == primary || state.nodes[node].primary_of() == Some(primary) {
            state.nodes[node].role = Role::Replica { of: replica };
        }
    }
}

fn initial_state(layout: &Layout) -> ClusterState {
    let nodes = (0..layout.nodes)
        .map(|index| {
            let (in_cluster, shard, role) = if index < layout.shards {
                (true, index, Role::Primary)
            } else {
                let replica = index - layout.shards;
                if replica < layout.shards * layout.replicas {
                    let shard = replica % layout.shards;
                    (true, shard, Role::Replica { of: shard })
                } else {
                    (false, layout.nodes + index, Role::Primary)
                }
            };
            SimNode {
                in_cluster,
                shard,
                role,
                down: false,
                pfail: false,
                fail: false,
                offset: 1,
                epoch: if index < layout.shards {
                    index as u64 + 1
                } else {
                    0
                },
            }
        })
        .collect();
    let mut state = ClusterState {
        nodes,
        slots: Vec::new(),
        migrations: Vec::new(),
        current_epoch: layout.shards as u64,
    };
    for shard in 0..layout.shards {
        let start = shard * SLOT_COUNT / layout.shards;
        let end = (shard + 1) * SLOT_COUNT / layout.shards - 1;
        state.assign(start as u16, end as u16, Some(shard));
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(args: &str) -> SimConfig {
        let args = args
            .split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        SimConfig::parse(&args, 0).unwrap()
    }

    fn build(args: &str, nodes: usize, primaries: usize) -> Timeline {
        Timeline::build(config(args), nodes, primaries).unwrap()
    }

    #[test]
    fn parses_options_and_rejects_invalid_ones() {
        let parsed = config(
            "partial seed 9 every 5 start 3 shards 2 replicas 1 steps 4 full_coverage yes reads_when_down YES flavor valkey",
        );
        assert_eq!(parsed.scenario, Scenario::Partial);
        assert_eq!(parsed.seed, 9);
        assert_eq!((parsed.every, parsed.start, parsed.steps), (5, 3, 4));
        assert_eq!((parsed.shards, parsed.replicas), (Some(2), Some(1)));
        assert!(parsed.full_coverage && parsed.reads_when_down);
        assert_eq!(parsed.flavor, Flavor::Valkey);
        for bad in [
            "",
            "UNKNOWN",
            "STABLE SEED",
            "STABLE SEED -1",
            "STABLE EVERY 0",
            "STABLE SHARDS 0",
            "STABLE STEPS 257",
            "STABLE FULL_COVERAGE maybe",
            "STABLE FLAVOR dragonfly",
            "STABLE SEED 1 SEED 2",
            "STABLE BOGUS 1",
        ] {
            let args = bad
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            assert!(SimConfig::parse(&args, 0).is_err(), "{bad}");
        }
    }

    #[test]
    fn layouts_follow_listeners_and_reject_oversubscription() {
        let stable = config("STABLE");
        assert_eq!(
            Layout::resolve(&stable, 6, 3).unwrap(),
            Layout {
                nodes: 6,
                shards: 3,
                replicas: 1
            }
        );
        assert_eq!(Layout::resolve(&stable, 7, 3).unwrap().replicas, 1);
        assert!(Layout::resolve(&config("STABLE SHARDS 7"), 6, 3).is_err());
        assert!(
            Layout::resolve(&config("STABLE SHARDS 3 REPLICAS 2"), 6, 3)
                .is_err()
        );
        let initial = initial_state(&Layout {
            nodes: 7,
            shards: 3,
            replicas: 1,
        });
        assert_eq!(initial.assigned_slots(), SLOT_COUNT);
        assert!(!initial.nodes[6].in_cluster);
        assert_eq!(initial.nodes[4].role, Role::Replica { of: 1 });
    }

    #[test]
    fn every_scenario_and_seed_produces_valid_converging_timelines() {
        for scenario in [
            "STABLE",
            "PARTIAL",
            "FAILOVER",
            "MANUAL_FAILOVER",
            "REPLICAS",
            "RESHARD",
            "RANDOM STEPS 24",
        ] {
            for seed in 0..40 {
                for (nodes, primaries) in [(6, 3), (7, 3), (4, 2), (9, 3)] {
                    let timeline = build(
                        &format!("{scenario} SEED {seed}"),
                        nodes,
                        primaries,
                    );
                    let last = timeline.stages.last().unwrap();
                    assert!(
                        last.views.iter().all(|view| *view == last.auth),
                        "{scenario} seed {seed} does not converge"
                    );
                    let final_state =
                        timeline.authoritative(timeline.stages.len() - 1);
                    assert_eq!(final_state.assigned_slots(), SLOT_COUNT);
                    assert!(final_state.state_ok(true), "{scenario} {seed}");
                    for stage in &timeline.stages {
                        assert_eq!(stage.views.len(), nodes);
                    }
                }
            }
        }
    }

    #[test]
    fn timelines_are_deterministic_and_seed_sensitive() {
        let first = build("RANDOM SEED 3 STEPS 16", 9, 3);
        let second = build("RANDOM SEED 3 STEPS 16", 9, 3);
        assert_eq!(first.stages, second.stages);
        assert_eq!(first.states, second.states);
        assert_eq!(first.node_ids, second.node_ids);
        let other = build("RANDOM SEED 4 STEPS 16", 9, 3);
        assert!(
            first.states != other.states || first.node_ids != other.node_ids
        );
        assert!(first.node_ids.iter().all(|id| id.len() == 40));
    }

    #[test]
    fn partial_scenario_starts_with_holes_and_stale_observers() {
        let timeline = build("PARTIAL SEED 1", 6, 3);
        let first = timeline.authoritative(0);
        assert!(first.assigned_slots() < SLOT_COUNT);
        // Assigning a hole leaves at least one observer with the old map.
        let stage = &timeline.stages[1];
        assert!(stage.views.iter().any(|view| *view != stage.auth));
        assert_eq!(timeline.stage_index(0), 0);
        assert_eq!(timeline.stage_index(99), 0);
        assert_eq!(timeline.stage_index(100), 1);
        assert_eq!(timeline.stage_index(u64::MAX), timeline.stages.len() - 1);
        assert_eq!(timeline.stage_start(2), 200);
    }

    #[test]
    fn automatic_failover_lists_failed_and_promoted_primaries() {
        let timeline = build("FAILOVER SEED 2", 6, 3);
        let labels = timeline
            .stages
            .iter()
            .map(|stage| stage.label.as_str())
            .collect::<Vec<_>>();
        let promoted = labels
            .iter()
            .position(|label| label.contains("promoted"))
            .unwrap();
        let state = timeline.authoritative(promoted);
        let (_, members) = state
            .shards()
            .into_iter()
            .find(|(_, members)| {
                members
                    .iter()
                    .filter(|n| state.nodes[**n].is_primary())
                    .count()
                    == 2
            })
            .unwrap();
        assert!(members.iter().any(|n| state.nodes[*n].fail));
        assert!(labels.iter().any(|label| label.contains("loading")));
        assert!(
            timeline
                .authoritative(promoted - 1)
                .nodes
                .iter()
                .any(|n| n.down)
        );
    }

    #[test]
    fn manual_failover_can_show_two_online_primaries_to_observers() {
        let found = (0..20).any(|seed| {
            let timeline = build(&format!("MANUAL_FAILOVER SEED {seed}"), 6, 3);
            timeline.states.iter().any(|state| {
                state.shards().iter().any(|(_, members)| {
                    members
                        .iter()
                        .filter(|n| {
                            let node = &state.nodes[**n];
                            node.is_primary() && !node.fail
                        })
                        .count()
                        == 2
                })
            })
        });
        assert!(found);
    }

    #[test]
    fn scripted_scenarios_reject_layouts_that_cannot_run_them() {
        for (scenario, nodes, primaries) in [
            ("FAILOVER", 3, 3),
            ("MANUAL_FAILOVER", 3, 3),
            ("REPLICAS", 3, 3),
            ("RESHARD", 2, 1),
        ] {
            let error = Timeline::build(config(scenario), nodes, primaries)
                .unwrap_err();
            assert!(error.to_string().contains(scenario), "{error}");
        }
    }

    #[test]
    fn stale_views_never_belong_to_involved_nodes() {
        for seed in 0..30 {
            let timeline = build(&format!("RANDOM SEED {seed} STEPS 20"), 9, 3);
            for stage in &timeline.stages {
                let auth = &timeline.states[stage.auth];
                for (node, view) in stage.views.iter().enumerate() {
                    if *view != stage.auth {
                        assert!(auth.nodes[node].in_cluster);
                        assert!(timeline.states[*view].nodes[node].in_cluster);
                        assert_eq!(
                            timeline.states[*view].nodes[node].role,
                            auth.nodes[node].role,
                            "stale observer {node} disagrees about itself"
                        );
                    }
                }
            }
        }
    }
}
