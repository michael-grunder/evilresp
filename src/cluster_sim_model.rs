//! Pure model of one simulated cluster snapshot for `DEBUG EVIL CLUSTER`.
//!
//! A [`ClusterState`] describes either the authoritative cluster at one
//! timeline stage or the (possibly stale) view a single node holds. Virtual
//! node `n` is always served by local listener `n`; data lives in the real
//! upstream cluster, so simulated ownership never has to match real
//! ownership.

pub(crate) const SLOT_COUNT: usize = 16_384;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Role {
    Primary,
    Replica { of: usize },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SimNode {
    /// False for spare or forgotten nodes, which only know themselves.
    pub in_cluster: bool,
    pub shard: usize,
    pub role: Role,
    /// The process is unreachable. Meaningful in authoritative states only;
    /// observers learn about it through `pfail`/`fail`.
    pub down: bool,
    pub pfail: bool,
    pub fail: bool,
    /// Replication offset; zero on a replica means it is still loading.
    pub offset: u64,
    pub epoch: u64,
}

impl SimNode {
    pub(crate) fn is_primary(&self) -> bool {
        self.role == Role::Primary
    }

    pub(crate) fn primary_of(&self) -> Option<usize> {
        match self.role {
            Role::Primary => None,
            Role::Replica { of } => Some(of),
        }
    }

    pub(crate) fn loading(&self) -> bool {
        !self.is_primary() && self.offset == 0 && !self.fail
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SlotRange {
    pub start: u16,
    pub end: u16,
    pub owner: usize,
}

/// An open `MIGRATING`/`IMPORTING` slot range. `progress` is the percentage
/// of keys already moved to the target (see [`key_moved`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Migration {
    pub start: u16,
    pub end: u16,
    pub from: usize,
    pub to: usize,
    pub progress: u8,
}

impl Migration {
    pub(crate) fn contains(&self, slot: u16) -> bool {
        (self.start..=self.end).contains(&slot)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClusterState {
    pub nodes: Vec<SimNode>,
    /// Sorted, non-overlapping, coalesced per owner.
    pub slots: Vec<SlotRange>,
    pub migrations: Vec<Migration>,
    pub current_epoch: u64,
}

impl ClusterState {
    pub(crate) fn owner(&self, slot: u16) -> Option<usize> {
        let index = self.slots.partition_point(|range| range.end < slot);
        self.slots
            .get(index)
            .filter(|range| range.start <= slot)
            .map(|range| range.owner)
    }

    pub(crate) fn ranges_of(&self, node: usize) -> Vec<(u16, u16)> {
        self.slots
            .iter()
            .filter(|range| range.owner == node)
            .map(|range| (range.start, range.end))
            .collect()
    }

    pub(crate) fn assigned_slots(&self) -> usize {
        self.slots
            .iter()
            .map(|range| usize::from(range.end - range.start) + 1)
            .sum()
    }

    pub(crate) fn migration(&self, slot: u16) -> Option<&Migration> {
        self.migrations.iter().find(|m| m.contains(slot))
    }

    /// Cluster members in membership (node index) order.
    pub(crate) fn members(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.nodes.len()).filter(|node| self.nodes[*node].in_cluster)
    }

    /// Shards in order of their lowest member, each with its members.
    pub(crate) fn shards(&self) -> Vec<(usize, Vec<usize>)> {
        let mut shards: Vec<(usize, Vec<usize>)> = Vec::new();
        for node in self.members() {
            let shard = self.nodes[node].shard;
            match shards.iter_mut().find(|(id, _)| *id == shard) {
                Some((_, members)) => members.push(node),
                None => shards.push((shard, vec![node])),
            }
        }
        shards
    }

    /// The primary whose slots a shard advertises: an owner of slots if
    /// any, else the first non-failed primary, else the first primary.
    pub(crate) fn shard_slot_source(&self, members: &[usize]) -> Option<usize> {
        let primaries = members
            .iter()
            .copied()
            .filter(|node| self.nodes[*node].is_primary());
        let primaries = primaries.collect::<Vec<_>>();
        primaries
            .iter()
            .copied()
            .find(|node| self.slots.iter().any(|r| r.owner == *node))
            .or_else(|| {
                primaries
                    .iter()
                    .copied()
                    .find(|node| !self.nodes[*node].fail)
            })
            .or_else(|| primaries.first().copied())
    }

    /// `clusterUpdateState()` restricted to what the simulation models.
    pub(crate) fn state_ok(&self, full_coverage: bool) -> bool {
        if !full_coverage {
            return true;
        }
        self.assigned_slots() == SLOT_COUNT
            && self.slots.iter().all(|range| !self.nodes[range.owner].fail)
    }

    /// The view of a node that is not part of the cluster: only itself,
    /// as a slotless primary in its own shard.
    pub(crate) fn solo(&self, node: usize) -> Self {
        let mut nodes = self.nodes.clone();
        for (index, entry) in nodes.iter_mut().enumerate() {
            entry.in_cluster = index == node;
        }
        let entry = &mut nodes[node];
        entry.role = Role::Primary;
        entry.pfail = false;
        entry.fail = false;
        Self {
            nodes,
            slots: Vec::new(),
            migrations: Vec::new(),
            current_epoch: self.current_epoch,
        }
    }

    pub(crate) fn owner_table(&self) -> Vec<Option<usize>> {
        let mut table = vec![None; SLOT_COUNT];
        for range in &self.slots {
            for slot in range.start..=range.end {
                table[usize::from(slot)] = Some(range.owner);
            }
        }
        table
    }

    pub(crate) fn set_owner_table(&mut self, table: &[Option<usize>]) {
        let mut slots: Vec<SlotRange> = Vec::new();
        for (slot, owner) in table.iter().enumerate() {
            let Some(owner) = *owner else {
                continue;
            };
            // SLOT_COUNT fits in u16 indexes.
            let slot = slot as u16;
            match slots.last_mut() {
                Some(last) if last.owner == owner && last.end + 1 == slot => {
                    last.end = slot;
                }
                _ => slots.push(SlotRange {
                    start: slot,
                    end: slot,
                    owner,
                }),
            }
        }
        self.slots = slots;
    }

    pub(crate) fn assign(
        &mut self,
        start: u16,
        end: u16,
        owner: Option<usize>,
    ) {
        let mut table = self.owner_table();
        for slot in start..=end {
            table[usize::from(slot)] = owner;
        }
        self.set_owner_table(&table);
    }

    /// Structural checks that hold for every state, stale views included.
    pub(crate) fn validate_structure(&self) -> Result<(), String> {
        let mut previous: Option<&SlotRange> = None;
        for range in &self.slots {
            if range.start > range.end || usize::from(range.end) >= SLOT_COUNT {
                return Err(format!("invalid range {range:?}"));
            }
            if previous.is_some_and(|prev| prev.end >= range.start) {
                return Err("overlapping or unsorted ranges".to_owned());
            }
            let owner = self
                .nodes
                .get(range.owner)
                .ok_or("range owner out of bounds")?;
            if !owner.in_cluster || !owner.is_primary() {
                return Err(format!(
                    "range owner {} not a primary",
                    range.owner
                ));
            }
            previous = Some(range);
        }
        for (index, node) in self.nodes.iter().enumerate() {
            if !node.in_cluster {
                continue;
            }
            if let Some(of) = node.primary_of() {
                let primary = self.nodes.get(of).ok_or("bad replica link")?;
                if of == index
                    || !primary.in_cluster
                    || !primary.is_primary()
                    || primary.shard != node.shard
                {
                    return Err(format!("node {index} replicates {of}"));
                }
            }
        }
        for migration in &self.migrations {
            if migration.progress > 100
                || migration.from == migration.to
                || (migration.start..=migration.end)
                    .any(|slot| self.owner(slot) != Some(migration.from))
                || !self.nodes[migration.to].is_primary()
            {
                return Err(format!("invalid migration {migration:?}"));
            }
        }
        Ok(())
    }

    /// Additional invariants of an authoritative snapshot: one non-failed
    /// primary per shard, and only that shard's primary owns its slots.
    pub(crate) fn validate_authoritative(&self) -> Result<(), String> {
        self.validate_structure()?;
        for (shard, members) in self.shards() {
            let live = members
                .iter()
                .filter(|n| {
                    let node = &self.nodes[**n];
                    node.is_primary() && !node.fail
                })
                .count();
            if live > 1 {
                return Err(format!("shard {shard} has {live} live primaries"));
            }
            let owners = members
                .iter()
                .filter(|n| self.slots.iter().any(|r| r.owner == **n))
                .count();
            if owners > 1 {
                return Err(format!("shard {shard} has {owners} slot owners"));
            }
        }
        Ok(())
    }
}

/// Whether `key` has already moved for a migration at `progress` percent.
/// The decision depends only on the timeline seed and key bytes, so every
/// connection agrees on it.
pub(crate) fn key_moved(seed: u64, key: &[u8], progress: u8) -> bool {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"evilresp-cluster-migration");
    hasher.update(seed.to_be_bytes());
    hasher.update(key);
    let digest = hasher.finalize();
    u16::from_be_bytes([digest[0], digest[1]]) % 100 < u16::from(progress)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(shard: usize, role: Role) -> SimNode {
        SimNode {
            in_cluster: true,
            shard,
            role,
            down: false,
            pfail: false,
            fail: false,
            offset: 1,
            epoch: 0,
        }
    }

    fn two_shards() -> ClusterState {
        let mut state = ClusterState {
            nodes: vec![
                node(0, Role::Primary),
                node(1, Role::Primary),
                node(0, Role::Replica { of: 0 }),
            ],
            slots: Vec::new(),
            migrations: Vec::new(),
            current_epoch: 0,
        };
        state.assign(0, 8191, Some(0));
        state.assign(8192, 16383, Some(1));
        state
    }

    #[test]
    fn owner_lookup_and_reassignment_coalesce_ranges() {
        let mut state = two_shards();
        assert_eq!(state.owner(0), Some(0));
        assert_eq!(state.owner(8191), Some(0));
        assert_eq!(state.owner(8192), Some(1));
        state.assign(100, 100, None);
        assert_eq!(state.owner(100), None);
        assert_eq!(state.assigned_slots(), SLOT_COUNT - 1);
        assert!(!state.state_ok(true));
        assert!(state.state_ok(false));
        state.assign(100, 100, Some(0));
        assert_eq!(state.slots.len(), 2);
        assert!(state.state_ok(true));
        state.validate_authoritative().unwrap();
    }

    #[test]
    fn invalid_structures_are_rejected() {
        let mut state = two_shards();
        state.nodes[2].role = Role::Replica { of: 1 };
        assert!(state.validate_structure().is_err());

        let mut state = two_shards();
        state.slots[0].owner = 2;
        assert!(state.validate_structure().is_err());

        let mut state = two_shards();
        state.nodes[2].role = Role::Primary;
        state.validate_structure().unwrap();
        assert!(state.validate_authoritative().is_err());
        state.nodes[2].fail = true;
        state.validate_authoritative().unwrap();
    }

    #[test]
    fn failed_owner_breaks_full_coverage_and_solo_view_is_slotless() {
        let mut state = two_shards();
        state.nodes[1].fail = true;
        assert!(!state.state_ok(true));
        let solo = state.solo(2);
        assert_eq!(solo.members().collect::<Vec<_>>(), vec![2]);
        assert!(solo.slots.is_empty());
        assert!(solo.nodes[2].is_primary());
        solo.validate_structure().unwrap();
    }

    #[test]
    fn migration_key_split_is_deterministic_and_bounded() {
        assert!(!key_moved(1, b"k", 0));
        assert!(key_moved(1, b"k", 100));
        let moved = (0..1000)
            .filter(|i| key_moved(7, format!("key:{i}").as_bytes(), 50))
            .count();
        assert!((350..650).contains(&moved), "{moved}");
        assert_eq!(key_moved(7, b"x", 50), key_moved(7, b"x", 50));
    }
}
