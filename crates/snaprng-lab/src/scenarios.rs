//! Snapshot / clone event models.
//!
//! Each scenario mutates a [`FakeEnv`] the way the corresponding real-world
//! event would change the signals a restored guest observes. The RNG's
//! internal state is always copied byte-for-byte separately — these only
//! describe what the *environment* looks like after the event.

use snaprng::fake_env::{FakeEnv, FakeState};

/// Kinds of disaster the lab can reproduce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    /// Full rollback to an earlier instant: monotonic and wall clocks both
    /// jump backwards, hypervisor rotates the generation ID.
    SnapshotRollback,
    /// `fork(2)`-style: new pid, kernel wipes the sentinel page.
    Fork,
    /// Linked clone of a *running* VM: clocks keep moving forward from the same
    /// readings, only the hypervisor generation ID differs. This is the case a
    /// clock-only detector cannot see.
    RunningVmClone,
    /// VM paused for hours then resumed: wall time leaps, monotonic clock was
    /// frozen with the saved state and barely advances.
    PausedResumed,
    /// Worst case on purpose: byte-identical environment, no hypervisor ID, no
    /// clock divergence — an immediate draw in the clone. Shows the residual
    /// risk that only VM Generation ID (or post-restore OS entropy rekey) can
    /// close deterministically.
    UndetectableClone,
    /// Control: nothing happens. Tripwires must stay quiet; streams must still
    /// be unique because every RNG was independently constructed.
    NoEvent,
}

impl Scenario {
    pub const ALL: [Scenario; 6] = [
        Scenario::SnapshotRollback,
        Scenario::Fork,
        Scenario::RunningVmClone,
        Scenario::PausedResumed,
        Scenario::UndetectableClone,
        Scenario::NoEvent,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Scenario::SnapshotRollback => "snapshot rollback (clocks rewind + vmgenid)",
            Scenario::Fork => "process fork (pid change + WIPEONFORK)",
            Scenario::RunningVmClone => "running-VM linked clone (vmgenid only)",
            Scenario::PausedResumed => "pause/resume (monotonic stall)",
            Scenario::UndetectableClone => "undetectable clone (no signal, immediate draw)",
            Scenario::NoEvent => "no event (control)",
        }
    }

    /// Apply this scenario to a freshly cloned environment. `index`
    /// differentiates per-clone values the way distinct physical clones differ.
    pub fn apply(self, env: &FakeEnv, index: u32) {
        match self {
            Scenario::SnapshotRollback => {
                let base = env.snapshot_state();
                env.rollback(FakeState {
                    monotonic_ns: base
                        .monotonic_ns
                        .saturating_sub(30_000_000_000 + index as u64),
                    wall_ns: base.wall_ns.saturating_sub(30_000_000_000),
                    vm_generation_id: Some(rotate_id(index)),
                    ..base
                });
            }
            Scenario::Fork => {
                env.edit(|s| {
                    s.pid += 1 + index;
                    s.fork_sentinel = [0u8; 8];
                });
            }
            Scenario::RunningVmClone => {
                // Clocks advance a little, identically; only vmgenid rotates.
                env.tick(5_000_000 + index as u64 * 1_000);
                env.edit(|s| {
                    s.vm_generation_id = Some(rotate_id(index));
                });
            }
            Scenario::PausedResumed => {
                let base = env.snapshot_state();
                // Hypervisor generation ID deliberately unchanged (device
                // absent on this guest): the clock tripwires must catch it.
                env.rollback(FakeState {
                    // Monotonic effectively frozen (1 ms of measured runtime),
                    // wall clock jumps three hours.
                    monotonic_ns: base.monotonic_ns + 1_000_000,
                    wall_ns: base.wall_ns + 3 * 3_600_000_000_000,
                    ..base
                });
            }
            Scenario::UndetectableClone => {
                // Deliberately no mutation at all.
            }
            Scenario::NoEvent => {
                env.tick(60_000_000_000);
            }
        }
    }
}

fn rotate_id(index: u32) -> [u8; 16] {
    let mut id = [0u8; 16];
    let hi = 0x534e_4150u64 ^ index.wrapping_add(1) as u64;
    let lo = (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    id[..8].copy_from_slice(&hi.to_le_bytes());
    id[8..].copy_from_slice(&lo.to_le_bytes());
    id
}
