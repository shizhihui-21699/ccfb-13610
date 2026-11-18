//! Deterministic in-memory [`Env`] for tests and the clone-lab.
//!
//! Only compiled with the `test-util` feature — production code can never
//! accidentally construct a fake environment.

use crate::env::{Env, EnvSample, Nano};
use std::sync::{Arc, Mutex};

/// Mutable scriptable state shared between a "VM" and all of its "clones".
#[derive(Debug, Clone)]
pub struct FakeState {
    pub monotonic_ns: Nano,
    pub wall_ns: Nano,
    pub pid: u32,
    pub vm_generation_id: Option<[u8; 16]>,
    pub fork_sentinel: [u8; 8],
}

impl Default for FakeState {
    fn default() -> Self {
        Self {
            // Large base so tests can rewind by tens of seconds without
            // underflowing.
            monotonic_ns: 1_000_000_000_000,
            wall_ns: 1_700_000_000_000_000_000,
            pid: 1000,
            vm_generation_id: Some([1u8; 16]),
            fork_sentinel: *b"SNAPRNG1",
        }
    }
}

/// A controllable environment. Cloning the `Arc` models cloning a VM: every
/// replica initially observes identical state.
#[derive(Clone)]
pub struct FakeEnv {
    state: Arc<Mutex<FakeState>>,
}

impl FakeEnv {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(FakeState::default())),
        }
    }

    /// Apply a mutation to the environment, e.g. simulate a clock jump.
    pub fn edit(&self, f: impl FnOnce(&mut FakeState)) {
        f(&mut self.state.lock().unwrap());
    }

    /// Snapshot the current state into a *new* environment whose clock starts
    /// ticking from the same values — the software model of cloning a running
    /// VM from a memory snapshot.
    pub fn clone_vm(&self) -> FakeEnv {
        let snapshot = self.state.lock().unwrap().clone();
        FakeEnv {
            state: Arc::new(Mutex::new(snapshot)),
        }
    }

    /// Advance both clocks by `ns` (normal running time).
    pub fn tick(&self, ns: Nano) {
        self.edit(|s| {
            s.monotonic_ns += ns;
            s.wall_ns += ns;
        });
    }

    /// Model a snapshot rollback: monotonic time jumps backwards, wall time
    /// returns to an earlier instant, VM generation id rotates.
    pub fn rollback(&self, to: FakeState) {
        *self.state.lock().unwrap() = to;
    }

    /// Read a copy of the current state.
    pub fn snapshot_state(&self) -> FakeState {
        self.state.lock().unwrap().clone()
    }
}

impl Default for FakeEnv {
    fn default() -> Self {
        Self::new()
    }
}

impl Env for FakeEnv {
    fn sample(&self) -> EnvSample {
        let s = self.state.lock().unwrap();
        EnvSample {
            monotonic_ns: s.monotonic_ns,
            wall_ns: s.wall_ns,
            pid: s.pid,
            vm_generation_id: s.vm_generation_id,
            fork_sentinel: s.fork_sentinel,
        }
    }
}
