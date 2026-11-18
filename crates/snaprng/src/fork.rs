//! Process-fork handling.
//!
//! Two complementary mechanisms, both registered lazily on first use:
//!
//! * `pthread_atfork` — the child handler runs in the forked child before any
//!   other user code and raises a process-global atomic flag. No locks, no
//!   allocation, async-signal-safe by construction.
//! * `MADV_WIPEONFORK` (see [`crate::env`]) — kernel-level backstop that also
//!   covers `clone(CLONE_VM)` variants where atfork semantics differ.
//!
//! Every RNG instance (thread-local or owned) checks [`take_fork_dirty`] on
//! its fast path, so the very first draw after a fork is preceded by a reseed.

use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Once;

static FORK_DIRTY: AtomicBool = AtomicBool::new(false);
static REGISTER: Once = Once::new();

extern "C" fn atfork_child() {
    // Only async-signal-safe operations: a single atomic store.
    FORK_DIRTY.store(true, Ordering::SeqCst);
}

/// Register the atfork handlers exactly once per process. After a fork the
/// child inherits the `Once` as "complete" but the handler still runs because
/// pthread keeps the handler list across fork.
pub fn ensure_registered() {
    REGISTER.call_once(|| {
        // SAFETY: the handler is a plain function doing one atomic store.
        let rc = unsafe { libc::pthread_atfork(None, None, Some(atfork_child)) };
        if rc != 0 {
            // Registration failing is rare (resource exhaustion). The pid
            // comparison in the detector still catches every fork, so we only
            // record the fact via the dirty flag's sibling counter below.
            FORK_REG_FAILED.store(true, Ordering::Relaxed);
        }
    });
}

static FORK_REG_FAILED: AtomicBool = AtomicBool::new(false);

/// Whether atfork registration could not be performed (for diagnostics).
#[allow(dead_code)] // part of the public diagnostics surface
pub fn registration_failed() -> bool {
    FORK_REG_FAILED.load(Ordering::Relaxed)
}

/// Returns true once if this process is a fork child that has not yet reseeded.
pub fn take_fork_dirty() -> bool {
    FORK_DIRTY.swap(false, Ordering::SeqCst)
}

/// Raise the flag manually. Used by the watchdog when it detects a fork via
/// pid change, and by tests simulating forks without calling `fork(2)`.
pub fn mark_fork_dirty() {
    FORK_DIRTY.store(true, Ordering::SeqCst);
}
