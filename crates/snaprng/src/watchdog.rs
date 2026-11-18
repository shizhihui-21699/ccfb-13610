//! Background watchdog.
//!
//! Detection on every draw is cheap but only runs when the application asks
//! for randomness. A service that draws once at startup and then gets snapshot-
//! restored an hour later would still be protected on its *next* draw — but a
//! long-lived process that draws continuously benefits from having the clock
//! tripwires sampled between draws too. The watchdog:
//!
//! * samples the environment ~10 times per second,
//! * raises the global dirty flag (shared with the atfork path) on any
//!   detector trip,
//! * notices forks by pid change even if atfork registration failed,
//! * exits when the process has only one thread left impossible to detect
//!   portably, so it is spawned detached and simply sleeps in long-lived
//!   processes; it never holds locks and does no allocation in its loop.

use crate::detect::{Detector, DetectorConfig};
use crate::env::Env;
use crate::fork;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const TICK: Duration = Duration::from_millis(100);

/// Spawn the watchdog thread once. `env` is the shared environment used by all
/// RNGs; `config` supplies the same thresholds the per-draw checks use.
pub fn spawn(env: Arc<dyn Env>, config: DetectorConfig) {
    std::thread::Builder::new()
        .name("snaprng-watchdog".into())
        .spawn(move || run(env, config, None))
        .ok(); // A failed spawn degrades to per-draw detection only.
}

/// Test-only variant that reports when the first sample (and thus the
/// baseline) has been taken, so tests can mutate the environment without
/// racing watchdog startup.
#[cfg(feature = "test-util")]
pub fn spawn_with_ready(env: Arc<dyn Env>, config: DetectorConfig) -> Arc<AtomicBool> {
    let ready = Arc::new(AtomicBool::new(false));
    let ready_for_thread = Arc::clone(&ready);
    std::thread::Builder::new()
        .name("snaprng-watchdog".into())
        .spawn(move || run(env, config, Some(ready_for_thread)))
        .ok();
    ready
}

fn run(env: Arc<dyn Env>, config: DetectorConfig, ready: Option<Arc<AtomicBool>>) {
    // The watchdog owns a detector purely for its baseline logic. It never
    // generates randomness; it only raises flags for the RNGs to consume.
    let mut detector = Detector::new(config);
    let first = env.sample();
    detector.commit_initial(first);
    let mut last_pid = first.pid;
    if let Some(flag) = ready {
        flag.store(true, Ordering::SeqCst);
    }

    loop {
        std::thread::sleep(TICK);
        let sample = env.sample();

        if sample.pid != last_pid {
            // We survived a fork in a multithreaded process (only one fork
            // lineage keeps running this thread, but it still needs a reseed).
            fork::mark_fork_dirty();
            last_pid = sample.pid;
        }

        if detector.inspect(sample).is_some() {
            fork::mark_fork_dirty();
            // Rebase on the post-event sample so one event cannot re-fire on
            // every subsequent tick.
            detector.commit_baseline(sample, crate::detect::Trigger::MonotonicRewind);
        }
    }
}
