//! The watchdog must raise the global fork-dirty flag when its detector sees
//! an environment tripwire, even while the application draws nothing.
#![cfg(feature = "test-util")]

use snaprng::fake_env::FakeEnv;
use snaprng::Env;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn watchdog_flags_snapshot_restore_between_draws() {
    let env = Arc::new(FakeEnv::new());
    // Clear any flag other tests may have left.
    let _ = snaprng::testing::take_fork_dirty();

    // The watchdog holds the SAME environment the test mutates — modeling one
    // guest whose observed signals change underneath a running process.
    let ready = snaprng::testing::spawn_watchdog(Arc::clone(&env) as Arc<dyn Env>);

    // Wait until the watchdog has installed its baseline; otherwise a restore
    // applied during thread startup could be silently baked into the baseline.
    let deadline = Instant::now() + Duration::from_secs(2);
    while !ready.load(Ordering::SeqCst) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(ready.load(Ordering::SeqCst), "watchdog never became ready");

    // Simulate a restore on the shared environment: monotonic clock jumps
    // backwards while the other signals stay unchanged.
    let s = env.snapshot_state();
    env.rollback(snaprng::fake_env::FakeState {
        monotonic_ns: s.monotonic_ns - 5_000_000_000,
        wall_ns: s.wall_ns - 5_000_000_000,
        ..s
    });

    // Watchdog ticks every 100 ms; allow generous slack for CI scheduling.
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut flagged = false;
    while Instant::now() < deadline {
        if snaprng::testing::take_fork_dirty() {
            flagged = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(
        flagged,
        "watchdog did not raise the dirty flag on a clock rewind"
    );
}
