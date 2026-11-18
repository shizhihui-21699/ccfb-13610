//! Periodic output-budget reseeding and manual reseed behavior.
#![cfg(feature = "test-util")]

use rand::RngExt;
use snaprng::fake_env::FakeEnv;
use snaprng::{DetectorConfig, SnapRng, Trigger};
use std::sync::Arc;

#[test]
fn output_budget_forces_periodic_reseed() {
    let env = Arc::new(FakeEnv::new());
    let config = DetectorConfig {
        // Tiny budget so a handful of draws crosses it.
        output_budget: 64,
        ..DetectorConfig::default()
    };
    let mut rng = SnapRng::with_env_and_config(Arc::clone(&env) as Arc<dyn snaprng::Env>, config);

    let first: [u8; 32] = rng.random();
    let before = rng.reseed_counters();
    // Two 32-byte draws = 64 bytes total at the moment the budget trips; the
    // next draw path must reseed before emitting.
    let second: [u8; 32] = rng.random();
    let _ = second;
    let third: [u8; 32] = rng.random();
    let after = rng.reseed_counters();
    assert!(after[Trigger::PeriodicBudget as usize] > before[Trigger::PeriodicBudget as usize]);
    // Output across the reseed boundary stays unique.
    assert_ne!(first, third);
}

#[test]
fn manual_force_reseed_changes_stream() {
    let env = Arc::new(FakeEnv::new());
    let mut rng = SnapRng::with_env(Arc::clone(&env) as Arc<dyn snaprng::Env>);
    let a: [u8; 32] = rng.random();
    rng.force_reseed();
    let b: [u8; 32] = rng.random();
    assert_ne!(a, b);
    assert_eq!(rng.reseed_counters()[Trigger::ManualForce as usize], 1);
}

#[test]
fn fork_stream_is_independent_and_collision_free() {
    use std::collections::HashSet;
    let env = Arc::new(FakeEnv::new());
    let mut parent = SnapRng::with_env(Arc::clone(&env) as Arc<dyn snaprng::Env>);
    let _: [u8; 32] = parent.random();

    let mut seen = HashSet::new();
    for _ in 0..32 {
        let mut child = parent.fork_stream();
        let token: [u8; 32] = child.random();
        assert!(seen.insert(token));
    }
    // Parent stream continues unaffected.
    let parent_token: [u8; 32] = parent.random();
    assert!(seen.insert(parent_token));
}
