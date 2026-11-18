//! Experiment execution and collision statistics.

use crate::baseline::{CounterRng, NaiveChaCha};
use crate::scenarios::Scenario;
use rand::RngExt;
use rand_core::Rng;
use snaprng::fake_env::FakeEnv;
use snaprng::SnapRng;
use std::collections::HashMap;
use std::sync::Arc;

/// One 256-bit drawn value. Tokens are compared as opaque byte strings so the
/// metric is identical for every RNG under test.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Token(pub [u8; 32]);

/// Aggregated outcome for one (RNG, scenario) cell.
#[derive(Debug, Clone, Default)]
pub struct CellReport {
    pub clones: usize,
    pub tokens_per_clone: usize,
    pub total_tokens: usize,
    pub unique_tokens: usize,
    /// Number of extra copies beyond the first (`total - unique`).
    pub duplicate_tokens: usize,
    /// Distinct token values that appeared more than once.
    pub colliding_values: usize,
    /// Largest multiplicity any single token reached.
    pub max_multiplicity: usize,
    /// Reseed trigger counts (only meaningful for SnapRng).
    pub reseed_triggers: [u64; snaprng::detect::TRIGGER_COUNT],
}

impl CellReport {
    /// Zero collisions is the success criterion for the protected RNG.
    pub fn collision_free(&self) -> bool {
        self.duplicate_tokens == 0
    }
}

/// Run every scenario against the three RNG families.
pub fn run_suite(clones: usize, tokens_per_clone: usize) -> Vec<(String, Scenario, CellReport)> {
    let mut rows = Vec::new();
    for scenario in Scenario::ALL {
        rows.push((
            "NaiveChaCha20 (no protection)".to_string(),
            scenario,
            run_naive_chacha(scenario, clones, tokens_per_clone),
        ));
        rows.push((
            "CounterRng (nonce counter)".to_string(),
            scenario,
            run_counter(scenario, clones, tokens_per_clone),
        ));
        rows.push((
            "SnapRng (this crate)".to_string(),
            scenario,
            run_snaprng(scenario, clones, tokens_per_clone),
        ));
    }
    rows
}

fn tally(
    counts: HashMap<Token, usize>,
    clones: usize,
    per: usize,
    triggers: [u64; snaprng::detect::TRIGGER_COUNT],
) -> CellReport {
    let total_tokens: usize = counts.values().sum();
    let colliding_values = counts.values().filter(|c| **c > 1).count();
    let duplicate_tokens = counts.values().filter(|c| **c > 1).map(|c| c - 1).sum();
    let max_multiplicity = counts.values().copied().max().unwrap_or(0);
    CellReport {
        clones,
        tokens_per_clone: per,
        total_tokens,
        unique_tokens: counts.len(),
        duplicate_tokens,
        colliding_values,
        max_multiplicity,
        reseed_triggers: triggers,
    }
}

fn run_naive_chacha(scenario: Scenario, clones: usize, per: usize) -> CellReport {
    let mut counts: HashMap<Token, usize> = HashMap::new();
    if scenario == Scenario::NoEvent {
        // Control: every participant is an independently constructed RNG.
        for _ in 0..clones {
            let mut rng = NaiveChaCha::new();
            for _ in 0..per {
                let mut token = Token([0u8; 32]);
                rng.fill_bytes(&mut token.0);
                *counts.entry(token).or_insert(0) += 1;
            }
        }
    } else {
        // Disaster: one image, N byte-identical clones.
        let parent = NaiveChaCha::new();
        for _ in 0..clones {
            let mut rng = parent.snapshot_clone();
            for _ in 0..per {
                let mut token = Token([0u8; 32]);
                rng.fill_bytes(&mut token.0);
                *counts.entry(token).or_insert(0) += 1;
            }
        }
    }
    tally(counts, clones, per, [0; snaprng::detect::TRIGGER_COUNT])
}

fn run_counter(scenario: Scenario, clones: usize, per: usize) -> CellReport {
    let mut counts: HashMap<Token, usize> = HashMap::new();
    if scenario == Scenario::NoEvent {
        for _ in 0..clones {
            let mut rng = CounterRng::new();
            for _ in 0..per {
                let mut token = Token([0u8; 32]);
                rng.fill_bytes(&mut token.0);
                *counts.entry(token).or_insert(0) += 1;
            }
        }
    } else {
        let parent = CounterRng::new();
        for _ in 0..clones {
            let mut rng = parent.snapshot_clone();
            for _ in 0..per {
                let mut token = Token([0u8; 32]);
                rng.fill_bytes(&mut token.0);
                *counts.entry(token).or_insert(0) += 1;
            }
        }
    }
    tally(counts, clones, per, [0; snaprng::detect::TRIGGER_COUNT])
}

fn run_snaprng(scenario: Scenario, clones: usize, per: usize) -> CellReport {
    let mut counts: HashMap<Token, usize> = HashMap::new();
    let mut trigger_totals = [0u64; snaprng::detect::TRIGGER_COUNT];

    if scenario == Scenario::NoEvent {
        // Control: independent RNGs on independent environments, normal time.
        for i in 0..clones {
            let env = FakeEnv::new();
            env.tick(i as u64 * 1_000_000);
            let mut rng = SnapRng::with_env(Arc::new(env) as Arc<dyn snaprng::Env>);
            for _ in 0..per {
                let mut token = Token([0u8; 32]);
                rng.fill_bytes(&mut token.0);
                *counts.entry(token).or_insert(0) += 1;
            }
            for (t, n) in trigger_totals.iter_mut().zip(rng.reseed_counters()) {
                *t += n;
            }
        }
        return tally(counts, clones, per, trigger_totals);
    }

    // Disaster path: one warmed-up RNG, N byte-identical state clones, each
    // woken inside its own cloned environment that the scenario mutates.
    let env = Arc::new(FakeEnv::new());
    let mut parent = SnapRng::with_env(Arc::clone(&env) as Arc<dyn snaprng::Env>);
    let _: [u8; 32] = parent.random();

    for clone_idx in 0..clones {
        let clone_env = env.clone_vm();
        scenario.apply(&clone_env, clone_idx as u32);

        let mut clone = parent.snapshot_clone();
        clone.attach_env(Arc::new(clone_env) as Arc<dyn snaprng::Env>);

        let before = clone.reseed_counters();
        for _ in 0..per {
            let mut token = Token([0u8; 32]);
            clone.fill_bytes(&mut token.0);
            *counts.entry(token).or_insert(0) += 1;
        }
        let after = clone.reseed_counters();
        for (t, (a, b)) in trigger_totals
            .iter_mut()
            .zip(before.iter().zip(after.iter()))
        {
            *t += b - a;
        }
    }

    tally(counts, clones, per, trigger_totals)
}
