//! Snapshot / clone / fork detection logic.
//!
//! The detector is deliberately *aggressive*: every tripwire only fires on
//! events that genuinely imply duplicated RNG state, but an occasional
//! false-positive merely costs one extra reseed, never a collision. The
//! guarantee that matters is the other direction — no real event is missed.

use crate::env::{EnvSample, Nano};

/// Why a reseed was triggered. Exposed for observability and for the lab's
/// statistics; never affects generated output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// First-ever use of the RNG.
    InitialSeed,
    /// Process id changed (`fork`/`clone` without `exec`).
    PidChanged,
    /// The `MADV_WIPEONFORK` page was zeroed by a fork.
    ForkSentinelWiped,
    /// Monotonic clock went backwards: the whole VM state was rewound.
    MonotonicRewind,
    /// Wall-minus-monotonic offset jumped: a snapshot resumed at a different
    /// wall time while monotonic counters were restored.
    ClockOffsetJump,
    /// Monotonic time failed to advance across a long wall-time stretch:
    /// classic signature of a paused-then-resumed VM whose monotonic clock
    /// was restored from the snapshot.
    MonotonicStall,
    /// Hypervisor VM Generation ID changed.
    VmGenerationChanged,
    /// Periodic defensive reseed (output budget exhausted).
    PeriodicBudget,
    /// Explicit caller-driven [`crate::SnapRng::force_reseed`].
    ManualForce,
}

/// Number of distinct [`Trigger`] variants; size of counter arrays.
pub const TRIGGER_COUNT: usize = 9;

/// Tunable thresholds, grouped so the lab can sweep them.
#[derive(Debug, Clone, Copy)]
pub struct DetectorConfig {
    /// `wall - monotonic` offset change (ns) above which a restore is assumed.
    pub clock_offset_jump_ns: Nano,
    /// Wall-time gap (ns) with less than `stall_min_advance_ns` of monotonic
    /// progress that counts as a VM pause/restore.
    pub stall_wall_gap_ns: Nano,
    /// Monotonic progress below which a long gap is considered a stall.
    pub stall_min_advance_ns: Nano,
    /// Bytes generated between unconditional defensive reseeds.
    pub output_budget: u64,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            // 250 ms absorbs ordinary NTP slew and scheduler jitter while
            // staying far below the gaps produced by real snapshot restores.
            clock_offset_jump_ns: 250_000_000,
            // If one second of wall time passes but the monotonic clock moved
            // under 10 ms, the VM was almost certainly paused/restored.
            stall_wall_gap_ns: 1_000_000_000,
            stall_min_advance_ns: 10_000_000,
            // ChaCha20 has a 2^64-block period; 1 GiB is a conservative belt-
            // and-braces bound, cheap relative to the draws it spans.
            output_budget: 1 << 30,
        }
    }
}

/// Baselines captured at the last (re)seed. Everything here is part of the
/// RNG's effective state: a clone copies it byte-for-byte, which is exactly
/// what the comparisons below detect.
#[derive(Debug, Clone, Copy)]
struct Baseline {
    monotonic_ns: Nano,
    /// `wall_ns - monotonic_ns` at seed time.
    clock_offset: i128,
    pid: u32,
    vm_generation_id: Option<[u8; 16]>,
    fork_sentinel: [u8; 8],
}

/// Holds baselines and evaluates fresh samples. One instance per RNG.
#[derive(Clone)]
pub struct Detector {
    config: DetectorConfig,
    baseline: Option<Baseline>,
    bytes_since_reseed: u64,
    /// Count of reseeds by reason, for [`Detector::counters`].
    counts: [u64; TRIGGER_COUNT],
}

impl Detector {
    pub fn new(config: DetectorConfig) -> Self {
        Self {
            config,
            baseline: None,
            bytes_since_reseed: 0,
            counts: [0; TRIGGER_COUNT],
        }
    }

    /// Index of a trigger in the counters array.
    fn slot(t: Trigger) -> usize {
        match t {
            Trigger::InitialSeed => 0,
            Trigger::PidChanged => 1,
            Trigger::ForkSentinelWiped => 2,
            Trigger::MonotonicRewind => 3,
            Trigger::ClockOffsetJump => 4,
            Trigger::MonotonicStall => 5,
            Trigger::VmGenerationChanged => 6,
            Trigger::PeriodicBudget => 7,
            Trigger::ManualForce => 8,
        }
    }

    /// Reseed counts indexed by [`Trigger`] discriminant order.
    pub fn counters(&self) -> [u64; TRIGGER_COUNT] {
        self.counts
    }

    /// Bytes emitted since the most recent reseed.
    pub fn bytes_since_reseed(&self) -> u64 {
        self.bytes_since_reseed
    }

    /// Evaluate a fresh sample against the stored baselines.
    ///
    /// Returns the trigger that fired (the first match in priority order) or
    /// `None` when every signal is consistent with normal operation.
    pub fn inspect(&self, sample: EnvSample) -> Option<Trigger> {
        let baseline = self.baseline.as_ref()?;

        // 1. Process identity: fork without exec keeps every byte of RNG state
        //    but the kernel assigns a new pid.
        if sample.pid != baseline.pid {
            return Some(Trigger::PidChanged);
        }

        // 2. Kernel-managed fork wipe (Linux >= 4.14). A zeroed page cannot be
        //    produced by ordinary operation.
        if sample.fork_sentinel != baseline.fork_sentinel && sample.fork_sentinel == [0u8; 8] {
            return Some(Trigger::ForkSentinelWiped);
        }

        // 3. Hypervisor generation ID: authoritative when present, changed on
        //    every snapshot restore / clone-from-running-snapshot.
        match (sample.vm_generation_id, baseline.vm_generation_id) {
            (Some(cur), Some(old)) if cur != old => return Some(Trigger::VmGenerationChanged),
            // A device appearing after we were seeded (hot-plug) is itself
            // suspicious; treat appearance as a change only if it carries an id.
            (Some(cur), None) if cur != [0u8; 16] => {
                return Some(Trigger::VmGenerationChanged);
            }
            _ => {}
        }

        // 4. Monotonic rewind. A correct monotonic clock only moves forward;
        //    a smaller value means time itself was rolled back.
        if sample.monotonic_ns < baseline.monotonic_ns {
            return Some(Trigger::MonotonicRewind);
        }

        // 5. Monotonic stall across a large wall-time gap: the VM was paused
        //    and its monotonic clock was frozen/restored from the snapshot.
        //    Checked before the generic offset jump because it is the more
        //    specific diagnosis of the same displaced wall clock — a genuine
        //    pause has near-zero monotonic progress, which a plain offset jump
        //    does not imply.
        let mono_delta = sample.monotonic_ns.saturating_sub(baseline.monotonic_ns);
        let baseline_wall = (baseline.clock_offset + baseline.monotonic_ns as i128).max(0) as u64;
        let wall_delta = sample.wall_ns.saturating_sub(baseline_wall);
        if wall_delta > self.config.stall_wall_gap_ns
            && mono_delta < self.config.stall_min_advance_ns
        {
            return Some(Trigger::MonotonicStall);
        }

        // 6. Wall/monotonic offset jump. Snapshot restore typically rewinds or
        //    advances CLOCK_REALTIME while the restored monotonic baseline
        //    stays fixed, so the offset moves discontinuously.
        let offset = sample.wall_ns as i128 - sample.monotonic_ns as i128;
        if (offset - baseline.clock_offset).unsigned_abs()
            > self.config.clock_offset_jump_ns as u128
        {
            return Some(Trigger::ClockOffsetJump);
        }

        None
    }

    /// Account for `len` bytes about to be emitted. Callers must query
    /// [`Detector::budget_exceeded`] on the *next* draw (before emitting) so a
    /// reseed always precedes any output past the budget.
    pub fn account_bytes(&mut self, len: usize) {
        self.bytes_since_reseed = self.bytes_since_reseed.saturating_add(len as u64);
    }

    /// Whether the output budget since the last reseed has been exhausted.
    pub fn budget_exceeded(&self) -> bool {
        self.bytes_since_reseed >= self.config.output_budget
    }

    /// Rebase every signal on the current sample after a reseed.
    pub fn commit_baseline(&mut self, sample: EnvSample, trigger: Trigger) {
        self.baseline = Some(Baseline {
            monotonic_ns: sample.monotonic_ns,
            clock_offset: sample.wall_ns as i128 - sample.monotonic_ns as i128,
            pid: sample.pid,
            vm_generation_id: sample.vm_generation_id,
            fork_sentinel: sample.fork_sentinel,
        });
        self.bytes_since_reseed = 0;
        self.counts[Self::slot(trigger)] = self.counts[Self::slot(trigger)].saturating_add(1);
    }

    /// Establish the very first baseline.
    pub fn commit_initial(&mut self, sample: EnvSample) {
        self.commit_baseline(sample, Trigger::InitialSeed);
    }

    /// Whether a baseline currently exists.
    pub fn has_baseline(&self) -> bool {
        self.baseline.is_some()
    }

    /// Pid recorded in the current baseline (0 when unseeded).
    pub fn current_pid(&self) -> u32 {
        self.baseline.map(|b| b.pid).unwrap_or(0)
    }

    /// Refresh the clock portion of the baseline without counting a reseed.
    /// Called on every clean draw so the stall heuristic tracks adjacent draws.
    pub fn touch_baseline(&mut self, sample: EnvSample) {
        if let Some(b) = self.baseline.as_mut() {
            b.monotonic_ns = sample.monotonic_ns;
            b.clock_offset = sample.wall_ns as i128 - sample.monotonic_ns as i128;
            // Identity signals stay pinned to the last reseed; only clocks move.
        }
    }

    /// Rebase all signals after an externally-driven reseed (e.g. stream fork).
    pub fn rebase(&mut self, sample: EnvSample) {
        if let Some(b) = self.baseline.as_mut() {
            *b = Baseline {
                monotonic_ns: sample.monotonic_ns,
                clock_offset: sample.wall_ns as i128 - sample.monotonic_ns as i128,
                pid: sample.pid,
                vm_generation_id: sample.vm_generation_id,
                fork_sentinel: sample.fork_sentinel,
            };
            self.bytes_since_reseed = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::EnvSample;

    const SENTINEL: [u8; 8] = *b"SNAPRNG1";
    const GENID: Option<[u8; 16]> = Some([7u8; 16]);

    fn sample(
        mono: Nano,
        wall: Nano,
        pid: u32,
        genid: Option<[u8; 16]>,
        sentinel: [u8; 8],
    ) -> EnvSample {
        EnvSample {
            monotonic_ns: mono,
            wall_ns: wall,
            pid,
            vm_generation_id: genid,
            fork_sentinel: sentinel,
        }
    }

    fn seeded_detector() -> Detector {
        let mut d = Detector::new(DetectorConfig::default());
        d.commit_initial(sample(1_000, 1_001_000, 42, GENID, SENTINEL));
        d
    }

    #[test]
    fn quiet_when_nothing_moves() {
        let d = seeded_detector();
        let s = sample(1_100, 1_001_100, 42, GENID, SENTINEL);
        assert_eq!(d.inspect(s), None);
    }

    #[test]
    fn detects_pid_change() {
        let d = seeded_detector();
        let s = sample(1_100, 1_001_100, 43, GENID, SENTINEL);
        assert_eq!(d.inspect(s), Some(Trigger::PidChanged));
    }

    #[test]
    fn detects_wiped_sentinel() {
        let d = seeded_detector();
        let s = sample(1_100, 1_001_100, 42, GENID, [0u8; 8]);
        assert_eq!(d.inspect(s), Some(Trigger::ForkSentinelWiped));
    }

    #[test]
    fn detects_monotonic_rewind() {
        let d = seeded_detector();
        let s = sample(900, 1_000_900, 42, GENID, SENTINEL);
        assert_eq!(d.inspect(s), Some(Trigger::MonotonicRewind));
    }

    #[test]
    fn detects_clock_offset_jump() {
        let d = seeded_detector();
        // mono advances 100 ns; wall jumps an extra 500 ms (above the 250 ms
        // offset threshold, below the 1 s stall threshold with healthy mono).
        let s = sample(1_100, 1_001_100 + 500_000_000, 42, GENID, SENTINEL);
        assert_eq!(d.inspect(s), Some(Trigger::ClockOffsetJump));
    }

    #[test]
    fn detects_monotonic_stall() {
        let d = seeded_detector();
        // Wall time advances 5 s, monotonic only 1 ms (below the 10 ms
        // threshold): the specific stall diagnosis wins over a plain offset
        // jump even though the offset moved too.
        let s = sample(
            1_000 + 1_000_000,
            1_001_000 + 5_000_000_000,
            42,
            GENID,
            SENTINEL,
        );
        assert_eq!(d.inspect(s), Some(Trigger::MonotonicStall));
    }

    #[test]
    fn normal_advancement_is_not_a_stall() {
        let d = seeded_detector();
        // Both clocks advance 5 s in lockstep — long gap but healthy progress.
        let s = sample(
            1_000 + 5_000_000_000,
            1_001_000 + 5_000_000_000,
            42,
            GENID,
            SENTINEL,
        );
        assert_eq!(d.inspect(s), None);
    }

    #[test]
    fn detects_vmgenid_rotation() {
        let d = seeded_detector();
        let s = sample(1_100, 1_001_100, 42, Some([8u8; 16]), SENTINEL);
        assert_eq!(d.inspect(s), Some(Trigger::VmGenerationChanged));
    }

    #[test]
    fn budget_trips_after_configured_bytes() {
        let mut d = seeded_detector();
        assert!(!d.budget_exceeded());
        d.account_bytes(1024);
        assert!(!d.budget_exceeded());
        let big = DetectorConfig::default().output_budget;
        d.account_bytes(big as usize);
        assert!(d.budget_exceeded());
    }

    #[test]
    fn rebase_clears_previous_trip() {
        let mut d = seeded_detector();
        let s = sample(900, 1_000_900, 42, GENID, SENTINEL);
        assert_eq!(d.inspect(s), Some(Trigger::MonotonicRewind));
        d.commit_baseline(s, Trigger::MonotonicRewind);
        // Same values again are now the baseline — no re-fire.
        assert_eq!(d.inspect(s), None);
    }
}
