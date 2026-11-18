//! The snapshot-aware RNG and its thread-local / global entry points.

use crate::detect::{Detector, DetectorConfig, Trigger};
use crate::entropy;
use crate::env::{Env, EnvSample, OsEnv};
use crate::fork;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, Rng, SeedableRng, TryCryptoRng, TryRng};
use std::sync::Arc;

/// A ChaCha20-CSPRNG wrapper that reseeds itself before *any* output whenever
/// a fork, snapshot restore or VM clone is suspected.
///
/// `SnapRng` implements [`Rng`]/[`CryptoRng`], so it drops into every API
/// bounded by `R: Rng + ?Sized` (the standard rand ecosystem). It is
/// intentionally **not `Clone`**: an explicit clone of RNG state is the exact
/// hazard this crate exists to prevent. Use [`SnapRng::fork_stream`] to derive
/// an independently seeded stream.
pub struct SnapRng {
    inner: ChaCha20Rng,
    detector: Detector,
    env: Arc<dyn Env>,
    seeded: bool,
}

impl std::fmt::Debug for SnapRng {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapRng")
            .field("seeded", &self.seeded)
            .field("bytes_since_reseed", &self.detector.bytes_since_reseed())
            .field("reseed_counters", &self.detector.counters())
            .finish_non_exhaustive()
    }
}

impl SnapRng {
    /// Build an RNG over a specific environment (real OS or a test fake).
    /// Seeding is lazy: the first draw pays the entropy cost.
    pub fn with_env(env: Arc<dyn Env>) -> Self {
        Self::with_env_and_config(env, DetectorConfig::default())
    }

    /// Same as [`SnapRng::with_env`] but with custom detection thresholds.
    pub fn with_env_and_config(env: Arc<dyn Env>, config: DetectorConfig) -> Self {
        fork::ensure_registered();
        Self {
            // Temporary key; replaced before the first byte leaves the RNG.
            inner: ChaCha20Rng::from_seed([0u8; 32]),
            detector: Detector::new(config),
            env,
            seeded: false,
        }
    }

    /// Construct with the production [`OsEnv`].
    pub fn new() -> Self {
        Self::with_env(global_env())
    }

    /// The trigger that fired on the most recent reseed, for diagnostics.
    pub fn reseed_counters(&self) -> [u64; crate::detect::TRIGGER_COUNT] {
        self.detector.counters()
    }

    /// Bytes emitted since the current seed was installed.
    pub fn bytes_since_reseed(&self) -> u64 {
        self.detector.bytes_since_reseed()
    }

    /// Force an immediate reseed regardless of detector state.
    pub fn force_reseed(&mut self) {
        let sample = self.env.sample();
        self.reseed(sample, None, Trigger::ManualForce);
    }

    /// Derive a new, independently seeded stream (the safe replacement for
    /// `.clone()`).
    pub fn fork_stream(&mut self) -> SnapRng {
        let mut next =
            SnapRng::with_env_and_config(Arc::clone(&self.env), DetectorConfig::default());
        // Seed immediately from fresh platform entropy plus a contribution from
        // the parent stream, so the child is distinct yet causally tied to it.
        let sample = next.env.sample();
        let mut parent_contribution = [0u8; 32];
        self.inner.fill_bytes(&mut parent_contribution);
        next.reseed(sample, Some(&parent_contribution), Trigger::InitialSeed);
        next
    }

    /// Run all tripwires and reseed before any output if needed.
    /// This is the single chokepoint through which every `try_fill_bytes` /
    /// `try_next_u32` / `try_next_u64` call passes. Bytes are accounted by the
    /// caller *before* invoking the underlying generator, so an exhausted
    /// output budget is handled here too — no draw path can bypass it.
    fn ensure_fresh(&mut self) {
        // Cheap global flag first (set by atfork child handler or watchdog).
        let fork_dirty = fork::take_fork_dirty();
        let sample = self.env.sample();

        let trigger = if !self.seeded {
            Some(Trigger::InitialSeed)
        } else if fork_dirty {
            // The flag is authoritative for forks; prefer the most specific
            // reason the detector would give when available.
            Some(if sample.pid != self.last_pid() {
                Trigger::PidChanged
            } else {
                Trigger::ForkSentinelWiped
            })
        } else if self.detector.budget_exceeded() {
            Some(Trigger::PeriodicBudget)
        } else {
            self.detector.inspect(sample)
        };

        match trigger {
            Some(t) => self.reseed(sample, None, t),
            None => {
                // Keep the detector's clock baseline current between reseeds so
                // the stall heuristic compares adjacent draws, not seed time.
                self.detector.touch_baseline(sample);
            }
        }
    }

    fn last_pid(&self) -> u32 {
        self.detector.current_pid()
    }

    /// Mix all entropy sources (plus optional extra material) and install a
    /// fresh ChaCha20 key. No byte generated under the old key is emitted after
    /// this point, and the new key is independent across clones because every
    /// source is re-read post-event.
    fn reseed(&mut self, sample: EnvSample, extra: Option<&[u8]>, trigger: Trigger) {
        let mut mixer = entropy::Mixer::new();
        entropy::gather(&mut mixer, sample);
        if let Some(e) = extra {
            mixer.feed(b"caller-extra", e);
        }
        // Bind the seed to the reason it happened, so identical source bytes
        // across two different event kinds still diverge.
        mixer.feed(b"trigger", &[trigger as u8]);
        let mut seed = [0u8; entropy::SEED_LEN];
        mixer.finish(&mut seed);
        self.inner = ChaCha20Rng::from_seed(seed);
        // Wipe the seed bytes after handing them to ChaCha.
        for b in seed.iter_mut() {
            *b = 0;
        }
        self.seeded = true;
        if matches!(trigger, Trigger::InitialSeed) && self.detector.has_baseline() {
            // fork_stream seeds a fresh detector whose baseline was already set
            // by an earlier commit; only rebase without double-counting.
            self.detector.rebase(sample);
        } else if matches!(trigger, Trigger::InitialSeed) {
            self.detector.commit_initial(sample);
        } else {
            self.detector.commit_baseline(sample, trigger);
        }
    }

    /// Test-only state duplication used by the clone-lab to model a VM clone:
    /// every byte of RNG/detector state is copied, exactly as a memory snapshot
    /// would copy it. The environment is shared so the fake clock can drive the
    /// detection.
    #[cfg(feature = "test-util")]
    pub fn snapshot_clone(&self) -> SnapRng {
        Self {
            inner: self.inner.clone(),
            detector: self.detector.clone(),
            env: Arc::clone(&self.env),
            seeded: self.seeded,
        }
    }

    /// Point this RNG at a different (cloned) environment. Test-only: models a
    /// cloned RNG image waking up inside a distinct guest with its own clocks.
    #[cfg(feature = "test-util")]
    pub fn attach_env(&mut self, env: Arc<dyn Env>) {
        self.env = env;
    }
}

impl Default for SnapRng {
    fn default() -> Self {
        Self::new()
    }
}

// -- rand_core integration -------------------------------------------------

impl TryRng for SnapRng {
    type Error = core::convert::Infallible;

    #[inline]
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.detector.account_bytes(4);
        self.ensure_fresh();
        Ok(self.inner.next_u32())
    }

    #[inline]
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.detector.account_bytes(8);
        self.ensure_fresh();
        Ok(self.inner.next_u64())
    }

    #[inline]
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.detector.account_bytes(dst.len());
        self.ensure_fresh();
        self.inner.fill_bytes(dst);
        Ok(())
    }
}

impl TryCryptoRng for SnapRng {}

// `Rng` and `CryptoRng` are blanket-implemented for `TryRng<Error=Infallible>`
// in rand_core 0.10, so SnapRng satisfies both automatically.
fn _assert_traits(r: &SnapRng) {
    fn _dyn_safe(_: &dyn Rng) {}
    fn _crypto(_: &dyn CryptoRng) {}
    _dyn_safe(r);
    _crypto(r);
}

impl SeedableRng for SnapRng {
    type Seed = [u8; 32];

    /// Build from a caller-provided 32-byte seed. The seed is treated as
    /// *additional* entropy on top of the platform sources, never as the sole
    /// key material — two clones given the same caller seed still diverge.
    fn from_seed(seed: Self::Seed) -> Self {
        let mut rng = SnapRng::new();
        let sample = rng.env.sample();
        rng.reseed(sample, Some(&seed), Trigger::InitialSeed);
        rng
    }
}

// -- global environment ----------------------------------------------------

static GLOBAL_ENV: std::sync::OnceLock<Arc<OsEnv>> = std::sync::OnceLock::new();
static WATCHDOG_BOOT: std::sync::Once = std::sync::Once::new();

/// Shared process-wide environment (one mmap sentinel, one vmgenid probe).
pub fn global_env() -> Arc<OsEnv> {
    Arc::clone(GLOBAL_ENV.get_or_init(|| Arc::new(OsEnv::new())))
}

/// Start the background watchdog once. Called automatically by the thread-
/// local RNG; exposed for callers who only use owned [`SnapRng`] instances.
pub fn spawn_watchdog() {
    #[cfg(feature = "watchdog")]
    WATCHDOG_BOOT.call_once(|| {
        let env: Arc<dyn Env> = global_env();
        crate::watchdog::spawn(env, DetectorConfig::default());
    });
}

// -- thread-local RNG ------------------------------------------------------

/// Handle to the thread-local [`SnapRng`]. Mirrors `rand::rngs::ThreadRng`:
/// a lightweight wrapper that derefs to the per-thread generator.
#[derive(Debug)]
pub struct ThreadSnapRng {
    // !Send + !Sync, same as rand's ThreadRng.
    _not_send: core::marker::PhantomData<core::cell::Cell<()>>,
}

impl ThreadSnapRng {
    fn with<R>(&self, f: impl FnOnce(&mut SnapRng) -> R) -> R {
        THREAD_RNG.with(|cell| {
            let mut slot = cell.borrow_mut();
            if slot.is_none() {
                spawn_watchdog();
                *slot = Some(SnapRng::with_env(global_env()));
            }
            f(slot.as_mut().expect("just initialized"))
        })
    }
}

thread_local! {
    static THREAD_RNG: core::cell::RefCell<Option<SnapRng>> =
        const { core::cell::RefCell::new(None) };
}

impl TryRng for ThreadSnapRng {
    type Error = core::convert::Infallible;

    #[inline]
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.with(|r| r.try_next_u32())
    }

    #[inline]
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.with(|r| r.try_next_u64())
    }

    #[inline]
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.with(|r| r.try_fill_bytes(dst))
    }
}

impl TryCryptoRng for ThreadSnapRng {}

/// Return the thread-local snapshot-aware RNG. Drop-in name-for-name
/// replacement for `rand::rng()`.
#[inline]
pub fn rng() -> ThreadSnapRng {
    ThreadSnapRng {
        _not_send: core::marker::PhantomData,
    }
}

/// Explicit alias kept for readers migrating from rand 0.8 terminology.
#[inline]
pub fn thread_rng() -> ThreadSnapRng {
    rng()
}

// -- free functions mirroring rand's --------------------------------------

/// Generate a random value of any type implementing rand's standard
/// distribution. Drop-in replacement for `rand::random()`.
pub fn random<T>() -> T
where
    rand::distr::StandardUniform: rand::distr::Distribution<T>,
{
    use rand::RngExt;
    rng().random()
}

/// Fill a byte slice via the thread-local RNG (`rand::fill` equivalent).
pub fn fill_bytes(dst: &mut [u8]) {
    use rand_core::Rng;
    rng().fill_bytes(dst);
}
