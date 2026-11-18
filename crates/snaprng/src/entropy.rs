//! Entropy collection and seed mixing.
//!
//! A reseed never trusts a single source. Independent contributors are fed
//! into a SHA-256 sponge-style mixer so the failure or predictability of any
//! one of them cannot make two clones derive the same seed:
//!
//! 1. `getrandom` — the platform CSPRNG (`getrandom(2)` / `BCryptGenRandom`).
//! 2. RDSEED/RDRAND on x86 with runtime CPUID gating.
//! 3. Scheduler/clock jitter measured locally (works even when the OS entropy
//!    source was itself duplicated by a snapshot).
//! 4. The current environment sample — pid, clocks, VM generation id — plus
//!    an address from the allocator, which differs across independent
//!    processes/address-space layouts.

use crate::env::EnvSample;
use sha2::{Digest, Sha256};

/// Number of ChaCha20 seed bytes (256-bit key).
pub const SEED_LEN: usize = 32;

/// Accumulates entropy contributions. Every `feed` domain-separates its input
/// so identical bytes arriving through different channels cannot cancel out.
pub struct Mixer {
    hasher: Sha256,
    fed: usize,
}

impl Mixer {
    pub fn new() -> Self {
        let mut hasher = Sha256::new();
        // Domain prefix binds the digest to this construction.
        hasher.update(b"snaprng-seed-v1");
        Self { hasher, fed: 0 }
    }

    /// Add one labeled contribution.
    pub fn feed(&mut self, label: &[u8], data: &[u8]) {
        let len = (data.len() as u64).to_le_bytes();
        self.hasher.update(label);
        self.hasher.update(len);
        self.hasher.update(data);
        self.fed += 1;
    }

    fn feed_u64(&mut self, label: &[u8], v: u64) {
        self.feed(label, &v.to_le_bytes());
    }

    /// Finalize a 32-byte seed. When more than 32 bytes are needed (callers may
    /// request extra key material), expand via counter mode over the digest.
    pub fn finish(mut self, out: &mut [u8]) {
        self.feed(b"contrib-count", &(self.fed as u64).to_le_bytes());
        let base = self.hasher.finalize();
        let mut counter = 0u32;
        let mut written = 0;
        while written < out.len() {
            let mut h = Sha256::new();
            h.update(b"snaprng-expand-v1");
            h.update(base);
            h.update(counter.to_le_bytes());
            let block = h.finalize();
            let take = core::cmp::min(block.len(), out.len() - written);
            out[written..written + take].copy_from_slice(&block[..take]);
            written += take;
            counter += 1;
        }
    }
}

impl Default for Mixer {
    fn default() -> Self {
        Self::new()
    }
}

/// Gather every entropy source available on this platform into `mixer`.
///
/// `sample` is the environment reading taken for the same draw, guaranteeing
/// the reseed is bound to post-event conditions (new pid, new clock values).
pub fn gather(mixer: &mut Mixer, sample: EnvSample) {
    // 1. Platform CSPRNG. Two independent blocks; a short read is retried by
    //    getrandom itself. A hard failure is *not* fatal: the remaining sources
    //    plus the mandatory jitter still differentiate clones.
    let mut os_buf = [0u8; 64];
    match getrandom::fill(&mut os_buf) {
        Ok(()) => mixer.feed(b"getrandom", &os_buf),
        Err(_) => mixer.feed(b"getrandom-failed", b"unavailable"),
    }
    zeroize(&mut os_buf);

    // 2. CPU hardware entropy (x86-64 only; runtime-detected).
    #[cfg(all(feature = "rdseed", target_arch = "x86_64"))]
    {
        if let Some(hw) = hardware_entropy() {
            mixer.feed(b"rdseed-rdrand", &hw);
        }
    }

    // 3. Local timing jitter. Even inside a freshly cloned VM where clocks were
    //    restored, instruction/scheduling timing diverges immediately between
    //    instances. The loop's iteration count and per-iteration deltas both
    //    carry entropy; we mix raw timing samples rather than a hash of them.
    let jitter = measure_jitter();
    mixer.feed(b"jitter", &jitter);

    // 4. Environment signals and address-space fingerprint.
    mixer.feed_u64(b"monotonic-ns", sample.monotonic_ns);
    mixer.feed_u64(b"wall-ns", sample.wall_ns);
    mixer.feed_u64(b"pid", sample.pid as u64);
    if let Some(id) = sample.vm_generation_id {
        mixer.feed(b"vmgenid", &id);
    }
    mixer.feed(b"fork-sentinel", &sample.fork_sentinel);

    // Address-space fingerprint WITHOUT touching the allocator: addresses of a
    // stack local and a static item are ASLR-randomized per independent exec,
    // so they differentiate separately launched processes. They are identical
    // across fork (address space is copied), which is fine — pid, jitter and
    // the OS entropy sources already differentiate a forked child. Keeping
    // these off the heap makes the whole reseed path malloc-free and therefore
    // safe to run in a forked child even if a malloc lock was held at fork.
    let stack_marker = 0u64;
    mixer.feed_u64(b"stack-addr", raw_addr(&stack_marker));
    mixer.feed_u64(b"static-addr", raw_addr(&STATIC_ANCHOR));
}

/// A data-segment anchor whose address carries ASLR entropy; never dereferenced.
static STATIC_ANCHOR: u64 = 0x53_4e_41_50;

fn raw_addr<T>(p: *const T) -> u64 {
    p.addr() as u64
}

/// Overwrite a buffer; best effort without adding a zeroize dependency.
fn zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    // Prevent the compiler from eliding the writes on stable Rust.
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

// -- timing jitter ---------------------------------------------------------

const JITTER_ROUNDS: usize = 32;
const JITTER_BYTES: usize = JITTER_ROUNDS * 16;

/// Collect raw high-resolution timing samples with deliberately variable work
/// between them. Returns a fixed stack buffer of little-endian u64 pairs
/// (per-round delta and absolute timestamp) — deliberately allocation-free so
/// it is safe inside a post-fork child.
fn measure_jitter() -> [u8; JITTER_BYTES] {
    let mut out = [0u8; JITTER_BYTES];
    let mut last = fine_now();
    let mut acc = 0u64;
    for i in 0..JITTER_ROUNDS {
        // Variable-amount work so the scheduler can interleave at different
        // points in each clone.
        let spins = 1 + (i % 7);
        for _ in 0..spins {
            acc = acc
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            core::hint::black_box(acc);
        }
        let now = fine_now();
        let delta = now.wrapping_sub(last);
        last = now;
        let base = i * 16;
        out[base..base + 8].copy_from_slice(&delta.to_le_bytes());
        out[base + 8..base + 16].copy_from_slice(&now.to_le_bytes());
    }
    // Fold the accumulator so it cannot be optimized away.
    core::hint::black_box(acc);
    out
}

/// Highest-resolution monotonic timestamp the platform offers.
fn fine_now() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if rc != 0 {
        return 0;
    }
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

// -- x86 hardware entropy --------------------------------------------------

#[cfg(all(feature = "rdseed", target_arch = "x86_64"))]
mod x86 {
    use core::arch::x86_64::{__cpuid, __cpuid_count, _rdrand64_step, _rdseed64_step};

    /// Gather RDSEED (preferred) with RDRAND fallback, gated by CPUID.
    /// Returns 8 u64 words = 64 bytes, or `None` if neither is advertised.
    #[allow(unused_unsafe)] // __cpuid became safe on newer toolchains
    pub fn collect() -> Option<[u8; 64]> {
        // Leaf 7, subleaf 0, EBX bit 18 = RDSEED; leaf 1, ECX bit 30 = RDRAND.
        let features_ecx = unsafe { __cpuid(1) }.ecx;
        let rdrand = features_ecx & (1 << 30) != 0;
        let features_ebx = unsafe { __cpuid_count(7, 0) }.ebx;
        let rdseed = features_ebx & (1 << 18) != 0;
        if !rdrand && !rdseed {
            return None;
        }

        let mut words = [0u64; 8];
        for slot in words.iter_mut() {
            let mut word = 0u64;
            let mut ok = false;
            if rdseed {
                // RDSEED can legitimately fail under contention; retry briefly.
                for _ in 0..16 {
                    if unsafe { _rdseed64_step(&mut word) } == 1 {
                        ok = true;
                        break;
                    }
                }
            }
            if !ok && rdrand {
                for _ in 0..16 {
                    if unsafe { _rdrand64_step(&mut word) } == 1 {
                        ok = true;
                        break;
                    }
                }
            }
            // Even one failed slot does not poison the pool: record a timing
            // value instead and let the other sources carry the entropy.
            if !ok {
                word = fine_now_fallback();
            }
            *slot = word;
        }
        let mut out = [0u8; 64];
        for (i, w) in words.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        Some(out)
    }

    fn fine_now_fallback() -> u64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 {
            return 0;
        }
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    }
}

#[cfg(all(feature = "rdseed", target_arch = "x86_64"))]
fn hardware_entropy() -> Option<[u8; 64]> {
    x86::collect()
}
