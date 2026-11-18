# snaprng

Fork-, snapshot- and clone-aware CSPRNG for services that run in virtual
machines provisioned by cloning a golden snapshot.

## The problem

A VM snapshot copies memory verbatim, including the in-process state of every
random number generator. When dozens of machines are cloned from one running
image, they all wake up holding the **same ChaCha/HMAC-DRBG state** and emit
the same session keys and nonces until something happens to re-seed them.
`fork(2)` produces the identical hazard inside one machine: the child inherits
the parent's RNG byte-for-byte.

This crate wraps a ChaCha20 stream cipher with a set of independent
tripwires. Before **every** draw it checks whether the process was forked, the
VM was rolled back to a snapshot, or a running VM was cloned; on any suspicion
it re-seeds from fresh platform entropy *before emitting a single byte*.

## Detection signals and why each one is there

No single signal covers every cloning path, so the design is defense in
depth — any one tripwire firing is sufficient, and a false positive only costs
one extra reseed.

| Signal | Catches | Platform |
|---|---|---|
| `pthread_atfork` child flag | `fork(2)`, before any user code runs in the child | all Unix |
| pid change vs. seed-time baseline | fork/clone without `exec` | all |
| `MADV_WIPEONFORK` sentinel page | fork including `clone(CLONE_VM)`; kernel-zeroed, cannot be spoofed by userspace | Linux ≥ 4.14 |
| monotonic clock rewind | snapshot restore that rewinds time | all |
| wall−monotonic offset jump | restore where monotonic is preserved but wall time steps (NTP-corrected resume) | all |
| monotonic stall over a long wall gap | VM paused then resumed with a frozen clock | all |
| hypervisor VM Generation ID | authoritative hypervisor-generated ID rotated on every restore/linked clone | Linux ≥ 6.6 guests with vmgenid |
| background watchdog (10 Hz) | events that happen while the process draws nothing | all |

### Trade-offs that were deliberately accepted

- **Bias toward false positives over false negatives.** An extra reseed is
  microseconds of work; a missed event is a duplicated key. Clock thresholds
  (250 ms offset, 1 s stall gap) sit well above NTP slew/scheduler jitter but
  far below any real restore discontinuity.
- **Wall clock is never trusted alone.** It is only used via its *offset* from
  the monotonic clock, so manual `date` changes and NTP steps inside normal
  bounds do not fire, while a snapshot-induced discontinuity does.
- **VM Generation ID is the strongest signal but the least universally
  available.** On guests without the device, clock and identity tripwires
  still cover every event that changes an observable signal.
- **The watchdog is best-effort.** Spawn failure degrades to per-draw
  detection; per-draw checks alone already cover every event before the next
  output, which is the actual guarantee.
- **Entropy is never taken from one source.** Each reseed mixes platform
  `getrandom`, x86 RDSEED/RDRAND when present, local timing jitter, pid/clock
  values, and address-space fingerprints through SHA-256. A snapshot that
  duplicates the OS entropy pool still cannot make two clones derive the same
  seed, because jitter and addresses diverge immediately post-restore.
- **The reseed path is allocation-free.** A multithreaded process can hold an
  allocator lock at `fork(2)` time, so calling `malloc` in the child before
  `exec` can deadlock. Entropy is gathered into fixed stack buffers, the
  vmgenid file is read through a cached fd, and address fingerprints use
  stack/static rather than heap pointers — reseed never touches the allocator.
  One-time setup (sentinel mmap, fd open, atfork registration) runs only at
  construction.

## The one residual case

If an adversary can copy memory **and** every observable signal (pid, both
clocks, vmgenid, the fork page) **and** force a draw before any of them
changes, there is no userspace-observable difference to detect. The lab
models this as the `undetectable clone` scenario and reports it honestly
rather than papering over it. Closing it deterministically requires something
the snapshot cannot capture: a vmgenid device, a sealed vTPM, or a network
entropy broker.

## Usage — drop-in replacement for rand

The public surface mirrors `rand` 0.10 name-for-name, and `SnapRng`
implements `rand_core::Rng + CryptoRng`, so every generic function bounded by
`R: Rng + CryptoRng + ?Sized` accepts it unchanged.

```toml
[dependencies]
snaprng = { path = "crates/snaprng" }
```

```rust
use snaprng::prelude::*;

// thread-local generator (was: rand::rng())
let key: [u8; 32] = snaprng::rng().random();

// free function (was: rand::random())
let nonce: u64 = snaprng::random();

// owned, struct-stored generator for long-lived services
let mut rng = SnapRng::new();
let token: [u8; 12] = rng.random();
rng.force_reseed(); // optional, for security boundaries
```

`snaprng::rng()` and `SnapRng` deliberately do **not** implement `Clone` —
cloning RNG state is the hazard being prevented. Use `SnapRng::fork_stream()`
to derive an independently seeded child stream.

A full migration demo lives in `crates/snaprng/examples/migration.rs`:

```sh
cargo run -p snaprng --example migration
```

## Clone laboratory

`crates/snaprng-lab` is a batch experiment harness. It builds one warmed-up
RNG, makes N byte-identical copies of its state (exactly what a memory
snapshot does), applies a modeled disaster to each copy's environment, draws
256-bit tokens from every clone, and counts collisions. The same experiment
runs against two unprotected baselines.

```sh
cargo run --release -p snaprng-lab -- --clones 50 --tokens-per-clone 4
cargo run -release -p snaprng-lab -- --json > report.json
```

Scenarios:

| Scenario | What changes in the restored guest |
|---|---|
| `snapshot rollback` | both clocks rewind + vmgenid rotates |
| `process fork` | pid changes + WIPEONFORK page zeroed |
| `running-VM linked clone` | clocks keep ticking; only vmgenid rotates |
| `pause/resume` | monotonic frozen, wall leaps hours, **no** vmgenid (proves clock tripwires alone suffice) |
| `undetectable clone` | nothing changes at all — documented residual risk |
| `no event` (control) | independent RNGs, normal time |

Representative result (100 clones × 4 tokens): every protected cell with a
detectable signal is collision-free while both baselines duplicate their
entire output stream; only the intentionally undetectable cell collides.

## Repository layout

```
crates/
  snaprng/       the library
    src/env.rs       OS signals: clocks, pid, WIPEONFORK page, vmgenid
    src/detect.rs    baseline comparison and trigger logic
    src/entropy.rs   entropy sources and SHA-256 seed mixer
    src/fork.rs      pthread_atfork registration and global dirty flag
    src/watchdog.rs  background sampling thread
    src/rng.rs       SnapRng, thread-local RNG, rand trait integration
    tests/           real fork(2), watchdog, drop-in and budget tests
    examples/        migration demo
  snaprng-lab/   batch clone experiment harness and collision statistics
```

## Testing

```sh
cargo test --workspace --features snaprng/test-util
cargo clippy --workspace --all-targets --features snaprng/test-util
cargo check -p snaprng --target x86_64-unknown-linux-gnu   # Linux-only paths
```

The `test-util` feature exposes the scriptable fake environment and state
cloning used by the lab; never enable it in production builds.
