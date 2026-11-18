//! Drop-in migration demo: the same shapes of call production code makes
//! against `rand`, now served by the snapshot-aware generator.
//!
//! Run with: `cargo run -p snaprng --example migration`

use snaprng::prelude::*;

/// A session-key issuer written entirely against the standard rand traits,
/// so it accepts `rand::rng()` today and `snaprng::rng()` without changes.
fn issue_session_key<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> [u8; 32] {
    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);
    key
}

fn main() {
    // 1. Thread-local generator — replacement for `rand::rng()`.
    let mut rng = snaprng::rng();
    let key = issue_session_key(&mut rng);
    println!(
        "session key: {} bytes, first byte = {:#04x}",
        key.len(),
        key[0]
    );

    // 2. RngExt convenience methods all work through the prelude.
    let nonce: u64 = rng.random();
    let coin = rng.random_bool(0.5);
    let jitter = rng.random_range(0..100);
    println!("nonce={nonce:#018x}, coin={coin}, jitter={jitter}");

    // 3. Free-function replacement for `rand::random()`.
    let token: u128 = snaprng::random();
    println!("random u128: {token:#034x}");

    // 4. Owned, struct-stored generator for long-lived services.
    let mut service_rng = SnapRng::new();
    let service_key: [u8; 16] = service_rng.random();
    println!(
        "service key: {service_key:02x?}, reseeds so far: {:?}",
        service_rng.reseed_counters()
    );

    // 5. Explicit reseed after a security-relevant boundary (e.g. privilege
    //    drop), independent of the automatic tripwires.
    service_rng.force_reseed();
    println!("after force_reseed: {:?}", service_rng.reseed_counters());
}
