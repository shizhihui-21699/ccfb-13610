//! Drop-in compatibility: every shape of call that exists against `rand` must
//! compile unchanged against `snaprng`.
#![cfg(feature = "test-util")]

use rand_core::{CryptoRng, Rng};

/// A generic consumer written against the standard rand traits accepts both
/// the owned and the thread-local snaprng RNG.
fn issue_session_key<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> [u8; 32] {
    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);
    key
}

#[test]
fn owned_rng_is_a_crypto_rng() {
    let mut rng = snaprng::SnapRng::new();
    let k1 = issue_session_key(&mut rng);
    let k2 = issue_session_key(&mut rng);
    assert_ne!(k1, [0u8; 32]);
    assert_ne!(k1, k2);
}

#[test]
fn thread_local_rng_is_a_crypto_rng() {
    let mut rng = snaprng::rng();
    let k1 = issue_session_key(&mut rng);
    let k2 = issue_session_key(&mut rng);
    assert_ne!(k1, k2);
}

#[test]
fn free_function_replacements_work() {
    // `snaprng::random` for `rand::random`.
    let a: u64 = snaprng::random();
    let b: u64 = snaprng::random();
    assert_ne!(a, b);

    // `snaprng::fill_bytes` for `rand::fill`.
    let mut buf = [0u8; 64];
    snaprng::fill_bytes(&mut buf);
    assert!(buf.iter().any(|b| *b != 0));
}

#[test]
fn rng_ext_methods_are_available_through_prelude() {
    use snaprng::prelude::*;
    let mut rng = rng();
    let _x: u32 = rng.random();
    let _y: f64 = rng.random_range(0.0..1.0);
    let _z = rng.random_bool(0.5);
    let mut v = [1u32, 2, 3, 4];
    v.shuffle(&mut rng);
    let _ = v;
}

#[test]
fn dyn_rng_trait_object_works() {
    let mut owned = snaprng::SnapRng::new();
    let boxed: Box<dyn Rng> = Box::new(snaprng::rng());
    let mut from_box = boxed;
    let mut key = [0u8; 16];
    from_box.fill_bytes(&mut key);
    let _ = issue_session_key(&mut owned);
    assert!(key.iter().any(|b| *b != 0));
}
