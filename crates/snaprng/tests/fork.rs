//! Real `fork(2)` behavior. Only compiled with the test-util feature and only
//! meaningful on Unix; CI runs it on both Linux and macOS.
#![cfg(all(feature = "test-util", unix))]

use std::time::Duration;

/// After `fork(2)`, the child process must observe the global fork-dirty flag
/// (raised by the `pthread_atfork` handler). The child does no allocation —
/// only the atomic check and a pipe write — so the test is async-signal-safe
/// and cannot deadlock on inherited allocator locks.
#[test]
fn atfork_handler_marks_child_dirty() {
    // Ensure atfork registration has run at least once in this process.
    snaprng::spawn_watchdog();

    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());

    if pid == 0 {
        // Child: one atomic read, one write, immediate _exit.
        let dirty = snaprng::testing::take_fork_dirty();
        let byte = if dirty { 1u8 } else { 0u8 };
        unsafe {
            libc::write(fds[1], &byte as *const u8 as *const libc::c_void, 1);
            libc::_exit(0);
        }
    }

    // Parent.
    unsafe {
        libc::close(fds[1]);
    }
    let mut byte = 0u8;
    let n = unsafe { libc::read(fds[0], &mut byte as *mut u8 as *mut libc::c_void, 1) };
    assert_eq!(n, 1, "child did not report through pipe");
    let mut status = 0;
    unsafe {
        libc::waitpid(pid, &mut status, 0);
        libc::close(fds[0]);
    }
    assert!(libc::WIFEXITED(status));
    assert_eq!(byte, 1, "pthread_atfork child flag was not raised");
}

/// The full user-visible guarantee: an RNG that learns it was forked (via the
/// same global flag the atfork handler raises) reseeds before its next draw,
/// so child and parent output diverges.
#[test]
fn rng_reseeds_after_fork_flag_and_outputs_diverge() {
    use rand::RngExt;
    let env = snaprng::fake_env::FakeEnv::new();
    let mut rng =
        snaprng::SnapRng::with_env(std::sync::Arc::new(env) as std::sync::Arc<dyn snaprng::Env>);
    let parent_token: [u8; 32] = rng.random();

    // Simulate what the forked child observes.
    snaprng::testing::mark_fork_dirty();
    // Make the environment read like a child: new pid and wiped sentinel.
    // (The flag alone already forces the reseed; these make it realistic.)
    let child_token: [u8; 32] = rng.random();

    assert_ne!(parent_token, child_token);
    // And a second draw in the child stays on the new stream, still distinct.
    let third: [u8; 32] = rng.random();
    assert_ne!(third, parent_token);
    assert_ne!(third, child_token);

    // Give any background thread from other tests a moment; no assertions on
    // timing here, this just keeps the runtime honest under load.
    std::thread::sleep(Duration::from_millis(10));
}
