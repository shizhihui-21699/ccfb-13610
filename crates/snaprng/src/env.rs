//! Environment abstraction.
//!
//! Every signal source the detector relies on goes through the [`Env`] trait so
//! that the clone-lab can deterministically simulate snapshot rollback, clock
//! jumps and hypervisor generation-ID changes without a real hypervisor.

#[cfg(target_os = "linux")]
use core::sync::atomic::{AtomicBool, Ordering};

/// Monotonic clock reading, nanoseconds since an arbitrary epoch.
pub type Nano = u64;

/// Snapshot of every external signal the detector samples on each draw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvSample {
    /// `CLOCK_MONOTONIC`-style time (suspended time excluded).
    pub monotonic_ns: Nano,
    /// Wall-clock time (`CLOCK_REALTIME`-style), used via its *offset* against
    /// the monotonic clock, never on its own.
    pub wall_ns: Nano,
    /// OS process id (changes across `fork`; stable across snapshot restore).
    pub pid: u32,
    /// Hypervisor VM Generation ID, `None` when no device exists.
    /// Any change, including a shorter/zero value, means a restore event.
    pub vm_generation_id: Option<[u8; 16]>,
    /// Content of the `MADV_WIPEONFORK` sentinel page (Linux).
    /// Zero means the page was wiped by a `fork`.
    pub fork_sentinel: [u8; 8],
}

/// Read-only access to the outside world.
///
/// The real implementation is [`OsEnv`]. Tests and the clone-lab use
/// in-memory fakes implementing the same trait.
pub trait Env: Send + Sync {
    /// Sample every signal at once, so a single draw reasons about one
    /// consistent point in time.
    fn sample(&self) -> EnvSample;

    /// Best-effort monotonic timestamp for watchdog periodicity. Implementations
    /// that have no clock may return 0.
    fn now_monotonic(&self) -> Nano {
        self.sample().monotonic_ns
    }
}

// ---------------------------------------------------------------------------
// Real OS environment
// ---------------------------------------------------------------------------

/// Production environment backed by libc clocks, `/proc` and (on Linux) the
/// `MADV_WIPEONFORK` sentinel page.
pub struct OsEnv {
    /// Page whose first 8 bytes are nonzero; the kernel zeroes it on fork when
    /// `MADV_WIPEONFORK` is supported.
    #[cfg(all(feature = "wipe-on-fork", target_os = "linux"))]
    sentinel: *mut libc::c_void,
    /// Set if the kernel rejected `MADV_WIPEONFORK` (pre-4.14 kernels);
    /// the sentinel is then meaningless and must be ignored.
    #[cfg(all(feature = "wipe-on-fork", target_os = "linux"))]
    sentinel_broken: AtomicBool,
    /// Open fd on the VM Generation ID sysfs file, if present. Opened once at
    /// construction so the per-draw read path never touches the allocator.
    #[cfg(all(feature = "vmgenid", target_os = "linux"))]
    vmgenid_fd: Option<std::os::fd::RawFd>,
}

// The raw pointer is only ever dereferenced inside this crate; access is
// synchronized by the detector mutex and the pointer itself never changes
// after construction.
unsafe impl Send for OsEnv {}
unsafe impl Sync for OsEnv {}

/// Sentinel bytes installed in the `MADV_WIPEONFORK` page; also returned as
/// the neutral "no information" value on platforms without that mechanism.
const SENTINEL_MAGIC: [u8; 8] = *b"SNAPRNG1";

impl OsEnv {
    /// Construct the production environment, allocating OS resources once.
    pub fn new() -> Self {
        #[cfg(all(feature = "wipe-on-fork", target_os = "linux"))]
        {
            // One anonymous page, advised WIPEONFORK so the kernel zeroes it
            // whenever this process forks. mmap is async-signal-safe enough for
            // one-time setup; we never touch the heap in the fork child.
            let page = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    libc::sysconf(libc::_SC_PAGESIZE) as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            let broken = AtomicBool::new(page == libc::MAP_FAILED);
            if page != libc::MAP_FAILED {
                let rc = unsafe {
                    libc::madvise(
                        page,
                        libc::sysconf(libc::_SC_PAGESIZE) as usize,
                        libc::MADV_WIPEONFORK,
                    )
                };
                if rc == 0 {
                    unsafe {
                        core::ptr::copy_nonoverlapping(SENTINEL_MAGIC.as_ptr(), page as *mut u8, 8)
                    };
                } else {
                    // EINVAL on kernels predating 4.14: fall back to pid/atfork.
                    broken.store(true, Ordering::Relaxed);
                }
            }
            Self {
                sentinel: page,
                sentinel_broken: broken,
                #[cfg(all(feature = "vmgenid", target_os = "linux"))]
                vmgenid_fd: open_vmgenid(),
            }
        }
        #[cfg(not(all(feature = "wipe-on-fork", target_os = "linux")))]
        {
            Self {
                #[cfg(all(feature = "vmgenid", target_os = "linux"))]
                vmgenid_fd: open_vmgenid(),
            }
        }
    }

    #[cfg(all(feature = "wipe-on-fork", target_os = "linux"))]
    fn read_sentinel(&self) -> [u8; 8] {
        if self.sentinel_broken.load(Ordering::Relaxed) || self.sentinel == libc::MAP_FAILED {
            // A constant nonzero value means "no information": it can never
            // look like a wipe, and the other signals still cover forks.
            return SENTINEL_MAGIC;
        }
        let mut out = [0u8; 8];
        unsafe { core::ptr::copy_nonoverlapping(self.sentinel as *const u8, out.as_mut_ptr(), 8) };
        out
    }

    #[cfg(not(all(feature = "wipe-on-fork", target_os = "linux")))]
    fn read_sentinel(&self) -> [u8; 8] {
        SENTINEL_MAGIC
    }
}

impl Default for OsEnv {
    fn default() -> Self {
        Self::new()
    }
}

impl Env for OsEnv {
    fn sample(&self) -> EnvSample {
        let (monotonic_ns, wall_ns) = os_clocks();
        EnvSample {
            monotonic_ns,
            wall_ns,
            pid: os_pid(),
            vm_generation_id: self.read_vmgenid(),
            fork_sentinel: self.read_sentinel(),
        }
    }
}

// -- clocks ----------------------------------------------------------------

#[cfg(target_os = "linux")]
fn os_clocks() -> (Nano, Nano) {
    fn clk(kind: libc::clockid_t) -> Nano {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if unsafe { libc::clock_gettime(kind, &mut ts) } != 0 {
            return 0;
        }
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    }
    (clk(libc::CLOCK_MONOTONIC), clk(libc::CLOCK_REALTIME))
}

#[cfg(not(target_os = "linux"))]
fn os_clocks() -> (Nano, Nano) {
    // macOS/BSD: clock_gettime is available on all supported versions.
    fn clk(kind: libc::clockid_t) -> Nano {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if unsafe { libc::clock_gettime(kind, &mut ts) } != 0 {
            return 0;
        }
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    }
    (clk(libc::CLOCK_MONOTONIC), clk(libc::CLOCK_REALTIME))
}

fn os_pid() -> u32 {
    unsafe { libc::getpid() as u32 }
}

// -- VM Generation ID ------------------------------------------------------

#[cfg(all(feature = "vmgenid", target_os = "linux"))]
fn vmgenid_candidates() -> &'static [&'static str] {
    // The Linux vmgenid driver (kernel >= 6.6) exposes the 16-byte UUID here.
    // An explicit override is honored first so the lab can point at a fake.
    const DEFAULT: &[&str] = &[
        "/sys/devices/virtual/misc/vmgenid/id",
        "/sys/bus/acpi/devices/VMGENID:00/id",
    ];
    static OVERRIDE: std::sync::OnceLock<Option<&'static str>> = std::sync::OnceLock::new();
    if let Some(override_path) = OVERRIDE.get_or_init(|| {
        std::env::var_os("SNAPRNG_VMGENID_PATH")
            .and_then(|p| p.into_string().ok())
            .filter(|p| std::path::Path::new(p).is_file())
            .map(|p| &*Box::leak(p.into_boxed_str()))
    }) {
        // SAFETY: a one-element slice of a 'static reference is itself 'static.
        std::slice::from_ref(override_path)
    } else if std::env::var_os("SNAPRNG_VMGENID_PATH").is_some() {
        // Override explicitly set but invalid: do not fall back to defaults.
        &[]
    } else {
        DEFAULT
    }
}

/// Open the vmgenid file once. All allocation happens here, at construction;
/// the per-draw read uses the raw fd and a stack buffer.
#[cfg(all(feature = "vmgenid", target_os = "linux"))]
fn open_vmgenid() -> Option<std::os::fd::RawFd> {
    use std::os::fd::IntoRawFd;
    for path in vmgenid_candidates() {
        if let Ok(f) = std::fs::File::open(path) {
            return Some(f.into_raw_fd());
        }
    }
    None
}

#[cfg(all(feature = "vmgenid", target_os = "linux"))]
impl Drop for OsEnv {
    fn drop(&mut self) {
        if let Some(fd) = self.vmgenid_fd.take() {
            // Best effort; a process teardown would close it anyway.
            unsafe { libc::close(fd) };
        }
    }
}

#[cfg(all(feature = "vmgenid", target_os = "linux"))]
impl OsEnv {
    /// Read and parse the 16-byte UUID without any heap allocation. The sysfs
    /// file renders 36 ASCII characters (32 hex digits + 4 hyphens + newline).
    fn read_vmgenid(&self) -> Option<[u8; 16]> {
        let fd = self.vmgenid_fd?;
        // Seek back to the start so repeated reads re-read the whole record.
        unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
        let mut buf = [0u8; 64];
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            return None;
        }
        let raw = &buf[..n as usize];

        let mut hex = [0u8; 32];
        let mut written = 0usize;
        for &b in raw {
            if b == b'-' || b.is_ascii_whitespace() {
                continue;
            }
            *hex.get_mut(written)? = b;
            written += 1;
        }
        if written != 32 {
            return None;
        }
        let mut out = [0u8; 16];
        for (i, pair) in hex.chunks(2).enumerate() {
            let hi = (pair[0] as char).to_digit(16)?;
            let lo = (pair[1] as char).to_digit(16)?;
            out[i] = (hi << 4 | lo) as u8;
        }
        Some(out)
    }
}

#[cfg(not(all(feature = "vmgenid", target_os = "linux")))]
impl OsEnv {
    fn read_vmgenid(&self) -> Option<[u8; 16]> {
        None
    }
}
