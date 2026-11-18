//! VM Generation ID device reading via the `SNAPRNG_VMGENID_PATH` override.
//!
//! Linux-only: the override points `OsEnv` at a regular file standing in for
//! the sysfs UUID record, exercising the fd-based allocation-free read path.
//! The override is read once per process (matching production init), so each
//! test pins exactly one id; rotation is verified by rewriting the file the
//! open fd already points at, which is what the hypervisor does in place.
#![cfg(all(feature = "test-util", target_os = "linux"))]

use snaprng::Env;
use std::io::{Seek, Write};

fn temp_path(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("snaprng-vmgenid-{}-{}", std::process::id(), tag))
}

#[test]
fn os_env_parses_vmgenid_uuid() {
    let path = temp_path("parse");
    {
        let mut f = std::fs::File::create(&path).expect("create fake vmgenid file");
        writeln!(f, "11223344-5566-7788-99aa-bbccddeeff00").expect("write uuid");
    }
    std::env::set_var("SNAPRNG_VMGENID_PATH", &path);
    let env = snaprng::OsEnv::new();
    assert_eq!(
        env.sample().vm_generation_id,
        Some([
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00
        ])
    );
    std::env::remove_var("SNAPRNG_VMGENID_PATH");
    let _ = std::fs::remove_file(path);
}

#[test]
fn fd_picks_up_in_place_id_rotation() {
    let path = temp_path("rotate");
    let mut f = std::fs::File::create(&path).expect("create fake vmgenid file");
    writeln!(f, "11223344-5566-7788-99aa-bbccddeeff00").expect("write first uuid");
    std::env::set_var("SNAPRNG_VMGENID_PATH", &path);

    let env = snaprng::OsEnv::new();
    let first = env.sample().vm_generation_id;

    // Hypervisor updates the same file in place; the cached fd must see the new
    // contents because read_vmgenid re-seeks before every read.
    f.seek(std::io::SeekFrom::Start(0)).unwrap();
    writeln!(f, "ffeeddcc-bbaa-9988-7766-554433221100").expect("write second uuid");
    f.set_len(37).unwrap(); // trim if the new record were shorter
    drop(f);

    let second = env.sample().vm_generation_id;
    assert_ne!(first, second);
    assert_eq!(
        second,
        Some([
            0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
            0x11, 0x00
        ])
    );
    std::env::remove_var("SNAPRNG_VMGENID_PATH");
    let _ = std::fs::remove_file(path);
}

#[test]
fn malformed_vmgenid_yields_none_without_panicking() {
    let path = temp_path("bad");
    std::fs::write(&path, b"not-a-uuid\n").expect("write bad uuid");
    std::env::set_var("SNAPRNG_VMGENID_PATH", &path);
    let env = snaprng::OsEnv::new();
    assert_eq!(env.sample().vm_generation_id, None);
    std::env::remove_var("SNAPRNG_VMGENID_PATH");
    let _ = std::fs::remove_file(path);
}
