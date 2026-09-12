//! Repro: one sys_mmap breaks the next vsock connect.
//! Expected (bug): "echo #1 ok" prints, then the program hangs inside the
//! second connect/read. Expected (fixed): both echos print, exit 0.
//!
//! Pass `munmap` as the first program argument to additionally run the
//! Issue B frame-corruption check (mmap/munmap frame accounting).

#[cfg(target_os = "hermit")]
use hermit as _;

use std::mem::size_of;

use hermit_abi::{connect, read, sockaddr, sockaddr_vm, socket, write, AF_VSOCK, SOCK_STREAM};

const HOST_CID: u32 = 2;
const PORT: u32 = 9975;

/// Blocking vsock echo round-trip via raw hermit-abi calls.
fn vsock_echo(tag: &str) {
    unsafe {
        let fd = socket(AF_VSOCK, SOCK_STREAM, 0);
        assert!(fd >= 0, "socket() failed");
        let addr = sockaddr_vm {
            svm_len: size_of::<sockaddr_vm>() as u8,
            svm_family: AF_VSOCK as _,
            svm_reserved1: 0,
            svm_cid: HOST_CID,
            svm_port: PORT,
            svm_zero: [0; 4],
        };
        let r = connect(
            fd,
            &addr as *const _ as *const sockaddr,
            size_of::<sockaddr_vm>() as u32,
        );
        assert!(r >= 0, "connect() failed");

        let msg = b"ping\n";
        let n = write(fd, msg.as_ptr(), msg.len());
        assert_eq!(n as usize, msg.len(), "short write");

        let mut buf = [0u8; 8];
        let n = read(fd, buf.as_mut_ptr(), buf.len());
        assert!(n > 0, "read failed/EOF");
        println!(
            "echo {tag} ok: {:?}",
            core::str::from_utf8(&buf[..n as usize])
        );
    }
}

/// Issue B check: munmap must free exactly the frames backing the unmapped
/// range, not `[first_phys, first_phys + size)`.
fn munmap_frame_check() {
    let mut a: *mut u8 = core::ptr::null_mut();
    let mut b: *mut u8 = core::ptr::null_mut();
    unsafe {
        assert_eq!(hermit_abi::mmap(0x4000, 0b011, &mut a), 0);
        assert_eq!(hermit_abi::mmap(0x4000, 0b011, &mut b), 0);
        b.write_bytes(0xBB, 0x4000);
        assert_eq!(hermit_abi::munmap(a, 0x4000), 0);
        // Force fresh allocations that may receive b's frames if they were
        // wrongly freed:
        let mut c: *mut u8 = core::ptr::null_mut();
        assert_eq!(hermit_abi::mmap(0x4000, 0b011, &mut c), 0);
        c.write_bytes(0xCC, 0x4000);
        // BUG if this fails: b's contents were clobbered through c.
        assert!(
            core::slice::from_raw_parts(b, 0x4000).iter().all(|&x| x == 0xBB),
            "Issue B: b's frames were re-handed-out after munmap(a)"
        );
        assert_eq!(hermit_abi::munmap(b, 0x4000), 0);
        assert_eq!(hermit_abi::munmap(c, 0x4000), 0);
    }
    println!("munmap frame check ok");
}

fn main() {
    let run_munmap_check = std::env::args().any(|a| a == "munmap");

    vsock_echo("#1 (pre-mmap)");

    // THE trigger: one page, any protection.
    let mut ptr: *mut u8 = core::ptr::null_mut();
    let rc = unsafe { hermit_abi::mmap(0x1000, 0b111 /* R|W|X */, &mut ptr) };
    assert_eq!(rc, 0, "sys_mmap failed");
    println!("mmap'd one page at {ptr:p}");
    // Touch it so the mapping is demonstrably live.
    unsafe { ptr.write_volatile(0xAA) };

    vsock_echo("#2 (post-mmap)"); // <-- hangs here with the bug

    if run_munmap_check {
        munmap_frame_check();
        vsock_echo("#3 (post-munmap)");
    }

    println!("DONE — no collision");
}
