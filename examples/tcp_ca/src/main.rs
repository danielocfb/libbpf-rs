// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#![allow(clippy::let_unit_value)]

use std::ffi::c_int;
use std::ffi::c_void;
use std::ffi::OsStr;
use std::io;
use std::io::Read as _;
use std::io::Write as _;
use std::mem::MaybeUninit;
use std::mem::swap;
use std::net::TcpListener;
use std::net::TcpStream;
use std::os::fd::AsFd as _;
use std::os::fd::AsRawFd as _;
use std::os::fd::BorrowedFd;
use std::os::unix::ffi::OsStrExt as _;
use std::thread;

use clap::Parser;

use the_original_libbpf_rs::skel::SkelBuilder;
use the_original_libbpf_rs::ErrorExt as _;
use the_original_libbpf_rs::Result;

use libc::setsockopt;
use libc::IPPROTO_TCP;
use libc::TCP_CONGESTION;

use crate::tcp_ca::TcpCaSkelBuilder;

mod tcp_ca {
    // Skeleton rely on `libbpf_rs` being present in their "namespace". Because
    // we renamed the libbpf-rs dependency, we have to make it available under
    // the expected name here for the skeleton itself to work. None of this is
    // generally necessary, but it enables some niche use cases.
    use the_original_libbpf_rs as libbpf_rs;

    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/tcp_ca.skel.rs"
    ));
}

const TCP_CA_UPDATE: &str = "tcp_ca_update";

/// An example program adding a TCP congestion algorithm.
#[derive(Debug, Parser)]
struct Args {
    /// Verbose debug output
    #[arg(short, long)]
    verbose: bool,
}

fn set_sock_opt(
    fd: BorrowedFd<'_>,
    level: c_int,
    name: c_int,
    value: *const c_void,
    opt_len: usize,
) -> Result<()> {
    let rc = unsafe { setsockopt(fd.as_raw_fd(), level, name, value, opt_len as _) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error().into())
    }
}

/// Set the `tcp_ca_update` congestion algorithm on the socket represented by
/// the provided file descriptor.
fn set_tcp_ca(fd: BorrowedFd<'_>, tcp_ca: &OsStr) -> Result<()> {
    let bytes = tcp_ca.as_bytes();
    let () = set_sock_opt(
        fd,
        IPPROTO_TCP,
        TCP_CONGESTION,
        bytes.as_ptr().cast(),
        bytes.len() as _,
    )
    .with_context(|| {
        format!(
            "failed to set TCP_CONGESTION algorithm `{}`",
            tcp_ca.to_str().unwrap()
        )
    })?;
    Ok(())
}

/// Send and receive a bunch of data over TCP sockets using the `tcp_ca_update`
/// congestion algorithm.
fn send_recv(tcp_ca: &OsStr) -> Result<()> {
    let num_bytes = 8 * 1024 * 1024;
    let listener = TcpListener::bind("[::1]:0")?;
    let () = set_tcp_ca(listener.as_fd(), tcp_ca)?;
    let addr = listener.local_addr()?;

    let send_handle = thread::spawn(move || {
        let (mut stream, _addr) = listener.accept().unwrap();
        let to_send = (0..num_bytes).map(|_| b'x').collect::<Vec<u8>>();
        let () = stream.write_all(&to_send).unwrap();
    });

    let mut received = Vec::new();
    let mut stream = TcpStream::connect(addr)?;
    let () = set_tcp_ca(stream.as_fd(), tcp_ca)?;
    let _count = stream.read_to_end(&mut received)?;
    let () = send_handle.join().unwrap();

    assert_eq!(received.len(), num_bytes);
    Ok(())
}

fn test(name_to_register: Option<&OsStr>, name_to_use: &OsStr, verbose: bool) -> Result<()> {
    let skel_builder1 = TcpCaSkelBuilder::default();
    let mut open_object1 = MaybeUninit::uninit();
    let mut open_skel1 = skel_builder1.open(&mut open_object1)?;
    let prog1 = &mut open_skel1.progs.ca_update_init;

    let skel_builder2 = TcpCaSkelBuilder::default();
    let mut open_object2 = MaybeUninit::uninit();
    let mut open_skel2 = skel_builder2.open(&mut open_object2)?;
    let prog2 = &mut open_skel2.progs.ca_update_init;

    swap(prog1, prog2);
    drop(open_skel1);

    println!("PROG TYPE: {:?}", prog2.prog_type());

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    let tcp_ca = OsStr::new(TCP_CA_UPDATE);
    let () = test(None, tcp_ca, args.verbose)?;
    Ok(())
}
