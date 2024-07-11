// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#![allow(clippy::let_unit_value)]

use std::ffi::c_int;
use std::ffi::c_void;
use std::ffi::CStr;
use std::io;
use std::io::Read as _;
use std::io::Write as _;
use std::mem::swap;
use std::net::TcpListener;
use std::net::TcpStream;
use std::os::fd::AsFd as _;
use std::os::fd::AsRawFd as _;
use std::os::fd::BorrowedFd;
use std::ptr::copy_nonoverlapping;
use std::thread;

use clap::Parser;

use the_original_libbpf_rs::skel::OpenSkel;
use the_original_libbpf_rs::skel::SkelBuilder;
use the_original_libbpf_rs::AsRawLibbpf as _;
use the_original_libbpf_rs::ErrorExt as _;
use the_original_libbpf_rs::ErrorKind;
use the_original_libbpf_rs::Result;
use the_original_libbpf_rs::ProgramType;

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

const TCP_CA_UPDATE: &[u8] = b"tcp_ca_update\0";

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
fn set_tcp_ca(fd: BorrowedFd<'_>, tcp_ca: &CStr) -> Result<()> {
    let () = set_sock_opt(
        fd,
        IPPROTO_TCP,
        TCP_CONGESTION,
        tcp_ca.as_ptr().cast(),
        tcp_ca.to_bytes().len() as _,
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
fn send_recv(tcp_ca: &CStr) -> Result<()> {
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

fn test(name_to_register: Option<&CStr>, name_to_use: &CStr, verbose: bool) -> Result<()> {
    let skel_builder1 = TcpCaSkelBuilder::default();
    let mut open_skel1 = skel_builder1.open()?;
    let mut progs1 = open_skel1.progs_mut();
    let prog1 = progs1.ca_update_init();

    let skel_builder2 = TcpCaSkelBuilder::default();
    let mut open_skel2 = skel_builder2.open()?;
    let mut progs2 = open_skel2.progs_mut();
    let prog2 = progs2.ca_update_init();

    swap(prog1, prog2);
    drop(open_skel1);

    println!("PROG TYPE: {:?}", prog2.prog_type());

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    let tcp_ca = CStr::from_bytes_until_nul(TCP_CA_UPDATE).unwrap();
    let () = test(None, tcp_ca, args.verbose)?;
    Ok(())
}
