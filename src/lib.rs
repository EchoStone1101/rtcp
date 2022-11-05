#[allow(unused)]

use rip::{RipCtl, RipError, Ipv4Packet, RipPacket};
use libc::{sockaddr, addrinfo, socklen_t, size_t, ssize_t, c_char, c_void};
use std::ffi::CStr;
use std::sync::{Mutex, Arc, Condvar};
use array_macro::*;
use lazy_static::*;

pub mod tcp_segment;
pub mod tcp;

pub use tcp::tcp::*;
pub use tcp_segment::tcp_segment::*;

/// This library, RTCP, implements basic TCP/IP (RFC 793) with flow control. 
/// The TCP implementation is bare-bone, and might not support many features.
/// 
/// It also provides POSIX interface for C programs, and can be dynamically
/// linked with normal C programs with link-time interpositioning. Again, many
/// features/options might not be supported.

#[derive(Debug)]
pub enum RtcpError {
    /// Error when operating buffer
    BufError(&'static str),
    /// Invalid TCP segment,
    InvalidSegment(&'static str),
    /// Error during TCP state transition
    InvalidStateTransition(&'static str),
    /// Error indicating a retry for TCP command
    TCPCommandRetry,
}

/// The maximum fd for a RTCP socket.
pub const MAX_SOCKET_FD: usize = 1024;

lazy_static! {
    /// Array of TCBs. Entry of None indicates the index is available
    /// for a new socket_fd.
    pub static ref TCBS: [Arc<TCB>; MAX_SOCKET_FD] = array![
        Arc::new(TCB {
            inner: Mutex::new(None),
            retry: Condvar::new(),
        }); MAX_SOCKET_FD];
}


#[no_mangle]
pub extern fn __rtcp_init() {
    eprintln!("[RTCP] Initializing");
}

#[no_mangle]
pub extern fn __rtcp_fildes_is_sock(_fildes: i32) -> i32 {
    0
}

#[no_mangle]
pub extern fn __wrap_socket(domain: i32, _type: i32, protocol: i32) -> i32 {
    println!("socket(domain={}, type={}, protocol={})", domain, _type, protocol);
    0
}

#[no_mangle]
pub extern fn __wrap_bind(socket: i32, address: *const sockaddr, address_len: socklen_t) -> i32 {
    println!("bind(socket={}, address={:p}, address_len={})", socket, address, address_len);
    0
}

#[no_mangle]
pub extern fn __wrap_listen(socket: i32, backlog: i32) -> i32 {
    println!("listen(socket={}, backlog={})", socket, backlog);
    0
}

#[no_mangle]
pub extern fn __wrap_connect(socket: i32, address: *const sockaddr, address_len: socklen_t) -> i32 {
    println!("connect(socket={}, address={:p}, address_len={})", socket, address, address_len);
    0
}

#[no_mangle]
pub extern fn __wrap_accept(socket: i32, address: *const sockaddr, address_len: socklen_t) -> i32 {
    println!("accept(socket={}, address={:p}, address_len={})", socket, address, address_len);
    0
}

#[no_mangle]
pub extern fn __wrap_recv(socket: i32, buffer: *mut c_void, length: size_t, flags: i32) -> ssize_t {
    println!("recv(socket={}, buffer={:p}, length={}, flags={})", socket, buffer, length, flags);
    0
}

#[no_mangle]
pub extern fn __wrap_send(socket: i32, buffer: *const c_void, length: size_t, flags: i32) -> ssize_t {
    println!("send(socket={}, buffer={:p}, length={}, flags={})", socket, buffer, length, flags);
    0
}

#[no_mangle]
pub extern fn __wrap_close(fildes: i32) -> i32 {
    println!("close(fildes={})", fildes);
    0
}

#[no_mangle]
pub extern fn __wrap_getaddrinfo(
    node: *const c_char,
    service: *const c_char,
    hints: *const addrinfo,
    res: *mut *mut addrinfo) -> i32 
{
    let node = unsafe { CStr::from_ptr(node) };
    let service = unsafe { CStr::from_ptr(service) };
    println!("getaddrinfo(node={}, service={}, hints={:p}, res={:p})", 
        node.to_str().unwrap_or_default(),
        service.to_str().unwrap_or_default(),
        hints,
        res,
    );
    0
}