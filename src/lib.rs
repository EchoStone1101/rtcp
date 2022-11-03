#[allow(unused)]

use rip::{RipCtl, RipError};
#[allow(unused_imports)]
use libc::{sockaddr, addrinfo, socklen_t, size_t, ssize_t, c_char};
#[allow(unused_imports)]
use std::ffi::CStr;

/// Testing basic exposure to C program
#[no_mangle]
pub extern fn hello_from_rust() {
    println!("hello from rust!");
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
pub extern fn __wrap_close(fildes: i32) -> i32 {
    println!("close(fildes={})", fildes);
    0
}

#[no_mangle]
pub extern fn __wrap_getaddrinfo(
    node: *const c_char,
    service: *const c_char,
    hints: *const addrinfo,
    res: *mut *mut addrinfo) -> i32 {
    println!("getaddrinfo(node={})", fildes);
    0
}