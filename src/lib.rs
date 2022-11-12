#[allow(unused)]

use rip::{RipCtl, RipError, Ipv4Packet};
use libc::{sockaddr, addrinfo, socklen_t, size_t, ssize_t, c_char, c_void};
use std::ffi::CStr;
use std::net::Ipv4Addr;
use std::thread;
use std::collections::HashMap;
use std::sync::{Mutex, Arc, Condvar};
use array_macro::*;
use lazy_static::*;

pub mod tcp_segment;
pub mod tcp;
pub mod posix;

pub use tcp::tcp::*;
pub use tcp_segment::tcp_segment::*;
pub use posix::posix::*;

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
    /// Error indicating abortion of TCP command
    TCPCommandAbort,
    /// Error indicating a retry for TCP command
    TCPCommandRetry,
    /// Error indicating unsupported POSIX functionalities
    UnsupportedPOSIX,
    /// Error indicating a failed POSIX emulation
    FailedPOSIX,
}

/// Maximum socket count.
pub const MAX_SOCKET_CNT: usize = 128;

lazy_static! {
    /// Array of TCBs. Entry of None indicates the index is available
    /// for a new socket_fd.
    pub static ref TCBS: [Arc<TCB>; MAX_SOCKET_CNT] = array![
        Arc::new(TCB {
            inner: Mutex::new(None),
            retry: Condvar::new(),
        }); MAX_SOCKET_CNT];
    
    /// The underlying RIP control.
    pub static ref RIP: Arc<RipCtl> = Arc::new(RipCtl::init(true));

    /// Mapping from FD to TCB id.
    pub static ref FD2ID: Arc<Mutex<HashMap<Fd, usize>>> = Arc::new(Mutex::new(HashMap::new()));
    
    /// Mapping from TcpConnection to TCB id.
    pub static ref TCT: Arc<Mutex<TcpConnTree>> = Arc::new(Mutex::new(TcpConnTree::new()));
}


#[no_mangle]
pub extern fn __rtcp_init() {
    eprintln!("[RTCP] Initializing");

    // Start the dispatching thread
    let rx = RIP.rx.clone();
    thread::spawn(move || {
        // Move `rx` here.
        let rx = rx;

        loop {
            let ip_packet = rx.recv().unwrap();
            let header = TCPHeader::deserialize(&ip_packet.data);
            if let Err(e) = header {
                eprintln!("{:?}", e);
                continue;
            }
            let header = header.unwrap();
            let left = header.data_ofs as usize * 4;
            let right = (ip_packet.hdr.tot_len as usize)-(ip_packet.hdr.hdr_len as usize*4);
            assert!(right >= left);
            let data = Vec::from(&ip_packet.data[left..right]);

            // if header.is_fin {
            //     println!("{:?}\n{}\ndata: {:?}", header, ip_packet.hdr.src_ip, &data[..std::cmp::min(data.len(), 20)]);
            // }

            // println!("{:?}\n{}\ndata: {:?}", header, ip_packet.hdr.src_ip, &data[..std::cmp::min(data.len(), 20)]);
            
            tcp_seg_arrive(10, TCPSegment {
                header,
                src_ip: ip_packet.hdr.src_ip,
                data,
            });

            // println!("[Status] {:?}\n===========================", tcp_status(10));
            

            // if header.is_fin {
            //     println!("[Status] {:?}\n===========================", tcp_status(10));
            // }

        }
    });

}

#[no_mangle]
pub extern fn __rtcp_fildes_is_sock(_fildes: i32) -> i32 {
    0
}

#[no_mangle]
pub extern fn __wrap_socket(domain: i32, _type: i32, protocol: i32) -> i32 {
    eprintln!("socket(domain={}, type={}, protocol={})", domain, _type, protocol);
    
    // Demo, TCP create
    tcp_create(10, &mut TCBS[10].inner.lock().unwrap() ,RIP.tx.clone()).unwrap();
    10
}

#[no_mangle]
pub extern fn __wrap_bind(socket: i32, address: *const sockaddr, address_len: socklen_t) -> i32 {
    eprintln!("bind(socket={}, address={:p}, address_len={})", socket, address, address_len);
    0
}

#[no_mangle]
pub extern fn __wrap_listen(socket: i32, backlog: i32) -> i32 {
    eprintln!("listen(socket={}, backlog={})", socket, backlog);

    // Demo, TCP passive OPEN
    tcp_open(10, 5678, Ipv4Addr::new(10, 100, 1, 2), 5678, true).unwrap();
    0
}

#[no_mangle]
pub extern fn __wrap_connect(socket: i32, address: *const sockaddr, address_len: socklen_t) -> i32 {
    eprintln!("connect(socket={}, address={:p}, address_len={})", socket, address, address_len);

    // Demo, TCP active OPEN
    tcp_open(10, 5678, Ipv4Addr::new(10, 100, 1, 1), 5678, false).unwrap();
    0
}

#[no_mangle]
pub extern fn __wrap_accept(socket: i32, address: *mut sockaddr, address_len: *mut socklen_t) -> i32 {
    println!("accept(socket={}, address={:p}, address_len={:p})", socket, address, address_len);
    0
}

#[no_mangle]
#[allow(unused)]
pub extern fn __wrap_recv(socket: i32, buffer: *mut c_void, length: size_t, flags: i32) -> ssize_t {
    // eprintln!("recv(socket={}, buffer={:p}, length={}, flags={})", socket, buffer, length, flags);

    // Demo, TCP RECV
    let mut buf = [0u8; 28000]; 
    let res = tcp_recv(10, &mut buf, false, false);
    // println!("[RECV] {:?}", res);
    // println!("buf: {:?}", &buf[..20]);
    // println!("[Status] {:?}\n===========================", tcp_status(10));
    res.unwrap_or(0) as ssize_t
}

#[no_mangle]
#[allow(unused)]
pub extern fn __wrap_send(socket: i32, buffer: *const c_void, length: size_t, flags: i32) -> ssize_t {
    // eprintln!("send(socket={}, buffer={:p}, length={}, flags={})", socket, buffer, length, flags);

    // Demo, TCP SEND
    let buf = [0xccu8; 28000]; 
    let res = tcp_send(10, &buf, false, false);
    // println!("[SEND] {:?}", res);
    // println!("[Status] {:?}\n===========================", tcp_status(10));
    res.unwrap_or(0) as ssize_t
}

#[no_mangle]
pub extern fn __wrap_close(fildes: i32) -> i32 {
    eprintln!("close(fildes={})", fildes);

    // Demo, TCP CLOSE
    println!("[CLOSE] {:?}", tcp_close(10));
    println!("[Status] {:?}\n===========================", tcp_status(10));
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