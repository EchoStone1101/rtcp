pub mod posix {
    //! This module implements the upper layer of POSIX TCP,
    //! namely the POSIX part. The TCP commands are wrapped
    //! properly as POSIX interface, and the mapping from
    //! FD (file descriptor) to TCB is maintained.

    #[allow(unused)]
    
    use std::hash::Hash;
    use std::collections::{HashMap, VecDeque};
    use libc::{sockaddr, socklen_t, sockaddr_in};
    use crate::tcp::tcp::*;
    use crate::{RtcpError, TCBS, RIP, FD2ID, Ipv4Addr, TCT};

    use errno::{set_errno, Errno};


    pub const POSIX_MAX_LISTEN_BACKLOG: usize = 16;


    /// POSIX file descriptor, provided to the end user.
    /// All POSIX interface use FD to refer to sockets, while internally we
    /// use id and TCB. 
    #[derive(Debug, Clone, Copy)]
    pub struct Fd {
        fd: i32,
        _non_block: bool,
    }
    impl PartialEq for Fd {
        fn eq(&self, other: &Self) -> bool {
            self.fd == other.fd
        }
    }
    impl Eq for Fd {}
    impl Hash for Fd {
        fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
            self.fd.hash(state)
        }
    }

    impl Fd {
        pub fn new(fildes: i32) -> Self {
            Fd {
                fd: fildes,
                _non_block: false,
            }
        }
    }

    /// TCP connection tree, for quick mapping from a TcpConnection
    /// (src_ip, src_port, dst_ip, dst_port) to id.
    pub struct TcpConnTree {
        /// Half open TCBs can only be described with (src_ip, src_port)
        /// A key of unspecified IP means wild-card.
        src_ip_map: HashMap<Ipv4Addr, TCTPorts>,

        /// Map directly to id for fully specified TcpConnection
        conn_map: HashMap<TcpConnection, usize>,
    }

    struct TCTPorts {
        pub src_port_map: HashMap<u16, TCTSocket>,
    }
    impl TCTPorts {
        pub fn new() -> Self {
            TCTPorts { src_port_map: HashMap::new() }
        }
    }

    pub struct TCTSocket {
        /// Half open TCBs can only be described with (src_ip, src_port)
        pub id: usize,

        /// Whether this (src_ip, src_port) refers to a listening queue,
        /// and the queue content.
        pub listen_queue: Option<VecDeque<usize>>,
    }
    impl TCTSocket {
        pub fn new(id: usize) -> Self {
            TCTSocket { id, listen_queue: None }
        }
    }

    impl TcpConnTree {
        pub fn new() -> Self {
            TcpConnTree { 
                src_ip_map: HashMap::new(),
                conn_map: HashMap::new(),
            }
        }

        /// Return an availabe ephemeral port under given IP,
        /// or None if all is used up.
        /// TODO: improve this
        pub fn next_ephemeral_port(&self, ip: Ipv4Addr) -> Option<u16> {
            let ports = self.src_ip_map.get(&ip);
            if let None = ports {
                Some(TCP_EPHEMERAL_PORT_LBOUND)
            }
            else {
                let ports = ports.unwrap();
                for port in TCP_EPHEMERAL_PORT_LBOUND as usize..u16::MAX as usize {
                    if !ports.src_port_map.contains_key(&(port as u16)) {
                        return Some(port as u16)
                    }
                }
                None
            }
        }

        pub fn get_src_socket(&mut self, src_ip: Ipv4Addr, src_port: u16) -> Option<&mut TCTSocket> {
            let Some(src_ports) = self.src_ip_map.get_mut(&src_ip) else {
                return None;
            };
            src_ports.src_port_map.get_mut(&src_port)
        }

        pub fn add_src_socket(&mut self, id: usize, src_ip: Ipv4Addr, src_port: u16) {
            if let Some(src_ports) = self.src_ip_map.get_mut(&src_ip) {
                _ = src_ports.src_port_map.insert(src_port, TCTSocket::new(id));
            }
            else {
                let mut port = TCTPorts::new();
                _  = port.src_port_map.insert(src_port, TCTSocket::new(id));

                _ = self.src_ip_map.insert(src_ip, port);
            }
            
        }
    }


    /// POSIX socket().
    /// For now, we only support AF_INET for `domain`, SOCK_STREAM for `type` (and also
    /// SOCK_NONBLOCK for specifying non-blocking behavior, since we do not emulate
    /// fcntl(), and `protocol` of 0.
    pub fn posix_socket(domain: i32, _type: i32, protocol: i32) -> Result<i32, RtcpError> {

        if domain != libc::AF_INET as i32 {
            set_errno(Errno(libc::EINVAL));
            return Err(RtcpError::UnsupportedPOSIX);
        }

        if _type & libc::SOCK_STREAM as i32 != 0 {
            set_errno(Errno(libc::EINVAL));
            return Err(RtcpError::UnsupportedPOSIX);
        }

        if protocol != 0 {
            set_errno(Errno(libc::EPROTONOSUPPORT));
            return Err(RtcpError::UnsupportedPOSIX);
        }

        // Allocate a FD by calling `dup()` on STDIN
        let fd = unsafe {libc::dup(libc::STDIN_FILENO)};
        if fd < 0 {
            set_errno(Errno(libc::EMFILE));
            return Err(RtcpError::FailedPOSIX);
        }

        let mut id = None;
        for (idx, tcb) in TCBS.iter().enumerate() {
            if let Ok(mut guard) = tcb.inner.try_lock() {
                if guard.is_none() {
                    // Create new TCB
                    _ = tcp_create(idx, &mut guard, RIP.tx.clone());
                    id = Some(idx);
                    break;
                }
                
            }
        }
        if id.is_none() {
            set_errno(Errno(libc::ENOMEM));
            return Err(RtcpError::FailedPOSIX);
        }

        let id = id.unwrap();
        let fd = Fd {fd, _non_block: if _type & libc::SOCK_NONBLOCK != 0 {true} else {false} };
        FD2ID.lock().unwrap().insert(fd, id);

        Ok(fd.fd)
    }

    /// POSIX bind().
    /// `socket` must be a FD managed by RTCP;
    /// `address` must point to valid address (we are not the OS
    /// and cannot check for memory validity);
    pub fn posix_bind(socket: i32, address: *const sockaddr, _address_len: socklen_t) -> Result<i32, RtcpError> {

        let libc::sockaddr_in {
            sin_family, sin_port, sin_addr, ..
        } = unsafe {
            *(address as *const libc::sockaddr_in)
        };

        if sin_family != libc::AF_INET as u16 {
            set_errno(Errno(libc::EINVAL));
            return Err(RtcpError::FailedPOSIX);
        }

        // ID
        let fd2id_guard = FD2ID.lock().unwrap();
        let Some(&id) = fd2id_guard.get(&Fd::new(socket)) else {
            set_errno(Errno(libc::ENOTSOCK));
            return Err(RtcpError::FailedPOSIX);
        };

        // IP address
        let mut ip = Ipv4Addr::from(sin_addr.s_addr);
        let local_ip = RIP.local_ip.lock().unwrap().clone();
        if ip.is_broadcast() {
            ip = Ipv4Addr::UNSPECIFIED;
        }
        if !ip.is_unspecified() && !local_ip.contains(&ip) {
            set_errno(Errno(libc::EADDRNOTAVAIL));
            return Err(RtcpError::FailedPOSIX);
        }

        // Port
        let mut port = sin_port;
        let mut tct = TCT.lock().unwrap();
        if port == TCP_UNSPECIFIED_PORT {
            if let Some(p) = tct.next_ephemeral_port(ip) {
                port = p;
            }
            else {
                set_errno(Errno(libc::EADDRINUSE));
                return Err(RtcpError::FailedPOSIX);
            }
        }
        else {
            if tct.get_src_socket(ip, port).is_some() {
                set_errno(Errno(libc::EADDRINUSE));
                return Err(RtcpError::FailedPOSIX);
            }
        }

        let mut tcb_guard = TCBS[id].inner.lock().unwrap();
        assert!(tcb_guard.is_some());
        let tcb = tcb_guard.as_mut().unwrap();

        // Binding
        // Binding on `ip`==UNSPECIFIED means binding to all local ip,
        // while binding on `port`==0 means selecting a random ephemeral 
        // that is available.
        if tcb.conn.src_sock_unspecified() {
            tcb.conn.src_ip = ip;
            tcb.conn.src_port = port;

            tct.add_src_socket(id, ip, port);
        }
        else {
            set_errno(Errno(libc::EINVAL));
            return Err(RtcpError::FailedPOSIX);
        }

        Ok(0)
    }


    /// POSIX listen().
    /// `socket` must be a FD managed by RTCP;
    /// `backlog` may get truncated.
    /// 
    /// Note: The underlying TCB for a listen()-ed socket remains Closed,
    /// and the actual passive open is done when segments arrive at the
    /// said TCB. More detailedly, a new TCB is spawned, passively opened,
    /// its ID added to listen()-ed socket's `listen_queue`, then the packet
    /// is redirected to the new TCB for handling.
    /// Closed TCBs in `listen_queue` are freed, while SynRcvd / Established
    /// TCBs can be accept()-ed.
    pub fn posix_listen(socket: i32, backlog: i32) -> Result<i32, RtcpError> {

        let fd2id_guard = FD2ID.lock().unwrap();
        let Some(&id) = fd2id_guard.get(&Fd::new(socket)) else {
            set_errno(Errno(libc::ENOTSOCK));
            return Err(RtcpError::FailedPOSIX);
        };

        let mut tct = TCT.lock().unwrap();

        let mut tcb_guard = TCBS[id].inner.lock().unwrap();
        assert!(tcb_guard.is_some());
        let tcb = tcb_guard.as_mut().unwrap();

        
        // listen(): for a socket that was not bind()-ed, bind it now
        if tcb.conn.src_sock_unspecified() {
            if let Some(p) = tct.next_ephemeral_port(Ipv4Addr::UNSPECIFIED) {
                tcb.conn.src_ip = Ipv4Addr::UNSPECIFIED;
                tcb.conn.src_port = p;
                tct.add_src_socket(id, Ipv4Addr::UNSPECIFIED, p);
            }
            else {
                set_errno(Errno(libc::EADDRINUSE));
                return Err(RtcpError::FailedPOSIX);
            }
        }

        let src_ip = tcb.conn.src_ip;
        let src_port = tcb.conn.src_port;
        let tct_socket = tct.get_src_socket(src_ip, src_port).unwrap();
        if tct_socket.listen_queue.is_some() {
            set_errno(Errno(libc::EADDRINUSE));
            return Err(RtcpError::FailedPOSIX);
        }

        // OK
        let backlog = backlog.clamp(0, POSIX_MAX_LISTEN_BACKLOG as i32) as usize;
        _ = tct_socket.listen_queue.insert(VecDeque::with_capacity(backlog));

        Ok(0)
    }

    /// POSIX connect()
    /// To be consistent with POSIX error code, after triggering an 
    /// active open, connect() will block until the State is no longer
    /// SynSent, for the caller may assume that returning from connect()
    /// shows whether connection is successful.
    pub fn posix_connect(socket: i32, address: *const sockaddr, _address_len: socklen_t) -> Result<i32, RtcpError> {

        let libc::sockaddr_in {
            sin_family, sin_port, sin_addr, ..
        } = unsafe {
            *(address as *const libc::sockaddr_in)
        };

        if sin_family != libc::AF_INET as u16 {
            set_errno(Errno(libc::EAFNOSUPPORT));
            return Err(RtcpError::FailedPOSIX);
        }

        let dst_ip = Ipv4Addr::from(sin_addr.s_addr);
        let dst_port = sin_port;


        // Grab locks
        let fd2id_guard = FD2ID.lock().unwrap();
        let Some(&id) = fd2id_guard.get(&Fd::new(socket)) else {
            set_errno(Errno(libc::ENOTSOCK));
            return Err(RtcpError::FailedPOSIX);
        };

        let mut tct = TCT.lock().unwrap();

        let mut tcb_guard = TCBS[id].inner.lock().unwrap();
        assert!(tcb_guard.is_some());
        let tcb = tcb_guard.as_mut().unwrap();

        // connect(): pick random src IP if not binded
        if tcb.conn.src_ip.is_unspecified() {
            let local_ip = RIP.local_ip.lock().unwrap().clone();
            if local_ip.is_empty() {
                set_errno(Errno(libc::ENETUNREACH));
                return Err(RtcpError::FailedPOSIX);
            }
            else {
                tcb.conn.src_ip = local_ip[tcp_timestamp() as usize % local_ip.len()];
            }
        }
        if tcb.conn.src_port == TCP_UNSPECIFIED_PORT {
            if let Some(p) = tct.next_ephemeral_port(tcb.conn.src_ip) {
                tcb.conn.src_port = p;
            }
            else {
                set_errno(Errno(libc::EADDRINUSE));
                return Err(RtcpError::FailedPOSIX);
            }
        }

        let src_ip = tcb.conn.src_ip;
        let src_port = tcb.conn.src_port;

        // This filters away connect() on listen()-ed fd.
        if let Some(sock) =  tct.get_src_socket(tcb.conn.src_ip, tcb.conn.src_port) {
            if sock.listen_queue.is_some() {
                set_errno(Errno(libc::EADDRINUSE));
                return Err(RtcpError::FailedPOSIX);
            }
            // bind()-ed before; OK
        }
        else {
            tct.add_src_socket(id, src_ip, src_port);
        }

        // Try an active open()
        drop(tcb_guard);
        drop(tct);
        drop(fd2id_guard);

        if let Err(RtcpError::InvalidStateTransition(_)) = tcp_open(id, src_port, dst_ip, dst_port, false) {
            // Must be "already connected"
            set_errno(Errno(libc::EISCONN));
            return Err(RtcpError::FailedPOSIX);
        }

        // Block until not SynSent
        loop {
            match tcp_status(id) {
                TcpState::SynSent => {
                    // Wait
                    let guard = TCBS[id].inner.lock().unwrap();
                    _ = TCBS[id].retry.wait(guard);
                },
                TcpState::Established | TcpState::SynReceived => {
                    // Done!
                    break;
                }
                _ => {
                    let mut guard = TCBS[id].inner.lock().unwrap();
                    _ = tcp_abort(id, &mut guard);
                    // TODO: Free this TCB and clean up TCT
                    set_errno(Errno(libc::ETIMEDOUT));
                    return Err(RtcpError::FailedPOSIX);
                }
            }

        }

        Ok(0)
    }

    /// POSIX accept()
    /// To be consistent with POSIX error code, if there is no Established
    /// socket in the listen_queue, accept() may block on one SynRcvd socket and
    /// wait until it becomes Established.
    pub fn posix_accept(socket: i32, address: *mut sockaddr, address_len: *mut socklen_t) -> Result<i32, RtcpError> {

        // Allocate a FD by calling `dup()` on STDIN
        let fd = unsafe {libc::dup(libc::STDIN_FILENO)};
        if fd < 0 {
            set_errno(Errno(libc::EMFILE));
            return Err(RtcpError::FailedPOSIX);
        }

        // Grab locks
        let mut fd2id_guard = FD2ID.lock().unwrap();
        let Some(&id) = fd2id_guard.get(&Fd::new(socket)) else {
            set_errno(Errno(libc::ENOTSOCK));
            return Err(RtcpError::FailedPOSIX);
        };
        let mut tct = TCT.lock().unwrap();
        let mut tcb_guard = TCBS[id].inner.lock().unwrap();
        assert!(tcb_guard.is_some());
        let tcb = tcb_guard.as_mut().unwrap(); // ...these are for the listen()-ed socket

        // Check is listen()-ed socket
        let Some(sock) = tct.get_src_socket(tcb.conn.src_ip, tcb.conn.src_port) else {
            set_errno(Errno(libc::EINVAL));
            return Err(RtcpError::FailedPOSIX);
        };
        if sock.listen_queue.is_none() {
            set_errno(Errno(libc::EINVAL));
            return Err(RtcpError::FailedPOSIX);
        }
        drop(tcb);

        for idx in 0..sock.listen_queue.as_ref().unwrap().len() {
            let conn_id = sock.listen_queue.as_ref().unwrap()[idx];
            match tcp_status(conn_id) {
                TcpState::Established | TcpState::SynReceived => {
                    // Found one!
                    _ = sock.listen_queue.as_mut().unwrap().remove(idx);

                    let fd = Fd::new(fd);
                    fd2id_guard.insert(fd, conn_id);
                    let mut tcb_guard = TCBS[id].inner.lock().unwrap();
                    assert!(tcb_guard.is_some());
                    let tcb = tcb_guard.as_mut().unwrap(); 

                    unsafe {
                        let address = address as *mut sockaddr_in;
                        *address = sockaddr_in {
                            sin_family: libc::AF_INET as u16,
                            sin_port: tcb.conn.dst_port,
                            sin_addr: libc::in_addr { s_addr: u32::from_be_bytes(tcb.conn.dst_ip.octets()) },
                            sin_zero: [0u8; 8],
                        };
                        *address_len = 16;
                    };

                    return Ok(fd.fd);
                },
                // TODO: Block on other state
                _ => {}
            }
        }


        Ok(0)
    }
}