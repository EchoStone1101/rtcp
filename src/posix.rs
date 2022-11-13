pub mod posix {
    //! This module implements the upper layer of POSIX TCP,
    //! namely the POSIX part. The TCP commands are wrapped
    //! properly as POSIX interface, and the mapping from
    //! FD (file descriptor) to TCB is maintained.

    #[allow(unused)]
    
    use std::hash::Hash;
    use std::collections::{HashMap, VecDeque};
    use libc::{sockaddr, socklen_t, sockaddr_in, ssize_t, c_void, size_t};
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
        pub conn_map: HashMap<TcpConnection, usize>,
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

        pub backlog: usize,
    }
    impl TCTSocket {
        pub fn new(id: usize) -> Self {
            TCTSocket { id, listen_queue: None, backlog: 0 }
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
        pub fn remove_src_socket(&mut self, src_ip: Ipv4Addr, src_port: u16) {
            if let Some(src_ports) = self.src_ip_map.get_mut(&src_ip) {
                _ = src_ports.src_port_map.remove(&src_port);
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

        if _type & libc::SOCK_STREAM as i32 == 0 {
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
            unsafe { libc::close(fd) };
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

        // IP address (s_addr already network order)
        let ip_bytes = sin_addr.s_addr.to_le_bytes();
        let mut ip = Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
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

        eprintln!("[RTCP] bind {}:{} to id {}", ip, port, id);

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
        let backlog = backlog.clamp(1, POSIX_MAX_LISTEN_BACKLOG as i32) as usize;
        _ = tct_socket.listen_queue.insert(VecDeque::with_capacity(backlog));
        tct_socket.backlog = backlog;
        drop(tcb_guard);

        eprintln!("[RTCP] listen {}:{} with {}", src_ip, src_port, id);

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

        let ip_bytes = sin_addr.s_addr.to_le_bytes();
        let dst_ip = Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
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
        tct.remove_src_socket(tcb.conn.src_ip, tcb.conn.src_port); // First, no longer a half specified socket..
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
            // Now segments can already reach this TCB
            tcb.conn.dst_ip = dst_ip;
            tcb.conn.dst_port = dst_port;
            _ = tct.conn_map.insert(tcb.conn, id);
        }

        // Try an active open()
        let nonce = tcb.nonce;
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
            let mut guard = TCBS[id].inner.lock().unwrap();
            if guard.is_none() || guard.as_ref().unwrap().nonce != nonce {
                // The TCB was closed in between blocking
                set_errno(Errno(libc::EISCONN));
                return Err(RtcpError::FailedPOSIX);
            }
            let tcb = guard.as_ref().unwrap();

            match tcb.state {
                TcpState::SynSent => {
                    // Wait
                    _ = TCBS[id].retry.wait(guard);
                },
                TcpState::Established | TcpState::SynReceived => {
                    // Done!
                    break;
                }
                _ => {
                    _ = tcp_abort(id, &mut guard);
                    // The cleanup should be done by user calling close()
                    set_errno(Errno(libc::ETIMEDOUT));
                    return Err(RtcpError::FailedPOSIX);
                }
            }

        }

        eprintln!("[RTCP] connect {}:{} with {}", dst_ip, dst_port, id);

        Ok(0)
    }

    /// POSIX accept()
    /// With our implementation, it is guaranteed that there is at least one
    /// socket in the listen()-ed socket's `listen_queue`, and accept simply
    /// checks and returns that (may fail and set error code if it turns out
    /// to not be SynRcvd or Established).
    pub fn posix_accept(socket: i32, address: *mut sockaddr, address_len: *mut socklen_t) -> Result<i32, RtcpError> {

        let mut nonce = None;
        let mut conn_id;
        loop {
            // Grab locks
            let fd2id_guard = FD2ID.lock().unwrap();
            let Some(&id) = fd2id_guard.get(&Fd::new(socket)) else {
                set_errno(Errno(libc::ENOTSOCK));
                return Err(RtcpError::FailedPOSIX);
            };
            let mut tct = TCT.lock().unwrap();
            let mut tcb_guard = TCBS[id].inner.lock().unwrap();
            assert!(tcb_guard.is_some());
            let tcb = tcb_guard.as_mut().unwrap(); // ...these are for the listen()-ed socket
            
            if nonce.is_none() {
                nonce = Some(tcb.nonce);
            }
            else {
                if nonce.unwrap() != tcb.nonce {
                    set_errno(Errno(libc::ENOTSOCK));
                    return Err(RtcpError::FailedPOSIX);
                }
            }

            // Check is listen()-ed socket
            let Some(sock) = tct.get_src_socket(tcb.conn.src_ip, tcb.conn.src_port) else {
                set_errno(Errno(libc::EINVAL));
                return Err(RtcpError::FailedPOSIX);
            };
            if sock.listen_queue.is_none() {
                set_errno(Errno(libc::EINVAL));
                return Err(RtcpError::FailedPOSIX);
            }

            conn_id = sock.listen_queue.as_mut().unwrap().pop_front();
            if conn_id.is_none() {
                // No socket in queue. Wait.
                drop(tct);
                drop(fd2id_guard);
                _ = TCBS[id].retry.wait(tcb_guard);
            }
            else {
                break;
            }
        }
        let conn_id = conn_id.unwrap();
    

        // Now accept wait on this connection socket. Unlike connect(),
        // here we do not worry about user calling close() on this socket,
        // because the FD is not yet registered.

        // Allocate a FD by calling `dup()` on STDIN
        let fd = unsafe {libc::dup(libc::STDIN_FILENO)};
        if fd < 0 {
            set_errno(Errno(libc::EMFILE));
            return Err(RtcpError::FailedPOSIX);
        }
        loop {
            match tcp_status(conn_id) {
                TcpState::Established => {
                    // Found one!
                    let fd = Fd::new(fd);
                    let mut fd2id_guard = FD2ID.lock().unwrap();
    
                    fd2id_guard.insert(fd, conn_id);
                    let mut tcb_guard = TCBS[conn_id].inner.lock().unwrap();
                    assert!(tcb_guard.is_some());
                    let tcb = tcb_guard.as_mut().unwrap(); 
    
                    if !address.is_null() {
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
                    }

                    eprintln!("[RTCP] accept fd {} on id {}, conn: {:?}", fd.fd, conn_id, tcb.conn);
                    return Ok(fd.fd);
                },
                TcpState::Listen | TcpState::SynReceived => {
                    // Block waiting
                    let guard = TCBS[conn_id].inner.lock().unwrap();
                    assert!(guard.is_some());
                    _ = TCBS[conn_id].retry.wait(guard);
                }
                _ => {
                    // This connection has failed. Clean-up!
                    let mut guard = TCBS[conn_id].inner.lock().unwrap();
                    assert!(guard.is_some());
                    let conn = guard.as_ref().unwrap().conn.clone();
                    _ = tcp_abort(conn_id, &mut guard);
                    drop(guard);

                    let mut tct = TCT.lock().unwrap();
                    tct.remove_src_socket(conn.src_ip, conn.src_port);
                    _ = tct.conn_map.remove(&conn);

                    unsafe { libc::close(fd) };
                    set_errno(Errno(libc::ECONNABORTED));
                    return Err(RtcpError::FailedPOSIX);
                }
            }
        }

    }

    /// POSIX recv()
    /// Basically just TCP recv command.
    /// `flags` are ignored.
    pub fn posix_recv(socket: i32, buffer: *mut c_void, length: size_t, flags: i32) -> Result<ssize_t, RtcpError> {

        if length <= 0 {
            return Ok(0);
        }
        if flags != 0 {
            return Err(RtcpError::UnsupportedPOSIX);
        }

        // Grab locks
        let fd2id_guard = FD2ID.lock().unwrap();
        let Some((&fd, &id)) = fd2id_guard.get_key_value(&Fd::new(socket)) else {
            set_errno(Errno(libc::ENOTSOCK));
            return Err(RtcpError::FailedPOSIX);
        };

        let buf = unsafe {std::slice::from_raw_parts_mut(buffer as *mut u8, length as usize)};

        if fd._non_block {
            let res = tcp_recv_once(id, buf, &mut None);
            if matches!(res, Err(RtcpError::TCPCommandRetry)) {
                return Ok(0)
            }
            else if matches!(res, Err(RtcpError::InvalidStateTransition("error: connection closing"))) {
                return Ok(0) //EOF
            }
            else {
                return res.map(|n| n as ssize_t)
            }
        }
        else {
            let res = tcp_recv(id, buf, false, false).map(|n| n as ssize_t);
            if  matches!(res, Err(RtcpError::InvalidStateTransition("error: connection closing"))) {
                return Ok(0) //EOF
            }
            else {
                return res.map(|n| n as ssize_t)
            }
        }
    }

    /// POSIX send()
    /// Basically just TCP send command.
    /// `flags` are ignored.
    pub fn posix_send(socket: i32, buffer: *const c_void, length: size_t, flags: i32) -> Result<ssize_t, RtcpError> {

        if length <= 0 {
            return Ok(0);
        }
        if flags != 0 {
            return Err(RtcpError::UnsupportedPOSIX);
        }

        // Grab locks
        let fd2id_guard = FD2ID.lock().unwrap();
        let Some((&fd, &id)) = fd2id_guard.get_key_value(&Fd::new(socket)) else {
            set_errno(Errno(libc::ENOTSOCK));
            return Err(RtcpError::FailedPOSIX);
        };

        let buf = unsafe {std::slice::from_raw_parts(buffer as *mut u8, length as usize)};

        if fd._non_block {
            let res = tcp_send_once(id, buf, &mut None).map(|n| n as ssize_t);
            if matches!(res, Err(RtcpError::TCPCommandRetry)) {
                return Ok(0)
            }
            else {
                return res.map(|n| n as ssize_t)
            }
        }
        else {
            tcp_send(id, buf, false, false).map(|n| n as ssize_t)
        }
        
    }

    /// POSIX close()
    /// Apply TCP close command, and free the FD associated with
    /// the TCB. Note that the TCB may be kept alive for some while,
    /// due to TimeWait and stuff. The freeing of TCB resources are
    /// handled elsewhere.
    pub fn posix_close(fildes: i32) -> Result<i32, RtcpError> {
        let mut fd2id_guard = FD2ID.lock().unwrap();
        let Some((&fd, &id)) = fd2id_guard.get_key_value(&Fd::new(fildes)) else {
            set_errno(Errno(libc::EBADF));
            return Err(RtcpError::FailedPOSIX);
        };
        let mut tct = TCT.lock().unwrap();
        let mut tcb_guard = TCBS[id].inner.lock().unwrap();
        assert!(tcb_guard.is_some());
        let tcb = tcb_guard.as_mut().unwrap(); // ...these are for the listen()-ed socket

        let src_ip = tcb.conn.src_ip;
        let src_port = tcb.conn.src_port;
        tct.remove_src_socket(src_ip, src_port);
        _ = tct.conn_map.remove(&tcb.conn);

        fd2id_guard.remove(&fd);

        // Free the allocated FD
        unsafe { libc::close(fildes) };

        // Now that all FD related records are cleaned up, won't
        // be closing twice.

        drop(tcb_guard);
        drop(tct);
        drop(fd2id_guard);

        _ = tcp_close(id);

        std::thread::sleep(std::time::Duration::from_secs(3));
        println!("{:?}", tcp_status(id));
        Ok(0)
    }


    /// Map from TcpConnection to TCB ID.
    /// This is invoked by the dispatch thread whenever a TCP segment arrives,
    /// so that it knows which TCB to redirect it to.
    /// The "listen" logic is also implemented here: connections first try to 
    /// match using `conn_map` (only for fully specified connections), and may
    /// fall back to a search on the TCT. If the endpoint has a listen_queue,
    /// this will trigger the spawning of a new TCB.
    pub fn posix_conn_to_id(conn: &TcpConnection) -> Option<usize> {
        let mut tct = TCT.lock().unwrap();

        if let Some(&id) = tct.conn_map.get(conn) {
            return Some(id)
        }
        else {
            let mut tct_sock = tct.get_src_socket(conn.src_ip, conn.src_port);
            if let None = tct_sock {
                // Try wild-card IP
                let Some(ports) = tct.src_ip_map.get_mut(&Ipv4Addr::UNSPECIFIED) else {
                    return None;
                };

                if let Some(sock) = ports.src_port_map.get_mut(&conn.src_port) {
                    tct_sock = Some(sock);
                }
                else {
                    return None;
                }
            };
            let Some(tct_sock) = tct_sock else {
                return None;
            };

            if tct_sock.listen_queue.is_some() {
                // Triggers listen()!
                let listen_queue = tct_sock.listen_queue.as_mut().unwrap();

                // TODO: we may be able to reuse old TCBs in the queue that
                // is still Listen, due to the previous segments not being SYN.
                // But that is a little more involved...

                if listen_queue.len() == tct_sock.backlog {
                    // Queue too full
                    return None;
                }
                // Make a new TCB
                let mut listen_id = None;
                for (idx, tcb) in TCBS.iter().enumerate() {
                    if let Ok(mut guard) = tcb.inner.try_lock() {
                        if guard.is_none() {
                            // Create new TCB
                            _ = tcp_create(idx, &mut guard, RIP.tx.clone());
                            guard.as_mut().unwrap().conn = *conn;

                            listen_id = Some(idx);
                            break;
                        }
                        
                    }
                }
                if listen_id.is_none() {
                    // No resources for new connection
                    return None;
                }
                let listen_id = listen_id.unwrap();

                // Passive open to make it Listen
                _ = tcp_open(listen_id, conn.src_port, conn.dst_ip, conn.dst_port, true);

                // Register on TCT.
                TCBS[tct_sock.id].retry.notify_all(); // Notify blocking accept()s
                listen_queue.push_back(listen_id);
                _ = tct.conn_map.insert(*conn, listen_id);

                // Now can reach the TCB with id
                return Some(listen_id)
            }
            else {
                // In fact, non-listen half-specified sockets must be closed.
                return None;
            }
        }
    }
}