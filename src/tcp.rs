pub mod tcp {

    //! Implements the meat-and-potatoes of TCP (RFC 793).
    //! 
    //! This includes the suggested TCP user commands, the
    //! internal state machine, TCB (Transmission Control
    //! Block), flow control, congestion control (optional)
    //! and many other internal details. 
    //! 
    //! However, the implementation is also POSIX-aware, where many cases
    //! of the specification will not be reachable. We layout the sketch
    //! for these cases, only to handle them with a runtime panic.
    
    #[allow(unused)]
    
    use rip::{RipPacket, Ipv4Packet, RipCtl};
    use crate::{TCBS, MAX_SOCKET_FD, RtcpError, TCPHeader, TCPSegment};
    use std::collections::{VecDeque, LinkedList};
    use std::net::Ipv4Addr;
    use std::sync::{Mutex, Condvar};
    use chrono::Utc;

    /// An unspecified port.
    pub const UNSPECIFIED_PORT: u16 = 0;

    /// Global timeout for connections (abort if no ACKs), in ms.
    pub const TCP_GLOBAL_TIMEOUT: usize = 5 * 60 * 1000;

    /// TCP buffer size.
    pub const TCP_BUFFER_SZ: usize = 32768;

    /// The Transmission Control Block, one for each endpoint of a 
    /// TCP connection. 
    /// TCBs are identified by a quad: (src_ip, src_port, dst_ip, dst_port).
    /// The "dst" information is needed because multiple remote clients
    /// can be connected to the same (src_ip, src_port), and these connections
    /// need to be distinguished.
    /// 
    /// POSIX-wise, TCBs are in fact the equivalent of "socket", which
    /// confusingly is commonly thought of as (ip, port) pair instead of the
    /// quad. The point is - POSIX socket is actually (ip, port, fildes), where
    /// fildes is returned by `socket()` / `connect()` / `accept()`. The fildes
    /// indicates that "socket" is more than (ip, port); it is the unique endpoint
    /// of one TCP connection, as is a TCB.
    #[derive(Debug)]
    pub struct TCB {
        
        pub inner: Mutex<Option<_TCB>>,

        /// Requests pend on this condition for delayed processing.
        /// Note that the notification is not guaranteed to be FIFO.
        pub retry: Condvar,
    }

    /// TCB internal state, meant to be protected by a Mutex.
    #[derive(Debug)]
    pub struct _TCB {
        /// Identify this TCP as a connection endpoint.
        pub conn: TcpConnection,
        /// State of this TCB, on the TCP state machine.
        pub state: TcpState,
        /// Whether this TCB is opened passively or not. 
        pub passive: bool,

        pub send_buf: TcpSendBuf,
        pub recv_buf: TcpRecvBuf,
    }

    impl _TCB {
        /// Restore the TCB to a clean state, and CLOSED
        pub fn clear(&mut self) {
            self.conn.src_ip = Ipv4Addr::UNSPECIFIED;
            self.conn.dst_ip = Ipv4Addr::UNSPECIFIED;
            self.conn.src_port = UNSPECIFIED_PORT;
            self.conn.dst_port = UNSPECIFIED_PORT;

            self.state = TcpState::Closed;
            self.passive = false;

        }
    }

    #[derive(Debug)]
    pub struct TcpSendBuf {
        /// Cicurlar data buffer
        pub buf: Box<[u8; TCP_BUFFER_SZ]>,
        /// Oldest Unacked SEQ
        pub snd_una: u32,
        /// Next SEQ to be sent
        pub snd_nxt: u32,
        /// Sender window
        pub snd_wnd: u16,
        /// Segment SEQ used for last window update
        pub snd_wl1: u32,
        /// Segment ACK used for last window update
        pub snd_wl2: u32,

        /// Initial send SEQ
        pub iss: u32,

        /// Retransmission queue (start, end, timestamp)
        pub re_rx_queue: VecDeque<ReRxItem>,

        /// Send handle
        pub tx: flume::Sender<RipPacket>,
    }

    /// A segment in retransmission queue.
    #[derive(Debug)]
    pub struct ReRxItem {
        pub start: u32,
        pub end: u32,
        pub timestamp: u64,
        pub is_syn: bool,
        pub is_fin: bool,
    }

    impl TcpSendBuf {
        /// Put `data` into buffer, and register the segment 
        /// in re_rx_queue. The validity of this call should be
        /// checked beforehand.
        fn put(&mut self, is_syn: bool, is_fin: bool, data: &[u8]) {
            assert!(data.len() < TCP_BUFFER_SZ as usize);
            assert!(u64::wrapping_add(self.snd_nxt as u64, data.len() as u64) <= u64::wrapping_add(self.snd_una as u64, self.snd_wnd as u64));
            let virt_len = data.len() as u32 
                + if is_syn {1} else {0}
                + if is_fin {1} else {0};

            if data.len() > 0 {
                // Make sure we do not overwrite buffer
                assert!(u64::wrapping_add(self.snd_una as u64, TCP_BUFFER_SZ as u64) > u64::wrapping_add(self.snd_nxt as u64, virt_len as u64));

                let mut left = self.snd_nxt as u16;
                if left > TCP_BUFFER_SZ as u16 {
                    left -= TCP_BUFFER_SZ as u16;
                }
                let right = left + data.len() as u16;
                if right > TCP_BUFFER_SZ as u16 {
                    self.buf[left as usize..].copy_from_slice(&data[..(TCP_BUFFER_SZ as u16 - left) as usize]);
                    self.buf[..(right-TCP_BUFFER_SZ as u16) as usize].copy_from_slice(&data[(TCP_BUFFER_SZ as u16 - left) as usize..]);
                }
                else {
                    self.buf[left as usize..right as usize].copy_from_slice(data);
                }
            }

            
            // For any TCP connection, there is exactly one extra byte for SYN and FIN.
            // The SYN will not cause problem because it occupies empty buffer. The FIN,
            // however, can cause snd_nxt > snd_una + TCP_BUFFER_SZ, where a next put()
            // will panic as left > TCP_BUFFER_SZ. This is fine, though, since FIN is the
            // last possible message to be put into buffer.
               
            self.re_rx_queue.push_back(ReRxItem {
                start: self.snd_nxt,
                end: u32::wrapping_add(self.snd_nxt, virt_len),
                timestamp: tcp_timestamp(),
                is_syn,
                is_fin,
            });
            self.snd_nxt = u32::wrapping_add(self.snd_nxt, virt_len);
        }

        /// Send a bare SYN segment
        pub fn send_syn(&mut self, conn: &TcpConnection, wnd: u16, ack: u32, is_ack: bool) {
            let mut buf = [0u8; 20];
            let hdr = TCPHeader {
                src_port: conn.src_port,
                dst_port: conn.dst_port,
                seq: self.snd_nxt,
                ack,
                data_ofs: 5,
                is_urg: false, is_ack, is_psh: false, is_rst: false, is_fin: false,
                is_syn: true,
                wnd,
                checksum: 0,
                urg_ptr: 0,
                _options: (),
            };
            // No actual data, must succeed
            self.put(hdr.is_syn, hdr.is_fin, &[]);
            _ = RipCtl::send_ipv4_packet(
                &mut self.tx,
                conn.src_ip,
                conn.dst_ip,
                {
                    hdr.serialize(&mut buf).unwrap();
                    &mut buf
                }
            ).unwrap();
        }

        /// Send a bare FIN segment
        pub fn send_fin(&mut self, conn: &TcpConnection, wnd: u16, ack: u32) {
            let mut buf = [0u8; 20];
            let hdr = TCPHeader {
                src_port: conn.src_port,
                dst_port: conn.dst_port,
                seq: self.snd_nxt,
                ack,
                data_ofs: 5,
                is_urg: false, is_psh: false, is_rst: false, is_syn: false,
                is_ack: true, // FIN must have ACK set
                is_fin: true,
                wnd,
                checksum: 0,
                urg_ptr: 0,
                _options: (),
            };
            // No actual data, must succeed
            self.put(hdr.is_syn, hdr.is_fin, &[]);
            _ = RipCtl::send_ipv4_packet(
                &mut self.tx,
                conn.src_ip,
                conn.dst_ip,
                {
                    hdr.serialize(&mut buf).unwrap();
                    &mut buf
                }
            ).unwrap();
        }

        /// Send a bare ACK segment
        pub fn send_ack(&mut self, conn: &TcpConnection, wnd: u16, ack: u32) {
            let mut buf = [0u8; 20];
            let hdr = TCPHeader {
                src_port: conn.src_port,
                dst_port: conn.dst_port,
                seq: self.snd_nxt,
                ack,
                data_ofs: 5,
                is_urg: false, is_fin: false, is_psh: false, is_rst: false, is_syn: false,
                is_ack: true,
                wnd,
                checksum: 0,
                urg_ptr: 0,
                _options: (),
            };
            // No actual data, must succeed
            self.put(hdr.is_syn, hdr.is_fin, &[]);
            _ = RipCtl::send_ipv4_packet(
                &mut self.tx,
                conn.src_ip,
                conn.dst_ip,
                {
                    hdr.serialize(&mut buf).unwrap();
                    &mut buf
                }
            ).unwrap();
        }

        /// Send a bare RST segment.
        /// RSTs are not put into re_rx_queue, and they might use different SEQ and ACK settings
        /// than what Self keeps.
        pub fn send_rst(&mut self, 
            conn: &TcpConnection, 
            wnd: u16, 
            seq: u32,
            ack: u32, is_ack: bool) {
            let mut buf = [0u8; 20];
            let hdr = TCPHeader {
                src_port: conn.src_port,
                dst_port: conn.dst_port,
                seq,
                ack,
                data_ofs: 5,
                is_urg: false, is_ack, is_psh: false, is_fin: false, is_syn: false,
                is_rst: true,
                wnd,
                checksum: 0,
                urg_ptr: 0,
                _options: (),
            };
            
            _ = RipCtl::send_ipv4_packet(
                &mut self.tx,
                conn.src_ip,
                conn.dst_ip,
                {
                    hdr.serialize(&mut buf).unwrap();
                    &mut buf
                }
            ).unwrap();
        }

        /// Put data into this send buffer, and send it. Do not support data 
        /// with SYN and FIN.
        /// The behavior is "retry until at least one byte gets put"; `data`
        /// can also be larger than buffer size, where it is guaranteed that
        /// all of the buffer is not put into buffer.
        pub fn send_text(&mut self, conn: &TcpConnection, data: &[u8], wnd: u16, ack: u32) -> Result<usize, RtcpError> {
            // Check for buffer space
            let free = u32::saturating_sub(u32::wrapping_add(self.snd_una, self.snd_wnd as u32), self.snd_nxt);
            if free == 0 {
                return Err(RtcpError::TCPCommandRetry);
            }
            let bytes_sent = std::cmp::min(free as usize, data.len());

            let mut buf = [0u8; 20];
            let hdr = TCPHeader {
                src_port: conn.src_port,
                dst_port: conn.dst_port,
                seq: self.snd_nxt,
                ack,
                data_ofs: 5,
                is_urg: false, is_psh: false, is_fin: false, is_syn: false,
                is_rst: true, is_ack: true,
                wnd,
                checksum: 0,
                urg_ptr: 0,
                _options: (),
            };

            self.put(false, false, &data[..bytes_sent as usize]);

            // TODO: MAX_PAYLOAD_SZ
            _ = RipCtl::send_ipv4_packet_with_header(
                &mut self.tx,
                conn.src_ip,
                conn.dst_ip,
                {
                    hdr.serialize(&mut buf).unwrap();
                    &buf
                },
                &data[..bytes_sent as usize],
            ).unwrap();
            Ok(bytes_sent)
        }

        /// ACK data in this send buffer, so that snd_una can be moved, and retransmission
        /// queue can be popped. `ack` should be checked beforehand and is assumed acceptable.
        pub fn ack(&mut self, ack: u32) -> (bool, bool) {
            let mut syn_acked = false;
            let mut fin_acked = false;
            while !self.re_rx_queue.is_empty() {
                let item = self.re_rx_queue.front_mut().unwrap();
                if i32::wrapping_sub(ack as i32, item.start as i32) < 0 {
                    break;
                }
                if i32::wrapping_sub(ack as i32, item.end as i32) >= 0 {
                    if item.is_syn {
                        syn_acked = true;
                    }
                    if item.is_fin {
                        fin_acked = true;
                    }
                    drop(item);
                    self.re_rx_queue.pop_front();
                }
                else {
                    item.start = ack;
                    break;
                }
            }
            // Advance SND.UNA
            self.snd_una = ack;

            (syn_acked, fin_acked)
        }

    }

    #[derive(Debug)]
    pub struct TcpRecvBuf {
        /// Cicurlar data buffer
        pub buf: Box<[u8; TCP_BUFFER_SZ]>,
        /// Oldest Unconsumed SEQ
        pub rcv_unc: u32,
        /// Next SEQ expected on incoming segments
        pub rcv_nxt: u32,
        /// Receive window
        pub rcv_wnd: u16,
        
        /// Initial receive SEQ
        pub irs: u32,

        /// Whether FIN is received. FIN will cause one extra
        /// bit in buffer that should not be received by user.
        pub finned: bool,

        /// Received segment queue, not necessarily cummulative.
        /// Essentially implements Selective-Repeat.
        pub seg_queue: LinkedList<SegItem>,
    }

    impl TcpRecvBuf {
        /// Put `data` into buffer, and register the segment 
        /// in seg_queue. The validity of this call should be
        /// checked beforehand.
        /// 
        /// Note that, unlike `TcpSendBuf`, SYN and FIN segments should
        /// never be put into receive buffer. The handling of these segments
        /// are restricted to only the `seg_arrives()` event, where their SEG.SEQ
        /// must match RCV.NXT. In other words, we do not handle control segments
        /// with delay, and a future SYN/FIN is simply dropped (maybe re-rxed).
        pub fn put(&mut self, data: &[u8], seg_seq: u32) {
            assert!(data.len() < TCP_BUFFER_SZ as usize);
            assert!(u64::wrapping_add(seg_seq as u64, data.len() as u64) <= u64::wrapping_add(self.rcv_nxt as u64, self.rcv_wnd as u64));
            assert!(i32::wrapping_sub(seg_seq as i32, self.rcv_nxt as i32) >= 0);

            // Make sure we do not overwrite buffer
            assert!(u64::wrapping_add(self.rcv_unc as u64, TCP_BUFFER_SZ as u64) >= u64::wrapping_add(self.rcv_nxt as u64, self.rcv_wnd as u64));

            let mut left = seg_seq as u16;
            if left > TCP_BUFFER_SZ as u16 {
                left -= TCP_BUFFER_SZ as u16;
            }
            let right = left + data.len() as u16;
            if right > TCP_BUFFER_SZ as u16 {
                self.buf[left as usize..].copy_from_slice(&data[..(TCP_BUFFER_SZ as u16 - left) as usize]);
                self.buf[..(right-TCP_BUFFER_SZ as u16) as usize].copy_from_slice(&data[(TCP_BUFFER_SZ as u16 - left) as usize..]);
            }
            else {
                self.buf[left as usize..right as usize].copy_from_slice(data);
            }

            // Manipulate `seg_queue`; insert and coalesce this segment.
            let queue = &mut self.seg_queue;
            let mut split_idx: usize = 0;
            for (idx, item) in queue.iter().enumerate() {
                split_idx = idx;
                if i32::wrapping_sub(item.end as i32, seg_seq as i32) >= 0 {
                    break;
                }
            }
            let mut part = queue.split_off(split_idx);
            let mut new_end = u32::wrapping_add(seg_seq, data.len() as u32);
            let mut new_start = seg_seq;
            while !part.is_empty() {
                let &SegItem { start, end} = part.front().unwrap();

                if i32::wrapping_sub(start as i32, new_end as i32) <= 0 {
                    _ = part.pop_front().unwrap();
                    if i32::wrapping_sub(new_start as i32, start as i32) > 0 {
                        new_start = start;
                    }
                    if i32::wrapping_sub(end as i32, new_end as i32) > 0 {
                        new_end = end;
                    }
                }
                else {
                    break;
                }
            }
            part.push_front(SegItem {start: new_start, end: new_end});
            self.seg_queue.append(&mut part);

            // Check if we can move RCV.NXT
            let &SegItem{start, end} = self.seg_queue.front().unwrap();
            if start == self.rcv_nxt {
                _ = self.seg_queue.pop_front().unwrap();
                self.rcv_nxt = end;
                self.rcv_wnd = u16::checked_sub(self.rcv_wnd, u32::wrapping_sub(end, start) as u16).unwrap();
            }
        }

        /// Get text from buffer.
        /// The behavior is "retry until at least one byte can be got"; `data`
        /// can also be larger than buffer size, where it is guaranteed that
        /// all of `data` is not filled.
        pub fn get_text(&mut self, data: &mut [u8]) -> Result<usize, RtcpError> {
            // Check for buffer space
            let avail = u32::checked_sub(
                u32::saturating_sub(self.rcv_nxt, self.rcv_unc), 
                if self.finned {1} else {0}
            ).unwrap();
            if avail == 0 {
                return Err(RtcpError::TCPCommandRetry);
            }
            let bytes_rcvd = std::cmp::min(avail as usize, data.len());


            let mut left = self.rcv_unc as u16;
            if left > TCP_BUFFER_SZ as u16 {
                left -= TCP_BUFFER_SZ as u16;
            }
            let right = left + bytes_rcvd as u16;
            if right > TCP_BUFFER_SZ as u16 {
                data[..(TCP_BUFFER_SZ as u16 - left) as usize].copy_from_slice(&self.buf[left as usize..]);
                data[(TCP_BUFFER_SZ as u16 - left) as usize..bytes_rcvd].copy_from_slice(&self.buf[..(right-TCP_BUFFER_SZ as u16) as usize]);
            }
            else {
                data[..bytes_rcvd].copy_from_slice(&self.buf[left as usize..right as usize]);
            }
            self.rcv_unc = u32::wrapping_add(self.rcv_unc, bytes_rcvd as u32);
            self.rcv_wnd = u16::wrapping_add(self.rcv_wnd, bytes_rcvd as u16);
            
            Ok(bytes_rcvd)
        }
    }

    /// A segment in receiver segment queue, for selective repeat.
    #[derive(Debug)]
    pub struct SegItem {
        pub start: u32,
        pub end: u32,
    }

    /// A TCP connection, identified by the quad.
    #[derive(Debug, Clone, Copy)]
    pub struct TcpConnection {
        pub src_ip: Ipv4Addr,
        pub dst_ip: Ipv4Addr,
        pub src_port: u16,
        pub dst_port: u16,
    }

    impl TcpConnection {
        pub fn dst_sock_unspecified(&self) -> bool {
            self.dst_ip.is_unspecified() || self.dst_port == UNSPECIFIED_PORT
        }
    }


    /// The states in a TCP state machine.
    #[derive(Debug, Clone, Copy)]
    pub enum TcpState {
        Closed,
        Listen,
        SynSent,
        SynReceived,
        Established,
        FinWait1,
        FinWait2,
        CloseWait,
        Closing,
        LastAck,
        TimeWait,
    }

    /// Generate timestamp for use in TCP. 
    fn tcp_timestamp() -> u64 {
        Utc::now().timestamp_micros() as u64
    }

    /// Generate ISN based on a timer that increments approximately
    /// every 4ms.
    fn tcp_gen_seq() -> u32 {
        (tcp_timestamp() as u32)>>2
    }

    /// TCP STATUS command.
    pub fn tcp_status(id: usize) -> TcpState {
        assert!(id < MAX_SOCKET_FD);

        let guard = TCBS[id].inner.lock().unwrap();
        assert!(!guard.is_none());

        let send_buf = &guard.as_ref().unwrap().send_buf;
        eprintln!("iss:{}, una:{}, nxt:{}, wnd:{}", send_buf.iss, send_buf.snd_una, send_buf.snd_nxt, send_buf.snd_wnd);
        let recv_buf = &guard.as_ref().unwrap().recv_buf;
        eprintln!("irs:{}, unc:{}, nxt:{}, wnd:{}", recv_buf.irs, recv_buf.rcv_unc, recv_buf.rcv_nxt, recv_buf.rcv_wnd);

        guard.as_ref().unwrap().state
    }

    /// Pseudo TCP CREATE command.
    /// Actual TCP creates TCB upon OPEN command; but for management reasons,
    /// it would be easier to break it down. Here, CREATE makes a CLOSED TCB,
    /// and OPEN acts on a given TCB just like any other TCP command.
    pub fn tcp_create(
        id: usize, 
        tx: flume::Sender<RipPacket>) 
        -> Result<(), RtcpError>
    {
        assert!(id < MAX_SOCKET_FD);

        let mut guard = TCBS[id].inner.lock().unwrap();
        assert!(guard.is_none());
        _ = guard.insert(_TCB {
                conn: TcpConnection { 
                    src_ip: Ipv4Addr::UNSPECIFIED, 
                    src_port: UNSPECIFIED_PORT, 
                    dst_ip: Ipv4Addr::UNSPECIFIED, 
                    dst_port: UNSPECIFIED_PORT
                },
                state: TcpState::Closed,
                passive: false,
                send_buf: TcpSendBuf {
                    buf: Box::new([0u8; TCP_BUFFER_SZ]),
                    snd_una: 0,
                    snd_nxt: 0,
                    snd_wnd: TCP_BUFFER_SZ as u16,
                    snd_wl1: 0,
                    snd_wl2: 0,
                    iss: 0,
                    re_rx_queue: VecDeque::new(),
                    tx,
                },
                recv_buf: TcpRecvBuf {
                    buf: Box::new([0u8; TCP_BUFFER_SZ]),
                    rcv_unc: 0,
                    rcv_nxt: 0,
                    rcv_wnd: TCP_BUFFER_SZ as u16,
                    irs: 0,
                    finned: false,
                    seg_queue: LinkedList::new(),
                }
        });

        Ok(())
    }

    /// TCP OPEN command.
    pub fn tcp_open(
        id: usize,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        passive: bool) -> Result<(), RtcpError>
    {
        assert!(id < MAX_SOCKET_FD);
        let mut guard = TCBS[id].inner.lock().unwrap();
        assert!(!guard.is_none());
        let mut tcb = guard.as_mut().unwrap();

        match tcb.state {
            TcpState::Closed => {
                tcb.conn.src_port = src_port;
                tcb.conn.dst_ip = dst_ip;
                tcb.conn.dst_port = dst_port;
                if passive {
                    tcb.passive = passive;
                    tcb.state = TcpState::Listen;
                    Ok(())
                }
                else {
                    if tcb.conn.dst_sock_unspecified() {
                        return Err(RtcpError::InvalidStateTransition("error: foreign socket unspecified"))
                    }
                    tcb.state = TcpState::SynSent;

                    // Send SYN
                    let send_buf = &mut tcb.send_buf;
                    let iss = tcp_gen_seq();
                    send_buf.iss = iss;
                    send_buf.snd_una = iss;
                    send_buf.snd_nxt = iss; // Will add one after send_syn()
                    send_buf.snd_wl1 = iss;
                    send_buf.snd_wl2 = iss;
                    
                    send_buf.send_syn(&tcb.conn, tcb.recv_buf.rcv_wnd, 0, false); // <SEQ=ISS><CTL=SYN>
                    
                    Ok(())
                }
                
            },
            TcpState::Listen => {
                // POSIX prevents this from happening
                unreachable!()
            },
            _ => {
                Err(RtcpError::InvalidStateTransition("error: connection already exists"))
            }
        }
    }

    /// TCP SEND command. Can be queued and retried.
    pub fn tcp_send(
        id: usize,
        _buf: &[u8],
        _push: bool,
        _urgent: bool) -> Result<usize, RtcpError>
    {
        loop {
            match tcp_send_once(id, _buf, _push, _urgent) {
                Err(e) if matches!(e, RtcpError::TCPCommandRetry) => {},
                Err(e) => return Err(e),
                Ok(cnt) => return Ok(cnt),
            }
        }
    }

    /// TCP SEND internal.
    fn tcp_send_once(
        id: usize,
        buf: &[u8],
        _push: bool,
        _urgent: bool) -> Result<usize, RtcpError>
    {
        assert!(id < MAX_SOCKET_FD);
        let mut guard = TCBS[id].inner.lock().unwrap();
        assert!(!guard.is_none());
        let tcb = guard.as_mut().unwrap();

        match tcb.state {
            TcpState::Closed => {
                Err(RtcpError::InvalidStateTransition("error: connection does not exist"))
            },
            TcpState::Listen => {
                // POSIX prevents this from happening
                unreachable!()
            },
            TcpState::SynSent | TcpState::SynReceived => {
                // accpet() will return connfd in SynRcvd
                _ = TCBS[id].retry.wait(guard).unwrap();
                Err(RtcpError::TCPCommandRetry)
            },
            TcpState::Established | TcpState::CloseWait => {
                // Segmentize the buffer
                let send_buf = &mut tcb.send_buf;

                let res = send_buf.send_text(
                    &tcb.conn, buf, tcb.recv_buf.rcv_wnd, tcb.recv_buf.rcv_nxt
                );
                if matches!(res, Err(RtcpError::TCPCommandRetry)) {
                    // Retry this command
                    _ = TCBS[id].retry.wait(guard).unwrap();
                }
                // TODO: issue a send buffer flush?
                res
            },
            _ => {
                Err(RtcpError::InvalidStateTransition("error: connection closing"))
            }
        }
    }

    /// TCP RECEIVE command
    pub fn tcp_recv(
        id: usize,
        _buf: &mut [u8],
        _push: bool,
        _urgent: bool) -> Result<usize, RtcpError> 
    {
        loop {
            match tcp_recv_once(id, _buf, _push, _urgent) {
                Err(e) if matches!(e, RtcpError::TCPCommandRetry) => {},
                Err(e) => return Err(e),
                Ok(cnt) => return Ok(cnt),
            }
        }
    }

    /// TCP RECEIVE internal
    fn tcp_recv_once(
        id: usize,
        buf: &mut [u8],
        _push: bool,
        _urgent: bool) -> Result<usize, RtcpError> 
    {
        assert!(id < MAX_SOCKET_FD);
        let mut guard = TCBS[id].inner.lock().unwrap();
        assert!(!guard.is_none());
        let tcb = guard.as_mut().unwrap();

        match tcb.state {
            TcpState::Closed => {
                Err(RtcpError::InvalidStateTransition("error: connection does not exist"))
            },
            TcpState::Listen | TcpState::SynSent | TcpState::SynReceived => {
                // Retry this command
                _ = TCBS[id].retry.wait(guard).unwrap();
                Err(RtcpError::TCPCommandRetry)
            },
            TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2 => {
                // Retrieve data between RCV.UNC and RCV.NXT, if any
                let recv_buf = &mut tcb.recv_buf;
                let res = recv_buf.get_text(buf);
                if matches!(res, Err(RtcpError::TCPCommandRetry)) {
                    // Retry this command
                    _ = TCBS[id].retry.wait(guard).unwrap();
                }
                res
            },
            TcpState::CloseWait => {
                // Likewise, but no retry since FIN is received
                let recv_buf = &mut tcb.recv_buf;
                let res = recv_buf.get_text(buf);
                if matches!(res, Err(RtcpError::TCPCommandRetry)) {
                    return Err(RtcpError::InvalidStateTransition("error: connection closing"))
                }
                res
            },
            _ => {
                Err(RtcpError::InvalidStateTransition("error: connection closing"))
            }
        }
    }

    
    /// TCP CLOSE command.
    /// 
    /// Note that for simplicity, this implementation treats CLOSE as if it
    /// has higher priority. Suppose multiple SENDs are pending (because of zero
    /// window, or TCP state); CLOSE will change state and wake up them afterwards, likely
    /// causing them to return with error. This does not harm sequentiality on single
    /// thread (CLOSE cannot happen before previous SEND returns), but can explicitly
    /// cause out of order results with multi-thread (one thread blocks on SEND; 1s later
    /// other thread calls CLOSE, then the SEND will fail).
    /// However, we do guarantee that returned SENDs must succeed.
    pub fn tcp_close(id: usize) -> Result<(), RtcpError> {
        assert!(id < MAX_SOCKET_FD);
        let mut guard = TCBS[id].inner.lock().unwrap();
        assert!(!guard.is_none());
        let mut tcb = guard.as_mut().unwrap();

        match tcb.state {
            TcpState::Closed => {
                Err(RtcpError::InvalidStateTransition("error: connection does not exist"))
            },
            TcpState::Listen | TcpState::SynSent => {
                tcb.clear();
                // Terminate outstanding RECV/SENDs
                TCBS[id].retry.notify_all();
                Ok(())
            },
            TcpState::SynReceived => {
                tcb.state = TcpState::FinWait1;

                // POSIX ensures that the send_buf must be empty (no text).
                // Send a FIN.
                tcb.send_buf.send_fin(&tcb.conn, tcb.recv_buf.rcv_wnd, tcb.recv_buf.rcv_nxt);

                // Terminate outstanding RECV/SENDs right away.
                TCBS[id].retry.notify_all();
                Ok(())
            },
            TcpState::Established => {
                // TODO: issue a send buffer flush?

                tcb.state = TcpState::FinWait1;
                // Send a FIN.
                tcb.send_buf.send_fin(&tcb.conn, tcb.recv_buf.rcv_wnd, tcb.recv_buf.rcv_nxt);
                TCBS[id].retry.notify_all();
                Ok(())
            },
            TcpState::FinWait1 | TcpState::FinWait2 => {
                Err(RtcpError::InvalidStateTransition("error: connection closing"))
            },
            TcpState::CloseWait => {
                // TODO: issue a send buffer flush?

                tcb.state = TcpState::Closing;
                // Send a FIN.
                tcb.send_buf.send_fin(&tcb.conn, tcb.recv_buf.rcv_wnd, tcb.recv_buf.rcv_nxt);
                TCBS[id].retry.notify_all();
                Ok(())
            },
            _ => {
                Err(RtcpError::InvalidStateTransition("error: connection closing"))
            },

        }
    }

    /// TCP ABORT command.
    pub fn tcp_abort(id: usize) -> Result<(), RtcpError> {
        assert!(id < MAX_SOCKET_FD);
        let mut guard = TCBS[id].inner.lock().unwrap();
        assert!(!guard.is_none());
        let tcb = guard.as_mut().unwrap();

        match tcb.state {
            TcpState::Closed => {
                Err(RtcpError::InvalidStateTransition("error: connection does not exist"))
            },
            TcpState::Listen | TcpState::SynSent => {
                tcb.clear();
                // Terminate outstanding RECV/SENDs
                TCBS[id].retry.notify_all();
                Ok(())
            },
            TcpState::SynReceived | TcpState::Established |
            TcpState::FinWait1 | TcpState::FinWait2 |
            TcpState::CloseWait => {
                // TODO: issue a send buffer flush?
                tcb.clear();

                // Send a RST
                tcb.send_buf.send_rst(&tcb.conn,
                    tcb.recv_buf.rcv_wnd, 
                    tcb.send_buf.snd_nxt,
                    tcb.recv_buf.rcv_nxt, true);
                // Terminate outstanding RECV/SENDs
                TCBS[id].retry.notify_all();
                Ok(())
            },
            _ => {
                tcb.clear();
                Ok(())
            }
        }
    }

    /// TCP SEGMENT-ARRIVES event.
    pub fn tcp_seg_arrive(
        id: usize,
        mut seg: TCPSegment,
    ) {
        assert!(id < MAX_SOCKET_FD);
        let mut guard = TCBS[id].inner.lock().unwrap();
        assert!(!guard.is_none());
        let tcb = guard.as_mut().unwrap();

        match tcb.state {
            TcpState::Closed => {
                // Discard data
                if !seg.header.is_rst {
                    let conn = TcpConnection {
                        dst_ip: seg.src_ip,
                        dst_port: seg.header.src_port,
                        src_port: seg.header.dst_port,
                        src_ip: Ipv4Addr::UNSPECIFIED,
                    };
                    // Send back a RST
                    if seg.header.is_ack {
                        // <SEQ=SEG.ACK><CTL=RST>
                        tcb.send_buf.send_rst(&conn, tcb.recv_buf.rcv_wnd, seg.header.ack, 0, false);
                    }
                    else {
                        // <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
                        tcb.send_buf.send_rst(&conn, tcb.recv_buf.rcv_wnd, 0, seg.header.seq + seg.data.len() as u32, true);
                    }

                }
            },
            TcpState::Listen => {
                if seg.header.is_rst {
                    // Ignore RST
                    return;
                }
                if seg.header.is_ack {
                    // Bad; send back a RST
                    let conn = TcpConnection {
                        dst_ip: seg.src_ip,
                        dst_port: seg.header.src_port,
                        src_port: seg.header.dst_port,
                        src_ip: tcb.conn.src_ip,
                    };
                    // <SEQ=SEG.ACK><CTL=RST>
                    tcb.send_buf.send_rst(&conn, tcb.recv_buf.rcv_wnd, seg.header.ack, 0, false);

                    return;
                }
                if seg.header.is_syn {
                    // Starting a new connection

                    tcb.recv_buf.rcv_unc = u32::wrapping_add(seg.header.seq, 1);
                    tcb.recv_buf.rcv_nxt = u32::wrapping_add(seg.header.seq, 1);
                    tcb.recv_buf.irs = seg.header.seq;

                    let iss = tcp_gen_seq();
                    tcb.send_buf.iss = iss;
                    tcb.send_buf.snd_una = iss;
                    tcb.send_buf.snd_nxt = iss; // Will add one after send_syn()
                    tcb.send_buf.snd_wl1 = iss;
                    tcb.send_buf.snd_wl2 = iss;

                    // <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
                    tcb.send_buf.send_syn(&tcb.conn, tcb.recv_buf.rcv_wnd, tcb.recv_buf.rcv_nxt,true); 

                    tcb.state = TcpState::SynReceived;
                    if tcb.conn.dst_ip.is_unspecified() {
                        tcb.conn.dst_ip = seg.src_ip;
                        tcb.conn.dst_port = seg.header.src_port;
                    }
                }

                // Any other control or text-bearing segment (not containing SYN)
                // must have an ACK and thus would be discarded by the ACK
                // processing.  An incoming RST segment could not be valid, since
                // it could not have been sent in response to anything sent by this
                // incarnation of the connection.  So you are unlikely to get here,
                // but if you do, drop the segment, and return.
                return;
            },
            TcpState::SynSent => {
                if seg.header.is_ack {
                    if i32::wrapping_sub(tcb.send_buf.iss as i32, seg.header.ack as i32) >= 0
                        || i32::wrapping_sub(seg.header.ack as i32, tcb.send_buf.snd_nxt as i32) > 0 
                    {
                        if seg.header.is_rst {
                            return;
                        }
                        // <SEQ=SEG.ACK><CTL=RST>
                        tcb.send_buf.send_rst(&tcb.conn, tcb.recv_buf.rcv_wnd, seg.header.ack, 0, false);
                        return;
                    }
                    // If SND.UNA =< SEG.ACK =< SND.NXT then the ACK is acceptable.
                }
                if seg.header.is_rst {
                    if seg.header.is_ack {
                        tcb.clear();
                        TCBS[id].retry.notify_all();
                    }
                    return;
                }
                if seg.header.is_syn {
                    // RCV.NXT is set to SEG.SEQ+1, IRS is set to
                    // SEG.SEQ.  SND.UNA should be advanced to equal SEG.ACK (if there
                    // is an ACK), and any segments on the retransmission queue which
                    // are thereby acknowledged should be removed.

                    tcb.recv_buf.rcv_unc = u32::wrapping_add(seg.header.seq, 1);
                    tcb.recv_buf.rcv_nxt = u32::wrapping_add(seg.header.seq, 1);
                    tcb.recv_buf.irs = seg.header.seq;

                    if seg.header.is_ack {
                        let (syn_acked, _) = tcb.send_buf.ack(seg.header.ack);
                        if syn_acked {
                            // Established!
                            assert!(i32::wrapping_sub(tcb.send_buf.snd_una as i32, tcb.send_buf.iss as i32) > 0);
                            tcb.state = TcpState::Established;
                            TCBS[id].retry.notify_all();

                            // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                            tcb.send_buf.send_ack(&tcb.conn, tcb.recv_buf.rcv_wnd, tcb.recv_buf.rcv_nxt);
                        }
                        else {
                            // Simutaneous OPEN
                            tcb.state = TcpState::SynReceived;

                            // <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
                            tcb.send_buf.send_syn(&tcb.conn, 
                                tcb.recv_buf.rcv_wnd, 
                                tcb.recv_buf.rcv_nxt, true);
                        }
                    }
                }
            }
            _ => {
                // first check sequence number

                // Segment Receive  Test
                // Length  Window
                // ------- -------  -------------------------------------------

                // 0       0     SEG.SEQ = RCV.NXT

                // 0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND

                // >0       0     not acceptable

                // >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
                //             or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND

                let seq_plus_len = u32::wrapping_add(seg.header.seq, seg.data.len() as u32);
                let nxt_plus_wnd = u32::wrapping_add(tcb.recv_buf.rcv_nxt, tcb.recv_buf.rcv_wnd as u32);
                let left = u32::saturating_sub(tcb.recv_buf.rcv_nxt, seg.header.seq) as usize;
                let right = usize::saturating_sub(seg.data.len(), u32::saturating_sub(seq_plus_len, nxt_plus_wnd) as usize);
                assert!(left <= right);

                let text_acceptable = right >= left;
                // Tailor the segment text, so that it starts after RCV.NXT, and ends before RCV.NXT+RCV.WND
                let seg_seq = u32::wrapping_add(seg.header.seq, left as u32);
                let data = &mut seg.data[left..right];
                
                // If SND.UNA =< SEG.ACK =< SND.NXT then the ACK is acceptable.
                // The ACK should then be accepted, even if the segment text is not.
                let ack_acceptable = seg.header.is_ack
                    && i32::wrapping_sub(seg.header.ack as i32, tcb.send_buf.snd_una as i32) >= 0
                    && i32::wrapping_sub(tcb.send_buf.snd_nxt as i32, seg.header.ack as i32) >= 0;

                if !text_acceptable {
                    // If an incoming segment is not acceptable, an acknowledgment
                    // should be sent in reply (unless the RST bit is set, if so drop
                    // the segment and return).

                    // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                    tcb.send_buf.send_ack(&tcb.conn, tcb.recv_buf.rcv_wnd, tcb.recv_buf.rcv_nxt);
                    // TODO: alternatively, flush the send_buf and piggyback ACK

                    if !ack_acceptable {
                        return;
                    }
                }
                

                // second check the RST bit
                if seg.header.is_rst {
                    // Control bits are handled in order
                    if seg_seq != tcb.recv_buf.rcv_nxt {
                        return;
                    }
                    match tcb.state {
                        TcpState::SynReceived => {
                            if tcb.passive {
                                // Unwind to Listen
                                tcb.state = TcpState::Listen;
                            }
                            else {
                                // Fail
                                tcb.clear();
                                TCBS[id].retry.notify_all();
                            }
                            return;
                        },
                        TcpState::Established | TcpState::FinWait1 |
                        TcpState::FinWait2 | TcpState::CloseWait => {
                            // TODO: flush send buffer
    
                            tcb.clear();
                            TCBS[id].retry.notify_all();
                            return;
                        },
                        TcpState::Closing | TcpState::LastAck | TcpState::TimeWait => {
                            tcb.clear();
                            return;
                        }
                        _ => unreachable!(),
                    }
                }

                // third, check the SYN bit
                if seg.header.is_syn {
                    // Control bits are handled in order
                    if seg_seq != tcb.recv_buf.rcv_nxt {
                        return;
                    }

                    // SYN in window, error
                    tcb.send_buf.send_rst(&tcb.conn, 
                        tcb.recv_buf.rcv_wnd, 
                        tcb.send_buf.snd_nxt, 
                        0, false);

                    // TODO: flush send buffer
    
                    tcb.clear();
                    TCBS[id].retry.notify_all();
                    return;
                }

                // fourth, check ACK bit
                if !seg.header.is_ack {
                    // Must have ACK for a data segment
                    return;
                }
                else {
                    if matches!(tcb.state, TcpState::SynReceived) {
                        // If SND.UNA =< SEG.ACK =< SND.NXT then enter ESTABLISHED state
                        // and continue processing.
                        if ack_acceptable {
                            tcb.state = TcpState::Established;
                            TCBS[id].retry.notify_all();
                        }
                        else {
                            // <SEQ=SEG.ACK><CTL=RST>
                            tcb.send_buf.send_rst(&tcb.conn, 
                                tcb.recv_buf.rcv_wnd, 
                                seg.header.ack, 0, false);
                            return;
                        }
                    }
                    match tcb.state {
                        TcpState::SynReceived => unreachable!(),
                        TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2 |
                        TcpState::CloseWait | TcpState::Closing => {
                            if ack_acceptable {
                                let (_, fin_acked) = tcb.send_buf.ack(seg.header.ack);

                                // Update SND.WND
                                let diff = i32::wrapping_sub(seg_seq as i32, tcb.send_buf.snd_wl1 as i32);
                                // The check here prevents using old segments to update the window.
                                if diff > 0 
                                    || (diff == 0 && i32::wrapping_sub(seg.header.ack as i32, tcb.send_buf.snd_wl2 as i32) >= 0) 
                                {
                                    tcb.send_buf.snd_wnd = seg.header.wnd;
                                    tcb.send_buf.snd_wl1 = seg_seq;
                                    tcb.send_buf.snd_wl2 = seg.header.ack;
                                }

                                if matches!(tcb.state, TcpState::FinWait1) {
                                    // In addition to the processing for the ESTABLISHED state, if
                                    // our FIN is now acknowledged then enter FIN-WAIT-2 and continue
                                    // processing in that state.
                                    if fin_acked {
                                        tcb.state = TcpState::FinWait2;
                                    }
                                }
                                if matches!(tcb.state, TcpState::Closing) {
                                    // In addition to the processing for the ESTABLISHED state, if
                                    // the ACK acknowledges our FIN then enter the TIME-WAIT state,
                                    // otherwise ignore the segment.
                                    if fin_acked {
                                        tcb.state = TcpState::TimeWait;
                                    }
                                }
                            }
                            else if i32::wrapping_sub(tcb.send_buf.snd_nxt as i32, seg.header.ack as i32) < 0 {
                                // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                                tcb.send_buf.send_ack(&tcb.conn, tcb.recv_buf.rcv_wnd, tcb.recv_buf.rcv_nxt);
                                // TODO: alternatively, flush the send_buf and piggyback ACK
                                return;
                            }
                            
                        },
                        TcpState::LastAck => {
                            // The only thing that can arrive in this state is an
                            // acknowledgment of our FIN.  If our FIN is now acknowledged,
                            // delete the TCB, enter the CLOSED state, and return.
                            if ack_acceptable {
                                let (_, fin_acked) = tcb.send_buf.ack(seg.header.ack);
                                if fin_acked {
                                    tcb.clear();
                                }
                            }
                            return;
                        },
                        TcpState::TimeWait => {
                            // The only thing that can arrive in this state is a
                            // retransmission of the remote FIN.  Acknowledge it, and restart
                            // the 2 MSL timeout.
                            if ack_acceptable {
                                let (_, fin_acked) = tcb.send_buf.ack(seg.header.ack);
                                if fin_acked {
                                    // TODO: MSL timer
                                }
                            }
                            return;
                        },
                        _ => unreachable!(),  
                    }
                }

                // fifth, process the segment text
                if data.len() > 0 {
                    match tcb.state {
                        TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2 => {
                            // Put data into TcpRecvBuf
                            // RCV.NXT and RCV.WND are adjusted accordingly.
                            tcb.recv_buf.put(data, seg_seq);
    
                            // Send an acknowledgment of the form:
                            // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                            // This acknowledgment should be piggybacked on a segment being
                            // transmitted if possible without incurring undue delay.
    
                            tcb.send_buf.send_ack(&tcb.conn, tcb.recv_buf.rcv_wnd, tcb.recv_buf.rcv_nxt);
                            // TODO: alternatively, flush the send_buf and piggyback ACK
                        },
                        _ => {
                            // This should not occur, since a FIN has been received from the
                            // remote side.  Ignore the segment text.
                        }
                    }
                }
                
                // sixth, check the FIN bit
                if seg.header.is_fin {
                    // Control bits are handled in order
                    if seg_seq != tcb.recv_buf.rcv_nxt {
                        return;
                    }
                    if matches!(tcb.state, TcpState::Closed) 
                        || matches!(tcb.state, TcpState::Listen) 
                        || matches!(tcb.state, TcpState::SynSent) {
                        return;
                    }

                    // If the FIN bit is set, signal the user "connection closing" and
                    // return any pending RECEIVEs with same message, advance RCV.NXT
                    // over the FIN, and send an acknowledgment for the FIN. 

                    tcb.recv_buf.rcv_nxt = u32::wrapping_add(tcb.recv_buf.rcv_nxt, 1);
                    tcb.recv_buf.finned = true;

                    tcb.send_buf.send_ack(&tcb.conn, tcb.recv_buf.rcv_wnd, tcb.recv_buf.rcv_nxt);
                    

                    match tcb.state {
                        TcpState::SynReceived | TcpState::Established => {
                            tcb.state = TcpState::CloseWait;
                            TCBS[id].retry.notify_all();
                            return;
                        },
                        TcpState::FinWait1 => {
                            // ACKed FIN would be handled previously.
                            // Just enter the CLOSING state.
                            tcb.state = TcpState::Closing;
                            return;
                        },
                        TcpState::FinWait2 => {
                            // Enter the TIME-WAIT state.  Start the time-wait timer, turn
                            // off the other timers.
                            tcb.state = TcpState::TimeWait;
                            // TODO: timer
                            return;
                        },
                        TcpState::CloseWait | TcpState::Closing | TcpState::LastAck => {
                            // Remains state
                            return;
                        },
                        TcpState::TimeWait => {
                            // TODO: Restart the 2 MSL time-wait timeout.
                        },
                        _ => unreachable!(),
                    }
                }

            }
        }
    }
}