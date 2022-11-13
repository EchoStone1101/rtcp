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
    //! 
    //! For now there is no congestion control. Without ACK-clocking, we
    //! also do not batch sends and all `send_xxx` methods send packets to 
    //! RIP immediately. Should a send queue be added for batching, all places 
    //! marked with FUTURE shall include a send queue flush.
    
    #[allow(unused)]
    
    use rip::{RipPacket, Ipv4Packet, RipCtl};
    use crate::{TCBS, MAX_SOCKET_CNT, RtcpError, TCPHeader, TCPSegment};
    use std::collections::{BinaryHeap, BTreeMap, VecDeque};
    use std::net::Ipv4Addr;
    use std::sync::{Mutex, Condvar, MutexGuard};
    use std::thread;
    use std::time::Duration;
    use chrono::Utc;

    /// An unspecified port.
    pub const TCP_UNSPECIFIED_PORT: u16 = 0;

    /// The lowest ephemeral port.
    pub const TCP_EPHEMERAL_PORT_LBOUND: u16 = 1025;

    /// TCP buffer size.
    pub const TCP_BUFFER_SZ: usize = 32768;

    /// TCP default retransmission timeout, in ms.
    pub const TCP_DFT_RETX_TIMEOUT: u32 = 1000;

    /// TCP maximum retransmission timeout, in ms.
    pub const TCP_MAX_RETX_TIMEOUT: u32 = 400;

    /// TCP minimal retransmission timeout, in ms.
    pub const TCP_MIN_RETX_TIMEOUT: u32 = 5;

    /// TCP Maximum Segment Life, in ms.
    /// For testing purposes, we set this to 5 seconds, which is
    /// drastically shorter than it should be.
    pub const TCP_MSL: u32 = 5_000;

    /// TCP global timeout, in ms.
    /// A TCP connection is aborted, if no segment is received on
    /// the TCB for this period of time.
    /// The normal practice is 5 minutes, which is also shortened for
    /// testing proposes here.
    pub const TCP_GLOBAL_TIMEOUT: u32 = 30_000;

    /// TCP maximal receiver segment queue size, for selective repeat.
    /// This constraint is picked only to defend against abnormal conditions.
    pub const TCP_MAX_SEGQUEUE_SZ: usize = 65536;

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

        /// Send data buffer.
        pub send_buf: TcpSendBuf,
        /// Receive data buffer.
        pub recv_buf: TcpRecvBuf,

        /// Retransmission timer thread
        pub re_tx_thread: thread::JoinHandle<()>,

        /// Global timeout / Time Wait thread
        pub timeout_thread: thread::JoinHandle<()>,

        /// The global timeout, either for abortion or closing (in
        /// Time Wait state).
        /// The name is picked in honor of God of War: Ragnarok, becasue
        /// why not?
        ragnarok: Option<u64>,

        /// An identifier of this TCB, for the proper termination
        /// of the timer threads.
        pub nonce: u64,

        /// Whether this TCB is finished.
        finished: bool,
    }

    impl _TCB {
        /// Restore the TCB to a clean state, and CLOSED
        pub fn clear(&mut self) {
            // Do not clear up `conn`: we need this information to
            // clean up POSIX related stuff.

            self.state = TcpState::Closed;
            self.passive = false;
            self.finished = true;

            // TODO: clear send_buf and recv_buf?
            
            // Since we spawn rx_thread in CLOSED state, we do not
            // join it here. Rather, it is joined when this _TCB is
            // freed to None.
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

        /// Retransmission queue.
        /// The actual data structure used is Search Tree with O(log(n)) look-up time.
        /// This is because we need to sort ReTxItem both by SEQ and timestamp.
        pub re_tx_queue_by_seq: VecDeque<ReTxItem>,
        pub re_tx_queue_by_seq_ofs: u64,
        pub re_tx_queue_by_ts: BTreeMap<TS, u64>,

        /// Retransmission timeout in ms
        pub re_tx_timeout: u32,

        /// Send handle
        pub tx: flume::Sender<RipPacket>,
    }

    /// A segment in retransmission queue.
    #[derive(Debug, Clone, Copy)]
    pub struct ReTxItem {
        pub start: u32,
        pub end: u32,
        pub is_syn: bool,
        pub is_fin: bool,
        pub is_ack: bool,
    }

    /// Sort by timestamp (and the end SEQ, should timestamp collide).
    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct TS(u64, u32);
    

    impl TcpSendBuf {
        /// Put `data` into buffer, and register the segment 
        /// in re_tx_queue. The validity of this call should be
        /// checked beforehand.
        fn put(&mut self, is_syn: bool, is_fin: bool, is_ack: bool, data: &[u8]) {
            assert!(data.len() <= TCP_BUFFER_SZ as usize);
            assert!(u64::wrapping_add(self.snd_nxt as u64, data.len() as u64) <= u64::wrapping_add(self.snd_una as u64, self.snd_wnd as u64));
            let virt_len = data.len() as u32 
                + if is_syn {1} else {0}
                + if is_fin {1} else {0};

            if data.len() > 0 {
                // Make sure we do not overwrite buffer
                assert!(u64::wrapping_add(self.snd_una as u64, TCP_BUFFER_SZ as u64) >= u64::wrapping_add(self.snd_nxt as u64, virt_len as u64));

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
            
            let end = u32::wrapping_add(self.snd_nxt, virt_len);
            let idx = self.re_tx_queue_by_seq.len();
            let item = ReTxItem {
                start: self.snd_nxt,
                end,
                is_syn,
                is_fin,
                is_ack,
            };
            self.re_tx_queue_by_seq.push_back(item);
            assert!(self.re_tx_queue_by_ts.insert(
                TS(tcp_timestamp(), end),
                self.re_tx_queue_by_seq_ofs + idx as u64,
            ).is_none());

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
            self.put(hdr.is_syn, hdr.is_fin, is_ack, &[]);
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
            self.put(hdr.is_syn, hdr.is_fin, true, &[]);
            _ = RipCtl::send_ipv4_packet(
                &mut self.tx,
                conn.src_ip,
                conn.dst_ip,
                {
                    hdr.serialize(&mut buf).unwrap();
                    &mut buf
                }
            ).unwrap();
            // println!("[SEND_FIN] {:?}", hdr);
        }

        /// Send a bare ACK segment.
        /// Bare ACKs are not put into re_tx_queue; for data transmission, ACK
        /// can be piggybacked by data segments. The only "important" bare ACKs
        /// are ACK of SYN/FIN, which if lost are triggered again by re-rx of
        /// SYN/FIN.
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
            // Do not put into re_tx_queue
            // self.put(hdr.is_syn, hdr.is_fin, &[]);
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
        /// RSTs are not put into re_tx_queue, and they might use different SEQ and ACK settings
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
            let free = i32::wrapping_sub(
                u32::wrapping_add(self.snd_una, self.snd_wnd as u32) as i32, 
                self.snd_nxt as i32);
            // assert!(free >= 0);
            if free <= 0 {
                return Err(RtcpError::TCPCommandRetry);
            }
            let bytes_sent = std::cmp::min(free as usize, data.len());

            let mut buf = [0u8; 20];

            let mut cur = 0;
            loop {
                let len = std::cmp::min(bytes_sent - cur, RipCtl::MAX_PAYLOAD_SZ);
                
                if len == 0 {
                    break;
                }

                let hdr = TCPHeader {
                    src_port: conn.src_port,
                    dst_port: conn.dst_port,
                    seq: self.snd_nxt,
                    ack,
                    data_ofs: 5,
                    is_urg: false, is_psh: false, is_fin: false, is_syn: false, is_rst: false,
                    is_ack: true,
                    wnd,
                    checksum: 0,
                    urg_ptr: 0,
                    _options: (),
                };
                hdr.serialize(&mut buf).unwrap();

                _ = RipCtl::send_ipv4_packet_with_header(
                    &mut self.tx, 
                    conn.src_ip, conn.dst_ip, 
                    &buf, 
                    &data[cur..cur+len]);
                self.put(false, false, true, &data[cur..cur+len]);

                if len < RipCtl::MAX_PAYLOAD_SZ {
                    break;
                }
                cur += RipCtl::MAX_PAYLOAD_SZ;
            }

            Ok(bytes_sent)
        }

        /// Retransmit a segment described by a ReTxItem, changing its timestamp.
        pub fn retransmit(&mut self, conn: &TcpConnection, item: &ReTxItem, ack: u32, wnd: u16) {
            assert!(i32::wrapping_sub(item.start as i32, self.snd_una as i32) >= 0);

            let mut left = u32::wrapping_add(item.start, if item.is_syn {1} else {0}) as u16;
            if left > TCP_BUFFER_SZ as u16 {
                left -= TCP_BUFFER_SZ as u16;
            }
            let right = u32::wrapping_sub(u32::wrapping_sub(item.end, if item.is_fin {1} else {0}), item.start) as u16 + left;

            assert!(left <= right);

            let mut hdr_buf = [0u8; 20];

            let hdr = TCPHeader {
                src_port: conn.src_port,
                dst_port: conn.dst_port,
                seq: item.start,
                ack,
                data_ofs: 5,
                is_urg: false, is_psh: false, is_rst: false,
                is_ack: item.is_ack, is_fin: item.is_fin, is_syn: item.is_syn,
                wnd,
                checksum: 0,
                urg_ptr: 0,
                _options: (),
            };
            hdr.serialize(&mut hdr_buf).unwrap();

            if right > TCP_BUFFER_SZ as u16 {
                _ = RipCtl::send_ipv4_packet_with_header_split(
                    &mut self.tx, 
                    conn.src_ip, conn.dst_ip, 
                    &hdr_buf, 
                    &self.buf[left as usize..],
                    &self.buf[..(right-TCP_BUFFER_SZ as u16) as usize],
                );
            }
            else {
                _ = RipCtl::send_ipv4_packet_with_header(
                    &mut self.tx, 
                    conn.src_ip, conn.dst_ip, 
                    &hdr_buf, 
                    &self.buf[left as usize..right as usize]
                );
            }
            // item.timestamp = tcp_timestamp();
            // println!("{:?}", conn);
            // eprintln!("[RETX] {}-{}", item.start, item.end);

        }

        /// ACK data in this send buffer, so that snd_una can be moved, and retransmission
        /// queue can be popped. `ack` should be checked beforehand and is assumed acceptable.
        pub fn ack(&mut self, ack: u32) -> (bool, bool, bool) {
            let mut syn_acked = false;
            let mut fin_acked = false;
            
            while !self.re_tx_queue_by_seq.is_empty() {

                let item = self.re_tx_queue_by_seq.front_mut().unwrap();

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
                    _ = self.re_tx_queue_by_seq.pop_front();
                    self.re_tx_queue_by_seq_ofs += 1;
                }
                else {
                    item.start = ack;
                    break;
                }
            }

            // Advance SND.UNA
            let advanced = i32::wrapping_sub(ack as i32, self.snd_una as i32);
            assert! (advanced >= 0);
            self.snd_una = ack;

            (syn_acked, fin_acked, advanced > 0)
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
        pub seg_queue: BinaryHeap<SegItem>,
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
        /// 
        /// This method might return false when the `seg_queue` is too full. Normally
        /// this should not be a concern, but if somehow an in-order segment is never 
        /// received, the future segments can cause `seg_queue` to drain memory.
        pub fn put(&mut self, data: &[u8], seg_seq: u32) -> (bool, bool) {
            if data.len() == 0 {
                return (true, false);
            }
            assert!(data.len() <= TCP_BUFFER_SZ as usize);
            assert!(u64::wrapping_add(seg_seq as u64, data.len() as u64) <= u64::wrapping_add(self.rcv_nxt as u64, self.rcv_wnd as u64));
            assert!(i32::wrapping_sub(seg_seq as i32, self.rcv_nxt as i32) >= 0);

            // Make sure we do not overwrite buffer
            assert!(u64::wrapping_add(self.rcv_unc as u64, TCP_BUFFER_SZ as u64) >= u64::wrapping_add(self.rcv_nxt as u64, self.rcv_wnd as u64));

            let queue = &mut self.seg_queue;
            if queue.len() >= TCP_MAX_SEGQUEUE_SZ {
                return (false, false);
            }

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

            // Manipulate `seg_queue`: insert the segment, delay the coalescing.
            queue.push(SegItem {start: seg_seq, end: u32::wrapping_add(seg_seq, data.len() as u32)});

            // if queue.len() > 20 {
            //     while !queue.is_empty() {
            //         println!("{:?}", queue.pop().unwrap());
            //     }
            //     panic!("let's see...");
            // }

            // Check if we can move RCV.NXT
            // println!("rcv_nxt: {}, seg_seq: {}", self.rcv_nxt, seg_seq);

            let &SegItem{start, end} = queue.peek().unwrap();
            let mut rcv_nxt_moved = false;
            if start == self.rcv_nxt {
                // Coalesce now
                let mut new_rcv_nxt = end;
                while !queue.is_empty() {
                    let &SegItem{start, end} = queue.peek().unwrap();
                    // println!("> {}, {}, {}", new_rcv_nxt, start, end);

                    if i32::wrapping_sub(new_rcv_nxt as i32, start as i32) < 0 {
                        break;
                    }
                    _ = queue.pop().unwrap();

                    if i32::wrapping_sub(end as i32, new_rcv_nxt as i32) > 0 {
                        new_rcv_nxt = end;
                        
                    }
                }
                rcv_nxt_moved = i32::wrapping_sub(new_rcv_nxt as i32, self.rcv_nxt as i32) > 0;
                self.rcv_nxt = new_rcv_nxt;
                self.rcv_wnd = u16::checked_sub(self.rcv_wnd, u32::wrapping_sub(new_rcv_nxt, start) as u16).unwrap();
            }

            (true, rcv_nxt_moved)
        }

        /// Get text from buffer.
        /// The behavior is "retry until at least one byte can be got"; `data`
        /// can also be larger than buffer size, where it is guaranteed that
        /// all of `data` is not filled.
        pub fn get_text(&mut self, data: &mut [u8]) -> Result<usize, RtcpError> {
            // Check for buffer space
            let avail = u32::checked_sub(
                i32::wrapping_sub(self.rcv_nxt as i32, self.rcv_unc as i32).clamp(0, i32::MAX) as u32, 
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
    #[derive(Debug, PartialEq, Eq)]
    pub struct SegItem {
        pub start: u32,
        pub end: u32,
    }

    // The Ord derivation must not be used, since the comparison is wrapped 
    // comparison.
    impl PartialOrd for SegItem {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            let diff1 = i32::wrapping_sub(self.start as i32, other.start as i32);
            let diff2 = i32::wrapping_sub(self.end as i32, other.end as i32);

            if diff1 == 0 {
                if diff2 < 0 {
                    Some(std::cmp::Ordering::Greater)
                }
                else if diff2 > 0 {
                    Some(std::cmp::Ordering::Less)
                }
                else {
                    Some(std::cmp::Ordering::Equal)
                }
            }
            else if diff1 > 0 {
                Some(std::cmp::Ordering::Less)
            }
            else {
                Some(std::cmp::Ordering::Greater)
            }
        }
    }
    impl Ord for SegItem {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            // Min heap
            self.partial_cmp(other).unwrap()
        }
    }

    /// A TCP connection, identified by the quad.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct TcpConnection {
        pub src_ip: Ipv4Addr,
        pub dst_ip: Ipv4Addr,
        pub src_port: u16,
        pub dst_port: u16,
    }

    impl TcpConnection {
        pub fn dst_sock_unspecified(&self) -> bool {
            self.dst_ip.is_unspecified() || self.dst_port == TCP_UNSPECIFIED_PORT
        }

        pub fn src_sock_unspecified(&self) -> bool {
            self.src_ip.is_unspecified() && self.src_port == TCP_UNSPECIFIED_PORT
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
    pub fn tcp_timestamp() -> u64 {
        Utc::now().timestamp_micros() as u64
    }

    /// Generate ISN based on a timer that increments approximately
    /// every 4us.
    fn tcp_gen_seq() -> u32 {
        (tcp_timestamp() as u32)>>2
    }


    /// TCP STATUS command.
    pub fn tcp_status(id: usize) -> TcpState {
        assert!(id < MAX_SOCKET_CNT);

        let guard = TCBS[id].inner.lock().unwrap();
        assert!(!guard.is_none());

        // let send_buf = &guard.as_ref().unwrap().send_buf;
        // eprintln!("iss:{}, una:{}, nxt:{}, wnd:{}", send_buf.iss, send_buf.snd_una, send_buf.snd_nxt, send_buf.snd_wnd);
        // let recv_buf = &guard.as_ref().unwrap().recv_buf;
        // eprintln!("irs:{}, unc:{}, nxt:{}, wnd:{}", recv_buf.irs, recv_buf.rcv_unc, recv_buf.rcv_nxt, recv_buf.rcv_wnd);

        guard.as_ref().unwrap().state
    }

    /// Pseudo TCP CREATE command.
    /// Actual TCP creates TCB upon OPEN command; but for management reasons,
    /// it would be easier to break it down. Here, CREATE makes a CLOSED TCB,
    /// and OPEN acts on a given TCB just like any other TCP command.
    pub fn tcp_create(
        id: usize, 
        guard: &mut MutexGuard<Option<_TCB>>,
        tx: flume::Sender<RipPacket>) 
        -> Result<(), RtcpError>
    {
        assert!(id < MAX_SOCKET_CNT);
        assert!(guard.is_none());
        let nonce = tcp_timestamp();
        _ = guard.insert(_TCB {
            conn: TcpConnection { 
                src_ip: Ipv4Addr::UNSPECIFIED, 
                src_port: TCP_UNSPECIFIED_PORT, 
                dst_ip: Ipv4Addr::UNSPECIFIED, 
                dst_port: TCP_UNSPECIFIED_PORT
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
                re_tx_queue_by_seq: VecDeque::new(),
                re_tx_queue_by_seq_ofs: 0,
                re_tx_queue_by_ts: BTreeMap::new(),
                re_tx_timeout: TCP_DFT_RETX_TIMEOUT,
                tx,
            },
            recv_buf: TcpRecvBuf {
                buf: Box::new([0u8; TCP_BUFFER_SZ]),
                rcv_unc: 0,
                rcv_nxt: 0,
                rcv_wnd: TCP_BUFFER_SZ as u16,
                irs: 0,
                finned: false,
                seg_queue: BinaryHeap::new(),
            },
            // Start the retransmission timer thread
            re_tx_thread: thread::spawn(move || {
                let my_nonce = nonce;

                loop {
                    let mut guard = TCBS[id].inner.lock().unwrap();
                    if guard.is_none() || my_nonce != guard.as_ref().unwrap().nonce {
                        // TCB has been deleted, or is now a new incarnation.
                        // Break and terminate.
                        drop(guard);
                        break;
                    }

                    // One round of retransmission
                    let tcb = guard.as_mut().unwrap();
                    if matches!(tcb.state, TcpState::Closed) {
                        if tcb.finished {
                            break;
                        }
                        _ = TCBS[id].retry.wait(guard);
                        continue;
                    }
                    if matches!(tcb.state, TcpState::TimeWait) {
                        // No longer retransmit in TimeWait
                        break;
                    }

                    let mut wakeup = None;

                    while !tcb.send_buf.re_tx_queue_by_ts.is_empty() {
                        let (&TS(ts, end), &idx) = tcb.send_buf.re_tx_queue_by_ts.iter().next().unwrap();

                        if idx < tcb.send_buf.re_tx_queue_by_seq_ofs {
                            // The SegItem is already acked, skip
                            assert!(tcb.send_buf.re_tx_queue_by_ts.remove(&TS(ts, end)).is_some());
                            continue
                        }
                        
                        if ts + (tcb.send_buf.re_tx_timeout * 1000) as u64 <= tcp_timestamp() {
                            
                            assert!(tcb.send_buf.re_tx_queue_by_ts.remove(&TS(ts, end)).is_some());

                            // Retransmit
                            let real_idx = (idx - tcb.send_buf.re_tx_queue_by_seq_ofs) as usize;
                            let item = tcb.send_buf.re_tx_queue_by_seq[real_idx];
                            tcb.send_buf.retransmit(&tcb.conn, &item, tcb.recv_buf.rcv_nxt, tcb.recv_buf.rcv_wnd);

                            tcb.send_buf.re_tx_queue_by_ts.insert(TS(tcp_timestamp(), end), idx);
                        }
                        else {
                            wakeup = Some(ts + (tcb.send_buf.re_tx_timeout * 1000) as u64);
                            break;
                        }
                    }

                    if !tcb.recv_buf.finned {
                        tcb.send_buf.send_ack(&tcb.conn, tcb.recv_buf.rcv_wnd, tcb.recv_buf.rcv_nxt);
                    }

                    let dft_timeout = tcb.send_buf.re_tx_timeout as u64;

                    drop(guard); // Drop before sleeping!

                    if let Some(future) = wakeup {
                        // println!("[SLEEP] {}", future - now);
                        thread::sleep(Duration::from_micros(
                            u64::clamp(u64::saturating_sub(future, tcp_timestamp()), 
                            TCP_MIN_RETX_TIMEOUT as u64 * 1000, 
                            TCP_MAX_RETX_TIMEOUT as u64 * 1000))
                        );
                    }
                    else {
                        // println!("[SLEEP] {}", dft_timeout);
                        thread::sleep(Duration::from_millis(dft_timeout));
                    }
                    
                    // drop(guard);
                    // thread::sleep(Duration::from_millis(100000000));
                }
            }),
            ragnarok: None,
            // Start the timeout thread 
            timeout_thread: thread::spawn(move|| {
                let my_nonce = nonce;

                loop {
                    let mut guard = TCBS[id].inner.lock().unwrap();
                    if guard.is_none() || my_nonce != guard.as_ref().unwrap().nonce {
                        // TCB has been deleted, or is now a new incarnation.
                        // Terminate.
                        drop(guard);
                        break;
                    }

                    let tcb = guard.as_mut().unwrap();
                    if matches!(tcb.state, TcpState::Closed) {
                        if tcb.finished {
                            break;
                        }
                        _ = TCBS[id].retry.wait(guard);
                        continue;
                    }

                    let now = tcp_timestamp();

                    if tcb.ragnarok.is_none() {
                        // Starting global timeout 
                        tcb.ragnarok = Some(now + (TCP_GLOBAL_TIMEOUT * 1000) as u64);
                    }

                    let ragnarok = tcb.ragnarok.unwrap();
                    if now < ragnarok {
                        drop(guard);
                        thread::sleep(Duration::from_micros(ragnarok - now));
                    }
                    else {
                        // Timeout!
                        if matches!(tcb.state, TcpState::TimeWait) {
                            tcb.clear();
                            eprintln!("[RTCP] TimeWait {} done", id);
                            break;
                        }
                        else {
                            tcp_abort(id, &mut guard).unwrap();
                            eprintln!("[RTCP] Abort {} due to timeout", id);
                            break;
                        }
                    }
                }

            }),
            nonce,
            finished: false,
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
        assert!(id < MAX_SOCKET_CNT);

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
                    TCBS[id].retry.notify_all();
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
                    TCBS[id].retry.notify_all();
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
        buf: &[u8],
        _push: bool,
        _urgent: bool) -> Result<usize, RtcpError>
    {
        loop {
            let mut nonce = None;
            match tcp_send_once(id, buf, &mut nonce) {
                Err(e) if matches!(e, RtcpError::TCPCommandRetry) => {},
                Err(e) => return Err(e),
                Ok(cnt) => return Ok(cnt),
            }
        }
    }

    /// TCP SEND internal.
    pub fn tcp_send_once(
        id: usize,
        buf: &[u8],
        nonce: &mut Option<u64>) -> Result<usize, RtcpError>
    {
        assert!(id < MAX_SOCKET_CNT);
        let mut guard = TCBS[id].inner.lock().unwrap();
        assert!(!guard.is_none());
        let tcb = guard.as_mut().unwrap();
        if nonce.is_none() {
            _ = nonce.insert(tcb.nonce);
        }
        else {
            if tcb.nonce.ne(nonce.as_ref().unwrap()) {
                return Err(RtcpError::TCPCommandAbort);
            }
        }

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
                let _mg = TCBS[id].retry.wait(guard).unwrap();
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
                    let _mg = TCBS[id].retry.wait(guard).unwrap();
                }
                // FUTURE: flush send queue
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
        buf: &mut [u8],
        _push: bool,
        _urgent: bool) -> Result<usize, RtcpError> 
    {
        loop {
            let mut nonce = None;
            match tcp_recv_once(id, buf, &mut nonce) {
                Err(e) if matches!(e, RtcpError::TCPCommandRetry) => {},
                Err(e) => return Err(e),
                Ok(cnt) => return Ok(cnt),
            }
        }
    }

    /// TCP RECEIVE internal
    pub fn tcp_recv_once(
        id: usize,
        buf: &mut [u8],
        nonce: &mut Option<u64>) -> Result<usize, RtcpError> 
    {
        assert!(id < MAX_SOCKET_CNT);
        let mut guard = TCBS[id].inner.lock().unwrap();
        assert!(!guard.is_none());
        let tcb = guard.as_mut().unwrap();
        if nonce.is_none() {
            _ = nonce.insert(tcb.nonce);
        }
        else {
            if tcb.nonce.ne(nonce.as_ref().unwrap()) {
                return Err(RtcpError::TCPCommandAbort);
            }
        }

        match tcb.state {
            TcpState::Closed => {
                Err(RtcpError::InvalidStateTransition("error: connection does not exist"))
            },
            TcpState::Listen | TcpState::SynSent | TcpState::SynReceived => {
                // Retry this command
                let _mg = TCBS[id].retry.wait(guard).unwrap();
                Err(RtcpError::TCPCommandRetry)
            },
            TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2 => {
                // Retrieve data between RCV.UNC and RCV.NXT, if any
                let recv_buf = &mut tcb.recv_buf;
                let res = recv_buf.get_text(buf);
                if matches!(res, Err(RtcpError::TCPCommandRetry)) {
                    // Retry this command
                    let _mg = TCBS[id].retry.wait(guard).unwrap();
                }
                else {
                    // RCV.WND must have moved; send an ACK updating the sender's window
                    if tcb.send_buf.re_tx_queue_by_seq.is_empty() {
                        tcb.send_buf.send_ack(&tcb.conn, tcb.recv_buf.rcv_wnd, tcb.recv_buf.rcv_nxt);
                    }
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
        assert!(id < MAX_SOCKET_CNT);
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
                // FUTURE: flush send queue

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
                // FUTURE: flush send queue

                tcb.state = TcpState::LastAck;
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
    pub fn tcp_abort(id: usize, guard: &mut MutexGuard<Option<_TCB>>) -> Result<(), RtcpError> {
        assert!(id < MAX_SOCKET_CNT);
        // let mut guard = TCBS[id].inner.lock().unwrap();
        // assert!(!guard.is_none());
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
                // FUTURE: flush send queue
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

    /// TCP SEGMENT-ARRIVE event.
    pub fn tcp_seg_arrive(
        id: usize,
        mut seg: TCPSegment,
    ) {
        assert!(id < MAX_SOCKET_CNT);
        let mut guard = TCBS[id].inner.lock().unwrap();
        assert!(!guard.is_none());
        let tcb = guard.as_mut().unwrap();

        // Refresh global timeout
        if !matches!(tcb.state, TcpState::TimeWait) && !matches!(tcb.state, TcpState::Closed) {
            if tcb.ragnarok.is_some() {
                tcb.ragnarok = Some(tcp_timestamp() + (TCP_GLOBAL_TIMEOUT * 1000) as u64);
            }
        }

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
                        let (syn_acked, _, _) = tcb.send_buf.ack(seg.header.ack);
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
                    else {
                        if i32::wrapping_sub(tcb.send_buf.snd_una as i32, tcb.send_buf.iss as i32) <= 0 {
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

                let left = i32::wrapping_sub(tcb.recv_buf.rcv_nxt as i32, seg.header.seq as i32).clamp(0, i32::MAX);
                let right = seg.data.len() as i32 - i32::wrapping_sub(seq_plus_len as i32, nxt_plus_wnd as i32).clamp(0, i32::MAX);
                // let left = usize::min(u32::saturating_sub(tcb.recv_buf.rcv_nxt, seg.header.seq) as usize, seg.data.len());
                // let right = usize::saturating_sub(seg.data.len(), u32::saturating_sub(seq_plus_len, nxt_plus_wnd) as usize);

                // assert!(left <= right);

                let text_acceptable = right >= left;

                let left = left as usize;
                let right = right.clamp(0, seg.data.len() as i32) as usize;

                // Tailor the segment text, so that it starts after RCV.NXT, and ends before RCV.NXT+RCV.WND
                let seg_seq = u32::wrapping_add(seg.header.seq, left as u32);
                let data = if text_acceptable {&mut seg.data[left..right]} else {&mut []};
                
                // If SND.UNA =< SEG.ACK =< SND.NXT then the ACK is acceptable.
                // The ACK should then be accepted, even if the segment text is not.
                let ack_acceptable = seg.header.is_ack
                    && i32::wrapping_sub(seg.header.ack as i32, tcb.send_buf.snd_una as i32) >= 0
                    && i32::wrapping_sub(tcb.send_buf.snd_nxt as i32, seg.header.ack as i32) >= 0;

                if !text_acceptable {
                    // If an incoming segment is not acceptable, an acknowledgment
                    // should be sent in reply (unless the RST bit is set, if so drop
                    // the segment and return).
                    if seg.header.is_rst {
                        return;
                    }

                    // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                    if tcb.send_buf.re_tx_queue_by_seq.is_empty() {
                        tcb.send_buf.send_ack(&tcb.conn, tcb.recv_buf.rcv_wnd, tcb.recv_buf.rcv_nxt);
                    }
                    // FUTURE: flush send queue and piggyback ACK

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
                            // FUTURE: flush send queue
    
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
                if seg.header.is_syn && seg_seq == seg.header.seq { // Nasty!! SYN might be trimmed
                    // Control bits are handled in order
                    if seg_seq != tcb.recv_buf.rcv_nxt {
                        return;
                    }

                    // SYN in window, error
                    tcb.send_buf.send_rst(&tcb.conn, 
                        tcb.recv_buf.rcv_wnd, 
                        tcb.send_buf.snd_nxt, 
                        0, false);

                    // FUTURE: flush send queue
    
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
                                let (_, fin_acked, una_advanced) = tcb.send_buf.ack(seg.header.ack);
                                let mut wnd_advanced = false;

                                // Update SND.WND
                                let diff = i32::wrapping_sub(seg_seq as i32, tcb.send_buf.snd_wl1 as i32);
                                // The check here prevents using old segments to update the window.
                                if diff > 0 
                                    || (diff == 0 && i32::wrapping_sub(seg.header.ack as i32, tcb.send_buf.snd_wl2 as i32) >= 0) 
                                {
                                    wnd_advanced = i32::wrapping_sub(seg.header.wnd as i32, tcb.send_buf.snd_wnd as i32) > 0;
                                    tcb.send_buf.snd_wnd = seg.header.wnd;
                                    tcb.send_buf.snd_wl1 = seg_seq;
                                    tcb.send_buf.snd_wl2 = seg.header.ack;
                                }

                                if una_advanced || wnd_advanced {
                                    // Pending send can now pass
                                    TCBS[id].retry.notify_all();
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
                                if tcb.send_buf.re_tx_queue_by_seq.is_empty() {
                                    tcb.send_buf.send_ack(&tcb.conn, tcb.recv_buf.rcv_wnd, tcb.recv_buf.rcv_nxt);
                                }
                                // FUTURE: flush send queue and piggyback ACK
                                return;
                            }
                            
                        },
                        TcpState::LastAck => {
                            // The only thing that can arrive in this state is an
                            // acknowledgment of our FIN.  If our FIN is now acknowledged,
                            // delete the TCB, enter the CLOSED state, and return.
                            if ack_acceptable {
                                let (_, fin_acked, _) = tcb.send_buf.ack(seg.header.ack);
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
                                let (_, fin_acked, _) = tcb.send_buf.ack(seg.header.ack);
                                if fin_acked {
                                    // MSL timer
                                    tcb.ragnarok = Some(tcp_timestamp() + 2 * 1000 * TCP_MSL as u64);
                                }
                            }
                            return;
                        },
                        _ => unreachable!(),  
                    }
                }

                // fifth, process the segment text
                if text_acceptable {
                    match tcb.state {
                        TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2 => {
                            // Put data into TcpRecvBuf
                            // RCV.NXT and RCV.WND are adjusted accordingly.
                            let (not_full, rcv_nxt_moved) = tcb.recv_buf.put(data, seg_seq);
                            if !not_full {
                                println!("[WARNING]: recv seg_queue full");
                            }
    
                            // Send an acknowledgment of the form:
                            // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                            // This acknowledgment should be piggybacked on a segment being
                            // transmitted if possible without incurring undue delay.
    
                            if tcb.send_buf.re_tx_queue_by_seq.is_empty() {
                                tcb.send_buf.send_ack(&tcb.conn, tcb.recv_buf.rcv_wnd, tcb.recv_buf.rcv_nxt);
                            }
                            if rcv_nxt_moved {
                                TCBS[id].retry.notify_all();
                            }

                            // FUTURE: flush send queue and piggyback ACK
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
                            tcb.ragnarok = Some(tcp_timestamp() + 2 * 1000 * TCP_MSL as u64);
                            return;
                        },
                        TcpState::CloseWait | TcpState::Closing | TcpState::LastAck => {
                            // Remains state
                            return;
                        },
                        TcpState::TimeWait => {
                            // Restart the 2 MSL time-wait timeout.
                            tcb.ragnarok = Some(tcp_timestamp() + 2 * 1000 * TCP_MSL as u64);
                        },
                        _ => unreachable!(),
                    }
                }

            }
        }
    }
}
