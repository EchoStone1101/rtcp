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
    
    use crate::{TCBS, MAX_SOCKET_FD, RtcpError, TCPHeader, TCPSegment};
    use std::collections::{VecDeque, LinkedList};
    use std::net::Ipv4Addr;
    use std::sync::{Mutex, Condvar};
    use chrono::{Duration, Utc};


    /// An unspecified port.
    pub const UNSPECIFIED_PORT: u16 = 0;

    /// Global timeout for connections (abort if no ACKs), in ms.
    pub const TCP_GLOBAL_TIMEOUT: usize = 5 * 60 * 1000;

    /// TCP buffer size.
    pub const TCP_BUFFER_SZ: usize = 65536;

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

        send_buf: TcpSendBuf,
        recv_buf: TcpRecvBuf,
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
    struct TcpSendBuf {
        /// Cicurlar data buffer
        pub buf: Box<[u8; TCP_BUFFER_SZ]>,
        /// Oldest Unacked SEQ
        pub snd_una: u32,
        /// Next SEQ to be sent
        pub snd_nxt: u32,
        /// Sender window
        pub snd_wnd: u32,
        /// Segment SEQ used for last window update
        pub snd_wl1: u32,
        /// Segment ACK used for last window update
        pub snd_wl2: u32,

        /// Initial send SEQ
        pub iss: u32,

        /// Retransmission queue (start, end, timestamp)
        pub re_rx_queue: VecDeque<(u32, u32, u64)>,
    }

    #[derive(Debug)]
    struct TcpRecvBuf {
        /// Cicurlar data buffer
        pub buf: Box<[u8; TCP_BUFFER_SZ]>,
        /// Next SEQ expected on incoming segments
        pub rcv_nxt: u32,
        /// Receive window
        pub rcv_wnd: u32,
        
        /// Initial receive SEQ
        pub irs: u32,

        /// Received segment queue, not necessarily cummulative.
        /// Essentially implements Selective-Repeat.
        pub seg_queue: LinkedList<(u32, u32)>
    }

    /// A TCP connection, identified by the quad.
    #[derive(Debug, Clone, Copy)]
    pub struct TcpConnection {
        pub src_ip: Ipv4Addr,
        pub src_port: u16,
        pub dst_ip: Ipv4Addr,
        pub dst_port: u16,
    }

    impl TcpConnection {
        pub fn dst_sock_unspecified(&self) -> bool {
            self.dst_ip.is_unspecified() || self.dst_port == UNSPECIFIED_PORT
        }
    }

    /// The states in a TCP state machine.
    #[derive(Debug)]
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


    /// Pseudo TCP CREATE command.
    /// Actual TCP creates TCB upon OPEN command; but for management reasons,
    /// it would be easier to break it down. Here, CREATE makes a CLOSED TCB,
    /// and OPEN acts on a given TCB just like any other TCP command.
    pub fn tcp_create(id: usize) -> Result<(), RtcpError>{
        assert!(id < MAX_SOCKET_FD);
        let mut guard = TCBS[id].inner.lock().unwrap();
        assert!(!guard.is_none());

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
                    snd_wnd: 0,
                    snd_wl1: 0,
                    snd_wl2: 0,
                    iss: 0,
                    re_rx_queue: VecDeque::new(),
                },
                recv_buf: TcpRecvBuf {
                    buf: Box::new([0u8; TCP_BUFFER_SZ]),
                    rcv_nxt: 0,
                    rcv_wnd: 0,
                    irs: 0,
                    seg_queue: LinkedList::new(),
                },
        });
        drop(guard);
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
                    // Send SYN

                    tcb.state = TcpState::SynSent;
                    Ok(())
                }
                
            },
            TcpState::Listen => {
                if !passive {
                    if tcb.conn.dst_sock_unspecified() {
                        return Err(RtcpError::InvalidStateTransition("error: foreign socket unspecified"))
                    }
                    // Change from passive to active, select ISS
                    // Send SYN
                    tcb.passive = passive;
                    tcb.state = TcpState::SynSent;
                    Ok(())
                }
                else {
                    return Err(RtcpError::InvalidStateTransition("error: is already passive"))
                }
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
        _buf: &[u8],
        _push: bool,
        _urgent: bool) -> Result<usize, RtcpError>
    {
        assert!(id < MAX_SOCKET_FD);
        let mut guard = TCBS[id].inner.lock().unwrap();
        assert!(!guard.is_none());
        let mut tcb = guard.as_mut().unwrap();

        match tcb.state {
            TcpState::Closed => {
                Err(RtcpError::InvalidStateTransition("error: connection does not exist"))
            },
            TcpState::Listen => {
                if tcb.conn.dst_sock_unspecified() {
                    return Err(RtcpError::InvalidStateTransition("error: foreign socket unspecified"))
                }
                // Change from passive to active, select ISS
                // Send SYN
                tcb.state = TcpState::SynSent;

                // Retry this command
                _ = TCBS[id].retry.wait(guard).unwrap();
                Err(RtcpError::TCPCommandRetry)
            },
            TcpState::SynSent | TcpState::SynReceived => {
                // Queue the data, or Err

                // Retry this command
                _ = TCBS[id].retry.wait(guard).unwrap();
                Err(RtcpError::TCPCommandRetry)
            },
            TcpState::Established | TcpState::CloseWait => {
                // TODO: Send data, or Err

                // Retry this command
                _ = TCBS[id].retry.wait(guard).unwrap();
                Err(RtcpError::TCPCommandRetry)
            },
            _ => {
                Err(RtcpError::InvalidStateTransition("error: connection closing"))
            }
        }
    }

    /// TCP SEND command
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

    fn tcp_recv_once(
        id: usize,
        _buf: &mut [u8],
        _push: bool,
        _urgent: bool) -> Result<usize, RtcpError> 
    {
        assert!(id < MAX_SOCKET_FD);
        let guard = TCBS[id].inner.lock().unwrap();
        assert!(!guard.is_none());
        let tcb = guard.as_ref().unwrap();

        match tcb.state {
            TcpState::Closed => {
                Err(RtcpError::InvalidStateTransition("error: connection does not exist"))
            },
            TcpState::Listen | TcpState::SynSent | TcpState::SynReceived => {
                // TODO: queue the request, or Err

                // Retry this command
                _ = TCBS[id].retry.wait(guard).unwrap();
                Err(RtcpError::TCPCommandRetry)
            },
            TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2 => {
                // TODO: reassemble data and return 
                Ok(0)
            },
            TcpState::CloseWait => {
                // TODO: reassemble data and return, or Err(closing)
                Ok(0)
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
                // Terminate outstanding RECV/SENDs
                tcb.state = TcpState::FinWait1;
                // TODO: send a FIN
                TCBS[id].retry.notify_all();
                Ok(())
            },
            TcpState::Established => {
                // Wait until send buffer is empty?
                // this is different from pending SENDs, which is not
                // in buffer yet.

                tcb.state = TcpState::FinWait1;
                // TODO: send a FIN
                TCBS[id].retry.notify_all();
                Ok(())
            },
            TcpState::FinWait1 | TcpState::FinWait2 => {
                Err(RtcpError::InvalidStateTransition("error: connection closing"))
            },
            TcpState::CloseWait => {
                // Wait until send buffer is empty?
                // this is different from pending SENDs, which is not
                // in buffer yet.

                // TODO: send a FIN
                tcb.state = TcpState::Closing;
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
                // TODO: Send RST
                // TODO: Flush send buffer?
                tcb.clear();
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
        seg: TCPSegment,
    ) {
        assert!(id < MAX_SOCKET_FD);
        let mut guard = TCBS[id].inner.lock().unwrap();
        assert!(!guard.is_none());
        let tcb = guard.as_mut().unwrap();

        match tcb.state {
            TcpState::Closed => {
                // Discard data
                if !seg.header.is_rst {
                    // Send back a RST
                    let _seq = if seg.header.is_ack {seg.header.ack} else {0};
                }
            },
            TcpState::Listen => {
                if seg.header.is_rst {
                    // Ignore RST
                    return;
                }
                if seg.header.is_ack {
                    // Bad; send back a RST
                    let _seq = seg.header.ack;
                    return;
                }
                if seg.header.is_syn {
                    // Starting a new connection

                    // Set RCV.NXT to SEG.SEQ+1, IRS is set to SEG.SEQ and any other
                    // control or text should be queued for processing later.  ISS
                    // should be selected and a SYN segment sent of the form:

                    // <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>

                    // SND.NXT is set to ISS+1 and SND.UNA to ISS.  The connection
                    // state should be changed to SYN-RECEIVED.  Note that any other
                    // incoming control or data (combined with SYN) will be processed
                    // in the SYN-RECEIVED state, but processing of SYN and ACK should
                    // not be repeated.  If the listen was not fully specified (i.e.,
                    // the foreign socket was not fully specified), then the
                    // unspecified fields should be filled in now.

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
            },
            TcpState::SynSent => {
                if seg.header.is_ack {
                    // If SEG.ACK =< ISS, or SEG.ACK > SND.NXT, send a reset (unless
                    // the RST bit is set, if so drop the segment and return)
            
                    //     <SEQ=SEG.ACK><CTL=RST>
            
                    // and discard the segment.  Return.
            
                    // If SND.UNA =< SEG.ACK =< SND.NXT then the ACK is acceptable.
                }
                if seg.header.is_rst {
                    if seg.header.is_ack { // TODO?
                        tcb.clear();
                    }
                    return;
                }
                if seg.header.is_syn {
                    // RCV.NXT is set to SEG.SEQ+1, IRS is set to
                    // SEG.SEQ.  SND.UNA should be advanced to equal SEG.ACK (if there
                    // is an ACK), and any segments on the retransmission queue which
                    // are thereby acknowledged should be removed.

                    // If SND.UNA > ISS (our SYN has been ACKed), change the connection
                    // state to ESTABLISHED, form an ACK segment

                    // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>

                    // and send it.  Data or controls which were queued for
                    // transmission may be included.  If there are other controls or
                    // text in the segment then continue processing at the sixth step
                    // below where the URG bit is checked, otherwise return.

                    // Otherwise enter SYN-RECEIVED, form a SYN,ACK segment

                    // <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>

                    // and send it.  If there are other controls or text in the
                    // segment, queue them for processing after the ESTABLISHED state
                    // has been reached, return.
                }
            }
            _ => {
                // first check sequence number

                // Segments are processed in sequence.  Initial tests on arrival
                // are used to discard old duplicates, but further processing is
                // done in SEG.SEQ order.  If a segment's contents straddle the
                // boundary between old and new, only the new parts should be
                // processed.

                // There are four cases for the acceptability test for an incoming
                // segment:

                // Segment Receive  Test
                // Length  Window
                // ------- -------  -------------------------------------------

                // 0       0     SEG.SEQ = RCV.NXT

                // 0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND

                // >0       0     not acceptable

                // >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
                //             or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND

                // If the RCV.WND is zero, no segments will be acceptable, but
                // special allowance should be made to accept valid ACKs, URGs and
                // RSTs.

                // If an incoming segment is not acceptable, an acknowledgment
                // should be sent in reply (unless the RST bit is set, if so drop
                // the segment and return):

                // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>

                // After sending the acknowledgment, drop the unacceptable segment
                // and return.

                // In the following it is assumed that the segment is the idealized
                // segment that begins at RCV.NXT and does not exceed the window.
                // One could tailor actual segments to fit this assumption by
                // trimming off any portions that lie outside the window (including
                // SYN and FIN), and only processing further if the segment then
                // begins at RCV.NXT.  Segments with higher begining sequence
                // numbers may be held for later processing.

                // second check the RST bit
                if seg.header.is_rst {
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
                            // TODO: flush all queues
    
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
                    // SYN in window, error
                    // TODO: flush all queues
    
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
                    match tcb.state {
                        TcpState::SynReceived => {
                            // If SND.UNA =< SEG.ACK =< SND.NXT then enter ESTABLISHED state
                            // and continue processing.
                  
                            //   If the segment acknowledgment is not acceptable, form a
                            //   reset segment,
                  
                            //     <SEQ=SEG.ACK><CTL=RST>
                  
                            //   and send it.
                        },
                        TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2 |
                        TcpState::CloseWait | TcpState::Closing => {
                            // If SND.UNA < SEG.ACK =< SND.NXT then, set SND.UNA <- SEG.ACK.
                            // Any segments on the retransmission queue which are thereby
                            // entirely acknowledged are removed.  Users should receive
                            // positive acknowledgments for buffers which have been SENT and
                            // fully acknowledged (i.e., SEND buffer should be returned with
                            // "ok" response).  If the ACK is a duplicate
                            // (SEG.ACK < SND.UNA), it can be ignored.  If the ACK acks
                            // something not yet sent (SEG.ACK > SND.NXT) then send an ACK,
                            // drop the segment, and return.

                            // If SND.UNA < SEG.ACK =< SND.NXT, the send window should be
                            // updated.  If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and
                            // SND.WL2 =< SEG.ACK)), set SND.WND <- SEG.WND, set
                            // SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK.

                            // Note that SND.WND is an offset from SND.UNA, that SND.WL1
                            // records the sequence number of the last segment used to update
                            // SND.WND, and that SND.WL2 records the acknowledgment number of
                            // the last segment used to update SND.WND.  The check here
                            // prevents using old segments to update the window.

                            if matches!(tcb.state, TcpState::FinWait1) {
                                // In addition to the processing for the ESTABLISHED state, if
                                // our FIN is now acknowledged then enter FIN-WAIT-2 and continue
                                // processing in that state.
                            }
                            if matches!(tcb.state, TcpState::Closing) {
                                // In addition to the processing for the ESTABLISHED state, if
                                // the ACK acknowledges our FIN then enter the TIME-WAIT state,
                                // otherwise ignore the segment.
                            }
                        },
                        TcpState::LastAck => {
                            // The only thing that can arrive in this state is an
                            // acknowledgment of our FIN.  If our FIN is now acknowledged,
                            // delete the TCB, enter the CLOSED state, and return.
                        },
                        TcpState::TimeWait => {
                            // The only thing that can arrive in this state is a
                            // retransmission of the remote FIN.  Acknowledge it, and restart
                            // the 2 MSL timeout.
                        },
                        _ => unreachable!(),  
                    }
                }

                // fifth, process the segment text
                match tcb.state {
                    TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2 => {
                        // Once in the ESTABLISHED state, it is possible to deliver segment
                        // text to user RECEIVE buffers.  Text from segments can be moved
                        // into buffers until either the buffer is full or the segment is
                        // empty.  If the segment empties and carries an PUSH flag, then
                        // the user is informed, when the buffer is returned, that a PUSH
                        // has been received.

                        // When the TCP takes responsibility for delivering the data to the
                        // user it must also acknowledge the receipt of the data.

                        // Once the TCP takes responsibility for the data it advances
                        // RCV.NXT over the data accepted, and adjusts RCV.WND as
                        // apporopriate to the current buffer availability.  The total of
                        // RCV.NXT and RCV.WND should not be reduced.

                        // Please note the window management suggestions in section 3.7.

                        // Send an acknowledgment of the form:

                        // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>

                        // This acknowledgment should be piggybacked on a segment being
                        // transmitted if possible without incurring undue delay.
                    },
                    _ => {
                        // This should not occur, since a FIN has been received from the
                        // remote side.  Ignore the segment text.
                    }
                }

                // sixth, check the FIN bit
                if seg.header.is_fin {
                    if matches!(tcb.state, TcpState::Closed) 
                        || matches!(tcb.state, TcpState::Listen) 
                        || matches!(tcb.state, TcpState::SynSent) {
                        return;
                    }

                    // If the FIN bit is set, signal the user "connection closing" and
                    // return any pending RECEIVEs with same message, advance RCV.NXT
                    // over the FIN, and send an acknowledgment for the FIN.  Note that
                    // FIN implies PUSH for any segment text not yet delivered to the
                    // user.

                    match tcb.state {
                        TcpState::SynReceived | TcpState::Established => {
                            tcb.state = TcpState::CloseWait;
                            TCBS[id].retry.notify_all();
                            return;
                        },
                        TcpState::FinWait1 => {
                            // If our FIN has been ACKed (perhaps in this segment), then
                            // enter TIME-WAIT, start the time-wait timer, turn off the other
                            // timers; otherwise enter the CLOSING state.
                        },
                        TcpState::FinWait2 => {
                            // Enter the TIME-WAIT state.  Start the time-wait timer, turn
                            // off the other timers.
                        },
                        TcpState::CloseWait | TcpState::Closing | TcpState::LastAck => {
                            // Remains state
                            return;
                        },
                        TcpState::TimeWait => {
                            // Restart the 2 MSL time-wait timeout.
                        },
                        _ => unreachable!(),
                    }
                }

            }
        }
    }
}