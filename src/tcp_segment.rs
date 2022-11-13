pub mod tcp_segment {

    use crate::RtcpError;
    use std::net::Ipv4Addr;
    
    /// The TCP segment header.
    #[derive(Debug, Clone, Copy)]
    pub struct TCPHeader {
        pub src_port: u16,
        pub dst_port: u16,
        pub seq: u32,
        pub ack: u32,
        pub data_ofs: u8,

        // Flags
        pub is_urg: bool,
        pub is_ack: bool,
        pub is_psh: bool,
        pub is_rst: bool,
        pub is_syn: bool,
        pub is_fin: bool,

        pub wnd: u16,
        pub checksum: u16,
        pub urg_ptr: u16,

        // Options are recognized but not handled
        pub _options: (),
    }

    impl TCPHeader {
        /// Deserialize a header from given buffer.
        pub fn deserialize(buf: &[u8]) -> Result<Self, RtcpError> {
            if buf.len() < 20 {
                return Err(RtcpError::BufError("buffer too small"));
            }
            if buf[12] & 0b1111 != 0 || buf[13] & 0b11000000 != 0 {
                return Err(RtcpError::InvalidSegment("reserved bits non zero"));
            }
            let data_ofs = buf[12] >> 4;
            if (data_ofs * 4) as usize > buf.len() {
                return Err(RtcpError::InvalidSegment("header too small"));
            }
            
            let src_port = u16::from_be_bytes(buf[0..2].try_into().unwrap());
            let dst_port = u16::from_be_bytes(buf[2..4].try_into().unwrap());
            let seq = u32::from_be_bytes(buf[4..8].try_into().unwrap());
            let ack = u32::from_be_bytes(buf[8..12].try_into().unwrap());
            
            let is_urg = buf[13] & 0b100000 != 0;
            let is_ack = buf[13] & 0b10000 != 0;
            let is_psh = buf[13] & 0b1000 != 0;
            let is_rst = buf[13] & 0b100 != 0;
            let is_syn = buf[13] & 0b10 != 0;
            let is_fin = buf[13] & 0b1 != 0;
            let wnd = u16::from_be_bytes(buf[14..16].try_into().unwrap());
            let checksum = u16::from_be_bytes(buf[16..18].try_into().unwrap());
            let urg_ptr = u16::from_be_bytes(buf[18..20].try_into().unwrap());
            let _options = ();

            Ok(TCPHeader {
                src_port,
                dst_port,
                seq,
                ack,
                data_ofs,
                is_urg, is_ack, is_psh, is_rst, is_syn, is_fin,
                wnd,
                checksum,
                urg_ptr,
                _options,
            })

        }

        /// Serialize the header inplace, in `buf`.
        pub fn serialize(&self, buf: &mut [u8]) -> Result<(), RtcpError>{
            if self.data_ofs < 5 {
                return Err(RtcpError::InvalidSegment("data_ofs too small"));
            }
            if buf.len() < (self.data_ofs as usize) * 4 {
                return Err(RtcpError::BufError("buffer too small"));
            }

            buf[0..2].copy_from_slice(&self.src_port.to_be_bytes());
            buf[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
            buf[4..8].copy_from_slice(&self.seq.to_be_bytes());
            buf[8..12].copy_from_slice(&self.ack.to_be_bytes());
            buf[12] = (self.data_ofs & 0b1111) << 4;

            buf[13] = 0;
            buf[13] |= if self.is_urg {0b100000} else {0};
            buf[13] |= if self.is_ack {0b10000} else {0};
            buf[13] |= if self.is_psh {0b1000} else {0};
            buf[13] |= if self.is_rst {0b100} else {0};
            buf[13] |= if self.is_syn {0b10} else {0};
            buf[13] |= if self.is_fin {0b1} else {0};

            buf[14..16].copy_from_slice(&self.wnd.to_be_bytes());
            buf[16..18].copy_from_slice(&self.checksum.to_be_bytes());
            buf[18..20].copy_from_slice(&self.urg_ptr.to_be_bytes());

            // Zeroes the options field
            buf[20..(self.data_ofs as usize * 4)].fill(0);

            Ok(())
        }
    }

    /// A TCP segment
    #[derive(Debug)]
    pub struct TCPSegment {
        pub header: TCPHeader,
        pub src_ip: Ipv4Addr,
        pub data: Vec<u8>,
    }
}