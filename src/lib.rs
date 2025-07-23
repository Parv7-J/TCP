use std::{fmt, io};

pub const SYN_FLAG: u8 = 0b0000_0010;
pub const ACK_FLAG: u8 = 0b0001_0000;
pub const PSH_FLAG: u8 = 0b0000_1000;

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum Protocol {
    ICMP = 1,
    IGMP = 2,
    TCP = 6,
    UDP = 17,
    ENCAP = 41,
    OSPF = 89,
    SCTP = 132,
    Unknown(u8),
}

impl Protocol {
    fn from_u8(val: u8) -> Self {
        match val {
            1 => Protocol::ICMP,
            2 => Protocol::IGMP,
            6 => Protocol::TCP,
            17 => Protocol::UDP,
            41 => Protocol::ENCAP,
            89 => Protocol::OSPF,
            132 => Protocol::SCTP,
            _ => Protocol::Unknown(val),
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::ICMP => write!(f, "ICMP"),
            Protocol::IGMP => write!(f, "IGMP"),
            Protocol::TCP => write!(f, "TCP"),
            Protocol::UDP => write!(f, "UDP"),
            Protocol::ENCAP => write!(f, "ENCAP"),
            Protocol::OSPF => write!(f, "OSPF"),
            Protocol::SCTP => write!(f, "SCTP"),
            Protocol::Unknown(val) => write!(f, "Unknown({})", val),
        }
    }
}

#[derive(Debug)]
pub struct Options {}

#[derive(Debug)]
pub struct Packet {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: Protocol,
    pub header_checksum: u16,
    pub source_address: u32,
    pub destination_address: u32,
    pub options: Option<Options>,
}

#[derive(Debug)]
pub struct Segment {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgement_number: u32,
    pub data_offset: u8,
    pub flags: u8,
    pub window: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: Option<Options>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum State {
    Listen,
    SynRcvd,
    Established,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug)]
pub struct Connection {
    pub state: State,
    pub source_address: u32,
    pub source_port: u16,
    pub destination_address: u32,
    pub destination_port: u16,
    pub send_next: u32,
    pub recv_next: u32,
}

pub enum RequestType {
    SYN,
    ACK,
    PSHACK,
    FIN,
    SYNACK,
    Unknown(u8),
}

impl Segment {
    pub fn parse(segment_data: &[u8], pseudo_header: [u16; 6]) -> Result<Self, io::Error> {
        if segment_data.len() < 20 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Segment too short for TCP header",
            ));
        }

        if !Self::validate(&segment_data, pseudo_header) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Segment Checksum Invalid",
            ));
        }

        let source_port = u16::from_be_bytes([segment_data[0], segment_data[1]]);

        let destination_port = u16::from_be_bytes([segment_data[2], segment_data[3]]);

        let sequence_number = u32::from_be_bytes([
            segment_data[4],
            segment_data[5],
            segment_data[6],
            segment_data[7],
        ]);

        let acknowledgement_number = u32::from_be_bytes([
            segment_data[8],
            segment_data[9],
            segment_data[10],
            segment_data[11],
        ]);

        let data_offset = segment_data[12] >> 4;

        let flags = segment_data[13];

        let window = u16::from_be_bytes([segment_data[14], segment_data[15]]);

        let checksum = u16::from_be_bytes([segment_data[16], segment_data[17]]);

        let urgent_pointer = u16::from_be_bytes([segment_data[18], segment_data[19]]);

        let options: Option<Options> = None;

        Ok(Segment {
            source_port,
            destination_port,
            sequence_number,
            acknowledgement_number,
            data_offset,
            flags,
            window,
            checksum,
            urgent_pointer,
            options,
        })
    }

    fn validate(segment_data: &[u8], pseudo_header: [u16; 6]) -> bool {
        let mut sum: u32 = 0;
        for i in pseudo_header {
            sum += i as u32;
        }
        for bytes in segment_data.chunks_exact(2) {
            sum += u16::from_be_bytes([bytes[0], bytes[1]]) as u32;
        }
        let rem = segment_data.chunks_exact(2).remainder();

        if rem.len() == 1 {
            sum += u16::from_be_bytes([rem[0], 0]) as u32;
        }

        while (sum >> 16) > 0 {
            sum = (sum >> 16) + (sum & 0xFFFF);
        }

        return sum == 0xFFFF;
    }

    pub fn check_flags(flags: u8) -> RequestType {
        if flags == SYN_FLAG {
            return RequestType::SYN;
        } else if flags == ACK_FLAG {
            return RequestType::ACK;
        } else if flags == PSH_FLAG | ACK_FLAG {
            return RequestType::PSHACK;
        //also handle fin
        } else {
            return RequestType::Unknown(flags);
        }
    }

    pub fn build(connection: &Connection, type_of_req: RequestType) -> Result<[u8; 20], io::Error> {
        let mut tcp_header = [0u8; 20];

        tcp_header[0..2].copy_from_slice(&connection.destination_port.to_be_bytes());

        tcp_header[2..4].copy_from_slice(&connection.source_port.to_be_bytes());

        let seq = (connection.send_next - 1).to_be_bytes();
        tcp_header[4..8].copy_from_slice(&seq);

        let ack = connection.recv_next.to_be_bytes();
        tcp_header[8..12].copy_from_slice(&ack);

        tcp_header[12] = 5 << 4;

        tcp_header[13] = match type_of_req {
            RequestType::ACK => ACK_FLAG,
            RequestType::SYNACK => SYN_FLAG | ACK_FLAG,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Wrong request type",
                ));
            }
        };

        let window = (65535 as u16).to_be_bytes();
        tcp_header[14..16].copy_from_slice(&window);

        let pseudo_header = [
            (connection.destination_address >> 16) as u16,
            (connection.destination_address & 0xFFFF) as u16,
            (connection.source_address >> 16) as u16,
            (connection.source_address & 0xFFFF) as u16,
            6,
            20,
        ];

        let checksum = Self::calculate_checksum(&tcp_header, pseudo_header).to_be_bytes();

        tcp_header[16..18].copy_from_slice(&checksum);

        if !Self::validate(&tcp_header, pseudo_header) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Checksum calculation wrong",
            ));
        }

        return Ok(tcp_header);
    }

    fn calculate_checksum(tcp_header: &[u8], pseudo_header: [u16; 6]) -> u16 {
        let mut sum: u32 = 0;
        for byte in pseudo_header {
            sum += byte as u32;
        }
        for byte in tcp_header.chunks_exact(2) {
            sum += u16::from_be_bytes([byte[0], byte[1]]) as u32;
        }

        while (sum >> 16) > 0 {
            sum = (sum >> 16) + (sum & 0xFFFF);
        }

        return !sum as u16;
    }
}

impl Packet {
    pub fn parse(packet_data: &[u8]) -> Result<Self, io::Error> {
        if packet_data.len() < 20 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Packet too short for IPv4 header",
            ));
        }

        let ihl = packet_data[0] & 0x0F;

        let header_length = ihl * 4;

        if !Self::validate(&packet_data[..header_length as usize]) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Packet Checksum Invalid",
            ));
        };

        let version = packet_data[0] >> 4;

        let dscp = packet_data[1] >> 2;
        let ecn = packet_data[1] & 0x03;

        let total_length = u16::from_be_bytes([packet_data[2], packet_data[3]]);

        let identification = u16::from_be_bytes([packet_data[4], packet_data[5]]);

        let flags = packet_data[6] >> 5;
        let fragment_offset = u16::from_be_bytes([packet_data[6] & 0x1F, packet_data[7]]);

        let ttl = packet_data[8];

        let protocol = Protocol::from_u8(packet_data[9]);

        let header_checksum = u16::from_be_bytes([packet_data[10], packet_data[11]]);

        let source_address = u32::from_be_bytes([
            packet_data[12],
            packet_data[13],
            packet_data[14],
            packet_data[15],
        ]);

        let destination_address = u32::from_be_bytes([
            packet_data[16],
            packet_data[17],
            packet_data[18],
            packet_data[19],
        ]);

        let options = if ihl > 5 { None } else { None };

        Ok(Packet {
            version,
            ihl,
            dscp,
            ecn,
            total_length,
            identification,
            flags,
            fragment_offset,
            ttl,
            protocol,
            header_checksum,
            source_address,
            destination_address,
            options,
        })
    }

    fn validate(packet_data: &[u8]) -> bool {
        let header_length = (packet_data[0] & 0x0F) * 4;
        let ip_header = &packet_data[..header_length as usize];

        let mut sum: u32 = 0;
        for chunk in ip_header.chunks_exact(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        let rem = packet_data.chunks_exact(2).remainder();

        if rem.len() == 1 {
            sum += u16::from_be_bytes([rem[0], 0]) as u32;
        }

        while (sum >> 16) > 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return sum == 0xFFFF;
    }

    pub fn build(tcp_header: [u8; 20], connection: &Connection) -> Result<[u8; 40], io::Error> {
        let mut ip_header = [0u8; 20];

        ip_header[0] = (4 << 4) | 5;

        let length = (40 as u16).to_be_bytes();

        ip_header[2..4].copy_from_slice(&length);

        ip_header[6] = 2 << 5;

        ip_header[8] = 64;

        ip_header[9] = 6;

        ip_header[12..16].copy_from_slice(&connection.destination_address.to_be_bytes());

        ip_header[16..20].copy_from_slice(&connection.source_address.to_be_bytes());

        let checksum = Self::calculate_checksum(&ip_header).to_be_bytes();

        ip_header[10..12].copy_from_slice(&checksum);

        if !Self::validate(&ip_header) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Checksum calculation wrong",
            ));
        }

        let mut ip_packet = [0u8; 40];
        ip_packet[0..20].copy_from_slice(&ip_header);
        ip_packet[20..40].copy_from_slice(&tcp_header);

        return Ok(ip_packet);
    }

    fn calculate_checksum(ip_packet: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        for byte in ip_packet.chunks_exact(2) {
            sum += u16::from_be_bytes([byte[0], byte[1]]) as u32;
        }

        while (sum >> 16) > 0 {
            sum = (sum >> 16) + (sum & 0xFFFF);
        }

        return !sum as u16;
    }
}
