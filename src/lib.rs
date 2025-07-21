use std::{fmt, io};

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

impl Packet {
    pub fn parse(packet_data: &[u8]) -> Result<Self, io::Error> {
        if packet_data.len() < 20 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Packet too short for IPv4 header",
            ));
        }

        // Byte 0: Version (4 bits) and IHL (4 bits)
        let version = packet_data[0] >> 4;
        let ihl = packet_data[0] & 0x0F;

        // Byte 1: DSCP (6 bits) and ECN (2 bits)
        let dscp = packet_data[1] >> 2;
        let ecn = packet_data[1] & 0x03;

        // Bytes 2-3: Total Length
        let total_length = u16::from_be_bytes([packet_data[2], packet_data[3]]);

        // Bytes 4-5: Identification
        let identification = u16::from_be_bytes([packet_data[4], packet_data[5]]);

        // Bytes 6-7: Flags (3 bits) and Fragment Offset (13 bits)
        let flags = packet_data[6] >> 5;
        let fragment_offset = u16::from_be_bytes([packet_data[6] & 0x1F, packet_data[7]]);

        // Byte 8: Time To Live (TTL)
        let ttl = packet_data[8];

        // Byte 9: Protocol
        let protocol = Protocol::from_u8(packet_data[9]);

        // Bytes 10-11: Header Checksum
        let header_checksum = u16::from_be_bytes([packet_data[10], packet_data[11]]);

        // Bytes 12-15: Source Address
        let source_address = u32::from_be_bytes([
            packet_data[12],
            packet_data[13],
            packet_data[14],
            packet_data[15],
        ]);

        // Bytes 16-19: Destination Address
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
}
