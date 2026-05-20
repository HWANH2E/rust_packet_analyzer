use std::fmt::{Display, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl Display for MacAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtherType {
    Ipv4,
    Ipv6,
    Arp,
    Other(u16),
}

impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        match value {
            0x0800 => Self::Ipv4,
            0x86dd => Self::Ipv6,
            0x0806 => Self::Arp,
            other => Self::Other(other),
        }
    }
}

impl Display for EtherType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ipv4 => write!(f, "IPv4"),
            Self::Ipv6 => write!(f, "IPv6"),
            Self::Arp => write!(f, "ARP"),
            Self::Other(value) => write!(f, "EtherType(0x{value:04x})"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    Icmp,
    Tcp,
    Udp,
    Icmpv6,
    Other(u8),
}

impl From<u8> for IpProtocol {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            58 => Self::Icmpv6,
            other => Self::Other(other),
        }
    }
}

impl Display for IpProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Icmp => write!(f, "ICMP"),
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Icmpv6 => write!(f, "ICMPv6"),
            Self::Other(value) => write!(f, "IPProto({value})"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketRecord {
    pub index: usize,
    pub ts_sec: u32,
    pub ts_subsec: u32,
    pub incl_len: u32,
    pub orig_len: u32,
    pub frame: Frame,
}

impl PacketRecord {
    pub fn summary(&self) -> String {
        format!("#{} {} len={}", self.index, self.frame.summary(), self.incl_len)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Ethernet(EthernetFrame),
    Unknown { len: usize },
}

impl Frame {
    pub fn summary(&self) -> String {
        match self {
            Self::Ethernet(frame) => frame.summary(),
            Self::Unknown { .. } => "UnknownFrame".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetFrame {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub ethertype: EtherType,
    pub payload: NetworkPacket,
}

impl EthernetFrame {
    pub fn summary(&self) -> String {
        match &self.payload {
            NetworkPacket::Ipv4(packet) => packet.summary(),
            NetworkPacket::Ipv6(packet) => packet.summary(),
            NetworkPacket::Arp { payload_len } => format!("Ethernet ARP payload_len={payload_len}"),
            NetworkPacket::Unknown {
                ethertype,
                payload_len,
            } => format!("Ethernet {ethertype} payload_len={payload_len}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkPacket {
    Ipv4(Ipv4Packet),
    Ipv6(Ipv6Packet),
    Arp { payload_len: usize },
    Unknown { ethertype: EtherType, payload_len: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Packet {
    pub ihl_bytes: u8,
    pub dscp_ecn: u8,
    pub total_len: u16,
    pub identification: u16,
    pub flags_fragment: u16,
    pub ttl: u8,
    pub protocol: IpProtocol,
    pub checksum: u16,
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub payload: TransportPacket,
}

impl Ipv4Packet {
    pub fn src_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.src)
    }

    pub fn dst_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.dst)
    }

    pub fn summary(&self) -> String {
        match &self.payload {
            TransportPacket::Tcp(segment) => format!(
                "Ethernet IPv4 TCP {}:{} -> {}:{}",
                self.src_addr(),
                segment.src_port,
                self.dst_addr(),
                segment.dst_port
            ),
            TransportPacket::Udp(datagram) => format!(
                "Ethernet IPv4 UDP {}:{} -> {}:{}",
                self.src_addr(),
                datagram.src_port,
                self.dst_addr(),
                datagram.dst_port
            ),
            TransportPacket::Icmp { payload_len } => format!(
                "Ethernet IPv4 ICMP {} -> {} payload_len={payload_len}",
                self.src_addr(),
                self.dst_addr()
            ),
            TransportPacket::Unknown {
                protocol,
                payload_len,
            } => format!(
                "Ethernet IPv4 {protocol} {} -> {} payload_len={payload_len}",
                self.src_addr(),
                self.dst_addr()
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Packet {
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_len: u16,
    pub next_header: IpProtocol,
    pub hop_limit: u8,
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub payload: TransportPacket,
}

impl Ipv6Packet {
    pub fn src_addr(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.src)
    }

    pub fn dst_addr(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.dst)
    }

    pub fn summary(&self) -> String {
        match &self.payload {
            TransportPacket::Tcp(segment) => format!(
                "Ethernet IPv6 TCP [{}]:{} -> [{}]:{}",
                self.src_addr(),
                segment.src_port,
                self.dst_addr(),
                segment.dst_port
            ),
            TransportPacket::Udp(datagram) => format!(
                "Ethernet IPv6 UDP [{}]:{} -> [{}]:{}",
                self.src_addr(),
                datagram.src_port,
                self.dst_addr(),
                datagram.dst_port
            ),
            TransportPacket::Icmp { payload_len } => format!(
                "Ethernet IPv6 ICMPv6 {} -> {} payload_len={payload_len}",
                self.src_addr(),
                self.dst_addr()
            ),
            TransportPacket::Unknown {
                protocol,
                payload_len,
            } => format!(
                "Ethernet IPv6 {protocol} {} -> {} payload_len={payload_len}",
                self.src_addr(),
                self.dst_addr()
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportPacket {
    Tcp(TcpSegment),
    Udp(UdpDatagram),
    Icmp { payload_len: usize },
    Unknown { protocol: IpProtocol, payload_len: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpSegment {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub data_offset_bytes: u8,
    pub flags: u16,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
    pub payload_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram {
    pub src_port: u16,
    pub dst_port: u16,
    pub len: u16,
    pub checksum: u16,
    pub payload_len: usize,
}
