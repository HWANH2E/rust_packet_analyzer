use packet_analyzer_core::{
    AnalyzerError, EtherType, EthernetFrame, Frame, IpProtocol, Ipv4Packet, Ipv6Packet, MacAddr,
    NetworkPacket, Result, TcpSegment, TransportPacket, UdpDatagram,
};

const ETHERNET_HEADER_LEN: usize = 14;
const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_MIN_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;

pub fn parse_frame(input: &[u8]) -> Result<Frame> {
    parse_ethernet(input).map(Frame::Ethernet)
}

pub fn parse_ethernet(input: &[u8]) -> Result<EthernetFrame> {
    ensure_len("ethernet header", input, ETHERNET_HEADER_LEN)?;

    let dst = MacAddr(read_array_6(input, 0)?);
    let src = MacAddr(read_array_6(input, 6)?);
    let ethertype = EtherType::from(read_u16_be(input, 12)?);
    let payload = &input[ETHERNET_HEADER_LEN..];

    let payload = match ethertype {
        EtherType::Ipv4 => NetworkPacket::Ipv4(parse_ipv4(payload)?),
        EtherType::Ipv6 => NetworkPacket::Ipv6(parse_ipv6(payload)?),
        EtherType::Arp => NetworkPacket::Arp {
            payload_len: payload.len(),
        },
        EtherType::Other(value) => NetworkPacket::Unknown {
            ethertype: EtherType::Other(value),
            payload_len: payload.len(),
        },
    };

    Ok(EthernetFrame {
        dst,
        src,
        ethertype,
        payload,
    })
}

pub fn parse_ipv4(input: &[u8]) -> Result<Ipv4Packet> {
    ensure_len("ipv4 header", input, IPV4_MIN_HEADER_LEN)?;

    let version = input[0] >> 4;
    if version != 4 {
        return Err(AnalyzerError::InvalidFormat(format!(
            "expected IPv4 version 4, got {version}"
        )));
    }

    let ihl_words = input[0] & 0x0f;
    let ihl_bytes = ihl_words.saturating_mul(4);
    let ihl_len = usize::from(ihl_bytes);
    if ihl_len < IPV4_MIN_HEADER_LEN {
        return Err(AnalyzerError::InvalidFormat(format!(
            "invalid IPv4 IHL: {ihl_len} bytes"
        )));
    }
    ensure_len("ipv4 options/header", input, ihl_len)?;

    let total_len = read_u16_be(input, 2)?;
    let total_len_usize = usize::from(total_len);
    if total_len_usize < ihl_len {
        return Err(AnalyzerError::InvalidFormat(format!(
            "IPv4 total length {total_len_usize} is smaller than header length {ihl_len}"
        )));
    }

    let available_packet_len = input.len().min(total_len_usize);
    let payload = &input[ihl_len..available_packet_len];
    let protocol = IpProtocol::from(input[9]);

    Ok(Ipv4Packet {
        ihl_bytes,
        dscp_ecn: input[1],
        total_len,
        identification: read_u16_be(input, 4)?,
        flags_fragment: read_u16_be(input, 6)?,
        ttl: input[8],
        protocol,
        checksum: read_u16_be(input, 10)?,
        src: read_array_4(input, 12)?,
        dst: read_array_4(input, 16)?,
        payload: parse_transport(protocol, payload)?,
    })
}

pub fn parse_ipv6(input: &[u8]) -> Result<Ipv6Packet> {
    ensure_len("ipv6 header", input, IPV6_HEADER_LEN)?;

    let version = input[0] >> 4;
    if version != 6 {
        return Err(AnalyzerError::InvalidFormat(format!(
            "expected IPv6 version 6, got {version}"
        )));
    }

    let first_word = read_u32_be(input, 0)?;
    let traffic_class = ((first_word >> 20) & 0xff) as u8;
    let flow_label = first_word & 0x000f_ffff;
    let payload_len = read_u16_be(input, 4)?;
    let next_header = IpProtocol::from(input[6]);
    let hop_limit = input[7];
    let payload_end = IPV6_HEADER_LEN + usize::from(payload_len);
    let available_payload_end = input.len().min(payload_end);
    let payload = &input[IPV6_HEADER_LEN..available_payload_end];

    Ok(Ipv6Packet {
        traffic_class,
        flow_label,
        payload_len,
        next_header,
        hop_limit,
        src: read_array_16(input, 8)?,
        dst: read_array_16(input, 24)?,
        payload: parse_transport(next_header, payload)?,
    })
}

pub fn parse_transport(protocol: IpProtocol, input: &[u8]) -> Result<TransportPacket> {
    match protocol {
        IpProtocol::Tcp => Ok(TransportPacket::Tcp(parse_tcp(input)?)),
        IpProtocol::Udp => Ok(TransportPacket::Udp(parse_udp(input)?)),
        IpProtocol::Icmp | IpProtocol::Icmpv6 => Ok(TransportPacket::Icmp {
            payload_len: input.len(),
        }),
        IpProtocol::Other(value) => Ok(TransportPacket::Unknown {
            protocol: IpProtocol::Other(value),
            payload_len: input.len(),
        }),
    }
}

pub fn parse_tcp(input: &[u8]) -> Result<TcpSegment> {
    ensure_len("tcp header", input, TCP_MIN_HEADER_LEN)?;

    let data_offset_words = input[12] >> 4;
    let data_offset_bytes = data_offset_words.saturating_mul(4);
    let header_len = usize::from(data_offset_bytes);
    if header_len < TCP_MIN_HEADER_LEN {
        return Err(AnalyzerError::InvalidFormat(format!(
            "invalid TCP data offset: {header_len} bytes"
        )));
    }
    ensure_len("tcp options/header", input, header_len)?;

    let payload_len = input.len().saturating_sub(header_len);
    let flags = read_u16_be(input, 12)? & 0x01ff;

    Ok(TcpSegment {
        src_port: read_u16_be(input, 0)?,
        dst_port: read_u16_be(input, 2)?,
        seq: read_u32_be(input, 4)?,
        ack: read_u32_be(input, 8)?,
        data_offset_bytes,
        flags,
        window: read_u16_be(input, 14)?,
        checksum: read_u16_be(input, 16)?,
        urgent_ptr: read_u16_be(input, 18)?,
        payload_len,
    })
}

pub fn parse_udp(input: &[u8]) -> Result<UdpDatagram> {
    ensure_len("udp header", input, UDP_HEADER_LEN)?;

    let len = read_u16_be(input, 4)?;
    if usize::from(len) < UDP_HEADER_LEN {
        return Err(AnalyzerError::InvalidFormat(format!(
            "invalid UDP length: {len} bytes"
        )));
    }

    let payload_len = usize::from(len)
        .saturating_sub(UDP_HEADER_LEN)
        .min(input.len().saturating_sub(UDP_HEADER_LEN));

    Ok(UdpDatagram {
        src_port: read_u16_be(input, 0)?,
        dst_port: read_u16_be(input, 2)?,
        len,
        checksum: read_u16_be(input, 6)?,
        payload_len,
    })
}

fn ensure_len(context: &'static str, input: &[u8], needed: usize) -> Result<()> {
    if input.len() < needed {
        return Err(AnalyzerError::truncated(context, needed, input.len()));
    }
    Ok(())
}

fn read_u16_be(input: &[u8], offset: usize) -> Result<u16> {
    ensure_len("u16", &input[offset.min(input.len())..], 2)?;
    Ok(u16::from_be_bytes([input[offset], input[offset + 1]]))
}

fn read_u32_be(input: &[u8], offset: usize) -> Result<u32> {
    ensure_len("u32", &input[offset.min(input.len())..], 4)?;
    Ok(u32::from_be_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ]))
}

fn read_array_4(input: &[u8], offset: usize) -> Result<[u8; 4]> {
    ensure_len("[u8; 4]", &input[offset.min(input.len())..], 4)?;
    Ok([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ])
}

fn read_array_6(input: &[u8], offset: usize) -> Result<[u8; 6]> {
    ensure_len("[u8; 6]", &input[offset.min(input.len())..], 6)?;
    Ok([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
        input[offset + 4],
        input[offset + 5],
    ])
}

fn read_array_16(input: &[u8], offset: usize) -> Result<[u8; 16]> {
    ensure_len("[u8; 16]", &input[offset.min(input.len())..], 16)?;
    Ok([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
        input[offset + 4],
        input[offset + 5],
        input[offset + 6],
        input[offset + 7],
        input[offset + 8],
        input[offset + 9],
        input[offset + 10],
        input[offset + 11],
        input[offset + 12],
        input[offset + 13],
        input[offset + 14],
        input[offset + 15],
    ])
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use packet_analyzer_core::{NetworkPacket, TransportPacket};

    #[test]
    fn parses_ethernet_ipv4_tcp() -> Result<()> {
        let packet = sample_ethernet_ipv4_tcp();
        let frame = parse_ethernet(&packet)?;

        assert_eq!(frame.ethertype, EtherType::Ipv4);
        match frame.payload {
            NetworkPacket::Ipv4(ip) => {
                assert_eq!(ip.src, [192, 168, 0, 10]);
                assert_eq!(ip.dst, [192, 168, 0, 22]);
                match ip.payload {
                    TransportPacket::Tcp(tcp) => {
                        assert_eq!(tcp.src_port, 443);
                        assert_eq!(tcp.dst_port, 53144);
                    }
                    other => panic!("expected TCP, got {other:?}"),
                }
            }
            other => panic!("expected IPv4, got {other:?}"),
        }

        Ok(())
    }

    fn sample_ethernet_ipv4_tcp() -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&[0, 1, 2, 3, 4, 5]);
        packet.extend_from_slice(&[6, 7, 8, 9, 10, 11]);
        packet.extend_from_slice(&[0x08, 0x00]);
        packet.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 64, 6, 0, 0, 192, 168, 0, 10,
            192, 168, 0, 22,
        ]);
        packet.extend_from_slice(&[
            0x01, 0xbb, 0xcf, 0x98, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0x20, 0x00, 0, 0,
            0, 0,
        ]);
        packet
    }
}
