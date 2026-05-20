use std::fs;
use std::path::Path;

use packet_analyzer_core::{AnalyzerError, PacketRecord, Result};
use packet_analyzer_parser::parse_frame;

const PCAP_GLOBAL_HEADER_LEN: usize = 24;
const PCAP_PACKET_HEADER_LEN: usize = 16;
const LINKTYPE_ETHERNET: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endian {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampPrecision {
    Microsecond,
    Nanosecond,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcapHeader {
    pub version_major: u16,
    pub version_minor: u16,
    pub snaplen: u32,
    pub linktype: u32,
    pub timestamp_precision: TimestampPrecision,
    endian: Endian,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcapFile {
    pub header: PcapHeader,
    pub packets: Vec<PacketRecord>,
}

pub fn read_pcap_file(path: impl AsRef<Path>) -> Result<PcapFile> {
    let bytes = fs::read(path)?;
    parse_pcap(&bytes)
}

pub fn parse_pcap(input: &[u8]) -> Result<PcapFile> {
    let header = parse_global_header(input)?;
    if header.linktype != LINKTYPE_ETHERNET {
        return Err(AnalyzerError::Unsupported(format!(
            "only Ethernet LINKTYPE 1 is supported in stage 1, got {}",
            header.linktype
        )));
    }

    let mut offset = PCAP_GLOBAL_HEADER_LEN;
    let mut packets = Vec::new();
    let mut index = 1usize;

    while offset < input.len() {
        ensure_len("pcap packet header", input, offset, PCAP_PACKET_HEADER_LEN)?;

        let ts_sec = read_u32(input, offset, header.endian)?;
        let ts_subsec = read_u32(input, offset + 4, header.endian)?;
        let incl_len = read_u32(input, offset + 8, header.endian)?;
        let orig_len = read_u32(input, offset + 12, header.endian)?;
        offset += PCAP_PACKET_HEADER_LEN;

        let incl_len_usize = incl_len as usize;
        ensure_len("pcap packet data", input, offset, incl_len_usize)?;
        let packet_bytes = &input[offset..offset + incl_len_usize];
        offset += incl_len_usize;

        let frame = parse_frame(packet_bytes)?;
        packets.push(PacketRecord {
            index,
            ts_sec,
            ts_subsec,
            incl_len,
            orig_len,
            frame,
        });
        index += 1;
    }

    Ok(PcapFile { header, packets })
}

fn parse_global_header(input: &[u8]) -> Result<PcapHeader> {
    ensure_len("pcap global header", input, 0, PCAP_GLOBAL_HEADER_LEN)?;

    let magic = read_array_4(input, 0)?;
    let (endian, timestamp_precision) = match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => (Endian::Little, TimestampPrecision::Microsecond),
        [0xa1, 0xb2, 0xc3, 0xd4] => (Endian::Big, TimestampPrecision::Microsecond),
        [0x4d, 0x3c, 0xb2, 0xa1] => (Endian::Little, TimestampPrecision::Nanosecond),
        [0xa1, 0xb2, 0x3c, 0x4d] => (Endian::Big, TimestampPrecision::Nanosecond),
        [0x0a, 0x0d, 0x0d, 0x0a] => {
            return Err(AnalyzerError::Unsupported(
                "PCAPNG is not supported in stage 1; use classic PCAP".to_string(),
            ));
        }
        other => {
            return Err(AnalyzerError::InvalidFormat(format!(
                "unknown PCAP magic {:02x} {:02x} {:02x} {:02x}",
                other[0], other[1], other[2], other[3]
            )));
        }
    };

    Ok(PcapHeader {
        version_major: read_u16(input, 4, endian)?,
        version_minor: read_u16(input, 6, endian)?,
        snaplen: read_u32(input, 16, endian)?,
        linktype: read_u32(input, 20, endian)?,
        timestamp_precision,
        endian,
    })
}

fn ensure_len(context: &'static str, input: &[u8], offset: usize, needed: usize) -> Result<()> {
    let available = input.len().saturating_sub(offset);
    if available < needed {
        return Err(AnalyzerError::truncated(context, needed, available));
    }
    Ok(())
}

fn read_array_4(input: &[u8], offset: usize) -> Result<[u8; 4]> {
    ensure_len("[u8; 4]", input, offset, 4)?;
    Ok([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ])
}

fn read_u16(input: &[u8], offset: usize, endian: Endian) -> Result<u16> {
    let bytes = read_array_2(input, offset)?;
    Ok(match endian {
        Endian::Little => u16::from_le_bytes(bytes),
        Endian::Big => u16::from_be_bytes(bytes),
    })
}

fn read_u32(input: &[u8], offset: usize, endian: Endian) -> Result<u32> {
    let bytes = read_array_4(input, offset)?;
    Ok(match endian {
        Endian::Little => u32::from_le_bytes(bytes),
        Endian::Big => u32::from_be_bytes(bytes),
    })
}

fn read_array_2(input: &[u8], offset: usize) -> Result<[u8; 2]> {
    ensure_len("[u8; 2]", input, offset, 2)?;
    Ok([input[offset], input[offset + 1]])
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_classic_pcap() -> Result<()> {
        let pcap = sample_pcap_bytes();
        let parsed = parse_pcap(&pcap)?;
        assert_eq!(parsed.header.linktype, LINKTYPE_ETHERNET);
        assert_eq!(parsed.packets.len(), 1);
        assert_eq!(parsed.packets[0].summary(), "#1 Ethernet IPv4 TCP 192.168.0.10:443 -> 192.168.0.22:53144 len=54");
        Ok(())
    }

    fn sample_pcap_bytes() -> Vec<u8> {
        let packet = sample_ethernet_ipv4_tcp();
        let mut pcap = Vec::new();

        pcap.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
        pcap.extend_from_slice(&2u16.to_le_bytes());
        pcap.extend_from_slice(&4u16.to_le_bytes());
        pcap.extend_from_slice(&0i32.to_le_bytes());
        pcap.extend_from_slice(&0u32.to_le_bytes());
        pcap.extend_from_slice(&65535u32.to_le_bytes());
        pcap.extend_from_slice(&LINKTYPE_ETHERNET.to_le_bytes());

        pcap.extend_from_slice(&1u32.to_le_bytes());
        pcap.extend_from_slice(&0u32.to_le_bytes());
        pcap.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        pcap.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        pcap.extend_from_slice(&packet);
        pcap
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
