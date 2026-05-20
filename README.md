# Rust Network Packet Analyzer - Stage 1 MVP

1단계 목표는 `PCAP 파일 -> Ethernet/IP/TCP/UDP 파싱 -> CLI 출력`까지 얇은 수직 파이프라인을 완성하는 것입니다.

## 실행

```bash
cargo run -p packet-analyzer -- read tests/fixtures/sample.pcap
```

예상 출력:

```text
#1 Ethernet IPv4 TCP 192.168.0.10:443 -> 192.168.0.22:53144 len=54
#2 Ethernet IPv4 UDP 192.168.0.22:5353 -> 224.0.0.251:5353 len=42
```

## 명령

```bash
packet-analyzer read <pcap-file> [--limit N]
packet-analyzer help
```

## 현재 지원 범위

- Classic PCAP 파일
- Little-endian / big-endian PCAP
- Microsecond / nanosecond timestamp magic
- Ethernet II
- IPv4
- IPv6 기본 헤더
- TCP
- UDP
- 알 수 없는 EtherType / IP protocol은 Unknown으로 표시

## 아직 제외한 것

- PCAPNG
- Live capture
- VLAN
- DNS / HTTP
- BPF 필터
- Flow/session 추적
