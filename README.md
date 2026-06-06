# rust_packet_analyzer

Rust 기반 네트워크 패킷 분석기 프로젝트입니다.

## 프로젝트 목표

이 프로젝트는 네트워크 패킷을 캡처하고 분석하여 패킷의 주요 정보를 확인할 수 있는 CLI 기반 도구를 만드는 것을 목표로 합니다.

주요 목표는 다음과 같습니다.

- 네트워크 인터페이스 목록 조회
- 실시간 패킷 캡처
- Ethernet 프레임 분석
- IPv4 / IPv6 패킷 분석
- TCP / UDP / ICMP 프로토콜 분석
- 패킷 필터링 기능
- 분석 결과 출력 및 저장

## 기술 스택

- Language: Rust
- Packet Capture: pcap
- Packet Parsing: etherparse 또는 pnet
- CLI: clap
- Logging: env_logger 또는 tracing

## 주요 기능

### 1. 인터페이스 조회

사용 가능한 네트워크 인터페이스 목록을 출력합니다.

```bash
rust_packet_analyzer interfaces
```

### 2. 패킷 캡처

지정한 네트워크 인터페이스에서 패킷을 캡처합니다.

```bash
rust_packet_analyzer capture --interface eth0
```

### 3. 패킷 분석

캡처한 패킷의 주요 정보를 분석합니다.

분석 대상:

- Source MAC
- Destination MAC
- Source IP
- Destination IP
- Protocol
- Source Port
- Destination Port
- Packet Length
- Payload Size

### 4. 필터링

특정 프로토콜 또는 포트 기준으로 패킷을 필터링합니다.

```bash
rust_packet_analyzer capture --interface eth0 --protocol tcp
```

```bash
rust_packet_analyzer capture --interface eth0 --port 443
```

## 프로젝트 구조

```text
rust_packet_analyzer/
├── Cargo.toml
├── README.md
└── src/
    ├── main.rs
    ├── cli.rs
    ├── capture.rs
    ├── parser.rs
    ├── packet.rs
    └── output.rs
```

## 설치 방법

Rust가 설치되어 있어야 합니다.

```bash
rustc --version
cargo --version
```

프로젝트를 클론합니다.

```bash
git clone https://github.com/USER_NAME/rust_packet_analyzer.git
cd rust_packet_analyzer
```

의존성을 설치하고 빌드합니다.

```bash
cargo build
```

## 실행 방법

기본 실행:

```bash
cargo run
```

릴리즈 빌드:

```bash
cargo build --release
```

실행 파일 위치:

```bash
target/release/rust_packet_analyzer
```

## 개발 단계

### Step 1. Rust 개발 환경 구성

- Rust 설치
- Cargo 프로젝트 생성
- GitHub 저장소 연결
- README 작성

### Step 2. CLI 구조 설계

- clap 기반 명령어 구성
- interfaces 명령어 추가
- capture 명령어 추가

### Step 3. 네트워크 인터페이스 조회

- 시스템 인터페이스 목록 출력
- 인터페이스 이름, 설명, IP 정보 표시

### Step 4. 패킷 캡처 구현

- pcap 라이브러리 연동
- 선택한 인터페이스에서 패킷 수신
- 캡처된 패킷 길이 출력

### Step 5. 패킷 파싱 구현

- Ethernet 헤더 분석
- IP 헤더 분석
- TCP / UDP / ICMP 분석

### Step 6. 출력 포맷 개선

- 사람이 읽기 쉬운 형태로 출력
- JSON 출력 옵션 추가
- 로그 레벨 설정

### Step 7. 필터링 기능 추가

- 프로토콜 필터
- 포트 필터
- IP 주소 필터

## 예시 출력

```text
[Packet]
Source MAC      : 00:11:22:33:44:55
Destination MAC : aa:bb:cc:dd:ee:ff
Source IP       : 192.168.0.10
Destination IP  : 142.250.207.14
Protocol        : TCP
Source Port     : 53210
Destination Port: 443
Length          : 1514 bytes
```

## 보안 및 권한

패킷 캡처는 운영체제에 따라 관리자 권한이 필요할 수 있습니다.

Linux/macOS:

```bash
sudo cargo run -- capture --interface eth0
```

Windows에서는 Npcap 설치가 필요할 수 있습니다.

## 향후 개선 사항

- PCAP 파일 저장
- PCAP 파일 읽기
- TUI 기반 실시간 대시보드
- DNS 패킷 분석
- HTTP 요청 분석
- TLS SNI 추출
- 통계 기능 추가
- 이상 트래픽 탐지 기능 추가

## 라이선스

MIT License캡처된 패킷 길이 출력
Step 5. 패킷 파싱 구현
Ethernet 헤더 분석
IP 헤더 분석
TCP / UDP / ICMP 분석
Step 6. 출력 포맷 개선
사람이 읽기 쉬운 형태로 출력
JSON 출력 옵션 추가
로그 레벨 설정
Step 7. 필터링 기능 추가
프로토콜 필터
포트 필터
IP 주소 필터
예시 출력
Plain text
[Packet]
Source MAC      : 00:11:22:33:44:55
Destination MAC : aa:bb:cc:dd:ee:ff
Source IP       : 192.168.0.10
Destination IP  : 142.250.207.14
Protocol        : TCP
Source Port     : 53210
Destination Port: 443
Length          : 1514 bytes
보안 및 권한
패킷 캡처는 운영체제에 따라 관리자 권한이 필요할 수 있습니다.
Linux/macOS:
Bash
sudo cargo run -- capture --interface eth0
Windows에서는 Npcap 설치가 필요할 수 있습니다.
향후 개선 사항
PCAP 파일 저장
PCAP 파일 읽기
TUI 기반 실시간 대시보드
DNS 패킷 분석
HTTP 요청 분석
TLS SNI 추출
통계 기능 추가
이상 트래픽 탐지 기능 추가
