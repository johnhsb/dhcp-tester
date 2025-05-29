# DHCP 성능 테스트 솔루션

Go 언어로 개발된 완전한 DHCP 테스트 환경으로, **고성능 클라이언트 테스터**와 **DHCP 서버 시뮬레이터**를 포함하여 실제 네트워크 환경을 완벽하게 시뮬레이션합니다.

## 🎯 솔루션 구성

### 📱 **DHCP 클라이언트 테스터** (`dhcp-tester`)
- 수천 개의 가상 DHCP 클라이언트 시뮬레이션
- 완전한 4-way handshake 수행
- 실시간 성능 모니터링
- Relay Agent 지원

### 🖥️ **DHCP 서버 시뮬레이터** (`dhcp-server`)
- RFC 준수 DHCP 서버 구현
- 동적 IP 풀 관리
- Relay Agent 완전 지원
- 네트워크 지연/손실 시뮬레이션

## 🚀 주요 기능

### 핵심 기능
- **완전한 DHCP 프로토콜**: `Discover → Offer → Request → ACK` 전체 과정
- **RFC 3046 Relay Agent**: Option 82, Circuit ID, Remote ID 완전 지원
- **고성능 동시 처리**: Go 루틴 기반 수천 개 동시 클라이언트
- **실시간 모니터링**: Curses 스타일 대시보드
- **완전한 테스트 환경**: 클라이언트와 서버 모두 제공

### 고급 기능
- **네트워크 시뮬레이션**: 지연, 패킷 손실, 대역폭 제한
- **성능 분석**: 응답 시간, 처리량, 성공률 상세 분석
- **시나리오 테스트**: 기업, ISP, 교육기관 환경 모사
- **부하 테스트**: 서버 한계점 및 병목 지점 발견

## 📋 시스템 요구사항

- **Go 1.16+** (컴파일용)
- **Linux/macOS/Windows** (크로스 플랫폼 지원)
- **네트워크 접근** (실제 DHCP 서버 테스트 시)
- **선택사항**: 관리자 권한 (포트 67/68 바인딩)

## 🔧 설치 및 컴파일

### 빠른 시작
```bash
# 클라이언트 테스터 컴파일
go build -o dhcp-tester dhcp-tester.go

# 서버 시뮬레이터 컴파일
go build -o dhcp-server dhcp-server.go

# 실행 권한 부여 (Linux/macOS)
chmod +x dhcp-tester dhcp-server
```

### 플랫폼별 컴파일
```bash
# Linux용
GOOS=linux GOARCH=amd64 go build -o dhcp-tester-linux dhcp-tester.go
GOOS=linux GOARCH=amd64 go build -o dhcp-server-linux dhcp-server.go

# Windows용
GOOS=windows GOARCH=amd64 go build -o dhcp-tester.exe dhcp-tester.go
GOOS=windows GOARCH=amd64 go build -o dhcp-server.exe dhcp-server.go
```

## 📖 기본 사용법

### 시나리오 1: 로컬 테스트 환경

**터미널 1 - DHCP 서버 시작**
```bash
# 실시간 모니터링과 함께 서버 시작
./dhcp-server -live -verbose \
  -start-ip 192.168.1.100 \
  -end-ip 192.168.1.200 \
  -gateway 192.168.1.1
```

**터미널 2 - 클라이언트 테스트**
```bash
# 서버 성능 테스트
./dhcp-tester -server 127.0.0.1 -clients 100 -concurrency 20 -live
```

### 시나리오 2: 실제 DHCP 서버 테스트

```bash
# 실제 운영 중인 DHCP 서버 테스트
./dhcp-tester -server 192.168.1.1 -clients 500 -concurrency 50 -live
```

## 🏢 실제 네트워크 환경별 사용법

### 기업 네트워크 환경

**서버 설정 (기업 환경)**
```bash
./dhcp-server -live \
  -start-ip 10.10.1.100 \
  -end-ip 10.10.1.200 \
  -gateway 10.10.1.1 \
  -dns1 10.10.1.10 \
  -dns2 8.8.8.8 \
  -domain "company.local" \
  -lease-time 8h
```

**클라이언트 테스트 (기업 환경)**
```bash
# 본사 네트워크 (2000명 규모)
./dhcp-tester -server 127.0.0.1 \
  -clients 2000 -concurrency 200 \
  -relay -relay-ip 10.10.1.1 \
  -circuit-id "본사빌딩/3층스위치/포트48" \
  -remote-id "직원네트워크" \
  -live -timeout 10s

# 지점 네트워크 (100명 규모)
./dhcp-tester -server 192.168.1.1 \
  -clients 100 -concurrency 20 \
  -relay -relay-ip 172.16.1.1 \
  -circuit-id "지점01/스위치01" \
  -live
```

### ISP/통신사 환경

**서버 설정 (ISP 환경)**
```bash
./dhcp-server -live \
  -start-ip 172.20.0.10 \
  -end-ip 172.20.10.250 \
  -gateway 172.20.0.1 \
  -lease-time 24h \
  -max-concurrent 5000 \
  -response-delay 10ms
```

**클라이언트 테스트 (ISP 환경)**
```bash
# FTTH 가입자 테스트 (10000명)
./dhcp-tester -server 127.0.0.1 \
  -clients 10000 -concurrency 500 \
  -relay -relay-ip 203.0.113.1 \
  -circuit-id "OLT-seoul-01/PON-24" \
  -remote-id "아파트단지A" \
  -live -timeout 15s

# 케이블 모뎀 환경
./dhcp-tester -server 127.0.0.1 \
  -clients 5000 -concurrency 200 \
  -relay -relay-ip 192.168.100.1 \
  -circuit-id "CMTS-01/DS-12/US-4" \
  -live
```

### 교육기관 네트워크

**서버 설정 (대학교)**
```bash
./dhcp-server -live \
  -start-ip 172.16.10.10 \
  -end-ip 172.16.20.250 \
  -gateway 172.16.10.1 \
  -dns1 172.16.1.10 \
  -domain "university.ac.kr" \
  -lease-time 12h
```

**클라이언트 테스트 (교육기관)**
```bash
# 대학교 기숙사 (1000명)
./dhcp-tester -server 127.0.0.1 \
  -clients 1000 -concurrency 100 \
  -relay -relay-ip 172.16.10.1 \
  -circuit-id "기숙사A동/스위치24" \
  -remote-id "학생네트워크" \
  -live

# 도서관 무선랜 (500명)
./dhcp-tester -server 127.0.0.1 \
  -clients 500 -concurrency 50 \
  -relay -relay-ip 172.20.1.1 \
  -circuit-id "도서관/무선AP-3층" \
  -live
```

## 🎛️ 명령행 옵션

### DHCP 클라이언트 테스터 (`dhcp-tester`)

#### 기본 옵션
| 옵션 | 기본값 | 설명 |
|------|---------|------|
| `-server` | `255.255.255.255` | DHCP 서버 IP 주소 |
| `-port` | `67` | DHCP 서버 포트 |
| `-clients` | `100` | 테스트할 클라이언트 수 |
| `-concurrency` | `10` | 동시 실행할 고루틴 수 |
| `-timeout` | `5s` | 응답 대기 시간 |

#### 표시 모드
| 옵션 | 설명 |
|------|------|
| `-live` | 실시간 대시보드 모니터링 |
| `-verbose` | 클라이언트별 상세 DHCP 과정 로그 |
| `-progress` | 간단한 진행률 표시 (기본값) |

#### Relay Agent 옵션
| 옵션 | 설명 |
|------|------|
| `-relay` | DHCP Relay Agent 모드 활성화 |
| `-relay-ip` | Relay Agent IP 주소 (giaddr) |
| `-circuit-id` | Option 82 Circuit ID |
| `-remote-id` | Option 82 Remote ID |
| `-hops` | Relay hop count (기본값: 1) |
| `-max-hops` | 최대 허용 hop count (기본값: 4) |

### DHCP 서버 시뮬레이터 (`dhcp-server`)

#### 기본 설정
| 옵션 | 기본값 | 설명 |
|------|---------|------|
| `-listen` | `0.0.0.0` | 서버 바인딩 IP |
| `-port` | `67` | 서버 포트 |
| `-start-ip` | `192.168.100.10` | IP 풀 시작 주소 |
| `-end-ip` | `192.168.100.250` | IP 풀 종료 주소 |
| `-gateway` | `192.168.100.1` | 기본 게이트웨이 |
| `-dns1` | `8.8.8.8` | 첫 번째 DNS 서버 |
| `-dns2` | `8.8.4.4` | 두 번째 DNS 서버 |
| `-domain` | `example.com` | 도메인 이름 |
| `-lease-time` | `24h` | IP 임대 시간 |

#### 성능 및 시뮬레이션
| 옵션 | 기본값 | 설명 |
|------|---------|------|
| `-max-concurrent` | `1000` | 최대 동시 처리 수 |
| `-response-delay` | `0` | 응답 지연 시뮬레이션 |
| `-drop-rate` | `0.0` | 패킷 드롭률 (0.0-1.0) |
| `-relay` | `true` | Relay Agent 지원 |
| `-max-hops` | `4` | 최대 허용 hop count |

#### 표시 옵션
| 옵션 | 설명 |
|------|------|
| `-live` | 실시간 서버 통계 대시보드 |
| `-verbose` | 상세 DHCP 메시지 로그 |

## 📊 실시간 모니터링

### 클라이언트 테스터 대시보드
```
╔══════════════════════════════════════════════════════════════════════╗
║                    DHCP 서버 성능 테스트 실시간 모니터                     ║
╚══════════════════════════════════════════════════════════════════════╝

테스트 설정
  서버: 127.0.0.1:67  (Relay: 192.168.1.1)
  클라이언트: 1000, 경과시간: 12s

전체 진행률
  진행: 456/1000 (45.6%) [████████████████████░░░░░░░░░░░░░░░░░░░░] 45.6%
  성공: 398, 실패: 58, 성공률: 87.3%

┌─ DHCP 4-Way Handshake 실시간 통계 ────────────────────────────────────┐
│  1. DISCOVER 전송:      456 개    3. REQUEST 전송:     398 개  │
│  2. OFFER 수신:         398 개    4. ACK 수신:         398 개  │
│                                                                    │
│  평균 응답시간:                                                    │
│    Discover → Offer:   15.2ms      Request → ACK:    12.8ms    │
└──────────────────────────────────────────────────────────────────────┘
```

### 서버 시뮬레이터 대시보드
```
╔════════════════════════════════════════════════════════════════════════╗
║                        DHCP 서버 실시간 모니터링                          ║
╚════════════════════════════════════════════════════════════════════════╝

서버 정보
  주소: 0.0.0.0:67  (Relay 지원)
  가동 시간: 2m34s
  IP 풀: 192.168.1.100 - 192.168.1.200 (101개)

┌─ DHCP 메시지 통계 ──────────────────────────────────────────────────────┐
│  수신: DISCOVER      456    REQUEST      398                         │
│  전송: OFFER         398    ACK          398    NAK        5     │
└────────────────────────────────────────────────────────────────────────┘

IP 풀 상태
  사용 중: 87, 사용 가능: 14, 사용률: 86.1%
  [████████████████████████████████████████████████░░░░] 86.1%
```

## 🧪 고급 테스트 시나리오

### 1. 네트워크 지연 및 손실 시뮬레이션

**높은 지연 환경**
```bash
# 서버: 100ms 응답 지연
./dhcp-server -response-delay 100ms -live

# 클라이언트: 지연된 환경에서 테스트
./dhcp-tester -server 127.0.0.1 -clients 200 -timeout 15s -live
```

**패킷 손실 환경**
```bash
# 서버: 5% 패킷 드롭
./dhcp-server -drop-rate 0.05 -live -verbose

# 클라이언트: 손실 환경에서 재전송 테스트
./dhcp-tester -server 127.0.0.1 -clients 300 -timeout 20s -live
```

### 2. IP 풀 고갈 테스트

**제한된 IP 풀**
```bash
# 서버: 작은 IP 풀 (20개만)
./dhcp-server -start-ip 192.168.1.10 -end-ip 192.168.1.29 -live

# 클라이언트: 풀보다 많은 클라이언트 (100개)
./dhcp-tester -server 127.0.0.1 -clients 100 -concurrency 20 -live
```

### 3. 대용량 성능 벤치마킹

**최대 성능 테스트**
```bash
# 서버: 대용량 IP 풀과 높은 동시성
./dhcp-server -live \
  -start-ip 10.0.0.10 \
  -end-ip 10.0.10.250 \
  -max-concurrent 2000

# 클라이언트: 대량 부하 테스트
./dhcp-tester -server 127.0.0.1 \
  -clients 10000 -concurrency 500 \
  -timeout 30s -live
```

### 4. Multi-hop Relay 환경

**복잡한 Relay 구조**
```bash
# 서버: 다중 홉 지원
./dhcp-server -live -max-hops 6 -response-delay 20ms

# 클라이언트: 3단계 Relay 시뮬레이션
./dhcp-tester -server 127.0.0.1 \
  -clients 500 -concurrency 50 \
  -relay -relay-ip 192.168.1.1 \
  -hops 3 -max-hops 6 \
  -circuit-id "라우터1/라우터2/스위치3/포트24" \
  -live
```

## 🔐 권한 요구사항

### 일반 사용자 모드 (권장)
- ✅ **완전한 테스트 환경**: 클라이언트와 서버 모두 동작
- ✅ **모든 기능**: Relay Agent, 실시간 모니터링 등
- ✅ **고성능**: 수천 개 동시 클라이언트 지원
- ⚠️ **제한사항**: 임시 포트 사용, 실제 브로드캐스트 제한

### 관리자 모드 (실제 환경)
```bash
# 실제 DHCP 포트 사용
sudo ./dhcp-server -port 67
sudo ./dhcp-tester -require-root
```
- ✅ **포트 67/68 바인딩**: 실제 DHCP 포트 사용
- ✅ **실제 브로드캐스트**: 진짜 네트워크 패킷
- ✅ **인터페이스 제어**: 특정 네트워크 인터페이스

## 📈 성능 벤치마크

### 일반적인 성능 (Intel i7, 16GB RAM)

#### 클라이언트 테스터
- **소규모**: 100개 클라이언트 → 1-2초
- **중간 규모**: 1,000개 클라이언트 → 5-10초  
- **대규모**: 10,000개 클라이언트 → 30-60초
- **극한 테스트**: 100,000개 클라이언트 지원

#### 서버 시뮬레이터
- **처리량**: 50,000+ RPS
- **동시 연결**: 10,000+ 동시 클라이언트
- **메모리**: 클라이언트 1,000개당 약 2MB
- **응답 시간**: 평균 1-5ms

### 하드웨어 권장사항
- **CPU**: 4코어 이상 (고성능 테스트용)
- **메모리**: 8GB 이상 (대량 클라이언트용)
- **네트워크**: 기가비트 이상 (실제 네트워크 테스트용)

## 🧪 QA 및 운영 사용 사례

### 개발/QA 환경

**일일 회귀 테스트**
```bash
#!/bin/bash
# 자동화된 DHCP 테스트 스크립트

echo "=== DHCP 성능 회귀 테스트 시작 ==="

# 1. 서버 시작
./dhcp-server -live > server.log 2>&1 &
SERVER_PID=$!
sleep 5

# 2. 기본 성능 테스트
echo "기본 성능 테스트..."
./dhcp-tester -server 127.0.0.1 -clients 100 -progress

# 3. Relay Agent 테스트
echo "Relay Agent 테스트..."
./dhcp-tester -server 127.0.0.1 -clients 200 \
  -relay -relay-ip 192.168.1.1 -progress

# 4. 고부하 테스트
echo "고부하 테스트..."
./dhcp-tester -server 127.0.0.1 -clients 1000 -concurrency 100 -progress

# 5. 서버 종료
kill $SERVER_PID
echo "=== 테스트 완료 ==="
```

### 운영 환경 검증

**신규 DHCP 서버 검증**
```bash
# 단계별 부하 증가 테스트
for clients in 100 500 1000 2000 5000; do
  echo "=== $clients 클라이언트 테스트 ==="
  ./dhcp-tester -server 192.168.1.1 \
    -clients $clients -concurrency $((clients/10)) \
    -timeout 10s -progress
  sleep 30
done
```

**Relay Agent 구성 검증**
```bash
# 다양한 Relay 구성 테스트
RELAY_IPS=("10.0.1.1" "10.0.2.1" "10.0.3.1")
for relay_ip in "${RELAY_IPS[@]}"; do
  echo "=== Relay $relay_ip 테스트 ==="
  ./dhcp-tester -server 192.168.1.1 \
    -clients 500 -concurrency 50 \
    -relay -relay-ip $relay_ip \
    -circuit-id "테스트환경/$relay_ip" \
    -progress
done
```

## 🔧 문제 해결

### 일반적인 문제들

**연결 실패**
```bash
# 포트 및 방화벽 확인
sudo netstat -ulnp | grep :67
sudo iptables -L | grep 67

# 테스트 연결
./dhcp-tester -server 127.0.0.1 -clients 1 -verbose
```

**성능 저하**
```bash
# 동시성 조정
./dhcp-tester -clients 1000 -concurrency 50  # 동시성 감소
./dhcp-server -max-concurrent 500            # 서버 제한

# 타임아웃 증가
./dhcp-tester -timeout 15s -clients 1000
```

**메모리 부족**
```bash
# 메모리 사용량 모니터링
top -p $(pgrep dhcp-server)
top -p $(pgrep dhcp-tester)

# 배치 처리로 분할
for i in {1..10}; do
  ./dhcp-tester -clients 500 -concurrency 25
  sleep 10
done
```

### 디버깅 모드

**상세 로그 분석**
```bash
# 클라이언트 상세 분석
./dhcp-tester -clients 5 -verbose -concurrency 1 -timeout 30s

# 서버 상세 분석
./dhcp-server -verbose -live

# 패킷 캡처 (고급)
sudo tcpdump -i any -w dhcp-test.pcap port 67 or port 68
```

## 📝 출력 예시

### 클라이언트 테스터 요약
```
======================================================================
DHCP 서버 성능 테스트 결과 (완전한 4-way handshake)
======================================================================
각 클라이언트가 수행한 과정: Discover → Offer → Request → ACK
----------------------------------------------------------------------
총 요청 수:               1000
성공 요청 수:              987
실패 요청 수:               13
성공률:                  98.7%
총 테스트 시간:            24s
초당 완료 수:            41.5 completions/s
Relay 테스트 수:           987

----------------------------------------------------------------------
완전한 DHCP 협상 시간 통계 (Discover~ACK 전체 과정)
----------------------------------------------------------------------
최소 협상 시간:          15.2ms
최대 협상 시간:         234.7ms
평균 협상 시간:          45.8ms
중간값 협상 시간:        42.1ms
95퍼센타일:             89.3ms
99퍼센타일:            156.2ms
```

### 서버 시뮬레이터 요약
```
======================================================================
DHCP 서버 최종 통계
======================================================================
가동 시간:           2m34s
처리된 DISCOVER:     1000
전송된 OFFER:        987
처리된 REQUEST:      987
전송된 ACK:          987
전송된 NAK:          13
평균 RPS:           45.2 requests/sec
최종 IP 사용률:      86.1% (87/101)
```

## 🤝 기여하기

### 개발 환경 설정
```bash
# 저장소 클론
git clone <저장소-URL>
cd dhcp-performance-test-suite

# 의존성 설치
go mod tidy

# 테스트 실행
go test ./...

# 빌드
make build
```

### 기여 가이드라인
- **코드 스타일**: `go fmt` 및 `go vet` 준수
- **테스트**: 새 기능에 대한 단위 테스트 작성
- **문서**: README 및 코드 주석 업데이트
- **이슈**: GitHub Issues로 버그 리포트 및 기능 요청

## 📄 라이선스

이 프로젝트는 MIT 라이선스를 따릅니다. 자세한 내용은 LICENSE 파일을 참조하세요.

## 🆘 지원 및 문의

- **GitHub Issues**: 버그 리포트 및 기능 요청
- **문제 해결 가이드**: 위의 문제 해결 섹션 참조
- **명령어 도움말**: `./dhcp-tester -h`, `./dhcp-server -h`

## 🔗 관련 기술

### DHCP 표준 문서
- **RFC 2131**: Dynamic Host Configuration Protocol
- **RFC 3046**: DHCP Relay Agent Information Option
- **RFC 4361**: Node-specific Client Identifiers
- **RFC 6842**: Client Identifier Option in Server Replies

### 네트워크 테스트 도구
- **iperf3**: 네트워크 대역폭 측정
- **netperf**: 네트워크 성능 벤치마킹
- **hping3**: 패킷 생성 및 분석
- **Wireshark**: 네트워크 프로토콜 분석

### DHCP 서버 구현체
- **ISC DHCP**: 가장 널리 사용되는 DHCP 서버
- **Kea DHCP**: ISC의 차세대 DHCP 서버
- **dnsmasq**: 경량 DHCP/DNS 서버
- **Windows DHCP**: Microsoft DHCP 서버

## 📚 사용 사례별 가이드

### 기업 네트워크 관리자
```bash
# 신규 DHCP 서버 도입 전 검증
./dhcp-server -start-ip 10.0.1.100 -end-ip 10.0.1.200 -live &
./dhcp-tester -server 127.0.0.1 -clients 500 -relay -relay-ip 10.0.1.1 -live

# 기존 서버 성능 모니터링
./dhcp-tester -server 10.0.1.10 -clients 200 -concurrency 20 -live
```

### ISP/통신사 엔지니어
```bash
# 대규모 가입자 환경 테스트
./dhcp-server -start-ip 172.16.0.10 -end-ip 172.16.10.250 \
  -max-concurrent 5000 -response-delay 50ms -live &
./dhcp-tester -server 127.0.0.1 -clients 10000 -concurrency 500 -live
```

### 네트워크 장비 개발자
```bash
# Relay Agent 기능 검증
./dhcp-tester -server 192.168.1.1 -clients 1000 \
  -relay -relay-ip 192.168.1.254 \
  -circuit-id "장비모델/포트번호" \
  -remote-id "고객식별자" \
  -verbose
```

---

**🇰🇷 한국 네트워크 환경 최적화** | **Go 고성능** | ** Johnny S.B.Hyeon 2025 **

> 한국의 다양한 네트워크 환경을 고려하여 제작된 전문적인 DHCP 성능 테스트 솔루션입니다.
> 기업, ISP, 교육기관에서 바로 사용할 수 있는 완전한 테스트 환경을 제공합니다.
