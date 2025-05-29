# DHCP 성능 테스터

Go 언어로 개발된 고성능 DHCP 서버 테스트 도구로, 수천 개의 동시 DHCP 클라이언트를 시뮬레이션하고 실시간 모니터링 기능을 제공합니다.

## 🚀 주요 기능

### 핵심 기능
- **완전한 DHCP 4-way Handshake**: 각 클라이언트마다 `Discover → Offer → Request → ACK` 전체 과정 시뮬레이션
- **고성능 동시 처리**: Go 루틴을 활용한 수천 개의 가상 클라이언트 동시 실행
- **DHCP Relay Agent 지원**: RFC 3046 준수 Relay Agent 시뮬레이션 및 Option 82 지원
- **실시간 모니터링**: Curses 스타일 터미널 UI로 실시간 대시보드 제공
- **상세 통계 분석**: 포괄적인 성능 지표 및 응답 시간 분석
- **다양한 테스트 모드**: 시뮬레이션, 상세 로그, 실시간 모니터링 모드

### 고급 기능
- **패킷 수준 검증**: Transaction ID 검증, 메시지 타입 확인, Relay IP 검증
- **에러 분류**: 타임아웃, 파싱, 네트워크 에러 분류 및 리포트
- **성능 지표**: 
  - Discover→Offer 응답 시간 (D-O)
  - Request→ACK 응답 시간 (R-A)
  - 전체 완료 시간
  - 초당 요청 수 (RPS)
  - 성공률 분석

## 📋 시스템 요구사항

- **Go 1.16+** (컴파일용)
- **Linux/macOS/Windows** (크로스 플랫폼 지원)
- **네트워크 접근** (대상 DHCP 서버)
- **선택사항**: 고급 기능용 관리자 권한 (포트 68 바인딩, 브로드캐스트)

## 🔧 설치 및 컴파일

### 빠른 시작
```bash
# 소스 코드 다운로드
# 바이너리 컴파일
go build -o dhcp-tester main.go

# 실행 권한 부여 (Linux/macOS)
chmod +x dhcp-tester

# 기본 테스트 실행
./dhcp-tester -clients 10 -server DHCP서버IP주소
```

### 플랫폼별 컴파일
```bash
# Linux용
GOOS=linux GOARCH=amd64 go build -o dhcp-tester-linux main.go

# Windows용
GOOS=windows GOARCH=amd64 go build -o dhcp-tester.exe main.go

# macOS용
GOOS=darwin GOARCH=amd64 go build -o dhcp-tester-mac main.go
```

## 📖 사용법

### 기본 사용 예시

```bash
# 간단한 성능 테스트
./dhcp-tester -clients 100 -server 192.168.1.1

# 실시간 모니터링과 함께 고부하 테스트
./dhcp-tester -clients 1000 -concurrency 100 -live

# DHCP Relay Agent 시뮬레이션
./dhcp-tester -clients 500 -relay -relay-ip 192.168.1.1 -circuit-id "SW01/Port24"

# 디버깅용 상세 모드
./dhcp-tester -clients 5 -verbose -concurrency 1
```

### 고급 사용 예시

```bash
# 기업 네트워크 환경 시뮬레이션
./dhcp-tester -clients 2000 -concurrency 200 \
  -relay -relay-ip 10.0.1.1 \
  -circuit-id "건물A/스위치01/포트24" \
  -remote-id "직원VLAN100" \
  -live

# ISP 환경 테스트
./dhcp-tester -clients 10000 -concurrency 500 \
  -timeout 15s -live \
  -relay -relay-ip 203.0.113.1 \
  -circuit-id "DSLAM-01/Port-4096"

# 부하 테스트 및 통계 분석
./dhcp-tester -clients 5000 -concurrency 1000 \
  -timeout 30s -progress
```

## 🎛️ 명령행 옵션

### 기본 옵션
| 옵션 | 기본값 | 설명 |
|------|---------|------|
| `-server` | `255.255.255.255` | DHCP 서버 IP 주소 |
| `-port` | `67` | DHCP 서버 포트 |
| `-clients` | `100` | 테스트할 클라이언트 수 |
| `-concurrency` | `10` | 동시 실행할 고루틴 수 |
| `-timeout` | `5s` | 응답 대기 시간 |

### 화면 표시 모드
| 옵션 | 설명 |
|------|------|
| `-live` | 실시간 대시보드 모니터링 (curses 스타일) |
| `-verbose` | 클라이언트별 상세 DHCP 과정 로그 |
| `-progress` | 간단한 진행률 표시 (기본값) |

### DHCP Relay Agent 옵션
| 옵션 | 설명 |
|------|------|
| `-relay` | DHCP Relay Agent 모드 활성화 |
| `-relay-ip` | Relay Agent IP 주소 (giaddr 필드) |
| `-circuit-id` | Option 82 Circuit ID |
| `-remote-id` | Option 82 Remote ID |
| `-hops` | Relay hop count (기본값: 1) |
| `-max-hops` | 최대 허용 hop 수 (기본값: 4) |

### 기타 옵션
| 옵션 | 설명 |
|------|------|
| `-seed` | 재현 가능한 테스트용 랜덤 시드 |
| `-require-root` | 관리자 권한 강제 요구 |
| `-skip-priv-check` | 권한 확인 건너뛰기 |

## 📊 실시간 대시보드

`-live` 모드는 다음과 같은 실시간 모니터링 인터페이스를 제공합니다:

```
╔══════════════════════════════════════════════════════════════════════╗
║                    DHCP 서버 성능 테스트 실시간 모니터                     ║
╚══════════════════════════════════════════════════════════════════════╝

테스트 설정
  서버: 192.168.1.1:67  (Relay: 192.168.1.1)
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

성능 지표
  완료율: 38.0 completions/sec
  성공율: 33.2 successful/sec
```

## 🔐 권한 요구사항

### 일반 사용자 모드 (권장)
- ✅ **기본 성능 테스트**: 특별한 권한 없이 동작
- ✅ **Relay Agent 시뮬레이션**: 모든 기능 사용 가능
- ✅ **고성능 동시 처리**: 수천 개의 동시 클라이언트 지원
- ⚠️ **제한사항**: 임시 포트 사용, 브로드캐스트 시뮬레이션만 가능

### 관리자 모드 (고급 기능)
```bash
# 고급 기능 사용을 위한 관리자 권한 실행
sudo ./dhcp-tester -clients 1000 -require-root
```
- ✅ **포트 68 바인딩**: 실제 DHCP 클라이언트 포트 사용
- ✅ **실제 브로드캐스트**: 진짜 브로드캐스트 패킷 전송
- ✅ **인터페이스 바인딩**: 특정 네트워크 인터페이스에 바인딩

## 🏗️ 아키텍처

### DHCP 프로토콜 구현
완전한 DHCP 클라이언트 스택을 구현:

1. **DHCP Discover**: IP 주소 요청을 위한 브로드캐스트
2. **DHCP Offer**: 사용 가능한 IP로 서버 응답
3. **DHCP Request**: 특정 IP에 대한 클라이언트 요청
4. **DHCP ACK**: IP 할당에 대한 서버 확인

### Relay Agent 지원 (RFC 3046)
- **Option 82 구현**: Circuit ID 및 Remote ID 서브 옵션
- **Gateway IP 주소**: 적절한 giaddr 필드 처리
- **Hop Count 관리**: RFC 준수 hop count 추적
- **네트워크 토폴로지 시뮬레이션**: 다중 홉 Relay 시나리오

### 성능 최적화
- **Go 루틴**: 효율적인 동시 클라이언트 시뮬레이션
- **메모리 관리**: 슬라이딩 윈도우로 메모리 사용량 제한
- **Atomic 연산**: 락 없는 통계 수집
- **효율적인 파싱**: 최적화된 DHCP 패킷 처리

## 📈 성능 벤치마크

### 일반적인 성능
- **소규모**: 100개 클라이언트 → 1-2초
- **중간 규모**: 1,000개 클라이언트 → 5-10초  
- **대규모**: 10,000개 클라이언트 → 30-60초
- **기업 규모**: 100,000개 이상 클라이언트 지원

### 하드웨어 요구사항
- **CPU**: 고성능 동시 처리를 위해 2코어 이상 권장
- **메모리**: 동시 클라이언트 1,000개당 약 1MB
- **네트워크**: 대규모 테스트를 위해 기가비트 네트워크 권장

## 🧪 사용 사례

### 네트워크 운영
- **DHCP 서버 용량 계획**: 최대 클라이언트 부하 결정
- **성능 회귀 테스트**: 서버 업데이트 검증
- **네트워크 인프라 검증**: Relay Agent 구성 테스트
- **재해 복구 테스트**: 백업 DHCP 서버 검증

### 개발 및 QA
- **부하 테스트**: DHCP 구현 스트레스 테스트
- **프로토콜 준수**: RFC 준수 검증
- **성능 최적화**: 병목 지점 식별
- **통합 테스트**: 네트워크 장비와의 테스트

### 네트워크 문제 해결
- **응답 시간 분석**: 느린 구성 요소 식별
- **에러 패턴 분석**: 실패 모드 분류
- **Relay 경로 검증**: 다중 홉 구성 확인
- **용량 계획**: 최적 서버 크기 결정

## 🔧 문제 해결

### 일반적인 문제들

**연결 거부됨**
```bash
# 서버 IP와 포트 확인
./dhcp-tester -server 192.168.1.1 -port 67 -clients 1
```

**권한 거부됨**
```bash
# 권한 요구 기능 없이 실행
./dhcp-tester -skip-priv-check -clients 10
```

**높은 실패율**
```bash
# 타임아웃 증가 및 동시성 감소
./dhcp-tester -timeout 10s -concurrency 5 -clients 100
```

**메모리 문제**
```bash
# 대규모 테스트 시 적절한 동시성 사용
./dhcp-tester -clients 10000 -concurrency 100
```

### 디버그 모드
```bash
# 문제 해결을 위한 상세 로그 활성화
./dhcp-tester -clients 3 -verbose -concurrency 1 -timeout 10s
```

## 📝 출력 예시

### 요약 보고서
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
직접 테스트 수:             13

----------------------------------------------------------------------
완전한 DHCP 협상 시간 통계 (Discover~ACK 전체 과정)
----------------------------------------------------------------------
최소 협상 시간:          15.2ms
최대 협상 시간:         234.7ms
평균 협상 시간:          45.8ms
중간값 협상 시간:        42.1ms
95퍼센타일:             89.3ms
99퍼센타일:            156.2ms

💡 참고: 위 시간은 각 클라이언트가 IP 주소를 완전히 획득하는데
   걸린 전체 시간입니다 (4단계 모두 포함)

----------------------------------------------------------------------
실패 원인 분석
----------------------------------------------------------------------
Offer 수신 실패: java.net.SocketTimeoutException: 8건
ACK 수신 실패: java.net.SocketTimeoutException: 5건
```

## 🚀 실제 사용 시나리오

### 기업 네트워크 환경
```bash
# 대기업 본사 네트워크 (2000명 규모)
./dhcp-tester -clients 2000 -concurrency 200 \
  -relay -relay-ip 10.0.1.1 \
  -circuit-id "본사빌딩/3층스위치/포트48" \
  -remote-id "직원네트워크" \
  -live -timeout 10s

# 지점 네트워크 (100명 규모)
./dhcp-tester -clients 100 -concurrency 20 \
  -relay -relay-ip 172.16.1.1 \
  -circuit-id "지점01/스위치01" \
  -live
```

### ISP/통신사 환경
```bash
# FTTH 가입자 테스트 (10000명)
./dhcp-tester -clients 10000 -concurrency 500 \
  -relay -relay-ip 203.0.113.1 \
  -circuit-id "OLT-seoul-01/PON-24" \
  -remote-id "아파트단지A" \
  -live -timeout 15s

# 케이블 모뎀 환경
./dhcp-tester -clients 5000 -concurrency 200 \
  -relay -relay-ip 192.168.100.1 \
  -circuit-id "CMTS-01/DS-12/US-4" \
  -live
```

### 교육기관 네트워크
```bash
# 대학교 기숙사 (1000명)
./dhcp-tester -clients 1000 -concurrency 100 \
  -relay -relay-ip 10.10.1.1 \
  -circuit-id "기숙사A동/스위치24" \
  -remote-id "학생네트워크" \
  -live

# 도서관 무선랜 (500명)
./dhcp-tester -clients 500 -concurrency 50 \
  -relay -relay-ip 172.20.1.1 \
  -circuit-id "도서관/무선AP-3층" \
  -live
```

## 🤝 기여하기

기여를 환영합니다! 이슈, 기능 요청, 또는 풀 리퀘스트를 자유롭게 제출해 주세요.

### 개발 환경 설정
```bash
# 저장소 클론
git clone <저장소-URL>
cd dhcp-performance-tester

# 의존성 설치
go mod tidy

# 테스트 실행
go test ./...

# 빌드
go build -o dhcp-tester main.go
```

### 개발 가이드라인
- 모든 새 기능에 대해 테스트 코드 작성
- 코드 스타일: `go fmt` 준수
- 커밋 메시지: 한국어 또는 영어로 명확하게
- 문서 업데이트: README와 코드 주석 갱신

## 📄 라이선스

이 프로젝트는 MIT 라이선스를 따릅니다. 자세한 내용은 LICENSE 파일을 참조하세요.

## 🆘 지원 및 문의

문제, 질문, 기능 요청은 다음과 같이 해주세요:
- GitHub에서 이슈 생성
- 문제 해결 섹션 확인
- `./dhcp-tester -h`로 명령행 옵션 확인

## 🔗 관련 프로젝트

- **ISC DHCP**: DHCP 서버 참조 구현
- **Kea DHCP**: ISC의 현대적인 DHCP 서버
- **dnsmasq**: 경량 DHCP/DNS 서버
- **Go DHCP 라이브러리**: dhcp4, dhcp6 패키지

## 📚 추가 자료

### DHCP 관련 RFC 문서
- **RFC 2131**: Dynamic Host Configuration Protocol
- **RFC 3046**: DHCP Relay Agent Information Option
- **RFC 4361**: Node-specific Client Identifiers for DHCP
- **RFC 6842**: Client Identifier Option in DHCP Server Replies

### 네트워크 성능 측정 도구
- **iperf3**: 네트워크 대역폭 측정
- **netperf**: 네트워크 성능 벤치마킹
- **hping3**: 네트워크 패킷 생성 및 분석

---

**Go로 제작** ❤️ | **고성능** | **실무 준비 완료**

> 작성자 : Johnny S.B.Hyeon, from sungnam, 2025.05.29
> 본 프로그램은 전문적인 DHCP 성능 테스트 도구입니다.
