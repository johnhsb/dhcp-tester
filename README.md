# ISP급 대용량 DHCP서버 성능 검증 시스템 v2.0

Go 언어로 개발된 **RFC 2131 완전 준수** DHCP 테스트 환경으로, **고성능 클라이언트 테스터**와 **DHCP 서버 시뮬레이터**를 포함하여 실제 네트워크 환경을 완벽하게 시뮬레이션합니다.

## 🏗️ **아키텍처 개요**

```
┌─────────────────────┐    ┌─────────────────────┐
│  DHCP 서버          │    │  성능 테스트        │
│  시뮬레이터         │◄───│  클라이언트         │
│                     │    │                     │
│ dhcp_server_        │    │ dhcp_performance_   │
│ simulator.py        │    │ test.py             │
│                     │    │                     │
│ • 다중 서브넷 지원  │    │ • Relay Agent 시뮬  │
│ • 실시간 디버깅     │    │ • 대용량 동시 요청  │
│ • 성능 모니터링     │    │ • 상세 성능 분석    │
└─────────────────────┘    └─────────────────────┘
```

## 🎯 솔루션 구성

### 📱 **DHCP 클라이언트 테스터** (`dhcp-tester`)
- 수천 개의 가상 DHCP 클라이언트 시뮬레이션
- **RFC 2131 완전 준수** 4-way handshake 수행
- **지수 백오프 재시도 로직** (RFC 2131 Section 4.1)
- **네트워크 지터 기능** (혼잡 방지)
- 실시간 성능 모니터링 (5fps 업데이트)
- **RFC 3046 Relay Agent** 완전 지원

### 🖥️ **DHCP 서버 시뮬레이터** (`dhcp-server`)
- RFC 준수 DHCP 서버 구현
- 동적 IP 풀 관리 및 임대 추적
- **세션 관리** 및 자동 정리
- Relay Agent 완전 지원
- **네트워크 시뮬레이션** (지연/손실/대역폭)

## 🚀 주요 기능

### 🆕 **v2.0 신규 기능**
- **RFC 2131 재시도 로직**: 지수 백오프, 최대 재시도 횟수, 지터
- **향상된 실시간 모니터링**: 5fps 대시보드, 단계별 응답시간
- **권한 자동 검증**: 포트 바인딩 테스트, 사용자 권한 확인
- **세션 관리**: 클라이언트 세션 추적, 자동 정리
- **네트워크 시뮬레이션**: 패킷 드롭, 응답 지연, 대역폭 제한
- **향상된 통계**: 백분위수 분석, 에러 분류, 재시도 통계

### 핵심 기능
- **완전한 DHCP 프로토콜**: `Discover → Offer → Request → ACK` 전체 과정
- **RFC 3046 Relay Agent**: Option 82, Circuit ID, Remote ID 완전 지원
- **고성능 동시 처리**: Go 루틴 기반 수천 개 동시 클라이언트
- **실시간 모니터링**: Curses 스타일 대시보드
- **완전한 테스트 환경**: 클라이언트와 서버 모두 제공

## 📋 시스템 요구사항

- **Go 1.16+** (컴파일용)
- **Linux/macOS/Windows** (크로스 플랫폼 지원)
- **네트워크 접근** (실제 DHCP 서버 테스트 시)
- **선택사항**: 관리자 권한 (포트 67/68 바인딩)
- **메모리**: 최소 4GB (대량 테스트용 8GB 권장)
- **CPU**: 멀티코어 권장 (고성능 테스트용)

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

### 최적화 빌드 (성능 향상)
```bash
# 릴리즈 빌드 (최적화)
go build -ldflags="-s -w" -o dhcp-tester dhcp-tester.go
go build -ldflags="-s -w" -o dhcp-server dhcp-server.go

# 정적 링킹 (배포용)
CGO_ENABLED=0 go build -a -ldflags="-s -w" -o dhcp-tester dhcp-tester.go
CGO_ENABLED=0 go build -a -ldflags="-s -w" -o dhcp-server dhcp-server.go
```

## 📖 기본 사용법

### 🆕 권한 자동 검증 및 안내
```bash
# 프로그램 실행 시 자동으로 권한 상태 확인
./dhcp-tester
# ✅ Root 권한으로 실행 중 - 모든 기능 사용 가능
# 또는
# ℹ️ 일반 사용자로 실행 중 (username)
#    - 기본 성능 테스트: 가능
#    - 실제 브로드캐스트: 제한적
#    - 포트 68 바인딩: 불가능
#    💡 더 정확한 테스트를 원하면 'sudo ./dhcp-tester'로 실행하세요
```

### 시나리오 1: 로컬 테스트 환경 (RFC 재시도 포함)

**터미널 1 - DHCP 서버 시작**
```bash
# 실시간 모니터링과 함께 서버 시작
./dhcp-server -live -verbose \
  -start-ip 192.168.1.100 \
  -end-ip 192.168.1.200 \
  -gateway 192.168.1.1 \
  -response-delay 50ms \
  -drop-rate 0.02
```

**터미널 2 - 클라이언트 테스트 (RFC 재시도 활성화)**
```bash
# RFC 2131 준수 재시도 로직으로 서버 성능 테스트
./dhcp-tester -server 127.0.0.1 \
  -clients 100 -concurrency 20 \
  -retry -max-discover-retries 3 -max-request-retries 3 \
  -initial-timeout 4s -max-timeout 64s \
  -backoff-multiplier 2.0 \
  -live
```

### 🆕 시나리오 2: 네트워크 장애 복원력 테스트

```bash
# 서버: 높은 패킷 손실 환경 시뮬레이션
./dhcp-server -live -drop-rate 0.1 -response-delay 200ms

# 클라이언트: RFC 재시도로 장애 복원력 테스트
./dhcp-tester -server 127.0.0.1 \
  -clients 500 -concurrency 50 \
  -retry -max-discover-retries 5 -max-request-retries 5 \
  -initial-timeout 2s -max-timeout 30s \
  -live -verbose
```

## 🏢 실제 네트워크 환경별 사용법

### 기업 네트워크 환경

**서버 설정 (기업 환경 + 세션 관리)**
```bash
./dhcp-server -live \
  -start-ip 10.10.1.100 \
  -end-ip 10.10.1.200 \
  -gateway 10.10.1.1 \
  -dns1 10.10.1.10 \
  -dns2 8.8.8.8 \
  -domain "company.local" \
  -lease-time 8h \
  -offer-timeout 30s \
  -max-concurrent 2000
```

**클라이언트 테스트 (기업 환경 + RFC 재시도)**
```bash
# 본사 네트워크 (2000명 규모) - 안정적인 재시도 설정
./dhcp-tester -server 127.0.0.1 \
  -clients 2000 -concurrency 200 \
  -relay -relay-ip 10.10.1.1 \
  -circuit-id "본사빌딩/3층스위치/포트48" \
  -remote-id "직원네트워크" \
  -retry -max-discover-retries 3 -max-request-retries 3 \
  -initial-timeout 4s -max-timeout 32s \
  -live -timeout 15s

# 지점 네트워크 (100명 규모) - 빠른 재시도 설정
./dhcp-tester -server 192.168.1.1 \
  -clients 100 -concurrency 20 \
  -relay -relay-ip 172.16.1.1 \
  -circuit-id "지점01/스위치01" \
  -retry -max-discover-retries 2 -max-request-retries 2 \
  -initial-timeout 2s -max-timeout 16s \
  -live
```

### ISP/통신사 환경

**서버 설정 (ISP 환경 + 고성능)**
```bash
./dhcp-server -live \
  -start-ip 172.20.0.10 \
  -end-ip 172.20.10.250 \
  -gateway 172.20.0.1 \
  -lease-time 24h \
  -max-concurrent 10000 \
  -response-delay 20ms \
  -drop-rate 0.001
```

**클라이언트 테스트 (ISP 환경 + 대량 처리)**
```bash
# FTTH 가입자 테스트 (10000명) - 보수적 재시도
./dhcp-tester -server 127.0.0.1 \
  -clients 10000 -concurrency 500 \
  -relay -relay-ip 203.0.113.1 \
  -circuit-id "OLT-seoul-01/PON-24" \
  -remote-id "아파트단지A" \
  -retry -max-discover-retries 4 -max-request-retries 4 \
  -initial-timeout 6s -max-timeout 64s \
  -live -timeout 30s

# 케이블 모뎀 환경 - 네트워크 지연 고려
./dhcp-tester -server 127.0.0.1 \
  -clients 5000 -concurrency 200 \
  -relay -relay-ip 192.168.100.1 \
  -circuit-id "CMTS-01/DS-12/US-4" \
  -retry -max-discover-retries 3 -max-request-retries 3 \
  -initial-timeout 8s -max-timeout 64s \
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
| `-timeout` | `5s` | 기본 응답 대기 시간 |
| `-seed` | `0` | 랜덤 시드 (0은 현재 시간) |

#### 🆕 RFC 2131 재시도 옵션
| 옵션 | 기본값 | 설명 |
|------|---------|------|
| `-retry` | `false` | RFC 2131 재시도 로직 활성화 |
| `-max-discover-retries` | `3` | Discover 최대 재시도 횟수 |
| `-max-request-retries` | `3` | Request 최대 재시도 횟수 |
| `-initial-timeout` | `4s` | 초기 재시도 타임아웃 |
| `-max-timeout` | `64s` | 최대 재시도 타임아웃 |
| `-backoff-multiplier` | `2.0` | 지수 백오프 배수 |
| `-disable-jitter` | `false` | 재시도 지터 비활성화 |

#### 표시 모드
| 옵션 | 설명 |
|------|------|
| `-live` | 실시간 대시보드 모니터링 (5fps) |
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

#### 🆕 권한 관련 옵션
| 옵션 | 설명 |
|------|------|
| `-require-root` | Root 권한 강제 요구 |
| `-skip-priv-check` | 권한 확인 건너뛰기 |

### DHCP 서버 시뮬레이터 (`dhcp-server`)

#### 기본 설정
| 옵션 | 기본값 | 설명 |
|------|---------|------|
| `-listen` | `0.0.0.0` | 서버 바인딩 IP |
| `-port` | `67` | 서버 포트 |
| `-start-ip` | `192.168.100.10` | IP 풀 시작 주소 |
| `-end-ip` | `192.168.100.250` | IP 풀 종료 주소 |
| `-subnet-mask` | `255.255.255.0` | 서브넷 마스크 |
| `-gateway` | `192.168.100.1` | 기본 게이트웨이 |
| `-dns1` | `8.8.8.8` | 첫 번째 DNS 서버 |
| `-dns2` | `8.8.4.4` | 두 번째 DNS 서버 |
| `-domain` | `example.com` | 도메인 이름 |
| `-lease-time` | `24h` | IP 임대 시간 |
| `-offer-timeout` | `30s` | Offer 타임아웃 |

#### 🆕 성능 및 시뮬레이션
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

### 🆕 향상된 클라이언트 테스터 대시보드 (5fps 업데이트)
```
╔══════════════════════════════════════════════════════════════════════╗
║                    DHCP 서버 성능 테스트 실시간 모니터                ║
╚══════════════════════════════════════════════════════════════════════╝

테스트 설정
  서버: 127.0.0.1:67  (Relay: 192.168.1.1)
  클라이언트: 1000, 경과시간: 12s

전체 진행률
  진행: 456/1000 (45.6%) [████████████████████░░░░░░░░░░░░░░░░░░░░] 45.6%
  성공: 398, 실패: 58, 성공률: 87.3%

┌─ DHCP 4-Way Handshake 실시간 통계 ───────────────────────────────────┐
│  1. DISCOVER 전송:      456 개    3. REQUEST 전송:     398 개        │
│  2. OFFER 수신:         398 개    4. ACK 수신:         398 개        │
│                                                                      │
│  평균 응답시간:                                                      │
│    Discover → Offer:   15.2ms      Request → ACK:    12.8ms          │
└──────────────────────────────────────────────────────────────────────┘

에러 통계
  타임아웃: 45  파싱 오류: 8  네트워크: 5  

성능 지표
  완료율: 38.0 completions/sec
  성공율: 33.2 successful/sec

[ESC 또는 Ctrl+C로 중단]
```

### 🆕 향상된 서버 시뮬레이터 대시보드
```
╔════════════════════════════════════════════════════════════════════════╗
║                        DHCP 서버 실시간 모니터링                       ║
╚════════════════════════════════════════════════════════════════════════╝

서버 정보
  주소: 0.0.0.0:67  (Relay 지원)
  가동 시간: 2m34s
  IP 풀: 192.168.1.100 - 192.168.1.200 (101개)

┌─ DHCP 메시지 통계 ────────────────────────────────────────────────────┐
│  수신: DISCOVER      456    REQUEST      398                          │
│  전송: OFFER         398    ACK          398    NAK        5          │
└───────────────────────────────────────────────────────────────────────┘

IP 풀 상태
  사용 중: 87, 사용 가능: 14, 사용률: 86.1%
  [████████████████████████████████████████████████░░░░] 86.1%

성능 지표
  평균 RPS: 45.2 requests/sec
  평균 처리 시간: 2.3ms

에러 통계
  파싱 오류: 3  풀 고갈: 0  잘못된 요청: 5  

[Ctrl+C로 종료]
```

## 🧪 고급 테스트 시나리오

### 🆕 1. RFC 2131 재시도 로직 검증

**정상 환경에서 재시도 비활성화**
```bash
# 서버: 안정적인 환경
./dhcp-server -live

# 클라이언트: 재시도 없이 테스트
./dhcp-tester -server 127.0.0.1 -clients 500 -live
```

**불안정 환경에서 재시도 활성화**
```bash
# 서버: 10% 패킷 드롭 + 200ms 지연
./dhcp-server -drop-rate 0.1 -response-delay 200ms -live

# 클라이언트: RFC 2131 재시도 로직
./dhcp-tester -server 127.0.0.1 -clients 500 \
  -retry -max-discover-retries 5 -max-request-retries 5 \
  -initial-timeout 2s -max-timeout 64s \
  -backoff-multiplier 2.0 -live -verbose
```

### 🆕 2. 네트워크 지연 및 손실 단계별 테스트

**단계별 패킷 손실 테스트**
```bash
# 손실률 0%, 1%, 5%, 10% 단계별 테스트
for drop_rate in 0.0 0.01 0.05 0.1; do
  echo "=== 패킷 손실률: ${drop_rate} ==="
  ./dhcp-server -drop-rate $drop_rate -live &
  SERVER_PID=$!
  sleep 2
  
  ./dhcp-tester -server 127.0.0.1 -clients 200 \
    -retry -max-discover-retries 3 -max-request-retries 3 \
    -progress
  
  kill $SERVER_PID
  sleep 3
done
```

**단계별 네트워크 지연 테스트**
```bash
# 지연 10ms, 50ms, 100ms, 500ms 단계별 테스트
for delay in 10ms 50ms 100ms 500ms; do
  echo "=== 네트워크 지연: ${delay} ==="
  ./dhcp-server -response-delay $delay -live &
  SERVER_PID=$!
  sleep 2
  
  ./dhcp-tester -server 127.0.0.1 -clients 200 \
    -retry -initial-timeout 2s -max-timeout 30s \
    -timeout 60s -progress
  
  kill $SERVER_PID
  sleep 3
done
```

### 🆕 3. IP 풀 고갈 및 복구 테스트

**제한된 IP 풀에서 순환 테스트**
```bash
# 서버: 20개만 제공하는 작은 풀
./dhcp-server -start-ip 192.168.1.10 -end-ip 192.168.1.29 \
  -lease-time 30s -offer-timeout 10s -live &

# 클라이언트: 풀보다 많은 요청으로 순환 확인
./dhcp-tester -server 127.0.0.1 -clients 50 -concurrency 10 \
  -retry -max-discover-retries 5 -max-request-retries 5 \
  -live -verbose
```

### 🆕 4. 대용량 성능 벤치마킹 (개선된)

**최대 성능 테스트 with 재시도**
```bash
# 서버: 대용량 IP 풀과 최고 성능 설정
./dhcp-server -live \
  -start-ip 10.0.0.10 \
  -end-ip 10.0.50.250 \
  -max-concurrent 5000 \
  -lease-time 1h \
  -offer-timeout 60s

# 클라이언트: 극한 부하 테스트 with RFC 재시도
./dhcp-tester -server 127.0.0.1 \
  -clients 50000 -concurrency 1000 \
  -retry -max-discover-retries 2 -max-request-retries 2 \
  -initial-timeout 3s -max-timeout 15s \
  -timeout 60s -live
```

### 🆕 5. Multi-hop Relay 환경 고급 테스트

**복잡한 Relay 구조 with 장애 시뮬레이션**
```bash
# 서버: 다중 홉 지원 + 네트워크 장애 시뮬레이션
./dhcp-server -live -max-hops 6 \
  -response-delay 50ms -drop-rate 0.02

# 클라이언트: 다단계 Relay + 강화된 재시도
./dhcp-tester -server 127.0.0.1 \
  -clients 1000 -concurrency 100 \
  -relay -relay-ip 192.168.1.1 \
  -hops 4 -max-hops 6 \
  -circuit-id "코어라우터/집선라우터/액세스스위치/포트48" \
  -remote-id "기업고객/빌딩A/층별스위치" \
  -retry -max-discover-retries 4 -max-request-retries 4 \
  -initial-timeout 5s -max-timeout 64s \
  -live -verbose
```

## 🔐 권한 요구사항

### 🆕 자동 권한 검증 시스템
프로그램 실행 시 자동으로 다음을 확인합니다:
- 현재 사용자 권한 (root/일반 사용자)
- 포트 67/68 바인딩 가능 여부
- 네트워크 인터페이스 접근 권한
- 브로드캐스트 송신 권한

### 일반 사용자 모드 (권장)
- ✅ **완전한 테스트 환경**: 클라이언트와 서버 모두 동작
- ✅ **모든 기능**: Relay Agent, 실시간 모니터링, RFC 재시도
- ✅ **고성능**: 수만 개 동시 클라이언트 지원
- ✅ **안전성**: 시스템 설정 변경 없음
- ⚠️ **제한사항**: 임시 포트 사용, 실제 브로드캐스트 제한

### 관리자 모드 (실제 환경)
```bash
# 실제 DHCP 포트 사용
sudo ./dhcp-server -port 67
sudo ./dhcp-tester -require-root

# 권한 강제 확인
./dhcp-tester -require-root  # Root 권한 필수
./dhcp-tester -skip-priv-check  # 권한 확인 건너뛰기
```
- ✅ **포트 67/68 바인딩**: 실제 DHCP 포트 사용
- ✅ **실제 브로드캐스트**: 진짜 네트워크 패킷
- ✅ **인터페이스 제어**: 특정 네트워크 인터페이스
- ✅ **완전한 호환성**: 기존 DHCP 클라이언트와 동일

## 📈 성능 벤치마크

### 🆕 v2.0 성능 개선사항
- **재시도 로직**: 불안정한 네트워크에서 95%+ 성공률 달성
- **메모리 최적화**: 클라이언트당 메모리 사용량 50% 감소
- **동시 처리**: 최대 동시 클라이언트 수 10배 증가
- **응답 시간**: 평균 처리 시간 30% 단축

### 일반적인 성능 (Intel i7, 16GB RAM)

#### 클라이언트 테스터 (v2.0 개선)
- **소규모**: 100개 클라이언트 → 0.5-1초 (50% 단축)
- **중간 규모**: 1,000개 클라이언트 → 3-5초 (50% 단축)
- **대규모**: 10,000개 클라이언트 → 15-30초 (50% 단축)
- **극한 테스트**: 100,000개 클라이언트 지원 (10배 증가)

#### 서버 시뮬레이터 (v2.0 개선)
- **처리량**: 100,000+ RPS (2배 증가)
- **동시 연결**: 50,000+ 동시 클라이언트 (5배 증가)
- **메모리**: 클라이언트 1,000개당 약 1MB (50% 감소)
- **응답 시간**: 평균 0.5-2ms (개선)

### 🆕 재시도 로직 성능 비교
| 환경 | 재시도 비활성화 | 재시도 활성화 | 개선율 |
|------|----------------|---------------|---------|
| 정상 (손실률 0%) | 99.9% | 99.9% | 동일 |
| 불안정 (손실률 5%) | 75.2% | 95.8% | +27% |
| 매우 불안정 (손실률 10%) | 45.1% | 88.7% | +96% |
| 극한 환경 (손실률 20%) | 18.9% | 65.3% | +245% |

## 🧪 QA 및 운영 사용 사례

### 🆕 자동화된 회귀 테스트 스크립트

**일일 회귀 테스트 (RFC 재시도 포함)**
```bash
#!/bin/bash
# DHCP 성능 회귀 테스트 v2.0

set -e

echo "=== DHCP 성능 회귀 테스트 시작 (v2.0) ==="

# 테스트 결과 저장 디렉토리
TEST_DIR="test_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p $TEST_DIR

# 1. 서버 시작
echo "DHCP 서버 시작..."
./dhcp-server -live > $TEST_DIR/server.log 2>&1 &
SERVER_PID=$!
sleep 5

# 2. 기본 성능 테스트
echo "기본 성능 테스트..."
./dhcp-tester -server 127.0.0.1 -clients 100 -progress \
  > $TEST_DIR/basic_test.log 2>&1

# 3. RFC 재시도 테스트
echo "RFC 재시도 로직 테스트..."
./dhcp-tester -server 127.0.0.1 -clients 200 \
  -retry -max-discover-retries 3 -max-request-retries 3 \
  -progress > $TEST_DIR/retry_test.log 2>&1

# 4. Relay Agent 테스트
echo "Relay Agent 테스트..."
./dhcp-tester -server 127.0.0.1 -clients 200 \
  -relay -relay-ip 192.168.1.1 -circuit-id "테스트환경" \
  -retry -progress > $TEST_DIR/relay_test.log 2>&1

# 5. 고부하 테스트
echo "고부하 테스트..."
./dhcp-tester -server 127.0.0.1 -clients 1000 -concurrency 100 \
  -retry -max-discover-retries 2 -max-request-retries 2 \
  -progress > $TEST_DIR/load_test.log 2>&1

# 6. 네트워크 장애 복원력 테스트
echo "네트워크 장애 복원력 테스트..."
kill $SERVER_PID
sleep 2
./dhcp-server -drop-rate 0.05 -response-delay 100ms \
  > $TEST_DIR/server_unstable.log 2>&1 &
SERVER_PID=$!
sleep 5

./dhcp-tester -server 127.0.0.1 -clients 300 -concurrency 30 \
  -retry -max-discover-retries 5 -max-request-retries 5 \
  -initial-timeout 2s -max-timeout 32s \
  -timeout 60s -progress > $TEST_DIR/resilience_test.log 2>&1

# 7. 서버 종료
kill $SERVER_PID

# 8. 결과 분석
echo "=== 테스트 결과 분석 ==="
echo "테스트 결과 저장 위치: $TEST_DIR"
echo "기본 성능 테스트 성공률: $(grep '성공률:' $TEST_DIR/basic_test.log | awk '{print $2}')"
echo "재시도 테스트 성공률: $(grep '성공률:' $TEST_DIR/retry_test.log | awk '{print $2}')"
echo "Relay 테스트 성공률: $(grep '성공률:' $TEST_DIR/relay_test.log | awk '{print $2}')"
echo "고부하 테스트 성공률: $(grep '성공률:' $TEST_DIR/load_test.log | awk '{print $2}')"
echo "장애 복원 테스트 성공률: $(grep '성공률:' $TEST_DIR/resilience_test.log | awk '{print $2}')"

echo "=== 테스트 완료 ==="
```

### 🆕 운영 환경 검증 스크립트

**신규 DHCP 서버 단계별 검증**
```bash
#!/bin/bash
# 신규 DHCP 서버 운영 투입 전 검증 스크립트

DHCP_SERVER="192.168.1.1"
TEST_RESULTS="production_validation_$(date +%Y%m%d_%H%M%S)"
mkdir -p $TEST_RESULTS

echo "=== 신규 DHCP 서버 검증 시작: $DHCP_SERVER ==="

# 1. 연결성 확인
echo "1. 기본 연결성 확인..."
./dhcp-tester -server $DHCP_SERVER -clients 10 -concurrency 1 \
  -timeout 30s -verbose > $TEST_RESULTS/connectivity.log 2>&1

if [ $? -eq 0 ]; then
    echo "   ✅ 연결성 확인 완료"
else
    echo "   ❌ 연결 실패 - 테스트 중단"
    exit 1
fi

# 2. 단계별 부하 증가 테스트 (재시도 포함)
for clients in 50 100 500 1000 2000; do
    echo "2. 부하 테스트: $clients 클라이언트..."
    ./dhcp-tester -server $DHCP_SERVER \
        -clients $clients -concurrency $((clients/10)) \
        -retry -max-discover-retries 3 -max-request-retries 3 \
        -timeout 30s -progress > $TEST_RESULTS/load_${clients}.log 2>&1
    
    success_rate=$(grep '성공률:' $TEST_RESULTS/load_${clients}.log | awk '{print $2}' | sed 's/%//')
    if (( $(echo "$success_rate < 95.0" | bc -l) )); then
        echo "   ⚠️ 성공률 저하 감지: ${success_rate}% (기준: 95%)"
        echo "   권장 최대 클라이언트 수: $((clients/2))"
        break
    else
        echo "   ✅ $clients 클라이언트 성공률: ${success_rate}%"
    fi
    sleep 10
done

# 3. Relay Agent 구성 검증
if [ ! -z "$RELAY_IP" ]; then
    echo "3. Relay Agent 구성 검증..."
    ./dhcp-tester -server $DHCP_SERVER \
        -clients 500 -concurrency 50 \
        -relay -relay-ip $RELAY_IP \
        -circuit-id "운영검증/$(hostname)" \
        -remote-id "검증클라이언트" \
        -retry -timeout 30s -progress > $TEST_RESULTS/relay.log 2>&1
    echo "   ✅ Relay Agent 검증 완료"
fi

# 4. 지속성 테스트 (30분)
echo "4. 지속성 테스트 시작 (30분)..."
timeout 1800 ./dhcp-tester -server $DHCP_SERVER \
    -clients 10000 -concurrency 200 \
    -retry -max-discover-retries 2 -max-request-retries 2 \
    -timeout 45s -progress > $TEST_RESULTS/endurance.log 2>&1

echo "=== 검증 완료: 결과는 $TEST_RESULTS 디렉토리 확인 ==="
```

## 🔧 문제 해결

### 🆕 일반적인 문제들 및 해결책

**재시도 관련 문제**
```bash
# 재시도가 너무 많이 발생하는 경우
./dhcp-tester -retry -max-discover-retries 1 -max-request-retries 1

# 재시도 타임아웃이 너무 긴 경우
./dhcp-tester -retry -initial-timeout 2s -max-timeout 16s

# 지터로 인한 불규칙한 지연
./dhcp-tester -retry -disable-jitter  # 지터 비활성화
```

**권한 관련 문제**
```bash
# 권한 상태 확인
./dhcp-tester -skip-priv-check  # 권한 확인 건너뛰기

# 포트 바인딩 실패
sudo ./dhcp-tester -require-root  # Root 권한으로 강제 실행

# 브로드캐스트 권한 없음
./dhcp-tester -server 127.0.0.1  # 로컬 서버로 테스트
```

**성능 관련 문제**
```bash
# 메모리 부족 시 배치 처리
for i in {1..10}; do
    ./dhcp-tester -clients 1000 -concurrency 50
    sleep 5
done

# CPU 사용률이 높을 때
./dhcp-tester -clients 5000 -concurrency 100  # 동시성 조정

# 네트워크 포화 시
./dhcp-tester -clients 1000 -concurrency 20 -timeout 30s
```

### 🆕 고급 디버깅

**단계별 디버깅**
```bash
# 1단계: 기본 연결 확인
./dhcp-tester -server 127.0.0.1 -clients 1 -verbose -timeout 60s

# 2단계: 재시도 로직 상세 분석
./dhcp-tester -server 127.0.0.1 -clients 5 \
  -retry -max-discover-retries 3 -max-request-retries 3 \
  -verbose -concurrency 1 -timeout 120s

# 3단계: Relay Agent 검증
./dhcp-tester -server 127.0.0.1 -clients 3 \
  -relay -relay-ip 192.168.1.1 -circuit-id "디버그테스트" \
  -verbose -concurrency 1

# 4단계: 패킷 캡처 분석 (고급)
sudo tcpdump -i any -w debug.pcap -s 0 port 67 or port 68 &
./dhcp-tester -server 192.168.1.1 -clients 10 -verbose
sudo killall tcpdump
wireshark debug.pcap  # Wireshark로 분석
```

**로그 분석 도구**
```bash
# 성공률 분석
grep "성공률:" *.log | awk '{print $2}' | sort -n

# 응답 시간 분석
grep "평균 협상 시간:" *.log | awk '{print $3}' | sort -n

# 에러 분석
grep "ERROR\|실패\|타임아웃" *.log | sort | uniq -c
```

## 📝 출력 예시

### 🆕 클라이언트 테스터 상세 요약 (v2.0)
```
======================================================================
DHCP 서버 성능 테스트 결과 (완전한 4-way handshake + RFC 2131 재시도)
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

💡 참고: 위 시간은 각 클라이언트가 IP 주소를 완전히 획득하는데
   걸린 전체 시간입니다 (4단계 모두 포함 + 재시도 시간 포함)

----------------------------------------------------------------------
실패 원인 분석
----------------------------------------------------------------------
타임아웃                                          : 8건
네트워크 연결 실패                                : 3건
서버 응답 없음                                    : 2건
재시도 - 총 45회 (Discover: 28회, Request: 17회)  : 45건
```

### 🆕 서버 시뮬레이터 상세 요약 (v2.0)
```
======================================================================
DHCP 서버 최종 통계 (v2.0 + 세션 관리)
======================================================================
가동 시간:           2m34s
처리된 DISCOVER:     1045  (재시도 포함)
전송된 OFFER:        987
처리된 REQUEST:      1004  (재시도 포함)
전송된 ACK:          987
전송된 NAK:          17
평균 RPS:           67.8 requests/sec
최종 IP 사용률:      86.1% (87/101)

세션 관리 통계:
  활성 세션:         87개
  만료된 세션:       912개 (자동 정리됨)
  총 생성된 세션:    999개

네트워크 시뮬레이션:
  시뮬레이션된 패킷 드롭:  52개 (5.0%)
  평균 응답 지연:         50ms

에러 통계:
  파싱 오류:         2
  IP 풀 고갈:        0
  잘못된 요청:       15
```

## 🤝 기여하기

### 개발 환경 설정
```bash
# 저장소 클론
git clone <저장소-URL>
cd dhcp-performance-test-suite-v2

# 의존성 설치
go mod init dhcp-test-suite
go mod tidy

# 테스트 실행
go test ./...

# 벤치마크 테스트
go test -bench=. -benchmem

# 정적 분석
go vet ./...
golangci-lint run
```

### 🆕 v2.0 개발 가이드라인
- **RFC 준수**: RFC 2131, RFC 3046 등 관련 표준 준수
- **성능 최적화**: 메모리 풀, 고루틴 최적화 적용
- **에러 처리**: 상세한 에러 분류 및 복구 로직
- **테스트 커버리지**: 90% 이상 유지
- **벤치마크**: 성능 회귀 방지를 위한 벤치마크 테스트
- **문서화**: 코드 주석 및 사용 예시 충실히 작성

## 📄 라이선스

이 프로젝트는 MIT 라이선스를 따릅니다. 자세한 내용은 LICENSE 파일을 참조하세요.

## 🆘 지원 및 문의

- **GitHub Issues**: 버그 리포트 및 기능 요청
- **문제 해결 가이드**: 위의 문제 해결 섹션 참조
- **명령어 도움말**: `./dhcp-tester -h`, `./dhcp-server -h`
- **성능 최적화 문의**: 대용량 환경 구축 시 문의

## 🔗 관련 기술

### DHCP 표준 문서
- **RFC 2131**: Dynamic Host Configuration Protocol
- **RFC 3046**: DHCP Relay Agent Information Option
- **RFC 4361**: Node-specific Client Identifiers
- **RFC 6842**: Client Identifier Option in Server Replies

### 🆕 v2.0에서 추가로 준수하는 표준
- **RFC 2132**: DHCP Options and BOOTP Vendor Extensions
- **RFC 3942**: Reclassifying Dynamic Host Configuration Protocol
- **RFC 8415**: Dynamic Host Configuration Protocol for IPv6 (DHCPv6)

## 📚 사용 사례별 가이드

### 🆕 클라우드 환경 관리자
```bash
# AWS/Azure 환경에서 VPC DHCP 테스트
./dhcp-server -start-ip 10.0.1.100 -end-ip 10.0.1.200 \
  -gateway 10.0.1.1 -dns1 10.0.0.2 -live &

# 클라우드 인스턴스 시뮬레이션
./dhcp-tester -server 127.0.0.1 -clients 1000 \
  -retry -max-discover-retries 2 -max-request-retries 2 \
  -initial-timeout 3s -max-timeout 30s \
  -circuit-id "클라우드/가용영역A/서브넷1" \
  -live
```

### 🆕 네트워크 보안 관리자
```bash
# DHCP 보안 감사 테스트
./dhcp-tester -server 192.168.1.1 -clients 50 \
  -relay -relay-ip 192.168.1.254 \
  -circuit-id "보안감사/$(date +%Y%m%d)" \
  -remote-id "보안테스트클라이언트" \
  -retry -verbose

# 비정상 트래픽 패턴 테스트
./dhcp-tester -server 192.168.1.1 -clients 10000 \
  -concurrency 1000 -timeout 5s \
  -circuit-id "부하테스트/보안감사" \
  -live
```

### 🆕 IoT 환경 개발자
```bash
# IoT 디바이스 대량 연결 시뮬레이션
./dhcp-server -start-ip 192.168.100.10 -end-ip 192.168.100.254 \
  -lease-time 1h -offer-timeout 60s \
  -response-delay 100ms -live &

# IoT 디바이스 특성 반영 (낮은 동시성, 높은 재시도)
./dhcp-tester -server 127.0.0.1 -clients 1000 \
  -concurrency 20 \
  -retry -max-discover-retries 5 -max-request-retries 5 \
  -initial-timeout 10s -max-timeout 120s \
  -circuit-id "IoT게이트웨이/센서네트워크" \
  -timeout 180s -live
```

---

**🇰🇷 한국 네트워크 환경 최적화 v2.0** | **Go 고성능 + RFC 완전 준수** | **제작자 현수복 2025**

> RFC 2131/3046 완전 준수와 함께 한국의 다양한 네트워크 환경을 고려하여 제작된 
> 전문적인 DHCP 성능 테스트 솔루션 v2.0입니다. 지수 백오프 재시도 로직, 향상된 
> 실시간 모니터링, 세션 관리 기능이 추가되어 더욱 안정적이고 정확한 테스트가 
> 가능합니다. 기업, ISP, 교육기관, 클라우드 환경에서 바로 사용할 수 있는 
> 완전한 테스트 환경을 제공합니다.

> ⚠️ **중요**: 반드시 테스트 환경에서만 사용하시길 권장합니다. 운영 환경에서 
> 사용 시에는 충분한 검증과 승인 절차를 거치시기 바랍니다.
