# FAQ 및 자주 묻는 질문

## 📋 목차
1. [설치 및 설정 관련](#1-설치-및-설정-관련)
2. [권한 및 보안 관련](#2-권한-및-보안-관련)
3. [성능 및 최적화 관련](#3-성능-및-최적화-관련)
4. [네트워크 및 연결 관련](#4-네트워크-및-연결-관련)
5. [Relay Agent 관련](#5-relay-agent-관련)
6. [재시도 로직 관련](#6-재시도-로직-관련)
7. [에러 및 트러블슈팅](#7-에러-및-트러블슈팅)
8. [운영 환경 관련](#8-운영-환경-관련)

## 1. 설치 및 설정 관련

### Q1.1: Go 컴파일 시 "module not found" 에러가 발생합니다.

**문제**: `go build` 실행 시 모듈을 찾을 수 없다는 에러가 발생

**해결책**:
```bash
# 1. Go 모듈 초기화
go mod init dhcp-test-suite

# 2. 필요한 의존성 자동 다운로드
go mod tidy

# 3. 다시 빌드
go build -o dhcp-tester dhcp-tester.go
go build -o dhcp-server dhcp-server.go
```

**추가 정보**: Go 1.16 이상에서는 모듈 모드가 기본값이므로, 반드시 `go.mod` 파일이 필요합니다.

### Q1.2: 빌드는 성공했는데 실행 파일이 너무 큽니다.

**문제**: 빌드된 바이너리 파일이 50MB 이상의 큰 크기

**해결책**:
```bash
# 최적화 빌드 (크기 축소)
go build -ldflags="-s -w" -o dhcp-tester dhcp-tester.go
go build -ldflags="-s -w" -o dhcp-server dhcp-server.go

# 추가 압축 (UPX 사용, 선택적)
upx --best dhcp-tester dhcp-server
```

**설명**:
- `-s`: 심볼 테이블 제거
- `-w`: DWARF 디버깅 정보 제거  
- `upx`: 실행 파일 압축 도구

### Q1.3: 크로스 컴파일 시 에러가 발생합니다.

**문제**: 다른 플랫폼용 빌드 시 네트워크 관련 에러

**해결책**:
```bash
# CGO 비활성화하여 순수 Go 바이너리 생성
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dhcp-tester-linux dhcp-tester.go
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o dhcp-tester.exe dhcp-tester.go

# 네트워크 태그 추가
go build -tags netgo -o dhcp-tester dhcp-tester.go
```

## 2. 권한 및 보안 관련

### Q2.1: "Permission denied" 에러가 계속 발생합니다.

**문제**: 포트 67/68 바인딩 시 권한 에러

**해결책**:

**방법 1: 관리자 권한 사용**
```bash
sudo ./dhcp-server
sudo ./dhcp-tester -require-root
```

**방법 2: 권한 없이 테스트**
```bash
# 다른 포트 사용
./dhcp-server -port 6700
./dhcp-tester -server 127.0.0.1 -port 6700

# 권한 확인 건너뛰기
./dhcp-tester -skip-priv-check
```

**방법 3: 사용자 권한 부여 (Linux)**
```bash
# 특정 사용자에게 raw socket 권한 부여
sudo setcap CAP_NET_RAW+ep ./dhcp-server
sudo setcap CAP_NET_BIND_SERVICE+ep ./dhcp-server
```

### Q2.2: 방화벽 때문에 테스트가 실패합니다.

**문제**: 방화벽이 DHCP 트래픽을 차단

**해결책**:

**Ubuntu/Debian (UFW)**:
```bash
sudo ufw allow 67/udp
sudo ufw allow 68/udp
# 또는 특정 IP에서만
sudo ufw allow from 192.168.1.0/24 to any port 67 proto udp
```

**CentOS/RHEL (firewalld)**:
```bash
sudo firewall-cmd --add-service=dhcp --permanent
sudo firewall-cmd --reload
# 또는 포트 직접 허용
sudo firewall-cmd --add-port=67/udp --permanent
sudo firewall-cmd --add-port=68/udp --permanent
```

**Windows**:
```powershell
# PowerShell 관리자 권한으로 실행
New-NetFirewallRule -DisplayName "DHCP Server" -Direction Inbound -Protocol UDP -LocalPort 67
New-NetFirewallRule -DisplayName "DHCP Client" -Direction Inbound -Protocol UDP -LocalPort 68
```

### Q2.3: 일반 사용자로도 모든 기능을 사용할 수 있나요?

**답변**: 예, 대부분의 기능은 일반 사용자 권한으로 사용 가능합니다.

**일반 사용자로 가능한 기능**:
- ✅ 완전한 DHCP 테스트 (시뮬레이션 모드)
- ✅ Relay Agent 테스트  
- ✅ 재시도 로직 테스트
- ✅ 실시간 모니터링
- ✅ 성능 벤치마킹

**관리자 권한이 필요한 기능**:
- 🔒 포트 67/68 직접 바인딩
- 🔒 실제 브로드캐스트 송신
- 🔒 로우 소켓 접근

## 3. 성능 및 최적화 관련

### Q3.1: 성능이 예상보다 낮습니다. 어떻게 개선할 수 있나요?

**일반적인 성능 개선 방법**:

**1. 동시성 조정**:
```bash
# CPU 코어 수에 맞춰 동시성 설정
CORES=$(nproc)
CONCURRENCY=$((CORES * 20))
./dhcp-tester -clients 5000 -concurrency $CONCURRENCY
```

**2. 시스템 리소스 최적화**:
```bash
# 네트워크 버퍼 크기 증가
echo 'net.core.rmem_max = 16777216' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 16777216' >> /etc/sysctl.conf
sysctl -p

# 파일 디스크립터 제한 증가
ulimit -n 65536
```

**3. Go 런타임 최적화**:
```bash
export GOMAXPROCS=$(nproc)
export GOGC=100
export GOMEMLIMIT=4GiB
```

### Q3.2: 메모리 사용량이 계속 증가합니다.

**문제**: 장시간 실행 시 메모리 누수 의심

**진단 방법**:
```bash
# 메모리 사용량 모니터링
ps -p $(pgrep dhcp-server) -o pid,rss,vsz,%mem,cmd

# Go 프로파일링 활성화
./dhcp-server -live &
go tool pprof http://localhost:6060/debug/pprof/heap
```

**해결책**:
```bash
# 1. 가비지 컬렉션 강제 실행 주기 단축
export GOGC=50

# 2. 메모리 제한 설정
export GOMEMLIMIT=2GiB

# 3. 주기적 재시작 설정
# systemd 서비스에서 RuntimeMaxSec 설정
RuntimeMaxSec=24h
```

### Q3.3: 높은 동시성 설정 시 에러가 발생합니다.

**문제**: `-concurrency 1000` 이상 설정 시 "too many open files" 에러

**해결책**:
```bash
# 1. 파일 디스크립터 제한 확인
ulimit -n

# 2. 제한 증가 (임시)
ulimit -n 65536

# 3. 영구 설정 변경
echo '* soft nofile 65536' >> /etc/security/limits.conf
echo '* hard nofile 65536' >> /etc/security/limits.conf

# 4. systemd 서비스에서 설정
[Service]
LimitNOFILE=65536
```

## 4. 네트워크 및 연결 관련

### Q4.1: "Connection refused" 에러가 발생합니다.

**문제**: DHCP 서버에 연결할 수 없음

**단계별 해결**:

**1. 서버 상태 확인**:
```bash
# 프로세스 확인
ps aux | grep dhcp-server

# 포트 바인딩 확인  
netstat -ulnp | grep :67
```

**2. 네트워크 연결 테스트**:
```bash
# UDP 연결 테스트
nc -u -z 127.0.0.1 67

# 다른 머신에서 테스트
nc -u -z [서버IP] 67
```

**3. 방화벽 확인**:
```bash
# 방화벽 상태 확인
sudo ufw status
sudo firewall-cmd --list-all
```

### Q4.2: 원격 DHCP 서버 테스트가 실패합니다.

**문제**: 다른 네트워크의 DHCP 서버 테스트 시 실패

**해결책**:

**1. 네트워크 경로 확인**:
```bash
# 경로 추적
traceroute [DHCP서버IP]

# 핑 테스트
ping [DHCP서버IP]
```

**2. 타임아웃 조정**:
```bash
# 원격 환경에서는 타임아웃 증가
./dhcp-tester -server [원격IP] -timeout 30s -retry \
  -initial-timeout 10s -max-timeout 60s
```

**3. 중간 라우터/방화벽 확인**:
- 중간 네트워크 장비의 DHCP 트래픽 차단 여부 확인
- VPN 환경에서는 UDP 포워딩 설정 확인

### Q4.3: IPv6 환경에서 사용할 수 있나요?

**현재 상태**: v2.0은 IPv4 전용이지만, IPv6 지원은 로드맵에 포함되어 있습니다.

**대안**:
```bash
# IPv4 mapped IPv6 주소 사용 (제한적)
./dhcp-tester -server ::ffff:192.168.1.1

# 듀얼 스택 환경에서 IPv4 강제 사용
./dhcp-tester -server 192.168.1.1 -timeout 30s
```

## 5. Relay Agent 관련

### Q5.1: Relay Agent 테스트 시 응답이 없습니다.

**문제**: Relay 설정 시 DHCP 서버로부터 응답이 없음

**확인사항**:

**1. 서버의 Relay 지원 확인**:
```bash
# 서버에서 Relay 지원 활성화
./dhcp-server -relay=true -max-hops 4 -verbose
```

**2. Relay IP 설정 확인**:
```bash
# 올바른 Relay IP 사용
./dhcp-tester -server [실제DHCP서버IP] \
  -relay -relay-ip [실제Relay라우터IP] \
  -verbose
```

**3. 네트워크 토폴로지 확인**:
- Relay Agent가 실제 존재하는지 확인
- DHCP 서버가 해당 Relay IP를 신뢰하는지 확인

### Q5.2: Option 82 정보가 제대로 전달되지 않습니다.

**문제**: Circuit ID, Remote ID가 서버에서 인식되지 않음

**해결책**:

**1. 상세 로그 확인**:
```bash
./dhcp-tester -server 127.0.0.1 \
  -relay -relay-ip 192.168.1.1 \
  -circuit-id "빌딩A/플로어3/스위치24/포트8" \
  -remote-id "사용자ID_12345" \
  -verbose
```

**2. 서버 측 Option 82 처리 확인**:
```bash
# 서버에서 Relay 정보 로깅 활성화
./dhcp-server -verbose -live
```

**3. 패킷 캡처로 검증**:
```bash
# Option 82 데이터 확인
sudo tcpdump -i any -w relay-test.pcap port 67 or port 68
# Wireshark에서 DHCP 옵션 확인
```

### Q5.3: 다중 홉 Relay 환경을 테스트하고 싶습니다.

**설정 예시**:
```bash
# 3홉 Relay 시뮬레이션
./dhcp-tester -server [최종DHCP서버IP] \
  -relay -relay-ip [마지막Relay라우터IP] \
  -hops 3 -max-hops 6 \
  -circuit-id "코어라우터/집선라우터/액세스스위치/포트" \
  -remote-id "지점A/빌딩B/층3" \
  -retry -timeout 60s -verbose
```

## 6. 재시도 로직 관련

### Q6.1: 재시도 기능이 작동하지 않습니다.

**문제**: `-retry` 옵션을 사용했는데 재시도가 발생하지 않음

**확인사항**:

**1. 재시도 활성화 확인**:
```bash
# 올바른 재시도 설정
./dhcp-tester -server 127.0.0.1 \
  -retry -max-discover-retries 3 -max-request-retries 3 \
  -verbose
```

**2. 재시도가 필요한 환경 생성**:
```bash
# 서버에서 패킷 손실 시뮬레이션
./dhcp-server -drop-rate 0.1 -response-delay 200ms

# 또는 짧은 타임아웃으로 재시도 유발
./dhcp-tester -server 127.0.0.1 -retry \
  -initial-timeout 1s -max-timeout 8s
```

### Q6.2: 재시도 시간이 너무 오래 걸립니다.

**문제**: 지수 백오프로 인해 재시도 간격이 너무 김

**해결책**:
```bash
# 재시도 간격 조정
./dhcp-tester -server 127.0.0.1 -retry \
  -initial-timeout 2s \
  -max-timeout 16s \
  -backoff-multiplier 1.5 \
  -disable-jitter
```

**파라미터 설명**:
- `initial-timeout`: 첫 번째 타임아웃 (기본: 4초)
- `max-timeout`: 최대 타임아웃 (기본: 64초)  
- `backoff-multiplier`: 증가 배수 (기본: 2.0)
- `disable-jitter`: 랜덤 지연 비활성화

### Q6.3: 재시도 통계를 확인하고 싶습니다.

**방법**:
```bash
# 상세 재시도 정보 출력
./dhcp-tester -server 127.0.0.1 -retry \
  -max-discover-retries 5 -max-request-retries 5 \
  -verbose -clients 100
```

**출력 예시**:
```
재시도 - 총 45회 (Discover: 28회, Request: 17회)  : 45건
```

## 7. 에러 및 트러블슈팅

### Q7.1: "패킷이 너무 짧습니다" 에러가 발생합니다.

**문제**: DHCP 패킷 파싱 시 길이 부족 에러

**원인 및 해결**:
```bash
# 1. 네트워크 MTU 확인
ip link show | grep mtu

# 2. 서버에서 패킷 크기 확인
./dhcp-server -verbose

# 3. 네트워크 장비의 패킷 변조 확인
sudo tcpdump -i any -s 1500 port 67 or port 68
```

### Q7.2: "잘못된 Transaction ID" 에러가 자주 발생합니다.

**문제**: 다른 클라이언트의 응답을 받는 상황

**해결책**:
```bash
# 1. 동시성 감소
./dhcp-tester -clients 1000 -concurrency 50

# 2. 더 고유한 클라이언트 식별자 사용
./dhcp-tester -seed 12345 -clients 500

# 3. 순차 실행으로 격리
./dhcp-tester -clients 10 -concurrency 1 -verbose
```

### Q7.3: 메모리 부족 에러가 발생합니다.

**문제**: 대량 클라이언트 테스트 시 OOM (Out of Memory)

**해결책**:
```bash
# 1. 배치 처리로 분할
for i in {1..10}; do
  ./dhcp-tester -clients 1000 -concurrency 50
  sleep 10
done

# 2. 메모리 제한 설정
export GOMEMLIMIT=2GiB
./dhcp-tester -clients 5000 -concurrency 100

# 3. 시스템 스왑 활성화
sudo swapon /swapfile
```

### Q7.4: "context deadline exceeded" 에러가 발생합니다.

**문제**: 타임아웃으로 인한 컨텍스트 취소

**해결책**:
```bash
# 전체 타임아웃 증가
./dhcp-tester -timeout 120s -clients 1000

# 재시도 타임아웃도 함께 조정
./dhcp-tester -timeout 120s -retry \
  -initial-timeout 10s -max-timeout 60s
```

## 8. 운영 환경 관련

### Q8.1: 운영 DHCP 서버를 테스트해도 안전한가요?

**주의사항**:
- ✅ **읽기 전용 테스트**: 기존 임대에 영향 없음
- ⚠️ **대량 테스트**: 서버 부하 증가 가능
- ❌ **IP 풀 고갈**: 실제 클라이언트가 IP를 받지 못할 수 있음

**안전한 테스트 방법**:
```bash
# 1. 소규모 테스트로 시작
./dhcp-tester -server [운영서버] -clients 10 -timeout 30s

# 2. 점진적 증가
./dhcp-tester -server [운영서버] -clients 50 -concurrency 5

# 3. 비즈니스 시간 외 테스트
# 새벽 시간대 또는 주말에 실행

# 4. 테스트 전용 IP 대역 사용 (가능한 경우)
```

### Q8.2: 프로덕션 환경에서 지속적인 모니터링을 하고 싶습니다.

**모니터링 설정**:
```bash
# 1. 주기적 헬스체크
crontab -e
*/5 * * * * /opt/dhcp-test/health-check.sh

# 2. 성능 벤치마크 (일일)
0 2 * * * /opt/dhcp-test/daily-benchmark.sh

# 3. 알림 설정
# Slack, 이메일 등과 연동
```

**권장 모니터링 주기**:
- **헬스체크**: 5분마다
- **성능 테스트**: 일일 1회 (새벽)
- **부하 테스트**: 주간 1회
- **종합 분석**: 월간 1회

### Q8.3: 여러 DHCP 서버를 동시에 테스트할 수 있나요?

**병렬 테스트 방법**:
```bash
#!/bin/bash
# 여러 서버 동시 테스트

SERVERS=("192.168.1.1" "192.168.2.1" "192.168.3.1")

for server in "${SERVERS[@]}"; do
  echo "테스트 시작: $server"
  
  ./dhcp-tester -server $server \
    -clients 200 -concurrency 20 \
    -progress > "test-${server}.log" 2>&1 &
done

# 모든 테스트 완료 대기
wait

# 결과 집계
for server in "${SERVERS[@]}"; do
  echo "=== $server 결과 ==="
  grep -E "성공률|평균.*시간" "test-${server}.log"
done
```

### Q8.4: 테스트 결과를 자동으로 보고서로 만들 수 있나요?

**자동 보고서 생성**:
```bash
#!/bin/bash
# 자동 보고서 생성 스크립트

DATE=$(date +%Y%m%d)
REPORT_FILE="dhcp-performance-report-${DATE}.html"

# HTML 보고서 생성
cat > $REPORT_FILE << EOF
<!DOCTYPE html>
<html>
<head>
    <title>DHCP 성능 테스트 보고서 - $DATE</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .success { color: green; }
        .warning { color: orange; }
        .error { color: red; }
    </style>
</head>
<body>
    <h1>DHCP 성능 테스트 보고서</h1>
    <p>생성 시간: $(date)</p>
EOF

# 테스트 실행 및 결과 추가
./dhcp-tester -server 127.0.0.1 -clients 500 \
  -progress > temp-result.log 2>&1

# 결과를 HTML에 추가
echo "<h2>테스트 결과</h2>" >> $REPORT_FILE
echo "<pre>" >> $REPORT_FILE
cat temp-result.log >> $REPORT_FILE
echo "</pre>" >> $REPORT_FILE

echo "</body></html>" >> $REPORT_FILE

echo "보고서 생성 완료: $REPORT_FILE"
```

## 🆘 추가 도움말

### 로그 수준별 확인 방법

**기본 정보만 확인**:
```bash
./dhcp-tester -progress
```

**상세 진행 과정 확인**:
```bash
./dhcp-tester -verbose
```

**실시간 모니터링**:
```bash
./dhcp-tester -live
```

**디버그 레벨**:
```bash
./dhcp-tester -verbose -retry -timeout 60s
```

### 성능 문제 진단 체크리스트

1. **시스템 리소스**
   - [ ] CPU 사용률 < 80%
   - [ ] 메모리 여유 공간 > 2GB
   - [ ] 디스크 여유 공간 > 1GB
   - [ ] 네트워크 대역폭 충분

2. **네트워크 설정**
   - [ ] 방화벽 규칙 확인
   - [ ] MTU 크기 적절
   - [ ] 라우팅 테이블 확인
   - [ ] DNS 설정 확인

3. **애플리케이션 설정**
   - [ ] 타임아웃 값 적절
   - [ ] 동시성 설정 최적화
   - [ ] 재시도 설정 적절
   - [ ] 로그 레벨 적절

### 문의 및 지원

**GitHub Issues**: 버그 리포트 및 기능 요청
- 문제 재현 단계 포함
- 시스템 환경 정보 포함
- 에러 로그 첨부

**문서 참조 순서**:
1. 이 FAQ 문서
2. README.md의 문제 해결 섹션
3. 기술명세서의 개발자 가이드
4. 운영 및 트러블슈팅 가이드

**성능 최적화 문의 시 포함할 정보**:
- 시스템 사양 (CPU, 메모리, 네트워크)
- 테스트 규모 (클라이언트 수, 동시성)
- 현재 성능 지표
- 목표 성능 지표
- 네트워크 환경 (LAN, WAN, 지연시간)

---

**💡 팁**: 이 FAQ에서 해결되지 않는 문제는 `-verbose` 옵션으로 상세 로그를 확인한 후, 해당 로그와 함께 GitHub Issues에 문의해 주세요.

**🔧 디버깅 도움**: `./dhcp-tester -verbose -retry -timeout 60s` 조합으로 대부분의 문제를 진단할 수 있습니다.