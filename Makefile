# DHCP 테스트 스위트 Makefile

# 기본 설정
GO = go
BINARY_DIR = bin
CLIENT_BINARY = $(BINARY_DIR)/dhcp-tester
SERVER_BINARY = $(BINARY_DIR)/dhcp-server

# 소스 파일
CLIENT_SRC = dhcp-tester.go
SERVER_SRC = dhcp-server.go

# 기본 타겟
.PHONY: all clean build client server test install help

all: build

# 빌드 디렉토리 생성
$(BINARY_DIR):
	mkdir -p $(BINARY_DIR)

# 클라이언트 테스터 빌드
client: $(BINARY_DIR)
	$(GO) build -o $(CLIENT_BINARY) $(CLIENT_SRC)
	@echo "✅ DHCP 클라이언트 테스터 빌드 완료: $(CLIENT_BINARY)"

# 서버 시뮬레이터 빌드
server: $(BINARY_DIR)
	$(GO) build -o $(SERVER_BINARY) $(SERVER_SRC)
	@echo "✅ DHCP 서버 시뮬레이터 빌드 완료: $(SERVER_BINARY)"

# 모든 바이너리 빌드
build: client server
	@echo "🎉 모든 바이너리 빌드 완료!"
	@echo "   클라이언트: $(CLIENT_BINARY)"
	@echo "   서버: $(SERVER_BINARY)"

# 플랫폼별 크로스 컴파일
build-linux: $(BINARY_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build -o $(CLIENT_BINARY)-linux $(CLIENT_SRC)
	GOOS=linux GOARCH=amd64 $(GO) build -o $(SERVER_BINARY)-linux $(SERVER_SRC)
	@echo "✅ Linux용 바이너리 빌드 완료"

build-windows: $(BINARY_DIR)
	GOOS=windows GOARCH=amd64 $(GO) build -o $(CLIENT_BINARY).exe $(CLIENT_SRC)
	GOOS=windows GOARCH=amd64 $(GO) build -o $(SERVER_BINARY).exe $(SERVER_SRC)
	@echo "✅ Windows용 바이너리 빌드 완료"

build-mac: $(BINARY_DIR)
	GOOS=darwin GOARCH=amd64 $(GO) build -o $(CLIENT_BINARY)-mac $(CLIENT_SRC)
	GOOS=darwin GOARCH=amd64 $(GO) build -o $(SERVER_BINARY)-mac $(SERVER_SRC)
	@echo "✅ macOS용 바이너리 빌드 완료"

# 모든 플랫폼용 빌드
build-all: build-linux build-windows build-mac
	@echo "🌍 모든 플랫폼용 빌드 완료!"

# 테스트 실행
test:
	$(GO) test -v ./...
	@echo "✅ 테스트 완료"

# 코드 검사
lint:
	$(GO) fmt ./...
	$(GO) vet ./...
	@echo "✅ 코드 검사 완료"

# 시스템에 설치 (Linux/macOS)
install: build
	@if [ -w /usr/local/bin ]; then \
		cp $(CLIENT_BINARY) /usr/local/bin/dhcp-tester; \
		cp $(SERVER_BINARY) /usr/local/bin/dhcp-server; \
		echo "✅ /usr/local/bin에 설치 완료"; \
	else \
		echo "❌ /usr/local/bin에 쓰기 권한이 없습니다. sudo make install을 시도하세요."; \
	fi

# 관리자 권한으로 설치
install-sudo: build
	sudo cp $(CLIENT_BINARY) /usr/local/bin/dhcp-tester
	sudo cp $(SERVER_BINARY) /usr/local/bin/dhcp-server
	sudo chmod +x /usr/local/bin/dhcp-tester
	sudo chmod +x /usr/local/bin/dhcp-server
	@echo "✅ 시스템에 설치 완료 (관리자 권한)"

# 빌드 결과물 정리
clean:
	rm -rf $(BINARY_DIR)
	@echo "🧹 빌드 결과물 정리 완료"

# 의존성 정리
tidy:
	$(GO) mod tidy
	@echo "✅ Go 모듈 의존성 정리 완료"

# 빠른 테스트 실행
quick-test: build
	@echo "🚀 빠른 테스트 실행..."
	@echo "1. 서버 시작 (백그라운드)"
	./$(SERVER_BINARY) -live > server.log 2>&1 &
	@echo $$! > server.pid
	@sleep 3
	@echo "2. 클라이언트 테스트"
	./$(CLIENT_BINARY) -server 127.0.0.1 -clients 10 -progress
	@echo "3. 서버 종료"
	@kill `cat server.pid` 2>/dev/null || true
	@rm -f server.pid server.log
	@echo "✅ 빠른 테스트 완료"

# 개발 환경 설정
dev-setup:
	$(GO) mod init dhcp-test-suite 2>/dev/null || true
	$(GO) mod tidy
	@echo "✅ 개발 환경 설정 완료"

# 도움말
help:
	@echo "DHCP 테스트 스위트 빌드 도구"
	@echo ""
	@echo "사용법:"
	@echo "  make [target]"
	@echo ""
	@echo "주요 타겟:"
	@echo "  build        - 모든 바이너리 빌드"
	@echo "  client       - 클라이언트 테스터만 빌드"
	@echo "  server       - 서버 시뮬레이터만 빌드"
	@echo "  build-all    - 모든 플랫폼용 빌드"
	@echo "  test         - 테스트 실행"
	@echo "  quick-test   - 빠른 통합 테스트"
	@echo "  install      - 시스템에 설치"
	@echo "  clean        - 빌드 결과물 정리"
	@echo "  dev-setup    - 개발 환경 초기 설정"
	@echo "  help         - 이 도움말 표시"
	@echo ""
	@echo "플랫폼별 빌드:"
	@echo "  build-linux  - Linux용 빌드"
	@echo "  build-windows- Windows용 빌드"
	@echo "  build-mac    - macOS용 빌드"
	@echo ""
	@echo "예시:"
	@echo "  make build           # 기본 빌드"
	@echo "  make quick-test      # 빠른 테스트"
	@echo "  make build-all       # 모든 플랫폼"
	@echo "  make install-sudo    # 시스템 설치"
