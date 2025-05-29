#!/bin/bash

# DHCP 테스트 스위트 빌드 스크립트
# 사용법: ./build.sh [옵션]

set -e

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 설정
BINARY_DIR="bin"
CLIENT_SRC="dhcp-tester.go"
SERVER_SRC="dhcp-server.go"
CLIENT_BINARY="$BINARY_DIR/dhcp-tester"
SERVER_BINARY="$BINARY_DIR/dhcp-server"

# 로그 함수
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# 도움말 함수
show_help() {
    echo "DHCP 테스트 스위트 빌드 스크립트"
    echo ""
    echo "사용법: $0 [옵션]"
    echo ""
    echo "옵션:"
    echo "  -h, --help       이 도움말 표시"
    echo "  -c, --client     클라이언트 테스터만 빌드"
    echo "  -s, --server     서버 시뮬레이터만 빌드"
    echo "  -a, --all        모든 플랫폼용 빌드"
    echo "  -t, --test       빌드 후 빠른 테스트 실행"
    echo "  -i, --install    시스템에 설치"
    echo "  --clean          빌드 결과물 정리"
    echo ""
    echo "예시:"
    echo "  $0               # 기본 빌드 (클라이언트 + 서버)"
    echo "  $0 -c            # 클라이언트만 빌드"
    echo "  $0 -a            # 모든 플랫폼용 빌드"
    echo "  $0 -t            # 빌드 + 테스트"
}

# Go 설치 확인
check_go() {
    if ! command -v go &> /dev/null; then
        log_error "Go가 설치되어 있지 않습니다. https://golang.org/dl/ 에서 설치하세요."
        exit 1
    fi
    
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    log_info "Go 버전: $GO_VERSION"
}

# Go 모듈 초기화
init_module() {
    if [ ! -f "go.mod" ]; then
        log_info "Go 모듈 초기화 중..."
        go mod init dhcp-test-suite
        log_success "Go 모듈 초기화 완료"
    fi
    
    go mod tidy
}

# 빌드 디렉토리 생성
create_bin_dir() {
    if [ ! -d "$BINARY_DIR" ]; then
        mkdir -p "$BINARY_DIR"
        log_info "빌드 디렉토리 생성: $BINARY_DIR"
    fi
}

# 소스 파일 확인
check_source_files() {
    if [ ! -f "$CLIENT_SRC" ]; then
        log_error "클라이언트 소스 파일을 찾을 수 없습니다: $CLIENT_SRC"
        exit 1
    fi
    
    if [ ! -f "$SERVER_SRC" ]; then
        log_error "서버 소스 파일을 찾을 수 없습니다: $SERVER_SRC"
        exit 1
    fi
}

# 클라이언트 빌드
build_client() {
    log_info "DHCP 클라이언트 테스터 빌드 중..."
    go build -o "$CLIENT_BINARY" "$CLIENT_SRC"
    log_success "클라이언트 빌드 완료: $CLIENT_BINARY"
}

# 서버 빌드
build_server() {
    log_info "DHCP 서버 시뮬레이터 빌드 중..."
    go build -o "$SERVER_BINARY" "$SERVER_SRC"
    log_success "서버 빌드 완료: $SERVER_BINARY"
}

# 플랫폼별 빌드
build_platform() {
    local os=$1
    local arch=$2
    local suffix=$3
    
    log_info "$os/$arch 빌드 중..."
    
    GOOS=$os GOARCH=$arch go build -o "${CLIENT_BINARY}${suffix}" "$CLIENT_SRC"
    GOOS=$os GOARCH=$arch go build -o "${SERVER_BINARY}${suffix}" "$SERVER_SRC"
    
    log_success "$os/$arch 빌드 완료"
}

# 모든 플랫폼 빌드
build_all_platforms() {
    log_info "모든 플랫폼용 빌드 시작..."
    
    # Linux
    build_platform "linux" "amd64" "-linux"
    
    # Windows
    build_platform "windows" "amd64" ".exe"
    
    # macOS
    build_platform "darwin" "amd64" "-mac"
    
    # ARM64 (M1 Mac)
    if [[ $(go version) == *"go1.16"* ]] || [[ $(go version) > *"go1.16"* ]]; then
        build_platform "darwin" "arm64" "-mac-arm64"
        build_platform "linux" "arm64" "-linux-arm64"
    fi
    
    log_success "모든 플랫폼 빌드 완료!"
    echo ""
    echo "빌드된 파일들:"
    ls -la "$BINARY_DIR"/*
}

# 빠른 테스트
quick_test() {
    log_info "빠른 통합 테스트 실행 중..."
    
    # 서버 시작 (백그라운드)
    log_info "테스트 서버 시작..."
    ./"$SERVER_BINARY" > server.log 2>&1 &
    SERVER_PID=$!
    echo $SERVER_PID > server.pid
    
    # 서버 시작 대기
    sleep 3
    
    # 클라이언트 테스트
    log_info "클라이언트 테스트 실행..."
    if ./"$CLIENT_BINARY" -server 127.0.0.1 -clients 10 -progress; then
        log_success "테스트 성공!"
    else
        log_error "테스트 실패!"
    fi
    
    # 서버 종료
    log_info "테스트 서버 종료..."
    kill $SERVER_PID 2>/dev/null || true
    rm -f server.pid server.log
    
    log_success "빠른 테스트 완료"
}

# 시스템 설치
install_system() {
    if [ ! -f "$CLIENT_BINARY" ] || [ ! -f "$SERVER_BINARY" ]; then
        log_error "설치할 바이너리가 없습니다. 먼저 빌드를 실행하세요."
        exit 1
    fi
    
    INSTALL_DIR="/usr/local/bin"
    
    if [ -w "$INSTALL_DIR" ]; then
        cp "$CLIENT_BINARY" "$INSTALL_DIR/dhcp-tester"
        cp "$SERVER_BINARY" "$INSTALL_DIR/dhcp-server"
        chmod +x "$INSTALL_DIR/dhcp-tester"
        chmod +x "$INSTALL_DIR/dhcp-server"
        log_success "$INSTALL_DIR에 설치 완료"
    else
        log_warning "$INSTALL_DIR에 쓰기 권한이 없습니다."
        log_info "sudo를 사용하여 설치 중..."
        sudo cp "$CLIENT_BINARY" "$INSTALL_DIR/dhcp-tester"
        sudo cp "$SERVER_BINARY" "$INSTALL_DIR/dhcp-server"
        sudo chmod +x "$INSTALL_DIR/dhcp-tester"
        sudo chmod +x "$INSTALL_DIR/dhcp-server"
        log_success "관리자 권한으로 설치 완료"
    fi
}

# 정리
clean() {
    log_info "빌드 결과물 정리 중..."
    rm -rf "$BINARY_DIR"
    rm -f server.pid server.log
    log_success "정리 완료"
}

# 메인 함수
main() {
    # 인수 파싱
    BUILD_CLIENT=false
    BUILD_SERVER=false
    BUILD_ALL=false
    RUN_TEST=false
    INSTALL=false
    CLEAN=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -c|--client)
                BUILD_CLIENT=true
                shift
                ;;
            -s|--server)
                BUILD_SERVER=true
                shift
                ;;
            -a|--all)
                BUILD_ALL=true
                shift
                ;;
            -t|--test)
                RUN_TEST=true
                shift
                ;;
            -i|--install)
                INSTALL=true
                shift
                ;;
            --clean)
                CLEAN=true
                shift
                ;;
            *)
                log_error "알 수 없는 옵션: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # 정리만 하는 경우
    if [ "$CLEAN" = true ]; then
        clean
        exit 0
    fi
    
    # 환경 확인
    check_go
    init_module
    create_bin_dir
    check_source_files
    
    # 빌드 실행
    if [ "$BUILD_ALL" = true ]; then
        build_all_platforms
    elif [ "$BUILD_CLIENT" = true ] && [ "$BUILD_SERVER" = false ]; then
        build_client
    elif [ "$BUILD_SERVER" = true ] && [ "$BUILD_CLIENT" = false ]; then
        build_server
    else
        # 기본값: 클라이언트와 서버 모두 빌드
        build_client
        build_server
        log_success "모든 바이너리 빌드 완료!"
    fi
    
    # 테스트 실행
    if [ "$RUN_TEST" = true ]; then
        quick_test
    fi
    
    # 시스템 설치
    if [ "$INSTALL" = true ]; then
        install_system
    fi
    
    echo ""
    log_success "모든 작업 완료!"
    echo ""
    echo "사용법:"
    echo "  ./$CLIENT_BINARY -h    # 클라이언트 도움말"
    echo "  ./$SERVER_BINARY -h    # 서버 도움말"
    echo ""
    echo "빠른 시작:"
    echo "  ./$SERVER_BINARY -live &"
    echo "  ./$CLIENT_BINARY -server 127.0.0.1 -clients 10 -live"
}

# 스크립트 실행
main "$@"
