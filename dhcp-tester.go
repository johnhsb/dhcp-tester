package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/user"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DHCP 메시지 타입
const (
	DHCPDiscover = 1
	DHCPOffer    = 2
	DHCPRequest  = 3
	DHCPAck      = 5
)

// DHCP 옵션 코드
const (
	DHCPMessageType       = 53
	DHCPClientID          = 61
	DHCPRequestedIP       = 50
	DHCPServerID          = 54
	DHCPLeaseTime         = 51
	DHCPRelayAgentInfo    = 82
	DHCPEnd               = 255
)

// Relay Agent Sub-options
const (
	RelayAgentCircuitID = 1
	RelayAgentRemoteID  = 2
)

// 테스트 모드 정의
type TestMode int

const (
	TestModeSimulation TestMode = iota
	TestModeRealistic
	TestModeBroadcast
)

// 보안 이벤트 타입
type SecurityEventType int

const (
	SecurityEventRateLimit SecurityEventType = iota
	SecurityEventInvalidMAC
	SecurityEventDuplicateXID
	SecurityEventSuspiciousPattern
)

// === 보안 강화: Rate Limiter ===
type RateLimiter struct {
	requests map[string][]time.Time
	mutex    sync.RWMutex
	maxRate  int
	window   time.Duration
}

func NewRateLimiter(maxRate int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string][]time.Time),
		maxRate:  maxRate,
		window:   window,
	}
}

func (rl *RateLimiter) IsAllowed(clientID string) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()
	
	now := time.Now()
	requests, exists := rl.requests[clientID]
	if !exists {
		requests = make([]time.Time, 0)
	}
	
	// 오래된 요청 기록 제거
	var validRequests []time.Time
	for _, reqTime := range requests {
		if now.Sub(reqTime) <= rl.window {
			validRequests = append(validRequests, reqTime)
		}
	}
	
	// 요청 제한 확인
	if len(validRequests) >= rl.maxRate {
		return false
	}
	
	// 새 요청 기록 추가
	validRequests = append(validRequests, now)
	rl.requests[clientID] = validRequests
	
	return true
}

func (rl *RateLimiter) GetStats() map[string]int {
	rl.mutex.RLock()
	defer rl.mutex.RUnlock()
	
	stats := make(map[string]int)
	now := time.Now()
	
	for clientID, requests := range rl.requests {
		activeRequests := 0
		for _, reqTime := range requests {
			if now.Sub(reqTime) <= rl.window {
				activeRequests++
			}
		}
		if activeRequests > 0 {
			stats[clientID] = activeRequests
		}
	}
	
	return stats
}

// === 보안 강화: 보안 로거 ===
type SecurityLogger struct {
	logFile   *os.File
	events    []SecurityEvent
	mutex     sync.Mutex
	enabled   bool
}

type SecurityEvent struct {
	Timestamp time.Time           `json:"timestamp"`
	Type      SecurityEventType   `json:"type"`
	ClientID  string             `json:"client_id"`
	Details   map[string]interface{} `json:"details"`
	Severity  string             `json:"severity"`
}

func NewSecurityLogger(filename string) *SecurityLogger {
	if filename == "" {
		return &SecurityLogger{enabled: false}
	}
	
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Printf("보안 로그 파일 생성 실패: %v", err)
		return &SecurityLogger{enabled: false}
	}
	
	return &SecurityLogger{
		logFile: file,
		events:  make([]SecurityEvent, 0),
		enabled: true,
	}
}

func (sl *SecurityLogger) LogEvent(eventType SecurityEventType, clientID string, details map[string]interface{}) {
	if !sl.enabled {
		return
	}
	
	event := SecurityEvent{
		Timestamp: time.Now().UTC(),
		Type:      eventType,
		ClientID:  clientID,
		Details:   details,
		Severity:  sl.getSeverity(eventType),
	}
	
	sl.mutex.Lock()
	defer sl.mutex.Unlock()
	
	sl.events = append(sl.events, event)
	
	// 파일에 JSON 형태로 기록
	if sl.logFile != nil {
		jsonData, _ := json.Marshal(event)
		sl.logFile.Write(jsonData)
		sl.logFile.WriteString("\n")
		sl.logFile.Sync()
	}
}

func (sl *SecurityLogger) getSeverity(eventType SecurityEventType) string {
	switch eventType {
	case SecurityEventRateLimit:
		return "MEDIUM"
	case SecurityEventInvalidMAC:
		return "HIGH"
	case SecurityEventDuplicateXID:
		return "HIGH"
	case SecurityEventSuspiciousPattern:
		return "CRITICAL"
	default:
		return "LOW"
	}
}

func (sl *SecurityLogger) Close() {
	if sl.enabled && sl.logFile != nil {
		sl.logFile.Close()
	}
}

// === 성능 최적화: 패킷 풀 ===
type PacketPool struct {
	pool sync.Pool
}

func NewPacketPool() *PacketPool {
	return &PacketPool{
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 1500) // MTU 크기
			},
		},
	}
}

func (pp *PacketPool) Get() []byte {
	return pp.pool.Get().([]byte)
}

func (pp *PacketPool) Put(packet []byte) {
	if cap(packet) == 1500 {
		pp.pool.Put(packet[:0]) // 길이를 0으로 리셋
	}
}

// === 성능 최적화: 워커 풀 ===
type WorkerPool struct {
	workerCount int
	jobQueue    chan func()
	quit        chan bool
	wg          sync.WaitGroup
	running     int64
}

func NewWorkerPool(workerCount int, queueSize int) *WorkerPool {
	return &WorkerPool{
		workerCount: workerCount,
		jobQueue:    make(chan func(), queueSize),
		quit:        make(chan bool),
	}
}

func (wp *WorkerPool) Start() {
	for i := 0; i < wp.workerCount; i++ {
		wp.wg.Add(1)
		go wp.worker()
	}
	atomic.StoreInt64(&wp.running, 1)
}

func (wp *WorkerPool) worker() {
	defer wp.wg.Done()
	for {
		select {
		case job := <-wp.jobQueue:
			job()
		case <-wp.quit:
			return
		}
	}
}

func (wp *WorkerPool) Submit(job func()) bool {
	if atomic.LoadInt64(&wp.running) == 0 {
		return false
	}
	
	select {
	case wp.jobQueue <- job:
		return true
	default:
		return false // 큐가 가득 함
	}
}

func (wp *WorkerPool) Stop() {
	// 이미 정지된 상태라면 리턴
	if atomic.LoadInt64(&wp.running) == 0 {
		return
	}
	
	atomic.StoreInt64(&wp.running, 0)
	
	// 채널이 이미 닫혔는지 확인하고 닫기
	select {
	case <-wp.quit:
		// 이미 닫힌 채널
		return
	default:
		close(wp.quit)
	}
	
	wp.wg.Wait()
}

func (wp *WorkerPool) GetStats() (queueSize int, isRunning bool) {
	return len(wp.jobQueue), atomic.LoadInt64(&wp.running) == 1
}

// === 성능 최적화: 연결 풀 ===
type ConnectionPool struct {
	connections chan *net.UDPConn
	serverAddr  *net.UDPAddr
	mutex       sync.Mutex
	maxSize     int
	timeout     time.Duration
}

func NewConnectionPool(serverAddr *net.UDPAddr, maxSize int, timeout time.Duration) *ConnectionPool {
	return &ConnectionPool{
		connections: make(chan *net.UDPConn, maxSize),
		serverAddr:  serverAddr,
		maxSize:     maxSize,
		timeout:     timeout,
	}
}

func (cp *ConnectionPool) Get() (*net.UDPConn, error) {
	select {
	case conn := <-cp.connections:
		return conn, nil
	default:
		// 새 연결 생성
		conn, err := net.DialTimeout("udp", cp.serverAddr.String(), cp.timeout)
		if err != nil {
			return nil, err
		}
		udpConn, ok := conn.(*net.UDPConn)
		if !ok {
			conn.Close()
			return nil, fmt.Errorf("connection is not UDP")
		}
		return udpConn, nil
	}
}

func (cp *ConnectionPool) Put(conn *net.UDPConn) {
	if conn == nil {
		return
	}
	
	select {
	case cp.connections <- conn:
		// 풀에 반환 성공
	default:
		// 풀이 가득 참, 연결 종료
		conn.Close()
	}
}

func (cp *ConnectionPool) Close() {
	close(cp.connections)
	for conn := range cp.connections {
		conn.Close()
	}
}

// DHCP 패킷 구조체
type DHCPPacket struct {
	Op      uint8
	HType   uint8
	HLen    uint8
	Hops    uint8
	Xid     uint32
	Secs    uint16
	Flags   uint16
	Ciaddr  [4]byte
	Yiaddr  [4]byte
	Siaddr  [4]byte
	Giaddr  [4]byte
	Chaddr  [16]byte
	Sname   [64]byte
	File    [128]byte
	Options []byte
}

// 테스트 결과 구조체 (개선됨)
type TestResult struct {
	ClientID      string
	Success       bool
	ResponseTime  time.Duration
	Error         string
	Timestamp     time.Time
	RelayUsed     bool
	
	// DHCP 과정 상세 정보
	DiscoverTime  time.Duration
	OfferTime     time.Duration
	RequestTime   time.Duration
	AckTime       time.Duration
	OfferedIP     string
	ServerID      string
	
	// 재시도 및 보안 통계
	DiscoverRetries int
	RequestRetries  int
	TotalRetries    int
	SecurityBlocked bool
	RateLimited     bool
	
	// 성능 메트릭
	PacketHash      string
	ConnectionReused bool
	MemoryUsed      int64
}

// 재시도 설정 구조체
type RetryConfig struct {
	Enabled           bool
	MaxDiscoverRetries int
	MaxRequestRetries  int
	InitialTimeout    time.Duration
	MaxTimeout        time.Duration
	BackoffMultiplier float64
	Jitter            bool
}

// Relay Agent 설정 구조체
type RelayConfig struct {
	Enabled      bool
	RelayIP      string
	CircuitID    string
	RemoteID     string
	HopCount     uint8
	MaxHops      uint8
}

// 보안 설정 구조체
type SecurityConfig struct {
	Enabled          bool
	RateLimitEnabled bool
	MaxRequestsPerMinute int
	MACValidation    bool
	DuplicateXIDCheck bool
	LogSecurityEvents bool
	LogFile          string
}

// 성능 설정 구조체
type PerformanceConfig struct {
	PacketPoolEnabled    bool
	WorkerPoolSize       int
	ConnectionPoolSize   int
	ConnectionReuse      bool
	MemoryOptimization   bool
	CacheEnabled         bool
}

// 통계 정보 구조체 (확장됨)
type Statistics struct {
	TotalRequests     int64
	SuccessfulRequests int64
	FailedRequests    int64
	SuccessRate       float64
	TotalTime         time.Duration
	RequestsPerSecond float64
	
	MinResponseTime    time.Duration
	MaxResponseTime    time.Duration
	AvgResponseTime    time.Duration
	MedianResponseTime time.Duration
	P95ResponseTime    time.Duration
	P99ResponseTime    time.Duration
	
	ErrorCounts map[string]int64
	RelayTests  int64
	
	// 보안 통계
	SecurityBlocked   int64
	RateLimited      int64
	InvalidMACs      int64
	DuplicateXIDs    int64
	
	// 성능 통계
	PacketPoolHits    int64
	PacketPoolMisses  int64
	ConnectionReused  int64
	MemoryAllocated   int64
	CacheHits        int64
	CacheMisses      int64
}

// 실시간 통계 구조체 (확장됨)
type LiveStats struct {
	// 패킷 카운터 (atomic)
	DiscoverSent    int64
	OfferReceived   int64
	RequestSent     int64
	AckReceived     int64
	
	// 보안 카운터 (atomic)
	SecurityBlocked int64
	RateLimited    int64
	
	// 성능 카운터 (atomic)
	PoolHits       int64
	PoolMisses     int64
	
	// 응답 시간 누적
	mutex           sync.RWMutex
	DiscoverOfferTimes []time.Duration
	RequestAckTimes    []time.Duration
	
	// 에러 카운터
	TimeoutErrors   int64
	ParsingErrors   int64
	NetworkErrors   int64
}

// DHCP 테스터 구조체 (대폭 개선됨)
type DHCPTester struct {
	serverIP     string
	serverPort   int
	clientPort   int
	timeout      time.Duration
	results      []TestResult
	resultsMutex sync.Mutex
	
	// 기존 설정
	relayConfig  *RelayConfig
	retryConfig  *RetryConfig
	testMode     TestMode
	verbose      bool
	showLiveStats bool
	liveStats    *LiveStats
	
	// 새로운 보안 및 성능 구성요소
	securityConfig   *SecurityConfig
	performanceConfig *PerformanceConfig
	rateLimiter      *RateLimiter
	securityLogger   *SecurityLogger
	packetPool       *PacketPool
	workerPool       *WorkerPool
	connectionPool   *ConnectionPool
	
	// 캐시 및 중복 검사
	xidCache         map[uint32]bool
	xidCacheMutex    sync.RWMutex
	packetCache      map[string]*DHCPPacket
	packetCacheMutex sync.RWMutex
	
	// 통계 카운터 (atomic 연산용)
	totalCount   int64
	successCount int64
	failureCount int64
	
	// 성능 메트릭
	startTime    time.Time
	memoryUsage  int64
}

// MAC 주소 검증 함수
func isValidMACAddress(mac [6]byte) bool {
	// 브로드캐스트 MAC 거부
	if bytes.Equal(mac[:], []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) {
		return false
	}
	
	// 모든 0인 MAC 거부
	if bytes.Equal(mac[:], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) {
		return false
	}
	
	// 멀티캐스트 비트 확인 (첫 번째 바이트의 최하위 비트)
	if mac[0]&0x01 != 0 {
		return false
	}
	
	return true
}

// 패킷 해시 생성
func generatePacketHash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:8])
}

// 권한 확인 함수
func checkPrivileges() {
	currentUser, err := user.Current()
	if err != nil {
		fmt.Printf("⚠️  사용자 정보를 확인할 수 없습니다: %v\n", err)
		return
	}
	
	if currentUser.Uid == "0" {
		fmt.Printf("✅ Root 권한으로 실행 중 - 모든 기능 사용 가능\n")
	} else {
		fmt.Printf("ℹ️  일반 사용자로 실행 중 (%s)\n", currentUser.Username)
		fmt.Printf("   - 기본 성능 테스트: 가능\n")
		fmt.Printf("   - 실제 브로드캐스트: 제한적\n")
		fmt.Printf("   - 포트 68 바인딩: 불가능\n")
		fmt.Printf("   💡 더 정확한 테스트를 원하면 'sudo %s'로 실행하세요\n", os.Args[0])
	}
	fmt.Println()
}

// 포트 바인딩 테스트
func testPortBinding(port int) bool {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

// 새로운 DHCP 테스터 생성 (개선됨)
func NewDHCPTester(serverIP string, serverPort int, timeout time.Duration) *DHCPTester {
	serverAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", serverIP, serverPort))
	
	dt := &DHCPTester{
		serverIP:   serverIP,
		serverPort: serverPort,
		clientPort: 68,
		timeout:    timeout,
		results:    make([]TestResult, 0),
		testMode:   TestModeSimulation,
		startTime:  time.Now(),
		
		// 기본 설정
		relayConfig: &RelayConfig{
			Enabled:  false,
			MaxHops:  4,
		},
		retryConfig: &RetryConfig{
			Enabled:           false,
			MaxDiscoverRetries: 3,
			MaxRequestRetries:  3,
			InitialTimeout:    4 * time.Second,
			MaxTimeout:        64 * time.Second,
			BackoffMultiplier: 2.0,
			Jitter:           true,
		},
		
		// 보안 설정 (기본값)
		securityConfig: &SecurityConfig{
			Enabled:          true,
			RateLimitEnabled: true,
			MaxRequestsPerMinute: 60,
			MACValidation:    true,
			DuplicateXIDCheck: true,
			LogSecurityEvents: false,
		},
		
		// 성능 설정 (기본값)
		performanceConfig: &PerformanceConfig{
			PacketPoolEnabled:  true,
			WorkerPoolSize:     10,
			ConnectionPoolSize: 50,
			ConnectionReuse:    true,
			MemoryOptimization: true,
			CacheEnabled:      true,
		},
		
		// 실시간 통계
		liveStats: &LiveStats{
			DiscoverOfferTimes: make([]time.Duration, 0),
			RequestAckTimes:    make([]time.Duration, 0),
		},
		
		// 캐시
		xidCache:    make(map[uint32]bool),
		packetCache: make(map[string]*DHCPPacket),
	}
	
	// 보안 구성요소 초기화
	if dt.securityConfig.RateLimitEnabled {
		dt.rateLimiter = NewRateLimiter(dt.securityConfig.MaxRequestsPerMinute, time.Minute)
	}
	
	if dt.securityConfig.LogSecurityEvents && dt.securityConfig.LogFile != "" {
		dt.securityLogger = NewSecurityLogger(dt.securityConfig.LogFile)
	}
	
	// 성능 구성요소 초기화
	if dt.performanceConfig.PacketPoolEnabled {
		dt.packetPool = NewPacketPool()
	}
	
	if dt.performanceConfig.WorkerPoolSize > 0 {
		dt.workerPool = NewWorkerPool(dt.performanceConfig.WorkerPoolSize, dt.performanceConfig.WorkerPoolSize*2)
	}
	
	if dt.performanceConfig.ConnectionReuse && dt.performanceConfig.ConnectionPoolSize > 0 {
		dt.connectionPool = NewConnectionPool(serverAddr, dt.performanceConfig.ConnectionPoolSize, timeout)
	}
	
	return dt
}

// ANSI escape sequences
const (
	ANSI_CLEAR_SCREEN = "\033[2J"
	ANSI_CURSOR_HOME  = "\033[H"
	ANSI_HIDE_CURSOR  = "\033[?25l"
	ANSI_SHOW_CURSOR  = "\033[?25h"
	ANSI_BOLD         = "\033[1m"
	ANSI_RESET        = "\033[0m"
	ANSI_RED          = "\033[31m"
	ANSI_GREEN        = "\033[32m"
	ANSI_YELLOW       = "\033[33m"
	ANSI_BLUE         = "\033[34m"
	ANSI_CYAN         = "\033[36m"
	ANSI_WHITE        = "\033[37m"
	ANSI_MAGENTA      = "\033[35m"
)

// 터미널 화면 초기화
func initTerminal() {
	fmt.Print(ANSI_CLEAR_SCREEN)
	fmt.Print(ANSI_CURSOR_HOME)
	fmt.Print(ANSI_HIDE_CURSOR)
}

// 터미널 화면 복원
func restoreTerminal() {
	fmt.Print(ANSI_SHOW_CURSOR)
	fmt.Print(ANSI_RESET)
}

// 실시간 대시보드 출력 (개선됨)
func (dt *DHCPTester) printLiveDashboard(numClients int, elapsedTime time.Duration) {
	fmt.Print(ANSI_CURSOR_HOME)
	
	// 헤더
	fmt.Printf("%s%s╔══════════════════════════════════════════════════════════════════════╗%s\n", ANSI_BOLD, ANSI_CYAN, ANSI_RESET)
	fmt.Printf("%s%s║             DHCP 서버 성능 테스트 실시간 모니터 (보안 강화)          ║%s\n", ANSI_BOLD, ANSI_CYAN, ANSI_RESET)
	fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════════════╝%s\n", ANSI_BOLD, ANSI_CYAN, ANSI_RESET)
	fmt.Println()
	
	// 기본 정보
	fmt.Printf("%s테스트 설정%s\n", ANSI_BOLD, ANSI_RESET)
	fmt.Printf("  서버: %s%s:%d%s", ANSI_YELLOW, dt.serverIP, dt.serverPort, ANSI_RESET)
	if dt.relayConfig.Enabled {
		fmt.Printf("  (Relay: %s%s%s)", ANSI_GREEN, dt.relayConfig.RelayIP, ANSI_RESET)
	}
	fmt.Println()
	fmt.Printf("  클라이언트: %s%d%s, 경과시간: %s%v%s", ANSI_YELLOW, numClients, ANSI_RESET, ANSI_YELLOW, elapsedTime.Truncate(time.Second), ANSI_RESET)
	
	// 보안 및 성능 상태 표시
	if dt.securityConfig.Enabled {
		fmt.Printf("  🔒%s보안 활성화%s", ANSI_GREEN, ANSI_RESET)
	}
	if dt.performanceConfig.PacketPoolEnabled {
		fmt.Printf("  ⚡%s성능 최적화%s", ANSI_GREEN, ANSI_RESET)
	}
	fmt.Println("\n")
	
	// 전체 진행률
	completed := atomic.LoadInt64(&dt.totalCount)
	success := atomic.LoadInt64(&dt.successCount)
	failed := atomic.LoadInt64(&dt.failureCount)
	progressPct := float64(completed) / float64(numClients) * 100
	
	fmt.Printf("%s전체 진행률%s\n", ANSI_BOLD, ANSI_RESET)
	fmt.Printf("  진행: %s%d/%d%s (%.1f%%) ", ANSI_GREEN, completed, numClients, ANSI_RESET, progressPct)
	
	// 진행률 바
	barWidth := 40
	filledWidth := int(progressPct / 100.0 * float64(barWidth))
	fmt.Print("[")
	for i := 0; i < barWidth; i++ {
		if i < filledWidth {
			fmt.Printf("%s█%s", ANSI_GREEN, ANSI_RESET)
		} else {
			fmt.Print("░")
		}
	}
	fmt.Printf("] %.1f%%\n", progressPct)
	
	fmt.Printf("  성공: %s%d%s, 실패: %s%d%s", ANSI_GREEN, success, ANSI_RESET, ANSI_RED, failed, ANSI_RESET)
	if completed > 0 {
		successRate := float64(success) / float64(completed) * 100
		fmt.Printf(", 성공률: %s%.1f%%%s", ANSI_GREEN, successRate, ANSI_RESET)
	}
	fmt.Println("\n")
	
	// DHCP 단계별 통계
	fmt.Printf("%s%s┌─ DHCP 4-Way Handshake 실시간 통계 ────────────────────────────────────┐%s\n", ANSI_BOLD, ANSI_BLUE, ANSI_RESET)
	
	discoverSent := atomic.LoadInt64(&dt.liveStats.DiscoverSent)
	offerReceived := atomic.LoadInt64(&dt.liveStats.OfferReceived)
	requestSent := atomic.LoadInt64(&dt.liveStats.RequestSent)
	ackReceived := atomic.LoadInt64(&dt.liveStats.AckReceived)
	
	fmt.Printf("%s│%s  1. %sDISCOVER%s 전송:  %s%8d%s 개    ", ANSI_BLUE, ANSI_RESET, ANSI_CYAN, ANSI_RESET, ANSI_WHITE, discoverSent, ANSI_RESET)
	fmt.Printf("3. %sREQUEST%s 전송:   %s%8d%s 개  %s%s│%s\n", ANSI_CYAN, ANSI_RESET, ANSI_WHITE, requestSent, ANSI_RESET, ANSI_BLUE, ANSI_RESET)
	
	fmt.Printf("%s│%s  2. %sOFFER%s 수신:    %s%8d%s 개    ", ANSI_BLUE, ANSI_RESET, ANSI_GREEN, ANSI_RESET, ANSI_WHITE, offerReceived, ANSI_RESET)
	fmt.Printf("4. %sACK%s 수신:      %s%8d%s 개  %s%s│%s\n", ANSI_GREEN, ANSI_RESET, ANSI_WHITE, ackReceived, ANSI_RESET, ANSI_BLUE, ANSI_RESET)
	
	// 평균 응답 시간
	dt.liveStats.mutex.RLock()
	var avgDO, avgRA time.Duration
	if len(dt.liveStats.DiscoverOfferTimes) > 0 {
		var total time.Duration
		for _, t := range dt.liveStats.DiscoverOfferTimes {
			total += t
		}
		avgDO = total / time.Duration(len(dt.liveStats.DiscoverOfferTimes))
	}
	if len(dt.liveStats.RequestAckTimes) > 0 {
		var total time.Duration
		for _, t := range dt.liveStats.RequestAckTimes {
			total += t
		}
		avgRA = total / time.Duration(len(dt.liveStats.RequestAckTimes))
	}
	dt.liveStats.mutex.RUnlock()
	
	fmt.Printf("%s│%s  평균 응답시간: D→O: %s%10v%s  R→A: %s%10v%s              %s%s│%s\n", 
		ANSI_BLUE, ANSI_RESET, ANSI_YELLOW, avgDO, ANSI_RESET, ANSI_YELLOW, avgRA, ANSI_RESET, ANSI_BLUE, ANSI_RESET)
	
	fmt.Printf("%s%s└──────────────────────────────────────────────────────────────────────┘%s\n", ANSI_BOLD, ANSI_BLUE, ANSI_RESET)
	fmt.Println()
	
	// 보안 통계
	securityBlocked := atomic.LoadInt64(&dt.liveStats.SecurityBlocked)
	rateLimited := atomic.LoadInt64(&dt.liveStats.RateLimited)
	
	if dt.securityConfig.Enabled && (securityBlocked > 0 || rateLimited > 0) {
		fmt.Printf("%s%s┌─ 보안 통계 ──────────────────────────────────────────────────────────┐%s\n", ANSI_BOLD, ANSI_MAGENTA, ANSI_RESET)
		fmt.Printf("%s│%s  보안 차단: %s%8d%s 건    Rate Limit: %s%8d%s 건                %s%s│%s\n", 
			ANSI_MAGENTA, ANSI_RESET, ANSI_RED, securityBlocked, ANSI_RESET, ANSI_RED, rateLimited, ANSI_RESET, ANSI_MAGENTA, ANSI_RESET)
		fmt.Printf("%s%s└──────────────────────────────────────────────────────────────────────┘%s\n", ANSI_BOLD, ANSI_MAGENTA, ANSI_RESET)
		fmt.Println()
	}
	
	// 성능 통계
	poolHits := atomic.LoadInt64(&dt.liveStats.PoolHits)
	poolMisses := atomic.LoadInt64(&dt.liveStats.PoolMisses)
	
	if dt.performanceConfig.PacketPoolEnabled && (poolHits > 0 || poolMisses > 0) {
		hitRatio := float64(poolHits) / float64(poolHits+poolMisses) * 100
		fmt.Printf("%s%s┌─ 성능 통계 ──────────────────────────────────────────────────────────┐%s\n", ANSI_BOLD, ANSI_CYAN, ANSI_RESET)
		fmt.Printf("%s│%s  Pool Hit: %s%8d%s      Pool Miss: %s%8d%s      Hit Rate: %s%.1f%%%s  %s%s│%s\n", 
			ANSI_CYAN, ANSI_RESET, ANSI_GREEN, poolHits, ANSI_RESET, ANSI_YELLOW, poolMisses, ANSI_RESET, ANSI_GREEN, hitRatio, ANSI_RESET, ANSI_CYAN, ANSI_RESET)
		
		// 워커 풀 통계
		if dt.workerPool != nil {
			queueSize, isRunning := dt.workerPool.GetStats()
			status := "정지됨"
			if isRunning {
				status = "실행중"
			}
			fmt.Printf("%s│%s  워커 풀: %s%s%s        큐 크기: %s%8d%s                          %s%s│%s\n", 
				ANSI_CYAN, ANSI_RESET, ANSI_GREEN, status, ANSI_RESET, ANSI_YELLOW, queueSize, ANSI_RESET, ANSI_CYAN, ANSI_RESET)
		}
		
		fmt.Printf("%s%s└──────────────────────────────────────────────────────────────────────┘%s\n", ANSI_BOLD, ANSI_CYAN, ANSI_RESET)
		fmt.Println()
	}
	
	// 에러 통계
	timeoutErr := atomic.LoadInt64(&dt.liveStats.TimeoutErrors)
	parseErr := atomic.LoadInt64(&dt.liveStats.ParsingErrors)
	netErr := atomic.LoadInt64(&dt.liveStats.NetworkErrors)
	
	if timeoutErr > 0 || parseErr > 0 || netErr > 0 {
		fmt.Printf("%s에러 통계%s\n", ANSI_BOLD, ANSI_RESET)
		if timeoutErr > 0 {
			fmt.Printf("  타임아웃: %s%d%s  ", ANSI_RED, timeoutErr, ANSI_RESET)
		}
		if parseErr > 0 {
			fmt.Printf("  파싱 오류: %s%d%s  ", ANSI_RED, parseErr, ANSI_RESET)
		}
		if netErr > 0 {
			fmt.Printf("  네트워크: %s%d%s  ", ANSI_RED, netErr, ANSI_RESET)
		}
		fmt.Println("\n")
	}
	
	// 성능 지표
	if elapsedTime > 0 {
		rps := float64(completed) / elapsedTime.Seconds()
		fmt.Printf("%s성능 지표%s\n", ANSI_BOLD, ANSI_RESET)
		fmt.Printf("  완료율: %s%.1f completions/sec%s", ANSI_GREEN, rps, ANSI_RESET)
		
		if success > 0 {
			successRps := float64(success) / elapsedTime.Seconds()
			fmt.Printf("  성공율: %s%.1f successful/sec%s", ANSI_GREEN, successRps, ANSI_RESET)
		}
		
		// 메모리 사용량 (대략적)
		memoryMB := atomic.LoadInt64(&dt.memoryUsage) / 1024 / 1024
		if memoryMB > 0 {
			fmt.Printf("  메모리: %s%dMB%s", ANSI_YELLOW, memoryMB, ANSI_RESET)
		}
		fmt.Println("\n")
	}
	
	fmt.Printf("%s%s[ESC 또는 Ctrl+C로 중단]%s", ANSI_BOLD, ANSI_WHITE, ANSI_RESET)
}

// 설정 메서드들
func (dt *DHCPTester) SetRelayConfig(config *RelayConfig) {
	dt.relayConfig = config
}

func (dt *DHCPTester) SetVerbose(verbose bool) {
	dt.verbose = verbose
}

func (dt *DHCPTester) SetLiveStats(enabled bool) {
	dt.showLiveStats = enabled
}

func (dt *DHCPTester) SetRetryConfig(config *RetryConfig) {
	dt.retryConfig = config
}

func (dt *DHCPTester) SetSecurityConfig(config *SecurityConfig) {
	dt.securityConfig = config
	
	// 보안 구성요소 재초기화
	if config.RateLimitEnabled {
		dt.rateLimiter = NewRateLimiter(config.MaxRequestsPerMinute, time.Minute)
	}
	
	if config.LogSecurityEvents && config.LogFile != "" {
		if dt.securityLogger != nil {
			dt.securityLogger.Close()
		}
		dt.securityLogger = NewSecurityLogger(config.LogFile)
	}
}

func (dt *DHCPTester) SetPerformanceConfig(config *PerformanceConfig) {
	dt.performanceConfig = config
	
	// 성능 구성요소 재초기화
	if config.PacketPoolEnabled && dt.packetPool == nil {
		dt.packetPool = NewPacketPool()
	}
	
	if config.WorkerPoolSize > 0 && dt.workerPool == nil {
		dt.workerPool = NewWorkerPool(config.WorkerPoolSize, config.WorkerPoolSize*2)
	}
}

// 지수 백오프 타임아웃 계산
func (dt *DHCPTester) calculateBackoffTimeout(attempt int, baseTimeout time.Duration) time.Duration {
	if !dt.retryConfig.Enabled {
		return baseTimeout
	}
	
	multiplier := 1.0
	for i := 0; i < attempt; i++ {
		multiplier *= dt.retryConfig.BackoffMultiplier
	}
	
	timeout := time.Duration(float64(baseTimeout) * multiplier)
	
	if timeout > dt.retryConfig.MaxTimeout {
		timeout = dt.retryConfig.MaxTimeout
	}
	
	if dt.retryConfig.Jitter {
		jitterRange := float64(timeout) * 0.25
		jitter := (rand.Float64() - 0.5) * 2 * jitterRange
		timeout = time.Duration(float64(timeout) + jitter)
		
		if timeout < time.Second {
			timeout = time.Second
		}
	}
	
	return timeout
}

// 재시도 간 대기
func (dt *DHCPTester) waitBeforeRetry(attempt int) {
	if !dt.retryConfig.Enabled || attempt == 0 {
		return
	}
	
	if attempt == 1 {
		delay := time.Duration(rand.Intn(10)+1) * time.Second
		if dt.verbose {
			fmt.Printf("   재시도 전 대기: %v\n", delay)
		}
		time.Sleep(delay)
		return
	}
	
	baseDelay := 4 * time.Second
	delay := dt.calculateBackoffTimeout(attempt-1, baseDelay)
	
	if dt.verbose {
		fmt.Printf("   재시도 #%d 전 대기: %v\n", attempt, delay)
	}
	time.Sleep(delay)
}

// 실시간 통계 업데이트 (개선됨)
func (dt *DHCPTester) updateLiveStats(stage string, responseTime time.Duration, errorType string) {
	switch stage {
	case "discover":
		atomic.AddInt64(&dt.liveStats.DiscoverSent, 1)
	case "offer":
		atomic.AddInt64(&dt.liveStats.OfferReceived, 1)
		dt.liveStats.mutex.Lock()
		dt.liveStats.DiscoverOfferTimes = append(dt.liveStats.DiscoverOfferTimes, responseTime)
		if len(dt.liveStats.DiscoverOfferTimes) > 1000 {
			dt.liveStats.DiscoverOfferTimes = dt.liveStats.DiscoverOfferTimes[len(dt.liveStats.DiscoverOfferTimes)-1000:]
		}
		dt.liveStats.mutex.Unlock()
	case "request":
		atomic.AddInt64(&dt.liveStats.RequestSent, 1)
	case "ack":
		atomic.AddInt64(&dt.liveStats.AckReceived, 1)
		dt.liveStats.mutex.Lock()
		dt.liveStats.RequestAckTimes = append(dt.liveStats.RequestAckTimes, responseTime)
		if len(dt.liveStats.RequestAckTimes) > 1000 {
			dt.liveStats.RequestAckTimes = dt.liveStats.RequestAckTimes[len(dt.liveStats.RequestAckTimes)-1000:]
		}
		dt.liveStats.mutex.Unlock()
	case "error":
		switch errorType {
		case "timeout":
			atomic.AddInt64(&dt.liveStats.TimeoutErrors, 1)
		case "parsing":
			atomic.AddInt64(&dt.liveStats.ParsingErrors, 1)
		case "network":
			atomic.AddInt64(&dt.liveStats.NetworkErrors, 1)
		case "security":
			atomic.AddInt64(&dt.liveStats.SecurityBlocked, 1)
		case "ratelimit":
			atomic.AddInt64(&dt.liveStats.RateLimited, 1)
		}
	case "pool_hit":
		atomic.AddInt64(&dt.liveStats.PoolHits, 1)
	case "pool_miss":
		atomic.AddInt64(&dt.liveStats.PoolMisses, 1)
	}
}

// IP 주소를 [4]byte로 변환
func ipToBytes(ip string) ([4]byte, error) {
	addr := net.ParseIP(ip)
	if addr == nil {
		return [4]byte{}, fmt.Errorf("잘못된 IP 주소: %s", ip)
	}
	ip4 := addr.To4()
	if ip4 == nil {
		return [4]byte{}, fmt.Errorf("IPv4 주소가 아닙니다: %s", ip)
	}
	return [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}, nil
}

// Option 82 생성
func createRelayAgentOption(circuitID, remoteID string) []byte {
	if circuitID == "" && remoteID == "" {
		return nil
	}
	
	var suboptions []byte
	
	if circuitID != "" {
		circuitIDBytes := []byte(circuitID)
		suboptions = append(suboptions, RelayAgentCircuitID)
		suboptions = append(suboptions, byte(len(circuitIDBytes)))
		suboptions = append(suboptions, circuitIDBytes...)
	}
	
	if remoteID != "" {
		remoteIDBytes := []byte(remoteID)
		suboptions = append(suboptions, RelayAgentRemoteID)
		suboptions = append(suboptions, byte(len(remoteIDBytes)))
		suboptions = append(suboptions, remoteIDBytes...)
	}
	
	option82 := []byte{DHCPRelayAgentInfo, byte(len(suboptions))}
	option82 = append(option82, suboptions...)
	
	return option82
}

// MAC 주소 생성 (보안 강화됨)
func generateMACAddress() [6]byte {
	mac := [6]byte{}
	mac[0] = 0x02 // 로컬 관리 비트 설정
	for i := 1; i < 6; i++ {
		mac[i] = byte(rand.Intn(256))
	}
	
	// 유효성 재검사
	if !isValidMACAddress(mac) {
		return generateMACAddress() // 재귀 호출로 유효한 MAC 생성
	}
	
	return mac
}

// DHCP Discover 패킷 생성
func createDiscoverPacket(xid uint32, clientMAC [6]byte, relayConfig *RelayConfig) []byte {
	packet := make([]byte, 240)
	
	packet[0] = 1
	packet[1] = 1
	packet[2] = 6
	
	if relayConfig != nil && relayConfig.Enabled {
		packet[3] = relayConfig.HopCount
	} else {
		packet[3] = 0
	}
	
	binary.BigEndian.PutUint32(packet[4:8], xid)
	binary.BigEndian.PutUint16(packet[8:10], 0)
	binary.BigEndian.PutUint16(packet[10:12], 0)
	
	if relayConfig != nil && relayConfig.Enabled && relayConfig.RelayIP != "" {
		relayIPBytes, err := ipToBytes(relayConfig.RelayIP)
		if err == nil {
			copy(packet[24:28], relayIPBytes[:])
		}
	}
	
	copy(packet[28:34], clientMAC[:])
	
	// Magic Cookie
	packet = append(packet, 0x63, 0x82, 0x53, 0x63)
	
	// DHCP 옵션
	packet = append(packet, DHCPMessageType, 1, DHCPDiscover)
	
	packet = append(packet, DHCPClientID, 7, 1)
	packet = append(packet, clientMAC[:]...)
	
	if relayConfig != nil && relayConfig.Enabled {
		option82 := createRelayAgentOption(relayConfig.CircuitID, relayConfig.RemoteID)
		if option82 != nil {
			packet = append(packet, option82...)
		}
	}
	
	packet = append(packet, DHCPEnd)
	
	return packet
}

// DHCP Request 패킷 생성
func createRequestPacket(xid uint32, clientMAC [6]byte, requestedIP, serverIP uint32, relayConfig *RelayConfig) []byte {
	packet := make([]byte, 240)
	
	packet[0] = 1
	packet[1] = 1
	packet[2] = 6
	
	if relayConfig != nil && relayConfig.Enabled {
		packet[3] = relayConfig.HopCount
	} else {
		packet[3] = 0
	}
	
	binary.BigEndian.PutUint32(packet[4:8], xid)
	binary.BigEndian.PutUint16(packet[8:10], 0)
	binary.BigEndian.PutUint16(packet[10:12], 0)
	
	if relayConfig != nil && relayConfig.Enabled && relayConfig.RelayIP != "" {
		relayIPBytes, err := ipToBytes(relayConfig.RelayIP)
		if err == nil {
			copy(packet[24:28], relayIPBytes[:])
		}
	}
	
	copy(packet[28:34], clientMAC[:])
	
	// Magic Cookie
	packet = append(packet, 0x63, 0x82, 0x53, 0x63)
	
	// DHCP 옵션
	packet = append(packet, DHCPMessageType, 1, DHCPRequest)
	
	packet = append(packet, DHCPRequestedIP, 4)
	reqIPBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(reqIPBytes, requestedIP)
	packet = append(packet, reqIPBytes...)
	
	packet = append(packet, DHCPServerID, 4)
	serverIPBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(serverIPBytes, serverIP)
	packet = append(packet, serverIPBytes...)
	
	packet = append(packet, DHCPClientID, 7, 1)
	packet = append(packet, clientMAC[:]...)
	
	if relayConfig != nil && relayConfig.Enabled {
		option82 := createRelayAgentOption(relayConfig.CircuitID, relayConfig.RemoteID)
		if option82 != nil {
			packet = append(packet, option82...)
		}
	}
	
	packet = append(packet, DHCPEnd)
	
	return packet
}

// DHCP 패킷 파싱
func parseDHCPPacket(data []byte) (*DHCPPacket, error) {
	if len(data) < 240 {
		return nil, fmt.Errorf("패킷이 너무 짧습니다")
	}
	
	packet := &DHCPPacket{}
	
	packet.Op = data[0]
	packet.HType = data[1]
	packet.HLen = data[2]
	packet.Hops = data[3]
	packet.Xid = binary.BigEndian.Uint32(data[4:8])
	packet.Secs = binary.BigEndian.Uint16(data[8:10])
	packet.Flags = binary.BigEndian.Uint16(data[10:12])
	
	copy(packet.Ciaddr[:], data[12:16])
	copy(packet.Yiaddr[:], data[16:20])
	copy(packet.Siaddr[:], data[20:24])
	copy(packet.Giaddr[:], data[24:28])
	copy(packet.Chaddr[:], data[28:44])
	copy(packet.Sname[:], data[44:108])
	copy(packet.File[:], data[108:236])
	
	if len(data) > 240 && bytes.Equal(data[236:240], []byte{0x63, 0x82, 0x53, 0x63}) {
		packet.Options = data[240:]
	}
	
	return packet, nil
}

// DHCP 옵션에서 메시지 타입 추출
func getMessageType(options []byte) (uint8, error) {
	for i := 0; i < len(options); {
		if options[i] == DHCPEnd {
			break
		}
		if options[i] == 0 {
			i++
			continue
		}
		
		optionCode := options[i]
		if i+1 >= len(options) {
			break
		}
		optionLength := int(options[i+1])
		
		if optionCode == DHCPMessageType && optionLength == 1 && i+2 < len(options) {
			return options[i+2], nil
		}
		
		i += 2 + optionLength
	}
	return 0, fmt.Errorf("메시지 타입을 찾을 수 없습니다")
}

// 서버 ID 추출
func getServerID(options []byte) (uint32, error) {
	for i := 0; i < len(options); {
		if options[i] == DHCPEnd {
			break
		}
		if options[i] == 0 {
			i++
			continue
		}
		
		optionCode := options[i]
		if i+1 >= len(options) {
			break
		}
		optionLength := int(options[i+1])
		
		if optionCode == DHCPServerID && optionLength == 4 && i+6 <= len(options) {
			return binary.BigEndian.Uint32(options[i+2:i+6]), nil
		}
		
		i += 2 + optionLength
	}
	return 0, fmt.Errorf("서버 ID를 찾을 수 없습니다")
}

// 단일 클라이언트 테스트 (보안 및 성능 강화됨)
func (dt *DHCPTester) testSingleClient(clientID string) TestResult {
	overallStart := time.Now()
	result := TestResult{
		ClientID:  clientID,
		Timestamp: overallStart,
		RelayUsed: dt.relayConfig.Enabled,
	}
	
	// 보안 검사: Rate Limiting
	if dt.securityConfig.Enabled && dt.securityConfig.RateLimitEnabled && dt.rateLimiter != nil {
		if !dt.rateLimiter.IsAllowed(clientID) {
			result.Error = "Rate limit exceeded"
			result.RateLimited = true
			dt.updateLiveStats("error", 0, "ratelimit")
			
			if dt.securityLogger != nil {
				dt.securityLogger.LogEvent(SecurityEventRateLimit, clientID, map[string]interface{}{
					"reason": "rate_limit_exceeded",
				})
			}
			
			atomic.AddInt64(&dt.failureCount, 1)
			return result
		}
	}
	
	if dt.verbose {
		fmt.Printf("[%s] DHCP 4-way handshake 시작 (보안 강화 모드)", clientID)
		if dt.retryConfig.Enabled {
			fmt.Printf(" (재시도: D:%d회, R:%d회)",
				dt.retryConfig.MaxDiscoverRetries, dt.retryConfig.MaxRequestRetries)
		}
		fmt.Println()
	}
	
	// Relay Agent 검증
	if dt.relayConfig.Enabled {
		if dt.relayConfig.HopCount >= dt.relayConfig.MaxHops {
			result.Error = fmt.Sprintf("최대 hop count 초과: %d >= %d", dt.relayConfig.HopCount, dt.relayConfig.MaxHops)
			dt.updateLiveStats("error", 0, "network")
			atomic.AddInt64(&dt.failureCount, 1)
			return result
		}
		if dt.relayConfig.RelayIP == "" {
			result.Error = "Relay IP가 설정되지 않았습니다"
			dt.updateLiveStats("error", 0, "network")
			atomic.AddInt64(&dt.failureCount, 1)
			return result
		}
	}
	
	// 연결 생성 (연결 풀 사용 시)
	var conn *net.UDPConn
	var err error
	var connectionReused bool
	
	if dt.performanceConfig.ConnectionReuse && dt.connectionPool != nil {
		conn, err = dt.connectionPool.Get()
		connectionReused = true
		dt.updateLiveStats("pool_hit", 0, "")
		result.ConnectionReused = true
	} else {
		netConn, dialErr := net.DialTimeout("udp", fmt.Sprintf("%s:%d", dt.serverIP, dt.serverPort), dt.timeout)
		if dialErr != nil {
			err = dialErr
		} else {
			var ok bool
			conn, ok = netConn.(*net.UDPConn)
			if !ok {
				netConn.Close()
				err = fmt.Errorf("connection is not UDP")
			}
		}
		dt.updateLiveStats("pool_miss", 0, "")
	}
	
	if err != nil {
		result.Error = fmt.Sprintf("연결 실패: %v", err)
		dt.updateLiveStats("error", 0, "network")
		atomic.AddInt64(&dt.failureCount, 1)
		return result
	}
	
	defer func() {
		if connectionReused && dt.connectionPool != nil {
			dt.connectionPool.Put(conn)
		} else {
			conn.Close()
		}
	}()
	
	// 클라이언트 정보 생성
	xid := rand.Uint32()
	clientMAC := generateMACAddress()
	
	// 보안 검사: MAC 주소 검증
	if dt.securityConfig.Enabled && dt.securityConfig.MACValidation {
		if !isValidMACAddress(clientMAC) {
			result.Error = "Invalid MAC address generated"
			result.SecurityBlocked = true
			dt.updateLiveStats("error", 0, "security")
			
			if dt.securityLogger != nil {
				dt.securityLogger.LogEvent(SecurityEventInvalidMAC, clientID, map[string]interface{}{
					"mac": fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
						clientMAC[0], clientMAC[1], clientMAC[2], clientMAC[3], clientMAC[4], clientMAC[5]),
				})
			}
			
			atomic.AddInt64(&dt.failureCount, 1)
			return result
		}
	}
	
	// 보안 검사: Transaction ID 중복 확인
	if dt.securityConfig.Enabled && dt.securityConfig.DuplicateXIDCheck {
		dt.xidCacheMutex.Lock()
		if dt.xidCache[xid] {
			dt.xidCacheMutex.Unlock()
			result.Error = "Duplicate transaction ID"
			result.SecurityBlocked = true
			dt.updateLiveStats("error", 0, "security")
			
			if dt.securityLogger != nil {
				dt.securityLogger.LogEvent(SecurityEventDuplicateXID, clientID, map[string]interface{}{
					"xid": fmt.Sprintf("0x%08X", xid),
				})
			}
			
			atomic.AddInt64(&dt.failureCount, 1)
			return result
		}
		dt.xidCache[xid] = true
		dt.xidCacheMutex.Unlock()
		
		// 캐시 정리 (메모리 절약)
		defer func() {
			dt.xidCacheMutex.Lock()
			delete(dt.xidCache, xid)
			dt.xidCacheMutex.Unlock()
		}()
	}
	
	if dt.verbose {
		fmt.Printf("[%s] Transaction ID: 0x%08X, MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
			clientID, xid, clientMAC[0], clientMAC[1], clientMAC[2], clientMAC[3], clientMAC[4], clientMAC[5])
		if connectionReused {
			fmt.Printf("[%s] 연결 풀에서 재사용된 연결 사용\n", clientID)
		}
	}
	
	// === 1단계: DHCP Discover ===
	var offerPacket *DHCPPacket
	var discoverOfferTime time.Duration
	
	for attempt := 0; attempt <= dt.retryConfig.MaxDiscoverRetries; attempt++ {
		if attempt > 0 {
			result.DiscoverRetries++
			result.TotalRetries++
			if dt.verbose {
				fmt.Printf("[%s] Discover 재시도 #%d\n", clientID, attempt)
			}
			dt.waitBeforeRetry(attempt)
		}
		
		currentTimeout := dt.calculateBackoffTimeout(attempt, dt.retryConfig.InitialTimeout)
		conn.SetDeadline(time.Now().Add(currentTimeout))
		
		discoverStart := time.Now()
		
		// 패킷 생성 (패킷 풀 사용 시 메모리 최적화)
		discoverPacket := createDiscoverPacket(xid, clientMAC, dt.relayConfig)
		
		// 패킷 해시 생성 (캐시 키로 사용)
		if dt.performanceConfig.CacheEnabled {
			result.PacketHash = generatePacketHash(discoverPacket)
		}
		
		_, err = conn.Write(discoverPacket)
		if err != nil {
			if attempt >= dt.retryConfig.MaxDiscoverRetries {
				result.Error = fmt.Sprintf("Discover 전송 실패 (최대 재시도 초과): %v", err)
				dt.updateLiveStats("error", 0, "network")
				atomic.AddInt64(&dt.failureCount, 1)
				return result
			}
			continue
		}
		result.DiscoverTime = time.Since(discoverStart)
		dt.updateLiveStats("discover", 0, "")
		
		if dt.verbose {
			fmt.Printf("[%s] ➤ DHCP Discover 전송 (시도 #%d, 타임아웃: %v)\n", 
				clientID, attempt+1, currentTimeout)
		}
		
		// DHCP Offer 수신
		offerStart := time.Now()
		
		// 버퍼 할당 (패킷 풀 사용 시)
		var buffer []byte
		if dt.performanceConfig.PacketPoolEnabled && dt.packetPool != nil {
			buffer = dt.packetPool.Get()
			defer dt.packetPool.Put(buffer)
		} else {
			buffer = make([]byte, 1500)
		}
		
		n, err := conn.Read(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if attempt >= dt.retryConfig.MaxDiscoverRetries {
					result.Error = "Offer 수신 타임아웃 (최대 재시도 초과)"
					dt.updateLiveStats("error", 0, "timeout")
					atomic.AddInt64(&dt.failureCount, 1)
					return result
				}
				if dt.verbose {
					fmt.Printf("[%s] Offer 수신 타임아웃, 재시도 예정...\n", clientID)
				}
				continue
			}
			if attempt >= dt.retryConfig.MaxDiscoverRetries {
				result.Error = fmt.Sprintf("Offer 수신 실패 (최대 재시도 초과): %v", err)
				dt.updateLiveStats("error", 0, "network")
				atomic.AddInt64(&dt.failureCount, 1)
				return result
			}
			continue
		}
		result.OfferTime = time.Since(offerStart)
		
		// 패킷 파싱 (캐시 사용 시)
		var packetCacheKey string
		if dt.performanceConfig.CacheEnabled {
			packetCacheKey = generatePacketHash(buffer[:n])
			dt.packetCacheMutex.RLock()
			if cachedPacket, exists := dt.packetCache[packetCacheKey]; exists {
				offerPacket = cachedPacket
				dt.packetCacheMutex.RUnlock()
				goto packetCached
			}
			dt.packetCacheMutex.RUnlock()
		}
		
		offerPacket, err = parseDHCPPacket(buffer[:n])
		if err != nil {
			if attempt >= dt.retryConfig.MaxDiscoverRetries {
				result.Error = fmt.Sprintf("Offer 파싱 실패 (최대 재시도 초과): %v", err)
				dt.updateLiveStats("error", 0, "parsing")
				atomic.AddInt64(&dt.failureCount, 1)
				return result
			}
			continue
		}
		
		// 캐시에 저장
		if dt.performanceConfig.CacheEnabled {
			dt.packetCacheMutex.Lock()
			if len(dt.packetCache) > 1000 { // 캐시 크기 제한
				// 간단한 LRU: 첫 번째 항목 제거
				for k := range dt.packetCache {
					delete(dt.packetCache, k)
					break
				}
			}
			dt.packetCache[packetCacheKey] = offerPacket
			dt.packetCacheMutex.Unlock()
		}
		
	packetCached:
		if offerPacket.Xid != xid {
			if attempt >= dt.retryConfig.MaxDiscoverRetries {
				result.Error = "잘못된 Transaction ID (Offer, 최대 재시도 초과)"
				dt.updateLiveStats("error", 0, "parsing")
				atomic.AddInt64(&dt.failureCount, 1)
				return result
			}
			continue
		}
		
		discoverOfferTime = time.Since(discoverStart)
		dt.updateLiveStats("offer", discoverOfferTime, "")
		
		if dt.verbose {
			fmt.Printf("[%s] ◀ DHCP Offer 수신 (시도 #%d)\n", clientID, attempt+1)
		}
		break
	}
	
	// Offer 검증
	messageType, err := getMessageType(offerPacket.Options)
	if err != nil || messageType != DHCPOffer {
		result.Error = "DHCP Offer가 아닙니다"
		dt.updateLiveStats("error", 0, "parsing")
		atomic.AddInt64(&dt.failureCount, 1)
		return result
	}
	
	// Relay Agent 검증
	if dt.relayConfig.Enabled {
		expectedRelayIP, _ := ipToBytes(dt.relayConfig.RelayIP)
		if !bytes.Equal(offerPacket.Giaddr[:], expectedRelayIP[:]) {
			result.Error = fmt.Sprintf("Relay IP 불일치: 예상=%s, 실제=%d.%d.%d.%d", 
				dt.relayConfig.RelayIP,
				offerPacket.Giaddr[0], offerPacket.Giaddr[1], 
				offerPacket.Giaddr[2], offerPacket.Giaddr[3])
			dt.updateLiveStats("error", 0, "parsing")
			atomic.AddInt64(&dt.failureCount, 1)
			return result
		}
	}
	
	// 제공받은 IP와 서버 ID 추출
	offeredIP := binary.BigEndian.Uint32(offerPacket.Yiaddr[:])
	result.OfferedIP = fmt.Sprintf("%d.%d.%d.%d", 
		(offeredIP>>24)&0xFF, (offeredIP>>16)&0xFF, (offeredIP>>8)&0xFF, offeredIP&0xFF)
	
	serverID, err := getServerID(offerPacket.Options)
	if err != nil {
		result.Error = fmt.Sprintf("서버 ID 추출 실패: %v", err)
		dt.updateLiveStats("error", 0, "parsing")
		atomic.AddInt64(&dt.failureCount, 1)
		return result
	}
	result.ServerID = fmt.Sprintf("%d.%d.%d.%d", 
		(serverID>>24)&0xFF, (serverID>>16)&0xFF, (serverID>>8)&0xFF, serverID&0xFF)
	
	if dt.verbose {
		fmt.Printf("[%s] Offer 검증 완료 - IP: %s, 서버: %s\n", 
			clientID, result.OfferedIP, result.ServerID)
	}
	
	// === 3단계: DHCP Request ===
	var ackPacket *DHCPPacket
	var requestAckTime time.Duration
	
	for attempt := 0; attempt <= dt.retryConfig.MaxRequestRetries; attempt++ {
		if attempt > 0 {
			result.RequestRetries++
			result.TotalRetries++
			if dt.verbose {
				fmt.Printf("[%s] Request 재시도 #%d\n", clientID, attempt)
			}
			dt.waitBeforeRetry(attempt)
		}
		
		currentTimeout := dt.calculateBackoffTimeout(attempt, dt.retryConfig.InitialTimeout)
		conn.SetDeadline(time.Now().Add(currentTimeout))
		
		requestStart := time.Now()
		requestPacket := createRequestPacket(xid, clientMAC, offeredIP, serverID, dt.relayConfig)
		_, err = conn.Write(requestPacket)
		if err != nil {
			if attempt >= dt.retryConfig.MaxRequestRetries {
				result.Error = fmt.Sprintf("Request 전송 실패 (최대 재시도 초과): %v", err)
				dt.updateLiveStats("error", 0, "network")
				atomic.AddInt64(&dt.failureCount, 1)
				return result
			}
			continue
		}
		result.RequestTime = time.Since(requestStart)
		dt.updateLiveStats("request", 0, "")
		
		if dt.verbose {
			fmt.Printf("[%s] ➤ DHCP Request 전송 (시도 #%d, 타임아웃: %v)\n", 
				clientID, attempt+1, currentTimeout)
		}
		
		// DHCP ACK 수신
		ackStart := time.Now()
		
		// 버퍼 할당 (패킷 풀 재사용)
		var buffer []byte
		if dt.performanceConfig.PacketPoolEnabled && dt.packetPool != nil {
			buffer = dt.packetPool.Get()
			defer dt.packetPool.Put(buffer)
		} else {
			buffer = make([]byte, 1500)
		}
		
		n, err := conn.Read(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if attempt >= dt.retryConfig.MaxRequestRetries {
					result.Error = "ACK 수신 타임아웃 (최대 재시도 초과)"
					dt.updateLiveStats("error", 0, "timeout")
					atomic.AddInt64(&dt.failureCount, 1)
					return result
				}
				if dt.verbose {
					fmt.Printf("[%s] ACK 수신 타임아웃, 재시도 예정...\n", clientID)
				}
				continue
			}
			if attempt >= dt.retryConfig.MaxRequestRetries {
				result.Error = fmt.Sprintf("ACK 수신 실패 (최대 재시도 초과): %v", err)
				dt.updateLiveStats("error", 0, "network")
				atomic.AddInt64(&dt.failureCount, 1)
				return result
			}
			continue
		}
		result.AckTime = time.Since(ackStart)
		
		ackPacket, err = parseDHCPPacket(buffer[:n])
		if err != nil {
			if attempt >= dt.retryConfig.MaxRequestRetries {
				result.Error = fmt.Sprintf("ACK 파싱 실패 (최대 재시도 초과): %v", err)
				dt.updateLiveStats("error", 0, "parsing")
				atomic.AddInt64(&dt.failureCount, 1)
				return result
			}
			continue
		}
		
		if ackPacket.Xid != xid {
			if attempt >= dt.retryConfig.MaxRequestRetries {
				result.Error = "잘못된 Transaction ID (ACK, 최대 재시도 초과)"
				dt.updateLiveStats("error", 0, "parsing")
				atomic.AddInt64(&dt.failureCount, 1)
				return result
			}
			continue
		}
		
		requestAckTime = time.Since(requestStart)
		dt.updateLiveStats("ack", requestAckTime, "")
		
		if dt.verbose {
			fmt.Printf("[%s] ◀ DHCP ACK 수신 (시도 #%d)\n", clientID, attempt+1)
		}
		break
	}
	
	messageType, err = getMessageType(ackPacket.Options)
	if err != nil || messageType != DHCPAck {
		result.Error = "DHCP ACK가 아닙니다"
		dt.updateLiveStats("error", 0, "parsing")
		atomic.AddInt64(&dt.failureCount, 1)
		return result
	}
	
	// === 성공: 전체 과정 완료 ===
	result.Success = true
	result.ResponseTime = time.Since(overallStart)
	
	// 메모리 사용량 추정 (대략적)
	result.MemoryUsed = int64(len(result.ClientID) + len(result.Error) + len(result.OfferedIP) + len(result.ServerID) + 200)
	atomic.AddInt64(&dt.memoryUsage, result.MemoryUsed)
	
	atomic.AddInt64(&dt.successCount, 1)
	
	if dt.verbose {
		fmt.Printf("[%s] ✅ DHCP 4-way handshake 완료 (총 시간: %v)\n", clientID, result.ResponseTime)
		fmt.Printf("[%s]    단계별 시간: D=%v, O=%v, R=%v, A=%v\n",
			clientID, result.DiscoverTime, result.OfferTime, result.RequestTime, result.AckTime)
		fmt.Printf("[%s]    응답 시간: D-O=%v, R-A=%v\n", clientID, discoverOfferTime, requestAckTime)
		if result.TotalRetries > 0 {
			fmt.Printf("[%s]    재시도: D=%d, R=%d, 총=%d회\n", 
				clientID, result.DiscoverRetries, result.RequestRetries, result.TotalRetries)
		}
		if result.ConnectionReused {
			fmt.Printf("[%s]    연결 풀 재사용됨\n", clientID)
		}
		fmt.Println()
	}
	
	return result
}

// 나머지 메서드들은 기존과 동일하지만 새로운 통계 포함...
// 성능 테스트 실행
func (dt *DHCPTester) RunPerformanceTest(numClients int, concurrency int, showProgress bool) *Statistics {
	// 워커 풀 시작
	if dt.workerPool != nil {
		dt.workerPool.Start()
		defer dt.workerPool.Stop()
	}
	
	if dt.showLiveStats {
		return dt.runTestWithLiveStats(numClients, concurrency)
	} else {
		return dt.runTestWithProgressBar(numClients, concurrency, showProgress)
	}
}

// 실시간 통계로 테스트 실행
func (dt *DHCPTester) runTestWithLiveStats(numClients int, concurrency int) *Statistics {
	fmt.Printf("DHCP 서버 성능 테스트 시작 (보안 강화 및 성능 최적화 모드)\n")
	fmt.Printf("대상 서버: %s:%d\n", dt.serverIP, dt.serverPort)
	fmt.Printf("총 클라이언트: %d, 동시 실행: %d\n", numClients, concurrency)
	
	if dt.securityConfig.Enabled {
		fmt.Printf("보안 기능: 활성화 (Rate Limit: %d req/min)\n", dt.securityConfig.MaxRequestsPerMinute)
	}
	if dt.performanceConfig.PacketPoolEnabled {
		fmt.Printf("성능 최적화: 활성화 (워커 풀: %d개)\n", dt.performanceConfig.WorkerPoolSize)
	}
	
	fmt.Printf("실시간 대시보드를 시작합니다...\n\n")
	
	time.Sleep(2 * time.Second)
	
	initTerminal()
	defer restoreTerminal()
	
	startTime := time.Now()
	
	resultChan := make(chan TestResult, numClients)
	workChan := make(chan string, numClients)
	
	for i := 0; i < numClients; i++ {
		workChan <- fmt.Sprintf("client_%05d", i+1)
	}
	close(workChan)
	
	var wg sync.WaitGroup
	
	// 워커 고루틴 (워커 풀 사용 시 제한됨)
	workerCount := concurrency
	if dt.workerPool != nil {
		workerCount = dt.performanceConfig.WorkerPoolSize
	}
	
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for clientID := range workChan {
				if dt.workerPool != nil {
					// 워커 풀에 작업 제출
					submitted := dt.workerPool.Submit(func() {
						result := dt.testSingleClient(clientID)
						atomic.AddInt64(&dt.totalCount, 1)
						resultChan <- result
					})
					if !submitted {
						// 워커 풀이 가득 참 - 직접 실행
						result := dt.testSingleClient(clientID)
						atomic.AddInt64(&dt.totalCount, 1)
						resultChan <- result
					}
				} else {
					// 기존 방식
					result := dt.testSingleClient(clientID)
					atomic.AddInt64(&dt.totalCount, 1)
					resultChan <- result
				}
			}
		}()
	}
	
	// 실시간 대시보드 고루틴
	var dashboardWG sync.WaitGroup
	dashboardWG.Add(1)
	done := make(chan bool)
	
	go func() {
		defer dashboardWG.Done()
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				completed := atomic.LoadInt64(&dt.totalCount)
				if completed >= int64(numClients) {
					return
				}
				dt.printLiveDashboard(numClients, time.Since(startTime))
			case <-done:
				return
			}
		}
	}()
	
	// 결과 수집
	go func() {
		wg.Wait()
		close(resultChan)
		done <- true
	}()
	
	for result := range resultChan {
		dt.resultsMutex.Lock()
		dt.results = append(dt.results, result)
		dt.resultsMutex.Unlock()
	}
	
	dashboardWG.Wait()
	
	dt.printLiveDashboard(numClients, time.Since(startTime))
	
	fmt.Printf("\n\n%s테스트 완료!%s\n", ANSI_BOLD+ANSI_GREEN, ANSI_RESET)
	
	totalTime := time.Since(startTime)
	return dt.calculateStatistics(totalTime)
}

// 기존 진행률 표시로 테스트 실행
func (dt *DHCPTester) runTestWithProgressBar(numClients int, concurrency int, showProgress bool) *Statistics {
	fmt.Printf("DHCP 서버 성능 테스트 시작 (보안 강화 및 성능 최적화)\n")
	fmt.Printf("대상 서버: %s:%d\n", dt.serverIP, dt.serverPort)
	fmt.Printf("총 클라이언트: %d, 동시 실행 수: %d\n", numClients, concurrency)
	fmt.Printf("타임아웃: %v\n", dt.timeout)
	
	if dt.securityConfig.Enabled {
		fmt.Printf("보안 강화: 활성화\n")
		if dt.securityConfig.RateLimitEnabled {
			fmt.Printf("  - Rate Limiting: %d 요청/분\n", dt.securityConfig.MaxRequestsPerMinute)
		}
		if dt.securityConfig.MACValidation {
			fmt.Printf("  - MAC 주소 검증: 활성화\n")
		}
		if dt.securityConfig.DuplicateXIDCheck {
			fmt.Printf("  - 중복 XID 검사: 활성화\n")
		}
	}
	
	if dt.performanceConfig.PacketPoolEnabled {
		fmt.Printf("성능 최적화: 활성화\n")
		fmt.Printf("  - 패킷 풀: 활성화\n")
		fmt.Printf("  - 워커 풀: %d개\n", dt.performanceConfig.WorkerPoolSize)
		if dt.performanceConfig.ConnectionReuse {
			fmt.Printf("  - 연결 재사용: 활성화 (풀 크기: %d)\n", dt.performanceConfig.ConnectionPoolSize)
		}
	}
	
	if dt.relayConfig.Enabled {
		fmt.Printf("Relay Agent: 활성화\n")
		fmt.Printf("  - Relay IP: %s\n", dt.relayConfig.RelayIP)
		fmt.Printf("  - Hop Count: %d\n", dt.relayConfig.HopCount)
	}
	
	fmt.Printf("%s\n", strings.Repeat("-", 70))
	
	startTime := time.Now()
	
	resultChan := make(chan TestResult, numClients)
	workChan := make(chan string, numClients)
	
	for i := 0; i < numClients; i++ {
		workChan <- fmt.Sprintf("client_%05d", i+1)
	}
	close(workChan)
	
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for clientID := range workChan {
				result := dt.testSingleClient(clientID)
				atomic.AddInt64(&dt.totalCount, 1)
				resultChan <- result
			}
		}()
	}
	
	// 진행상황 모니터링
	var progressWG sync.WaitGroup
	if showProgress {
		progressWG.Add(1)
		go func() {
			defer progressWG.Done()
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			
			for {
				select {
				case <-ticker.C:
					completed := atomic.LoadInt64(&dt.totalCount)
					success := atomic.LoadInt64(&dt.successCount)
					failure := atomic.LoadInt64(&dt.failureCount)
					
					if completed >= int64(numClients) {
						return
					}
					
					secBlocked := atomic.LoadInt64(&dt.liveStats.SecurityBlocked)
					rateLimit := atomic.LoadInt64(&dt.liveStats.RateLimited)
					
					fmt.Printf("\r진행: %d/%d (성공:%d, 실패:%d, 보안차단:%d, 제한:%d) [%.1f%%]",
						completed, numClients, success, failure, secBlocked, rateLimit,
						float64(completed)/float64(numClients)*100)
				}
			}
		}()
	}
	
	go func() {
		wg.Wait()
		close(resultChan)
	}()
	
	for result := range resultChan {
		dt.resultsMutex.Lock()
		dt.results = append(dt.results, result)
		dt.resultsMutex.Unlock()
	}
	
	if showProgress {
		progressWG.Wait()
		fmt.Printf("\n")
	}
	
	totalTime := time.Since(startTime)
	return dt.calculateStatistics(totalTime)
}

// 통계 계산 (확장됨)
func (dt *DHCPTester) calculateStatistics(totalTime time.Duration) *Statistics {
	stats := &Statistics{
		TotalRequests:  int64(len(dt.results)),
		ErrorCounts:    make(map[string]int64),
	}
	
	var responseTimes []time.Duration
	var discoverTimes, offerTimes, requestTimes, ackTimes []time.Duration
	var totalRetries, discoverRetries, requestRetries int64
	
	for _, result := range dt.results {
		if result.RelayUsed {
			stats.RelayTests++
		}
		
		// 보안 통계
		if result.SecurityBlocked {
			stats.SecurityBlocked++
		}
		if result.RateLimited {
			stats.RateLimited++
		}
		
		// 성능 통계
		if result.ConnectionReused {
			stats.ConnectionReused++
		}
		stats.MemoryAllocated += result.MemoryUsed
		
		totalRetries += int64(result.TotalRetries)
		discoverRetries += int64(result.DiscoverRetries)
		requestRetries += int64(result.RequestRetries)
		
		if result.Success {
			stats.SuccessfulRequests++
			responseTimes = append(responseTimes, result.ResponseTime)
			
			if result.DiscoverTime > 0 {
				discoverTimes = append(discoverTimes, result.DiscoverTime)
			}
			if result.OfferTime > 0 {
				offerTimes = append(offerTimes, result.OfferTime)
			}
			if result.RequestTime > 0 {
				requestTimes = append(requestTimes, result.RequestTime)
			}
			if result.AckTime > 0 {
				ackTimes = append(ackTimes, result.AckTime)
			}
		} else {
			stats.FailedRequests++
			stats.ErrorCounts[result.Error]++
		}
	}
	
	// 패킷 풀 통계
	stats.PacketPoolHits = atomic.LoadInt64(&dt.liveStats.PoolHits)
	stats.PacketPoolMisses = atomic.LoadInt64(&dt.liveStats.PoolMisses)
	
	stats.SuccessRate = float64(stats.SuccessfulRequests) / float64(stats.TotalRequests) * 100
	stats.TotalTime = totalTime
	stats.RequestsPerSecond = float64(stats.TotalRequests) / totalTime.Seconds()
	
	if len(responseTimes) > 0 {
		sort.Slice(responseTimes, func(i, j int) bool {
			return responseTimes[i] < responseTimes[j]
		})
		
		stats.MinResponseTime = responseTimes[0]
		stats.MaxResponseTime = responseTimes[len(responseTimes)-1]
		
		var total time.Duration
		for _, rt := range responseTimes {
			total += rt
		}
		stats.AvgResponseTime = total / time.Duration(len(responseTimes))
		
		stats.MedianResponseTime = responseTimes[len(responseTimes)/2]
		stats.P95ResponseTime = responseTimes[int(float64(len(responseTimes))*0.95)]
		stats.P99ResponseTime = responseTimes[int(float64(len(responseTimes))*0.99)]
	}
	
	if totalRetries > 0 {
		stats.ErrorCounts[fmt.Sprintf("재시도 - 총 %d회 (Discover: %d회, Request: %d회)", 
			totalRetries, discoverRetries, requestRetries)] = totalRetries
	}
	
	return stats
}

// 통계 출력 (확장됨)
func (stats *Statistics) PrintReport() {
	fmt.Printf("\n%s\n", strings.Repeat("=", 80))
	fmt.Printf("DHCP 서버 성능 테스트 결과 (보안 강화 및 성능 최적화)\n")
	fmt.Printf("%s\n", strings.Repeat("=", 80))
	fmt.Printf("각 클라이언트 수행 과정: Discover → Offer → Request → ACK\n")
	fmt.Printf("%s\n", strings.Repeat("-", 80))
	
	// 기본 통계
	fmt.Printf("%-25s %15d\n", "총 요청 수:", stats.TotalRequests)
	fmt.Printf("%-25s %15d\n", "성공 요청 수:", stats.SuccessfulRequests)
	fmt.Printf("%-25s %15d\n", "실패 요청 수:", stats.FailedRequests)
	fmt.Printf("%-25s %14.1f%%\n", "성공률:", stats.SuccessRate)
	fmt.Printf("%-25s %15v\n", "총 테스트 시간:", stats.TotalTime)
	fmt.Printf("%-25s %14.1f req/s\n", "초당 완료 수:", stats.RequestsPerSecond)
	
	// 보안 통계
	if stats.SecurityBlocked > 0 || stats.RateLimited > 0 {
		fmt.Printf("\n%s\n", strings.Repeat("-", 80))
		fmt.Printf("보안 통계\n")
		fmt.Printf("%s\n", strings.Repeat("-", 80))
		if stats.SecurityBlocked > 0 {
			fmt.Printf("%-25s %15d\n", "보안 차단:", stats.SecurityBlocked)
		}
		if stats.RateLimited > 0 {
			fmt.Printf("%-25s %15d\n", "Rate Limit 차단:", stats.RateLimited)
		}
		if stats.InvalidMACs > 0 {
			fmt.Printf("%-25s %15d\n", "잘못된 MAC:", stats.InvalidMACs)
		}
		if stats.DuplicateXIDs > 0 {
			fmt.Printf("%-25s %15d\n", "중복 XID:", stats.DuplicateXIDs)
		}
	}
	
	// 성능 통계
	if stats.PacketPoolHits > 0 || stats.ConnectionReused > 0 {
		fmt.Printf("\n%s\n", strings.Repeat("-", 80))
		fmt.Printf("성능 최적화 통계\n")
		fmt.Printf("%s\n", strings.Repeat("-", 80))
		
		if stats.PacketPoolHits > 0 || stats.PacketPoolMisses > 0 {
			total := stats.PacketPoolHits + stats.PacketPoolMisses
			hitRate := float64(stats.PacketPoolHits) / float64(total) * 100
			fmt.Printf("%-25s %15d\n", "패킷 풀 Hit:", stats.PacketPoolHits)
			fmt.Printf("%-25s %15d\n", "패킷 풀 Miss:", stats.PacketPoolMisses)
			fmt.Printf("%-25s %14.1f%%\n", "패킷 풀 Hit Rate:", hitRate)
		}
		
		if stats.ConnectionReused > 0 {
			reuseRate := float64(stats.ConnectionReused) / float64(stats.TotalRequests) * 100
			fmt.Printf("%-25s %15d\n", "연결 재사용:", stats.ConnectionReused)
			fmt.Printf("%-25s %14.1f%%\n", "연결 재사용률:", reuseRate)
		}
		
		if stats.MemoryAllocated > 0 {
			memoryMB := stats.MemoryAllocated / 1024 / 1024
			fmt.Printf("%-25s %12dMB\n", "메모리 사용량:", memoryMB)
		}
	}
	
	// Relay Agent 통계
	if stats.RelayTests > 0 {
		fmt.Printf("\n%s\n", strings.Repeat("-", 80))
		fmt.Printf("Relay Agent 통계\n")
		fmt.Printf("%s\n", strings.Repeat("-", 80))
		fmt.Printf("%-25s %15d\n", "Relay 테스트 수:", stats.RelayTests)
		fmt.Printf("%-25s %15d\n", "직접 테스트 수:", stats.TotalRequests-stats.RelayTests)
	}
	
	// 응답 시간 통계
	if stats.SuccessfulRequests > 0 {
		fmt.Printf("\n%s\n", strings.Repeat("-", 80))
		fmt.Printf("DHCP 4-way Handshake 응답 시간 통계\n")
		fmt.Printf("%s\n", strings.Repeat("-", 80))
		fmt.Printf("%-25s %15v\n", "최소 응답 시간:", stats.MinResponseTime)
		fmt.Printf("%-25s %15v\n", "최대 응답 시간:", stats.MaxResponseTime)
		fmt.Printf("%-25s %15v\n", "평균 응답 시간:", stats.AvgResponseTime)
		fmt.Printf("%-25s %15v\n", "중간값 응답 시간:", stats.MedianResponseTime)
		fmt.Printf("%-25s %15v\n", "95퍼센타일:", stats.P95ResponseTime)
		fmt.Printf("%-25s %15v\n", "99퍼센타일:", stats.P99ResponseTime)
		
		fmt.Printf("\n💡 참고: 위 시간은 각 클라이언트가 IP 주소를 완전히 획득하는데\n")
		fmt.Printf("   걸린 전체 시간입니다 (Discover → Offer → Request → ACK)\n")
	}
	
	// 에러 통계
	if stats.FailedRequests > 0 {
		fmt.Printf("\n%s\n", strings.Repeat("-", 80))
		fmt.Printf("실패 원인 분석\n")
		fmt.Printf("%s\n", strings.Repeat("-", 80))
		for error, count := range stats.ErrorCounts {
			fmt.Printf("%-50s: %d건\n", error, count)
		}
	}
	
	// 성능 요약
	fmt.Printf("\n%s\n", strings.Repeat("-", 80))
	fmt.Printf("성능 요약\n")
	fmt.Printf("%s\n", strings.Repeat("-", 80))
	
	if stats.TotalTime.Seconds() > 0 {
		avgRps := float64(stats.TotalRequests) / stats.TotalTime.Seconds()
		successRps := float64(stats.SuccessfulRequests) / stats.TotalTime.Seconds()
		
		fmt.Printf("%-25s %14.1f req/s\n", "평균 요청 처리율:", avgRps)
		fmt.Printf("%-25s %14.1f req/s\n", "성공 요청 처리율:", successRps)
		
		if stats.SuccessfulRequests > 0 {
			avgLatency := stats.AvgResponseTime.Milliseconds()
			fmt.Printf("%-25s %12dms\n", "평균 지연 시간:", avgLatency)
		}
	}
}

func (dt *DHCPTester) Cleanup() {
	if dt.securityLogger != nil {
		dt.securityLogger.Close()
		dt.securityLogger = nil
	}
	
	if dt.workerPool != nil {
		dt.workerPool.Stop()
		dt.workerPool = nil
	}
	
	if dt.connectionPool != nil {
		dt.connectionPool.Close()
		dt.connectionPool = nil
	}
	
	if dt.verbose {
		fmt.Println("리소스 정리 완료")
	}
}

// 테스터 설정 검증
func (dt *DHCPTester) validateConfig() error {
	// 보안 설정 검증
	if dt.securityConfig.Enabled {
		if dt.securityConfig.MaxRequestsPerMinute < 1 || dt.securityConfig.MaxRequestsPerMinute > 10000 {
			return fmt.Errorf("잘못된 Rate Limit 설정: %d (1-10000 범위)", dt.securityConfig.MaxRequestsPerMinute)
		}
	}
	
	// 성능 설정 검증
	if dt.performanceConfig.WorkerPoolSize < 1 || dt.performanceConfig.WorkerPoolSize > 1000 {
		return fmt.Errorf("잘못된 워커 풀 크기: %d (1-1000 범위)", dt.performanceConfig.WorkerPoolSize)
	}
	
	if dt.performanceConfig.ConnectionPoolSize < 1 || dt.performanceConfig.ConnectionPoolSize > 1000 {
		return fmt.Errorf("잘못된 연결 풀 크기: %d (1-1000 범위)", dt.performanceConfig.ConnectionPoolSize)
	}
	
	return nil
}

func main() {
	// 권한 확인
	checkPrivileges()
	
	// 명령행 플래그 정의
	var (
		serverIP    = flag.String("server", "255.255.255.255", "DHCP 서버 IP 주소")
		serverPort  = flag.Int("port", 67, "DHCP 서버 포트")
		numClients  = flag.Int("clients", 100, "테스트할 클라이언트 수")
		concurrency = flag.Int("concurrency", 10, "동시 실행 수")
		timeout     = flag.Duration("timeout", 5*time.Second, "응답 대기 시간")
		showProgress = flag.Bool("progress", true, "진행상황 표시")
		verbose     = flag.Bool("verbose", false, "상세 DHCP 과정 출력")
		liveStats   = flag.Bool("live", false, "실시간 대시보드 모니터링")
		seed        = flag.Int64("seed", 0, "랜덤 시드 (0은 현재 시간)")
		
		// Relay Agent 관련 플래그
		relayEnabled  = flag.Bool("relay", false, "DHCP Relay Agent 모드 활성화")
		relayIP       = flag.String("relay-ip", "", "Relay Agent IP 주소")
		relayCircuitID = flag.String("circuit-id", "", "Relay Agent Circuit ID")
		relayRemoteID  = flag.String("remote-id", "", "Relay Agent Remote ID")
		relayHops      = flag.Int("hops", 1, "Relay Agent Hop Count")
		relayMaxHops   = flag.Int("max-hops", 4, "최대 허용 Hop Count")
		
		// 재시도 관련 플래그
		retryEnabled       = flag.Bool("retry", false, "패킷 재시도 활성화")
		maxDiscoverRetries = flag.Int("max-discover-retries", 3, "Discover 최대 재시도 횟수")
		maxRequestRetries  = flag.Int("max-request-retries", 3, "Request 최대 재시도 횟수")
		initialTimeout     = flag.Duration("initial-timeout", 4*time.Second, "초기 재시도 타임아웃")
		maxTimeout         = flag.Duration("max-timeout", 64*time.Second, "최대 재시도 타임아웃")
		backoffMultiplier  = flag.Float64("backoff-multiplier", 2.0, "지수 백오프 배수")
		disableJitter      = flag.Bool("disable-jitter", false, "재시도 지터 비활성화")
		
		// 보안 관련 플래그 (새로 추가)
		enableSecurity     = flag.Bool("security", true, "보안 기능 활성화")
		enableRateLimit    = flag.Bool("rate-limit", true, "Rate limiting 활성화")
		maxReqPerMin       = flag.Int("max-req-per-min", 60, "분당 최대 요청 수")
		enableMACValidation = flag.Bool("mac-validation", true, "MAC 주소 검증")
		enableXIDCheck     = flag.Bool("xid-check", true, "중복 XID 검사")
		securityLogFile    = flag.String("security-log", "", "보안 이벤트 로그 파일")
		
		// 성능 관련 플래그 (새로 추가)
		enablePacketPool   = flag.Bool("packet-pool", true, "패킷 풀링 활성화")
		workerPoolSize     = flag.Int("worker-pool-size", 10, "워커 풀 크기")
		connectionPoolSize = flag.Int("conn-pool-size", 50, "연결 풀 크기")
		enableConnReuse    = flag.Bool("conn-reuse", true, "연결 재사용 활성화")
		enableMemOptim     = flag.Bool("mem-optim", true, "메모리 최적화")
		enableCache        = flag.Bool("cache", true, "패킷 캐싱 활성화")
		
		// 권한 관련 플래그
		forceRoot     = flag.Bool("require-root", false, "Root 권한 강제 요구")
		skipPrivCheck = flag.Bool("skip-priv-check", false, "권한 확인 건너뛰기")
	)
	flag.Parse()
	
	// Root 권한 강제 확인
	if *forceRoot {
		currentUser, err := user.Current()
		if err != nil || currentUser.Uid != "0" {
			log.Fatal("❌ 이 옵션은 root 권한이 필요합니다")
		}
	}
	
	// 포트 68 바인딩 테스트
	if !*skipPrivCheck {
		if testPortBinding(68) {
			fmt.Printf("✅ 포트 68 바인딩 가능 - 실제 DHCP 클라이언트 포트 사용 가능\n")
		} else {
			fmt.Printf("⚠️  포트 68 바인딩 실패 - 시뮬레이션 모드로 동작\n")
		}
		fmt.Println()
	}
	
	// 랜덤 시드 설정
	if *seed == 0 {
		rand.Seed(time.Now().UnixNano())
	} else {
		rand.Seed(*seed)
	}
	
	// 입력 검증
	if *numClients <= 0 {
		log.Fatal("클라이언트 수는 1 이상이어야 합니다")
	}
	if *concurrency <= 0 {
		log.Fatal("동시 실행 수는 1 이상이어야 합니다")
	}
	if *concurrency > *numClients {
		*concurrency = *numClients
	}
	
	// Relay Agent 검증
	if *relayEnabled {
		if *relayIP == "" {
			log.Fatal("Relay 모드에서는 relay-ip가 필요합니다")
		}
		if *relayHops < 0 || *relayHops > 255 {
			log.Fatal("Hop count는 0-255 범위여야 합니다")
		}
		if *relayMaxHops < 1 || *relayMaxHops > 255 {
			log.Fatal("Max hops는 1-255 범위여야 합니다")
		}
		if *relayHops >= *relayMaxHops {
			log.Fatal("Hop count가 max hops보다 작아야 합니다")
		}
	}
	
	// 재시도 설정 검증
	if *retryEnabled {
		if *maxDiscoverRetries < 0 || *maxDiscoverRetries > 10 {
			log.Fatal("Discover 재시도 횟수는 0-10 범위여야 합니다")
		}
		if *maxRequestRetries < 0 || *maxRequestRetries > 10 {
			log.Fatal("Request 재시도 횟수는 0-10 범위여야 합니다")
		}
		if *initialTimeout < time.Second || *initialTimeout > time.Minute {
			log.Fatal("초기 타임아웃은 1초-1분 범위여야 합니다")
		}
		if *maxTimeout < *initialTimeout || *maxTimeout > 5*time.Minute {
			log.Fatal("최대 타임아웃은 초기 타임아웃보다 크고 5분 이하여야 합니다")
		}
		if *backoffMultiplier < 1.0 || *backoffMultiplier > 10.0 {
			log.Fatal("백오프 배수는 1.0-10.0 범위여야 합니다")
		}
	}
	
	// 보안 설정 검증
	if *enableSecurity {
		if *maxReqPerMin < 1 || *maxReqPerMin > 10000 {
			log.Fatal("분당 최대 요청 수는 1-10000 범위여야 합니다")
		}
	}
	
	// 성능 설정 검증
	if *workerPoolSize < 1 || *workerPoolSize > 1000 {
		log.Fatal("워커 풀 크기는 1-1000 범위여야 합니다")
	}
	if *connectionPoolSize < 1 || *connectionPoolSize > 1000 {
		log.Fatal("연결 풀 크기는 1-1000 범위여야 합니다")
	}
	
	// 테스터 생성
	tester := NewDHCPTester(*serverIP, *serverPort, *timeout)
	defer tester.Cleanup()
	
	// 기본 설정
	tester.SetVerbose(*verbose)
	tester.SetLiveStats(*liveStats)
	
	// 재시도 설정
	if *retryEnabled {
		retryConfig := &RetryConfig{
			Enabled:           true,
			MaxDiscoverRetries: *maxDiscoverRetries,
			MaxRequestRetries:  *maxRequestRetries,
			InitialTimeout:    *initialTimeout,
			MaxTimeout:        *maxTimeout,
			BackoffMultiplier: *backoffMultiplier,
			Jitter:           !*disableJitter,
		}
		tester.SetRetryConfig(retryConfig)
		
		fmt.Printf("🔄 재시도 모드: RFC 2131 준수 지수 백오프\n")
		fmt.Printf("   최대 재시도: Discover %d회, Request %d회\n", *maxDiscoverRetries, *maxRequestRetries)
		fmt.Printf("   타임아웃: %v → %v (배수: %.1f)\n", *initialTimeout, *maxTimeout, *backoffMultiplier)
		if !*disableJitter {
			fmt.Printf("   지터: 활성화 (네트워크 혼잡 방지)\n")
		}
		fmt.Println()
	}
	
	// 보안 설정
	if *enableSecurity {
		securityConfig := &SecurityConfig{
			Enabled:          true,
			RateLimitEnabled: *enableRateLimit,
			MaxRequestsPerMinute: *maxReqPerMin,
			MACValidation:    *enableMACValidation,
			DuplicateXIDCheck: *enableXIDCheck,
			LogSecurityEvents: *securityLogFile != "",
			LogFile:          *securityLogFile,
		}
		tester.SetSecurityConfig(securityConfig)
		
		fmt.Printf("🔒 보안 강화 모드: 활성화\n")
		if *enableRateLimit {
			fmt.Printf("   Rate Limiting: %d 요청/분\n", *maxReqPerMin)
		}
		if *enableMACValidation {
			fmt.Printf("   MAC 주소 검증: 활성화\n")
		}
		if *enableXIDCheck {
			fmt.Printf("   중복 XID 검사: 활성화\n")
		}
		if *securityLogFile != "" {
			fmt.Printf("   보안 로그: %s\n", *securityLogFile)
		}
		fmt.Println()
	}
	
	// 성능 설정
	if *enablePacketPool || *enableConnReuse {
		performanceConfig := &PerformanceConfig{
			PacketPoolEnabled:  *enablePacketPool,
			WorkerPoolSize:     *workerPoolSize,
			ConnectionPoolSize: *connectionPoolSize,
			ConnectionReuse:    *enableConnReuse,
			MemoryOptimization: *enableMemOptim,
			CacheEnabled:      *enableCache,
		}
		tester.SetPerformanceConfig(performanceConfig)
		
		fmt.Printf("⚡ 성능 최적화: 활성화\n")
		if *enablePacketPool {
			fmt.Printf("   패킷 풀링: 활성화\n")
		}
		fmt.Printf("   워커 풀: %d개\n", *workerPoolSize)
		if *enableConnReuse {
			fmt.Printf("   연결 재사용: 활성화 (풀 크기: %d)\n", *connectionPoolSize)
		}
		if *enableMemOptim {
			fmt.Printf("   메모리 최적화: 활성화\n")
		}
		if *enableCache {
			fmt.Printf("   패킷 캐싱: 활성화\n")
		}
		fmt.Println()
	}
	
	// Relay Agent 설정
	if *relayEnabled {
		relayConfig := &RelayConfig{
			Enabled:   true,
			RelayIP:   *relayIP,
			CircuitID: *relayCircuitID,
			RemoteID:  *relayRemoteID,
			HopCount:  uint8(*relayHops),
			MaxHops:   uint8(*relayMaxHops),
		}
		tester.SetRelayConfig(relayConfig)
		
		fmt.Printf("🔄 Relay Agent 모드: 활성화\n")
		fmt.Printf("   Relay IP: %s, Hops: %d/%d\n", *relayIP, *relayHops, *relayMaxHops)
		if *relayCircuitID != "" {
			fmt.Printf("   Circuit ID: %s\n", *relayCircuitID)
		}
		if *relayRemoteID != "" {
			fmt.Printf("   Remote ID: %s\n", *relayRemoteID)
		}
		fmt.Println()
	}
	
	// 설정 검증
	if err := tester.validateConfig(); err != nil {
		log.Fatalf("설정 오류: %v", err)
	}
	
	// Live 모드와 Verbose 모드 동시 사용 방지
	if *liveStats && *verbose {
		fmt.Printf("⚠️  Live 모드와 Verbose 모드는 동시에 사용할 수 없습니다. Live 모드를 우선합니다.\n")
		tester.SetVerbose(false)
		fmt.Println()
	}
	
	// 모드 안내 메시지
	if *liveStats {
		fmt.Printf("📊 실시간 대시보드 모드: DHCP 4-way handshake + 보안/성능 통계 실시간 모니터링\n")
		fmt.Printf("   D-O, R-A 응답시간, 보안 차단, 성능 메트릭을 실시간 표시합니다\n\n")
	} else if *verbose {
		fmt.Printf("🔍 Verbose 모드: 각 클라이언트의 DHCP 과정을 상세히 표시합니다\n")
		fmt.Printf("   Discover → Offer → Request → ACK + 보안/성능 정보\n")
		if *retryEnabled {
			fmt.Printf("   재시도 과정도 상세히 표시됩니다\n")
		}
		fmt.Println()
	}
	
	// 테스트 실행
	fmt.Printf("🚀 테스트 시작...\n\n")
	stats := tester.RunPerformanceTest(*numClients, *concurrency, *showProgress)
	
	// 결과 출력
	stats.PrintReport()
	
	// 추가 성능 정보 출력
	if *enableSecurity || *enablePacketPool {
		fmt.Printf("\n%s\n", strings.Repeat("=", 80))
		fmt.Printf("추가 성능 정보\n")
		fmt.Printf("%s\n", strings.Repeat("=", 80))
		
		if tester.rateLimiter != nil {
			rateLimitStats := tester.rateLimiter.GetStats()
			if len(rateLimitStats) > 0 {
				fmt.Printf("Rate Limiter 상태:\n")
				for clientID, count := range rateLimitStats {
					fmt.Printf("  %s: %d개 활성 요청\n", clientID, count)
				}
			}
		}
		
		fmt.Printf("테스트 시간: %v\n", time.Since(tester.startTime))
		fmt.Printf("최종 메모리 사용량: %dMB\n", atomic.LoadInt64(&tester.memoryUsage)/1024/1024)
	}
	
	fmt.Printf("\n✅ 모든 테스트가 완료되었습니다!\n")
}
