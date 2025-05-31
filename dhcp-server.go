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
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// DHCP 메시지 타입
const (
	DHCPDiscover = 1
	DHCPOffer    = 2
	DHCPRequest  = 3
	DHCPDecline  = 4
	DHCPAck      = 5
	DHCPNak      = 6
	DHCPRelease  = 7
	DHCPInform   = 8
)

// DHCP 옵션 코드
const (
	DHCPMessageType       = 53
	DHCPClientID          = 61
	DHCPRequestedIP       = 50
	DHCPServerID          = 54
	DHCPLeaseTime         = 51
	DHCPSubnetMask        = 1
	DHCPRouter            = 3
	DHCPDomainNameServer  = 6
	DHCPDomainName        = 15
	DHCPRelayAgentInfo    = 82
	DHCPEnd               = 255
)

// Relay Agent Sub-options
const (
	RelayAgentCircuitID = 1
	RelayAgentRemoteID  = 2
)

// 보안 이벤트 타입
type SecurityEventType int

const (
	SecurityEventRateLimit SecurityEventType = iota
	SecurityEventInvalidMAC
	SecurityEventDuplicateXID
	SecurityEventIPSpoofing
	SecurityEventSuspiciousPattern
	SecurityEventDDoSAttempt
)

// === 보안 강화: Rate Limiter ===
type RateLimiter struct {
	requests    map[string][]time.Time
	mutex       sync.RWMutex
	maxRate     int
	window      time.Duration
	globalCount int64
	globalLimit int64
}

func NewRateLimiter(maxRate int, window time.Duration, globalLimit int64) *RateLimiter {
	return &RateLimiter{
		requests:    make(map[string][]time.Time),
		maxRate:     maxRate,
		window:      window,
		globalLimit: globalLimit,
	}
}

func (rl *RateLimiter) IsAllowed(clientIP string) (bool, string) {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()
	
	now := time.Now()
	
	// 글로벌 레이트 리미트 확인
	if rl.globalLimit > 0 && atomic.LoadInt64(&rl.globalCount) >= rl.globalLimit {
		return false, "global_rate_limit"
	}
	
	requests, exists := rl.requests[clientIP]
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
	
	// IP별 요청 제한 확인
	if len(validRequests) >= rl.maxRate {
		return false, "ip_rate_limit"
	}
	
	// 새 요청 기록 추가
	validRequests = append(validRequests, now)
	rl.requests[clientIP] = validRequests
	
	atomic.AddInt64(&rl.globalCount, 1)
	
	// 글로벌 카운터 주기적 리셋 (별도 고루틴에서 처리하는 것이 더 좋지만 단순화)
	go func() {
		time.Sleep(rl.window)
		atomic.AddInt64(&rl.globalCount, -1)
	}()
	
	return true, ""
}

func (rl *RateLimiter) GetStats() (ipStats map[string]int, globalCount int64) {
	rl.mutex.RLock()
	defer rl.mutex.RUnlock()
	
	stats := make(map[string]int)
	now := time.Now()
	
	for clientIP, requests := range rl.requests {
		activeRequests := 0
		for _, reqTime := range requests {
			if now.Sub(reqTime) <= rl.window {
				activeRequests++
			}
		}
		if activeRequests > 0 {
			stats[clientIP] = activeRequests
		}
	}
	
	return stats, atomic.LoadInt64(&rl.globalCount)
}

// === 보안 강화: 보안 로거 ===
type SecurityLogger struct {
	logFile   *os.File
	events    []SecurityEvent
	mutex     sync.Mutex
	enabled   bool
}

type SecurityEvent struct {
	Timestamp time.Time              `json:"timestamp"`
	Type      SecurityEventType      `json:"type"`
	ClientIP  string                 `json:"client_ip"`
	ClientMAC string                 `json:"client_mac,omitempty"`
	Details   map[string]interface{} `json:"details"`
	Severity  string                 `json:"severity"`
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

func (sl *SecurityLogger) LogEvent(eventType SecurityEventType, clientIP, clientMAC string, details map[string]interface{}) {
	if !sl.enabled {
		return
	}
	
	event := SecurityEvent{
		Timestamp: time.Now().UTC(),
		Type:      eventType,
		ClientIP:  clientIP,
		ClientMAC: clientMAC,
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
	case SecurityEventIPSpoofing:
		return "CRITICAL"
	case SecurityEventDDoSAttempt:
		return "CRITICAL"
	case SecurityEventSuspiciousPattern:
		return "HIGH"
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
	processed   int64
	dropped     int64
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
			atomic.AddInt64(&wp.processed, 1)
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
		atomic.AddInt64(&wp.dropped, 1)
		return false // 큐가 가득 함
	}
}

func (wp *WorkerPool) Stop() {
	atomic.StoreInt64(&wp.running, 0)
	close(wp.quit)
	wp.wg.Wait()
}

func (wp *WorkerPool) GetStats() (queueSize int, processed, dropped int64, isRunning bool) {
	return len(wp.jobQueue), 
		   atomic.LoadInt64(&wp.processed),
		   atomic.LoadInt64(&wp.dropped),
		   atomic.LoadInt64(&wp.running) == 1
}

// === 성능 최적화: 최적화된 IP 풀 ===
type OptimizedIPPool struct {
	availableIPs  map[uint32]*IPPoolEntry // 사용 가능한 IP들
	leasedIPs     map[uint32]*IPPoolEntry // 임대된 IP들
	macToIP       map[string]uint32       // MAC -> IP 매핑
	ipToMAC       map[uint32]string       // IP -> MAC 매핑 (빠른 조회)
	mutex         sync.RWMutex
	startIP       uint32
	endIP         uint32
	totalCount    int32
	leasedCount   int32
}

type IPPoolEntry struct {
	IP        net.IP
	Available bool
	LeaseTime time.Time
	ClientMAC [6]byte
	ClientID  string
	LastSeen  time.Time
}

func NewOptimizedIPPool(startIP, endIP net.IP) *OptimizedIPPool {
	start := ipToUint32(startIP)
	end := ipToUint32(endIP)
	
	pool := &OptimizedIPPool{
		availableIPs: make(map[uint32]*IPPoolEntry),
		leasedIPs:    make(map[uint32]*IPPoolEntry),
		macToIP:      make(map[string]uint32),
		ipToMAC:      make(map[uint32]string),
		startIP:      start,
		endIP:        end,
		totalCount:   int32(end - start + 1),
	}
	
	// 사용 가능한 IP 초기화
	for ip := start; ip <= end; ip++ {
		entry := &IPPoolEntry{
			IP:        uint32ToIP(ip),
			Available: true,
		}
		pool.availableIPs[ip] = entry
	}
	
	return pool
}

func (pool *OptimizedIPPool) AllocateIP(clientMAC [6]byte, clientID string) net.IP {
	pool.mutex.Lock()
	defer pool.mutex.Unlock()
	
	macStr := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", 
		clientMAC[0], clientMAC[1], clientMAC[2], clientMAC[3], clientMAC[4], clientMAC[5])
	
	// 기존 할당 확인
	if existingIP, exists := pool.macToIP[macStr]; exists {
		if entry, found := pool.leasedIPs[existingIP]; found {
			if time.Since(entry.LeaseTime) < 24*time.Hour { // lease time
				entry.LastSeen = time.Now()
				return entry.IP
			}
			// 만료된 경우 해제
			pool.releaseIPInternal(existingIP, macStr)
		}
	}
	
	// 새 IP 할당 (가장 빠른 IP 선택)
	for ip, entry := range pool.availableIPs {
		delete(pool.availableIPs, ip)
		entry.Available = false
		entry.ClientMAC = clientMAC
		entry.ClientID = clientID
		entry.LeaseTime = time.Now()
		entry.LastSeen = time.Now()
		
		pool.leasedIPs[ip] = entry
		pool.macToIP[macStr] = ip
		pool.ipToMAC[ip] = macStr
		
		atomic.AddInt32(&pool.leasedCount, 1)
		
		return entry.IP
	}
	
	return nil // 풀 고갈
}

func (pool *OptimizedIPPool) ReleaseIP(ip net.IP) {
	ipUint := ipToUint32(ip)
	pool.mutex.Lock()
	defer pool.mutex.Unlock()
	
	if macStr, exists := pool.ipToMAC[ipUint]; exists {
		pool.releaseIPInternal(ipUint, macStr)
	}
}

func (pool *OptimizedIPPool) releaseIPInternal(ip uint32, macStr string) {
	if entry, exists := pool.leasedIPs[ip]; exists {
		delete(pool.leasedIPs, ip)
		delete(pool.macToIP, macStr)
		delete(pool.ipToMAC, ip)
		
		entry.Available = true
		entry.ClientMAC = [6]byte{}
		entry.ClientID = ""
		
		pool.availableIPs[ip] = entry
		atomic.AddInt32(&pool.leasedCount, -1)
	}
}

func (pool *OptimizedIPPool) GetStats() (total, available, leased int32, utilizationPct float64) {
	total = pool.totalCount
	leased = atomic.LoadInt32(&pool.leasedCount)
	available = total - leased
	
	if total > 0 {
		utilizationPct = float64(leased) / float64(total) * 100
	}
	
	return
}

func (pool *OptimizedIPPool) CleanupExpired(leaseTime time.Duration) int {
	pool.mutex.Lock()
	defer pool.mutex.Unlock()
	
	now := time.Now()
	expired := 0
	
	for ip, entry := range pool.leasedIPs {
		if now.Sub(entry.LeaseTime) > leaseTime {
			macStr := pool.ipToMAC[ip]
			pool.releaseIPInternal(ip, macStr)
			expired++
		}
	}
	
	return expired
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

// 클라이언트 세션 정보 (확장됨)
type ClientSession struct {
	TransactionID uint32
	ClientMAC     [6]byte
	ClientID      string
	ClientIP      string
	OfferedIP     net.IP
	OfferTime     time.Time
	State         string // "offered", "leased", "expired"
	RelayIP       net.IP
	CircuitID     string
	RemoteID      string
	
	// 보안 정보
	FirstSeen     time.Time
	LastSeen      time.Time
	RequestCount  int64
	SecurityFlags []string
	
	// 성능 정보
	ProcessingTime time.Duration
	PacketSize     int
}

// 서버 통계 (확장됨)
type ServerStats struct {
	// 패킷 카운터 (atomic)
	DiscoverReceived int64
	OfferSent       int64
	RequestReceived int64
	AckSent         int64
	NakSent         int64
	
	// 보안 카운터 (atomic)
	SecurityBlocked  int64
	RateLimited     int64
	InvalidMACs     int64
	DuplicateXIDs   int64
	IPSpoofing      int64
	
	// 성능 카운터 (atomic)
	PacketPoolHits   int64
	PacketPoolMisses int64
	WorkerPoolJobs   int64
	WorkerPoolDropped int64
	
	// 성능 지표
	mutex           sync.RWMutex
	ProcessingTimes []time.Duration
	
	// 에러 카운터
	ParseErrors     int64
	PoolExhausted   int64
	InvalidRequests int64
	
	StartTime       time.Time
	TotalMemoryUsed int64
}

// 서버 설정 (확장됨)
type ServerConfig struct {
	ListenIP     string
	ListenPort   int
	StartIP      net.IP
	EndIP        net.IP
	SubnetMask   net.IP
	Gateway      net.IP
	DNSServers   []net.IP
	DomainName   string
	LeaseTime    time.Duration
	OfferTimeout time.Duration
	
	// 성능 제한
	MaxConcurrent    int
	ResponseDelay    time.Duration
	DropRate         float64
	
	// Relay Agent 지원
	SupportRelay     bool
	MaxHops          uint8
	
	// 보안 설정
	SecurityEnabled     bool
	RateLimitEnabled    bool
	MaxRequestsPerMin   int
	GlobalRateLimit     int64
	MACValidation       bool
	DuplicateXIDCheck   bool
	IPSpoofingCheck     bool
	SecurityLogFile     string
	
	// 성능 설정
	PacketPoolEnabled   bool
	WorkerPoolSize      int
	WorkerQueueSize     int
	MemoryOptimization  bool
	CacheEnabled        bool
	CleanupInterval     time.Duration
}

// DHCP 서버 구조체 (대폭 개선됨)
type DHCPServer struct {
	config       *ServerConfig
	ipPool       *OptimizedIPPool
	sessions     map[uint32]*ClientSession
	sessionMutex sync.RWMutex
	stats        *ServerStats
	running      bool
	runMutex     sync.RWMutex
	
	conn         *net.UDPConn
	verbose      bool
	showLiveStats bool
	
	// 보안 구성요소
	rateLimiter    *RateLimiter
	securityLogger *SecurityLogger
	xidCache       map[uint32]time.Time
	xidCacheMutex  sync.RWMutex
	
	// 성능 구성요소
	packetPool     *PacketPool
	workerPool     *WorkerPool
	packetCache    map[string]*DHCPPacket
	packetCacheMutex sync.RWMutex
	
	// 메모리 관리
	memoryUsage    int64
}

// 기본 서버 설정 (확장됨)
func NewServerConfig() *ServerConfig {
	return &ServerConfig{
		ListenIP:      "0.0.0.0",
		ListenPort:    67,
		StartIP:       net.ParseIP("192.168.100.10"),
		EndIP:         net.ParseIP("192.168.100.250"),
		SubnetMask:    net.ParseIP("255.255.255.0"),
		Gateway:       net.ParseIP("192.168.100.1"),
		DNSServers:    []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4")},
		DomainName:    "example.com",
		LeaseTime:     24 * time.Hour,
		OfferTimeout:  30 * time.Second,
		MaxConcurrent: 1000,
		ResponseDelay: 0,
		DropRate:      0.0,
		SupportRelay:  true,
		MaxHops:       4,
		
		// 보안 설정 기본값
		SecurityEnabled:     true,
		RateLimitEnabled:    true,
		MaxRequestsPerMin:   100,
		GlobalRateLimit:     1000,
		MACValidation:       true,
		DuplicateXIDCheck:   true,
		IPSpoofingCheck:     true,
		
		// 성능 설정 기본값
		PacketPoolEnabled:   true,
		WorkerPoolSize:      runtime.NumCPU() * 2,
		WorkerQueueSize:     1000,
		MemoryOptimization:  true,
		CacheEnabled:        true,
		CleanupInterval:     5 * time.Minute,
	}
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

// 새로운 DHCP 서버 생성 (개선됨)
func NewDHCPServer(config *ServerConfig) *DHCPServer {
	server := &DHCPServer{
		config:   config,
		sessions: make(map[uint32]*ClientSession),
		stats: &ServerStats{
			StartTime:       time.Now(),
			ProcessingTimes: make([]time.Duration, 0),
		},
		running:      false,
		xidCache:     make(map[uint32]time.Time),
		packetCache:  make(map[string]*DHCPPacket),
	}
	
	// IP 풀 초기화
	server.ipPool = NewOptimizedIPPool(config.StartIP, config.EndIP)
	
	// 보안 구성요소 초기화
	if config.SecurityEnabled {
		if config.RateLimitEnabled {
			server.rateLimiter = NewRateLimiter(
				config.MaxRequestsPerMin,
				time.Minute,
				config.GlobalRateLimit,
			)
		}
		
		if config.SecurityLogFile != "" {
			server.securityLogger = NewSecurityLogger(config.SecurityLogFile)
		}
	}
	
	// 성능 구성요소 초기화
	if config.PacketPoolEnabled {
		server.packetPool = NewPacketPool()
	}
	
	if config.WorkerPoolSize > 0 {
		server.workerPool = NewWorkerPool(config.WorkerPoolSize, config.WorkerQueueSize)
	}
	
	fmt.Printf("IP 풀 초기화 완료: %s - %s (%d개 주소)\n", 
		config.StartIP.String(), config.EndIP.String(), 
		ipToUint32(config.EndIP)-ipToUint32(config.StartIP)+1)
	
	return server
}

// IP 주소를 uint32로 변환
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return binary.BigEndian.Uint32(ip)
}

// uint32를 IP 주소로 변환
func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}

// DHCP 패킷 파싱 (캐시 지원)
func (s *DHCPServer) parseDHCPPacket(data []byte) (*DHCPPacket, error) {
	if len(data) < 240 {
		return nil, fmt.Errorf("패킷이 너무 짧습니다")
	}
	
	// 캐시 확인
	if s.config.CacheEnabled {
		packetHash := generatePacketHash(data)
		s.packetCacheMutex.RLock()
		if cachedPacket, exists := s.packetCache[packetHash]; exists {
			s.packetCacheMutex.RUnlock()
			atomic.AddInt64(&s.stats.PacketPoolHits, 1)
			return cachedPacket, nil
		}
		s.packetCacheMutex.RUnlock()
		atomic.AddInt64(&s.stats.PacketPoolMisses, 1)
	}
	
	packet := &DHCPPacket{}
	
	// 헤더 파싱
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
	
	// Magic Cookie 확인
	if len(data) > 240 && bytes.Equal(data[236:240], []byte{0x63, 0x82, 0x53, 0x63}) {
		packet.Options = data[240:]
	}
	
	// 캐시에 저장
	if s.config.CacheEnabled {
		packetHash := generatePacketHash(data)
		s.packetCacheMutex.Lock()
		if len(s.packetCache) > 1000 { // 캐시 크기 제한
			// 간단한 LRU: 첫 번째 항목 제거
			for k := range s.packetCache {
				delete(s.packetCache, k)
				break
			}
		}
		s.packetCache[packetHash] = packet
		s.packetCacheMutex.Unlock()
	}
	
	return packet, nil
}

// DHCP 옵션에서 메시지 타입 추출
func getMessageType(options []byte) (uint8, error) {
	for i := 0; i < len(options); {
		if options[i] == DHCPEnd {
			break
		}
		if options[i] == 0 { // Padding
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

// 클라이언트 ID 추출
func getClientID(options []byte, chaddr [16]byte) string {
	for i := 0; i < len(options); {
		if options[i] == DHCPEnd {
			break
		}
		if options[i] == 0 { // Padding
			i++
			continue
		}
		
		optionCode := options[i]
		if i+1 >= len(options) {
			break
		}
		optionLength := int(options[i+1])
		
		if optionCode == DHCPClientID && optionLength > 0 && i+2+optionLength <= len(options) {
			return fmt.Sprintf("%x", options[i+2:i+2+optionLength])
		}
		
		i += 2 + optionLength
	}
	
	// Client ID가 없으면 MAC 주소 사용
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", 
		chaddr[0], chaddr[1], chaddr[2], chaddr[3], chaddr[4], chaddr[5])
}

// Relay Agent 정보 추출
func getRelayAgentInfo(options []byte) (circuitID, remoteID string) {
	for i := 0; i < len(options); {
		if options[i] == DHCPEnd {
			break
		}
		if options[i] == 0 { // Padding
			i++
			continue
		}
		
		optionCode := options[i]
		if i+1 >= len(options) {
			break
		}
		optionLength := int(options[i+1])
		
		if optionCode == DHCPRelayAgentInfo && i+2+optionLength <= len(options) {
			suboptions := options[i+2 : i+2+optionLength]
			j := 0
			for j < len(suboptions) {
				subCode := suboptions[j]
				if j+1 >= len(suboptions) {
					break
				}
				subLength := int(suboptions[j+1])
				if j+2+subLength > len(suboptions) {
					break
				}
				
				if subCode == RelayAgentCircuitID {
					circuitID = string(suboptions[j+2 : j+2+subLength])
				} else if subCode == RelayAgentRemoteID {
					remoteID = string(suboptions[j+2 : j+2+subLength])
				}
				
				j += 2 + subLength
			}
		}
		
		i += 2 + optionLength
	}
	return
}

// DHCP 응답 패킷 생성 (최적화됨)
func (s *DHCPServer) createResponsePacket(request *DHCPPacket, msgType uint8, offeredIP net.IP, relayAgentInfo []byte) []byte {
	// 패킷 풀에서 버퍼 가져오기
	var packet []byte
	if s.config.PacketPoolEnabled && s.packetPool != nil {
		packet = s.packetPool.Get()
		defer s.packetPool.Put(packet)
		packet = packet[:240] // 기본 DHCP 헤더 크기로 조정
	} else {
		packet = make([]byte, 240)
	}
	
	// DHCP 헤더 설정
	packet[0] = 2 // Op: BOOTREPLY
	packet[1] = request.HType
	packet[2] = request.HLen
	packet[3] = request.Hops
	binary.BigEndian.PutUint32(packet[4:8], request.Xid)
	binary.BigEndian.PutUint16(packet[8:10], 0) // Secs
	binary.BigEndian.PutUint16(packet[10:12], request.Flags)
	
	copy(packet[12:16], request.Ciaddr[:]) // Ciaddr
	if offeredIP != nil {
		copy(packet[16:20], offeredIP.To4()) // Yiaddr
	}
	copy(packet[20:24], s.config.StartIP.To4()) // Siaddr (서버 IP)
	copy(packet[24:28], request.Giaddr[:])      // Giaddr (Relay IP)
	copy(packet[28:44], request.Chaddr[:])      // Client hardware address
	
	// Magic Cookie 추가
	packet = append(packet, 0x63, 0x82, 0x53, 0x63)
	
	// DHCP 옵션 추가
	// Message Type
	packet = append(packet, DHCPMessageType, 1, msgType)
	
	// Server Identifier
	serverIP := s.config.StartIP.To4()
	packet = append(packet, DHCPServerID, 4)
	packet = append(packet, serverIP...)
	
	// Lease Time
	leaseTime := uint32(s.config.LeaseTime.Seconds())
	packet = append(packet, DHCPLeaseTime, 4)
	leaseTimeBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(leaseTimeBytes, leaseTime)
	packet = append(packet, leaseTimeBytes...)
	
	// Subnet Mask
	if s.config.SubnetMask != nil {
		packet = append(packet, DHCPSubnetMask, 4)
		packet = append(packet, s.config.SubnetMask.To4()...)
	}
	
	// Router (Gateway)
	if s.config.Gateway != nil {
		packet = append(packet, DHCPRouter, 4)
		packet = append(packet, s.config.Gateway.To4()...)
	}
	
	// DNS Servers
	if len(s.config.DNSServers) > 0 {
		packet = append(packet, DHCPDomainNameServer, byte(len(s.config.DNSServers)*4))
		for _, dns := range s.config.DNSServers {
			packet = append(packet, dns.To4()...)
		}
	}
	
	// Domain Name
	if s.config.DomainName != "" {
		domainBytes := []byte(s.config.DomainName)
		packet = append(packet, DHCPDomainName, byte(len(domainBytes)))
		packet = append(packet, domainBytes...)
	}
	
	// Relay Agent Information (Option 82) - 요청에 있었다면 그대로 복사
	if relayAgentInfo != nil {
		packet = append(packet, relayAgentInfo...)
	}
	
	// End option
	packet = append(packet, DHCPEnd)
	
	// 메모리 사용량 추적
	atomic.AddInt64(&s.memoryUsage, int64(len(packet)))
	
	return packet
}

// DHCP Discover 처리 (보안 강화됨)
func (s *DHCPServer) handleDiscover(packet *DHCPPacket, clientAddr *net.UDPAddr) {
	start := time.Now()
	atomic.AddInt64(&s.stats.DiscoverReceived, 1)
	
	clientIP := clientAddr.IP.String()
	clientMAC := [6]byte{}
	copy(clientMAC[:], packet.Chaddr[:6])
	
	if s.verbose {
		fmt.Printf("[DISCOVER] XID: 0x%08X, Client: %02x:%02x:%02x:%02x:%02x:%02x, IP: %s\n",
			packet.Xid, clientMAC[0], clientMAC[1], clientMAC[2],
			clientMAC[3], clientMAC[4], clientMAC[5], clientIP)
	}
	
	// 보안 검사: Rate Limiting
	if s.config.SecurityEnabled && s.config.RateLimitEnabled && s.rateLimiter != nil {
		allowed, reason := s.rateLimiter.IsAllowed(clientIP)
		if !allowed {
			atomic.AddInt64(&s.stats.RateLimited, 1)
			atomic.AddInt64(&s.stats.SecurityBlocked, 1)
			
			if s.securityLogger != nil {
				s.securityLogger.LogEvent(SecurityEventRateLimit, clientIP, 
					fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", clientMAC[0], clientMAC[1], clientMAC[2], clientMAC[3], clientMAC[4], clientMAC[5]),
					map[string]interface{}{
						"reason": reason,
						"xid":    fmt.Sprintf("0x%08X", packet.Xid),
					})
			}
			
			if s.verbose {
				fmt.Printf("[DISCOVER] Rate limit exceeded for %s (reason: %s)\n", clientIP, reason)
			}
			return
		}
	}
	
	// 보안 검사: MAC 주소 검증
	if s.config.SecurityEnabled && s.config.MACValidation {
		if !isValidMACAddress(clientMAC) {
			atomic.AddInt64(&s.stats.InvalidMACs, 1)
			atomic.AddInt64(&s.stats.SecurityBlocked, 1)
			
			if s.securityLogger != nil {
				s.securityLogger.LogEvent(SecurityEventInvalidMAC, clientIP,
					fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", clientMAC[0], clientMAC[1], clientMAC[2], clientMAC[3], clientMAC[4], clientMAC[5]),
					map[string]interface{}{
						"mac": fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", clientMAC[0], clientMAC[1], clientMAC[2], clientMAC[3], clientMAC[4], clientMAC[5]),
						"xid": fmt.Sprintf("0x%08X", packet.Xid),
					})
			}
			
			if s.verbose {
				fmt.Printf("[DISCOVER] Invalid MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
					clientMAC[0], clientMAC[1], clientMAC[2], clientMAC[3], clientMAC[4], clientMAC[5])
			}
			return
		}
	}
	
	// 보안 검사: 중복 XID 확인
	if s.config.SecurityEnabled && s.config.DuplicateXIDCheck {
		s.xidCacheMutex.Lock()
		if lastSeen, exists := s.xidCache[packet.Xid]; exists {
			if time.Since(lastSeen) < 10*time.Second { // 10초 내 중복 XID
				s.xidCacheMutex.Unlock()
				atomic.AddInt64(&s.stats.DuplicateXIDs, 1)
				atomic.AddInt64(&s.stats.SecurityBlocked, 1)
				
				if s.securityLogger != nil {
					s.securityLogger.LogEvent(SecurityEventDuplicateXID, clientIP,
						fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", clientMAC[0], clientMAC[1], clientMAC[2], clientMAC[3], clientMAC[4], clientMAC[5]),
						map[string]interface{}{
							"xid":        fmt.Sprintf("0x%08X", packet.Xid),
							"last_seen":  lastSeen,
						})
				}
				
				if s.verbose {
					fmt.Printf("[DISCOVER] Duplicate XID detected: 0x%08X\n", packet.Xid)
				}
				return
			}
		}
		s.xidCache[packet.Xid] = time.Now()
		s.xidCacheMutex.Unlock()
	}
	
	// 드롭 시뮬레이션
	if s.config.DropRate > 0 && rand.Float64() < s.config.DropRate {
		if s.verbose {
			fmt.Printf("[DISCOVER] 패킷 드롭 시뮬레이션 (Drop Rate: %.1f%%)\n", s.config.DropRate*100)
		}
		return
	}
	
	// Client ID 추출
	clientID := getClientID(packet.Options, packet.Chaddr)
	
	// IP 주소 할당
	offeredIP := s.ipPool.AllocateIP(clientMAC, clientID)
	if offeredIP == nil {
		atomic.AddInt64(&s.stats.PoolExhausted, 1)
		if s.verbose {
			fmt.Printf("[DISCOVER] IP 풀 고갈\n")
		}
		return
	}
	
	// Relay Agent 정보 추출
	var relayAgentInfo []byte
	circuitID, remoteID := getRelayAgentInfo(packet.Options)
	if circuitID != "" || remoteID != "" {
		relayAgentInfo = s.preserveRelayAgentInfo(packet.Options)
	}
	
	// 세션 정보 저장 (확장됨)
	session := &ClientSession{
		TransactionID:  packet.Xid,
		ClientMAC:      clientMAC,
		ClientID:       clientID,
		ClientIP:       clientIP,
		OfferedIP:      offeredIP,
		OfferTime:      time.Now(),
		State:          "offered",
		CircuitID:      circuitID,
		RemoteID:       remoteID,
		FirstSeen:      time.Now(),
		LastSeen:       time.Now(),
		RequestCount:   1,
		ProcessingTime: time.Since(start),
		PacketSize:     len(packet.Options) + 240,
	}
	
	if !bytes.Equal(packet.Giaddr[:], []byte{0, 0, 0, 0}) {
		session.RelayIP = net.IP(packet.Giaddr[:])
	}
	
	s.sessionMutex.Lock()
	s.sessions[packet.Xid] = session
	s.sessionMutex.Unlock()
	
	// 응답 지연 시뮬레이션
	if s.config.ResponseDelay > 0 {
		time.Sleep(s.config.ResponseDelay)
	}
	
	// DHCP Offer 전송
	s.sendOffer(packet, offeredIP, clientAddr, relayAgentInfo)
	
	// 성능 메트릭 업데이트
	processingTime := time.Since(start)
	s.stats.mutex.Lock()
	s.stats.ProcessingTimes = append(s.stats.ProcessingTimes, processingTime)
	if len(s.stats.ProcessingTimes) > 1000 {
		s.stats.ProcessingTimes = s.stats.ProcessingTimes[len(s.stats.ProcessingTimes)-1000:]
	}
	s.stats.mutex.Unlock()
	
	if s.verbose {
		fmt.Printf("[OFFER] IP: %s → XID: 0x%08X (처리시간: %v)\n", offeredIP.String(), packet.Xid, processingTime)
		if circuitID != "" || remoteID != "" {
			fmt.Printf("[OFFER] Relay Info - Circuit: %s, Remote: %s\n", circuitID, remoteID)
		}
	}
}

// Relay Agent 정보 보존
func (s *DHCPServer) preserveRelayAgentInfo(options []byte) []byte {
	for i := 0; i < len(options); {
		if options[i] == DHCPEnd {
			break
		}
		if options[i] == 0 { // Padding
			i++
			continue
		}
		
		optionCode := options[i]
		if i+1 >= len(options) {
			break
		}
		optionLength := int(options[i+1])
		
		if optionCode == DHCPRelayAgentInfo && i+2+optionLength <= len(options) {
			// Option 82 전체 복사
			return options[i : i+2+optionLength]
		}
		
		i += 2 + optionLength
	}
	return nil
}

// DHCP Offer 전송
func (s *DHCPServer) sendOffer(request *DHCPPacket, offeredIP net.IP, clientAddr *net.UDPAddr, relayAgentInfo []byte) {
	offerPacket := s.createResponsePacket(request, DHCPOffer, offeredIP, relayAgentInfo)
	
	// Relay Agent가 있으면 Relay로 전송, 없으면 클라이언트로 직접 전송
	var destAddr *net.UDPAddr
	if !bytes.Equal(request.Giaddr[:], []byte{0, 0, 0, 0}) {
		// Relay Agent로 전송
		destAddr = &net.UDPAddr{
			IP:   net.IP(request.Giaddr[:]),
			Port: 67, // Relay Agent는 포트 67로 수신
		}
	} else {
		// 클라이언트로 직접 전송
		destAddr = &net.UDPAddr{
			IP:   net.IPv4bcast, // 브로드캐스트
			Port: 68,
		}
	}
	
	_, err := s.conn.WriteToUDP(offerPacket, destAddr)
	if err != nil {
		if s.verbose {
			fmt.Printf("[ERROR] Offer 전송 실패: %v\n", err)
		}
		return
	}
	
	atomic.AddInt64(&s.stats.OfferSent, 1)
}

// DHCP Request 처리 (보안 강화됨)
func (s *DHCPServer) handleRequest(packet *DHCPPacket, clientAddr *net.UDPAddr) {
	start := time.Now()
	atomic.AddInt64(&s.stats.RequestReceived, 1)
	
	clientIP := clientAddr.IP.String()
	
	if s.verbose {
		fmt.Printf("[REQUEST] XID: 0x%08X, Client IP: %s\n", packet.Xid, clientIP)
	}
	
	// Rate Limiting 확인 (Request도 제한)
	if s.config.SecurityEnabled && s.config.RateLimitEnabled && s.rateLimiter != nil {
		allowed, _ := s.rateLimiter.IsAllowed(clientIP)
		if !allowed {
			atomic.AddInt64(&s.stats.RateLimited, 1)
			atomic.AddInt64(&s.stats.SecurityBlocked, 1)
			s.sendNak(packet, clientAddr)
			atomic.AddInt64(&s.stats.NakSent, 1)
			return
		}
	}
	
	// 드롭 시뮬레이션
	if s.config.DropRate > 0 && rand.Float64() < s.config.DropRate {
		if s.verbose {
			fmt.Printf("[REQUEST] 패킷 드롭 시뮬레이션\n")
		}
		return
	}
	
	// 세션 확인
	s.sessionMutex.Lock()
	session, exists := s.sessions[packet.Xid]
	if exists {
		session.LastSeen = time.Now()
		session.RequestCount++
	}
	s.sessionMutex.Unlock()
	
	if !exists || session.State != "offered" {
		// NAK 전송
		s.sendNak(packet, clientAddr)
		atomic.AddInt64(&s.stats.NakSent, 1)
		atomic.AddInt64(&s.stats.InvalidRequests, 1)
		if s.verbose {
			fmt.Printf("[NAK] 세션을 찾을 수 없음: 0x%08X\n", packet.Xid)
		}
		return
	}
	
	// Offer 타임아웃 확인
	if time.Since(session.OfferTime) > s.config.OfferTimeout {
		// IP 해제 및 NAK 전송
		s.ipPool.ReleaseIP(session.OfferedIP)
		s.sendNak(packet, clientAddr)
		
		s.sessionMutex.Lock()
		delete(s.sessions, packet.Xid)
		s.sessionMutex.Unlock()
		
		atomic.AddInt64(&s.stats.NakSent, 1)
		if s.verbose {
			fmt.Printf("[NAK] Offer 타임아웃: 0x%08X\n", packet.Xid)
		}
		return
	}
	
	// 응답 지연 시뮬레이션
	if s.config.ResponseDelay > 0 {
		time.Sleep(s.config.ResponseDelay)
	}
	
	// Relay Agent 정보 보존
	var relayAgentInfo []byte
	if session.CircuitID != "" || session.RemoteID != "" {
		relayAgentInfo = s.preserveRelayAgentInfo(packet.Options)
	}
	
	// DHCP ACK 전송
	s.sendAck(packet, session.OfferedIP, clientAddr, relayAgentInfo)
	
	// 세션 상태 업데이트
	s.sessionMutex.Lock()
	session.State = "leased"
	session.ProcessingTime = time.Since(start)
	s.sessionMutex.Unlock()
	
	atomic.AddInt64(&s.stats.AckSent, 1)
	
	if s.verbose {
		fmt.Printf("[ACK] IP: %s → XID: 0x%08X (처리시간: %v)\n", 
			session.OfferedIP.String(), packet.Xid, time.Since(start))
	}
}

// DHCP ACK 전송
func (s *DHCPServer) sendAck(request *DHCPPacket, leasedIP net.IP, clientAddr *net.UDPAddr, relayAgentInfo []byte) {
	ackPacket := s.createResponsePacket(request, DHCPAck, leasedIP, relayAgentInfo)
	
	// Relay Agent가 있으면 Relay로 전송, 없으면 클라이언트로 직접 전송
	var destAddr *net.UDPAddr
	if !bytes.Equal(request.Giaddr[:], []byte{0, 0, 0, 0}) {
		destAddr = &net.UDPAddr{
			IP:   net.IP(request.Giaddr[:]),
			Port: 67,
		}
	} else {
		destAddr = &net.UDPAddr{
			IP:   net.IPv4bcast,
			Port: 68,
		}
	}
	
	_, err := s.conn.WriteToUDP(ackPacket, destAddr)
	if err != nil {
		if s.verbose {
			fmt.Printf("[ERROR] ACK 전송 실패: %v\n", err)
		}
	}
}

// DHCP NAK 전송
func (s *DHCPServer) sendNak(request *DHCPPacket, clientAddr *net.UDPAddr) {
	nakPacket := s.createResponsePacket(request, DHCPNak, nil, nil)
	
	var destAddr *net.UDPAddr
	if !bytes.Equal(request.Giaddr[:], []byte{0, 0, 0, 0}) {
		destAddr = &net.UDPAddr{
			IP:   net.IP(request.Giaddr[:]),
			Port: 67,
		}
	} else {
		destAddr = &net.UDPAddr{
			IP:   net.IPv4bcast,
			Port: 68,
		}
	}
	
	s.conn.WriteToUDP(nakPacket, destAddr)
}

// 패킷 처리 (보안 및 성능 강화됨)
func (s *DHCPServer) handlePacket(data []byte, clientAddr *net.UDPAddr) {
	start := time.Now()
	
	// 패킷 풀에서 버퍼 재사용
	var buffer []byte
	if s.config.PacketPoolEnabled && s.packetPool != nil {
		buffer = s.packetPool.Get()
		defer s.packetPool.Put(buffer)
		copy(buffer, data)
		data = buffer[:len(data)]
	}
	
	packet, err := s.parseDHCPPacket(data)
	if err != nil {
		atomic.AddInt64(&s.stats.ParseErrors, 1)
		if s.verbose {
			fmt.Printf("[ERROR] 패킷 파싱 실패: %v\n", err)
		}
		return
	}
	
	// BOOTREQUEST만 처리
	if packet.Op != 1 {
		return
	}
	
	// Hop count 확인 (Relay Agent)
	if s.config.SupportRelay && packet.Hops > s.config.MaxHops {
		if s.verbose {
			fmt.Printf("[ERROR] 최대 hop count 초과: %d > %d\n", packet.Hops, s.config.MaxHops)
		}
		return
	}
	
	msgType, err := getMessageType(packet.Options)
	if err != nil {
		atomic.AddInt64(&s.stats.ParseErrors, 1)
		if s.verbose {
			fmt.Printf("[ERROR] 메시지 타입 추출 실패: %v\n", err)
		}
		return
	}
	
	switch msgType {
	case DHCPDiscover:
		s.handleDiscover(packet, clientAddr)
	case DHCPRequest:
		s.handleRequest(packet, clientAddr)
	default:
		if s.verbose {
			fmt.Printf("[INFO] 지원하지 않는 메시지 타입: %d\n", msgType)
		}
	}
	
	// 처리 시간 기록
	processingTime := time.Since(start)
	s.stats.mutex.Lock()
	s.stats.ProcessingTimes = append(s.stats.ProcessingTimes, processingTime)
	// 메모리 절약을 위해 최근 1000개만 유지
	if len(s.stats.ProcessingTimes) > 1000 {
		s.stats.ProcessingTimes = s.stats.ProcessingTimes[len(s.stats.ProcessingTimes)-1000:]
	}
	s.stats.mutex.Unlock()
}

// 서버 시작 (개선됨)
func (s *DHCPServer) Start() error {
	s.runMutex.Lock()
	defer s.runMutex.Unlock()
	
	if s.running {
		return fmt.Errorf("서버가 이미 실행 중입니다")
	}
	
	// UDP 소켓 생성
	addr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", s.config.ListenIP, s.config.ListenPort))
	if err != nil {
		return fmt.Errorf("주소 해석 실패: %v", err)
	}
	
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return fmt.Errorf("UDP 소켓 생성 실패: %v", err)
	}
	
	s.conn = conn
	s.running = true
	
	fmt.Printf("DHCP 서버 시작: %s:%d\n", s.config.ListenIP, s.config.ListenPort)
	fmt.Printf("IP 범위: %s - %s\n", s.config.StartIP.String(), s.config.EndIP.String())
	fmt.Printf("임대 시간: %v\n", s.config.LeaseTime)
	
	if s.config.SupportRelay {
		fmt.Printf("Relay Agent 지원: 활성화 (최대 %d hops)\n", s.config.MaxHops)
	}
	
	if s.config.SecurityEnabled {
		fmt.Printf("보안 강화: 활성화\n")
		if s.config.RateLimitEnabled {
			fmt.Printf("  - Rate Limiting: %d req/min (글로벌: %d)\n", 
				s.config.MaxRequestsPerMin, s.config.GlobalRateLimit)
		}
		if s.config.MACValidation {
			fmt.Printf("  - MAC 주소 검증: 활성화\n")
		}
		if s.config.DuplicateXIDCheck {
			fmt.Printf("  - 중복 XID 검사: 활성화\n")
		}
	}
	
	if s.config.PacketPoolEnabled {
		fmt.Printf("성능 최적화: 활성화\n")
		fmt.Printf("  - 패킷 풀링: 활성화\n")
		fmt.Printf("  - 워커 풀: %d개 워커\n", s.config.WorkerPoolSize)
		if s.config.MemoryOptimization {
			fmt.Printf("  - 메모리 최적화: 활성화\n")
		}
		if s.config.CacheEnabled {
			fmt.Printf("  - 패킷 캐싱: 활성화\n")
		}
	}
	
	if s.config.DropRate > 0 {
		fmt.Printf("패킷 드롭 시뮬레이션: %.1f%%\n", s.config.DropRate*100)
	}
	if s.config.ResponseDelay > 0 {
		fmt.Printf("응답 지연 시뮬레이션: %v\n", s.config.ResponseDelay)
	}
	
	fmt.Println(strings.Repeat("-", 70))
	
	// 워커 풀 시작
	if s.workerPool != nil {
		s.workerPool.Start()
		fmt.Printf("워커 풀 시작됨: %d개 워커\n", s.config.WorkerPoolSize)
	}
	
	// 요청 처리 루프
	go s.serverLoop()
	
	// 실시간 통계 표시
	if s.showLiveStats {
		go s.liveStatsLoop()
	}
	
	// 세션 정리 루프
	go s.cleanupLoop()
	
	return nil
}

// 서버 메인 루프 (워커 풀 지원)
func (s *DHCPServer) serverLoop() {
	buffer := make([]byte, 1500)
	
	for s.isRunning() {
		s.conn.SetReadDeadline(time.Now().Add(time.Second))
		n, clientAddr, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if s.verbose {
				fmt.Printf("[ERROR] UDP 읽기 실패: %v\n", err)
			}
			continue
		}
		
		// 패킷 데이터 복사 (워커에서 안전하게 사용하기 위해)
		packetData := make([]byte, n)
		copy(packetData, buffer[:n])
		
		// 워커 풀에 작업 제출 또는 직접 처리
		if s.workerPool != nil {
			submitted := s.workerPool.Submit(func() {
				s.handlePacket(packetData, clientAddr)
			})
			if !submitted {
				// 워커 풀이 가득 참 - 직접 처리하거나 드롭
				atomic.AddInt64(&s.stats.WorkerPoolDropped, 1)
				// 중요한 패킷이므로 직접 처리
				go s.handlePacket(packetData, clientAddr)
			} else {
				atomic.AddInt64(&s.stats.WorkerPoolJobs, 1)
			}
		} else {
			// 기존 방식: 고루틴으로 패킷 처리
			go s.handlePacket(packetData, clientAddr)
		}
	}
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

// 실시간 통계 루프
func (s *DHCPServer) liveStatsLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	// 터미널 초기화
	fmt.Print(ANSI_CLEAR_SCREEN)
	fmt.Print(ANSI_CURSOR_HOME)
	fmt.Print(ANSI_HIDE_CURSOR)
	
	defer func() {
		fmt.Print(ANSI_SHOW_CURSOR)
		fmt.Print(ANSI_RESET)
	}()
	
	for s.isRunning() {
		select {
		case <-ticker.C:
			s.printLiveStats()
		}
	}
}

// 실시간 통계 출력 (개선됨)
func (s *DHCPServer) printLiveStats() {
	// 터미널 클리어 및 상단으로 이동
	fmt.Print(ANSI_CURSOR_HOME)
	
	// 헤더
	fmt.Printf("%s%s╔════════════════════════════════════════════════════════════════════════╗%s\n", ANSI_BOLD, ANSI_CYAN, ANSI_RESET)
	fmt.Printf("%s%s║               DHCP 서버 실시간 모니터링 (보안 강화)                    ║%s\n", ANSI_BOLD, ANSI_CYAN, ANSI_RESET)
	fmt.Printf("%s%s╚════════════════════════════════════════════════════════════════════════╝%s\n", ANSI_BOLD, ANSI_CYAN, ANSI_RESET)
	fmt.Println()
	
	// 서버 정보
	uptime := time.Since(s.stats.StartTime)
	fmt.Printf("%s서버 정보%s\n", ANSI_BOLD, ANSI_RESET)
	fmt.Printf("  주소: %s%s:%d%s", ANSI_YELLOW, s.config.ListenIP, s.config.ListenPort, ANSI_RESET)
	if s.config.SupportRelay {
		fmt.Printf("  (Relay 지원)")
	}
	if s.config.SecurityEnabled {
		fmt.Printf("  🔒%s보안 활성화%s", ANSI_GREEN, ANSI_RESET)
	}
	if s.config.PacketPoolEnabled {
		fmt.Printf("  ⚡%s성능 최적화%s", ANSI_GREEN, ANSI_RESET)
	}
	fmt.Println()
	fmt.Printf("  가동 시간: %s%v%s\n", ANSI_YELLOW, uptime.Truncate(time.Second), ANSI_RESET)
	
	// IP 풀 정보
	total, available, leased, utilizationPct := s.ipPool.GetStats()
	fmt.Printf("  IP 풀: %s%s - %s%s (%d개, 사용률: %.1f%%)\n\n", 
		ANSI_YELLOW, s.config.StartIP, s.config.EndIP, ANSI_RESET, total, utilizationPct)
	
	// DHCP 메시지 통계
	discoverRx := atomic.LoadInt64(&s.stats.DiscoverReceived)
	offerTx := atomic.LoadInt64(&s.stats.OfferSent)
	requestRx := atomic.LoadInt64(&s.stats.RequestReceived)
	ackTx := atomic.LoadInt64(&s.stats.AckSent)
	nakTx := atomic.LoadInt64(&s.stats.NakSent)
	
	fmt.Printf("%s%s┌─ DHCP 메시지 통계 ─────────────────────────────────────────────────────┐%s\n", ANSI_BOLD, ANSI_BLUE, ANSI_RESET)
	fmt.Printf("%s%s│%s  수신: DISCOVER %s%8d%s    REQUEST %s%8d%s                           %s%s│%s\n", 
		ANSI_BOLD, ANSI_BLUE, ANSI_RESET, ANSI_WHITE, discoverRx, ANSI_RESET, ANSI_WHITE, requestRx, ANSI_RESET, 
		ANSI_BOLD, ANSI_BLUE, ANSI_RESET)
	fmt.Printf("%s%s│%s  전송: OFFER    %s%8d%s    ACK     %s%8d%s    NAK %s%8d%s           %s%s│%s\n", 
		ANSI_BOLD, ANSI_BLUE, ANSI_RESET, ANSI_WHITE, offerTx, ANSI_RESET, ANSI_WHITE, ackTx, ANSI_RESET, 
		ANSI_WHITE, nakTx, ANSI_RESET, ANSI_BOLD, ANSI_BLUE, ANSI_RESET)
	
	// 성공률 계산
	totalProcessed := discoverRx + requestRx
	totalSuccess := offerTx + ackTx
	var successRate float64
	if totalProcessed > 0 {
		successRate = float64(totalSuccess) / float64(totalProcessed) * 100
	}
	fmt.Printf("%s%s│%s  성공률: %s%.1f%%%s                                                          %s%s│%s\n", 
		ANSI_BOLD, ANSI_BLUE, ANSI_RESET, ANSI_GREEN, successRate, ANSI_RESET, ANSI_BOLD, ANSI_BLUE, ANSI_RESET)
	fmt.Printf("%s%s└────────────────────────────────────────────────────────────────────────┘%s\n", ANSI_BOLD, ANSI_BLUE, ANSI_RESET)
	fmt.Println()
	
	// IP 풀 상태
	fmt.Printf("%sIP 풀 상태%s\n", ANSI_BOLD, ANSI_RESET)
	fmt.Printf("  사용 중: %s%d%s, 사용 가능: %s%d%s, 사용률: %s%.1f%%%s\n", 
		ANSI_GREEN, leased, ANSI_RESET, ANSI_CYAN, available, ANSI_RESET, ANSI_YELLOW, utilizationPct, ANSI_RESET)
	
	// 사용률 바
	barWidth := 50
	filledWidth := int(utilizationPct / 100.0 * float64(barWidth))
	fmt.Print("  [")
	for i := 0; i < barWidth; i++ {
		if i < filledWidth {
			if utilizationPct > 90 {
				fmt.Printf("%s█%s", ANSI_RED, ANSI_RESET)
			} else if utilizationPct > 70 {
				fmt.Printf("%s█%s", ANSI_YELLOW, ANSI_RESET)
			} else {
				fmt.Printf("%s█%s", ANSI_GREEN, ANSI_RESET)
			}
		} else {
			fmt.Print("░")
		}
	}
	fmt.Printf("] %.1f%%\n\n", utilizationPct)
	
	// 보안 통계
	securityBlocked := atomic.LoadInt64(&s.stats.SecurityBlocked)
	rateLimited := atomic.LoadInt64(&s.stats.RateLimited)
	invalidMACs := atomic.LoadInt64(&s.stats.InvalidMACs)
	duplicateXIDs := atomic.LoadInt64(&s.stats.DuplicateXIDs)
	
	if s.config.SecurityEnabled && (securityBlocked > 0 || rateLimited > 0) {
		fmt.Printf("%s%s┌─ 보안 통계 ──────────────────────────────────────────────────────────┐%s\n", ANSI_BOLD, ANSI_MAGENTA, ANSI_RESET)
		fmt.Printf("%s%s│%s  총 차단: %s%8d%s 건    Rate Limit: %s%8d%s 건                 %s%s│%s\n", 
			ANSI_BOLD, ANSI_MAGENTA, ANSI_RESET, ANSI_RED, securityBlocked, ANSI_RESET, 
			ANSI_RED, rateLimited, ANSI_RESET, ANSI_BOLD, ANSI_MAGENTA, ANSI_RESET)
		fmt.Printf("%s%s│%s  잘못된 MAC: %s%5d%s 건    중복 XID: %s%8d%s 건                %s%s│%s\n", 
			ANSI_BOLD, ANSI_MAGENTA, ANSI_RESET, ANSI_RED, invalidMACs, ANSI_RESET, 
			ANSI_RED, duplicateXIDs, ANSI_RESET, ANSI_BOLD, ANSI_MAGENTA, ANSI_RESET)
		fmt.Printf("%s%s└──────────────────────────────────────────────────────────────────────┘%s\n", ANSI_BOLD, ANSI_MAGENTA, ANSI_RESET)
		fmt.Println()
	}
	
	// 성능 통계
	poolHits := atomic.LoadInt64(&s.stats.PacketPoolHits)
	poolMisses := atomic.LoadInt64(&s.stats.PacketPoolMisses)
	workerJobs := atomic.LoadInt64(&s.stats.WorkerPoolJobs)
	
	if s.config.PacketPoolEnabled && (poolHits > 0 || poolMisses > 0 || workerJobs > 0) {
		fmt.Printf("%s%s┌─ 성능 통계 ──────────────────────────────────────────────────────────┐%s\n", ANSI_BOLD, ANSI_CYAN, ANSI_RESET)
		
		if poolHits > 0 || poolMisses > 0 {
			hitRate := float64(poolHits) / float64(poolHits+poolMisses) * 100
			fmt.Printf("%s%s│%s  캐시 Hit: %s%8d%s      Miss: %s%8d%s      Hit Rate: %s%.1f%%%s  %s%s│%s\n", 
				ANSI_BOLD, ANSI_CYAN, ANSI_RESET, ANSI_GREEN, poolHits, ANSI_RESET, ANSI_YELLOW, poolMisses, ANSI_RESET, 
				ANSI_GREEN, hitRate, ANSI_RESET, ANSI_BOLD, ANSI_CYAN, ANSI_RESET)
		}
		
		if s.workerPool != nil {
			queueSize, processed, dropped, isRunning := s.workerPool.GetStats()
			status := "정지됨"
			if isRunning {
				status = "실행중"
			}
			fmt.Printf("%s%s│%s  워커 풀: %s%s%s      큐: %s%3d%s      처리: %s%8d%s      드롭: %s%3d%s  %s%s│%s\n", 
				ANSI_BOLD, ANSI_CYAN, ANSI_RESET, ANSI_GREEN, status, ANSI_RESET, ANSI_YELLOW, queueSize, ANSI_RESET, 
				ANSI_WHITE, processed, ANSI_RESET, ANSI_RED, dropped, ANSI_RESET, ANSI_BOLD, ANSI_CYAN, ANSI_RESET)
		}
		
		fmt.Printf("%s%s└──────────────────────────────────────────────────────────────────────┘%s\n", ANSI_BOLD, ANSI_CYAN, ANSI_RESET)
		fmt.Println()
	}
	
	// 성능 지표
	if uptime > 0 {
		rps := float64(discoverRx+requestRx) / uptime.Seconds()
		fmt.Printf("%s성능 지표%s\n", ANSI_BOLD, ANSI_RESET)
		fmt.Printf("  평균 RPS: %s%.1f requests/sec%s", ANSI_GREEN, rps, ANSI_RESET)
		
		// 평균 처리 시간
		s.stats.mutex.RLock()
		if len(s.stats.ProcessingTimes) > 0 {
			var total time.Duration
			for _, t := range s.stats.ProcessingTimes {
				total += t
			}
			avgProcessing := total / time.Duration(len(s.stats.ProcessingTimes))
			fmt.Printf("  평균 처리 시간: %s%v%s", ANSI_GREEN, avgProcessing, ANSI_RESET)
		}
		s.stats.mutex.RUnlock()
		
		// 메모리 사용량
		memoryMB := atomic.LoadInt64(&s.memoryUsage) / 1024 / 1024
		if memoryMB > 0 {
			fmt.Printf("  메모리: %s%dMB%s", ANSI_YELLOW, memoryMB, ANSI_RESET)
		}
		fmt.Println()
	}
	
	// 에러 통계
	parseErrors := atomic.LoadInt64(&s.stats.ParseErrors)
	poolExhausted := atomic.LoadInt64(&s.stats.PoolExhausted)
	invalidRequests := atomic.LoadInt64(&s.stats.InvalidRequests)
	
	if parseErrors > 0 || poolExhausted > 0 || invalidRequests > 0 {
		fmt.Printf("\n%s에러 통계%s\n", ANSI_BOLD, ANSI_RESET)
		if parseErrors > 0 {
			fmt.Printf("  파싱 오류: %s%d%s  ", ANSI_RED, parseErrors, ANSI_RESET)
		}
		if poolExhausted > 0 {
			fmt.Printf("  풀 고갈: %s%d%s  ", ANSI_RED, poolExhausted, ANSI_RESET)
		}
		if invalidRequests > 0 {
			fmt.Printf("  잘못된 요청: %s%d%s  ", ANSI_RED, invalidRequests, ANSI_RESET)
		}
		fmt.Println()
	}
	
	fmt.Printf("\n%s%s[Ctrl+C로 종료]%s", ANSI_BOLD, ANSI_WHITE, ANSI_RESET)
}

// 세션 정리 루프 (개선됨)
func (s *DHCPServer) cleanupLoop() {
	ticker := time.NewTicker(s.config.CleanupInterval)
	defer ticker.Stop()
	
	for s.isRunning() {
		select {
		case <-ticker.C:
			s.cleanupExpiredSessions()
			s.cleanupExpiredXIDs()
			s.cleanupExpiredIPs()
		}
	}
}

// 만료된 세션 정리
func (s *DHCPServer) cleanupExpiredSessions() {
	s.sessionMutex.Lock()
	defer s.sessionMutex.Unlock()
	
	now := time.Now()
	cleanedSessions := 0
	
	for xid, session := range s.sessions {
		if session.State == "offered" && now.Sub(session.OfferTime) > s.config.OfferTimeout {
			// Offer 타임아웃된 세션 정리
			s.ipPool.ReleaseIP(session.OfferedIP)
			delete(s.sessions, xid)
			cleanedSessions++
		} else if session.State == "leased" && now.Sub(session.OfferTime) > s.config.LeaseTime {
			// 임대 시간 만료된 세션 정리
			s.ipPool.ReleaseIP(session.OfferedIP)
			delete(s.sessions, xid)
			cleanedSessions++
		}
	}
	
	if s.verbose && cleanedSessions > 0 {
		fmt.Printf("[CLEANUP] %d개 만료된 세션 정리됨\n", cleanedSessions)
	}
}

// 만료된 XID 캐시 정리
func (s *DHCPServer) cleanupExpiredXIDs() {
	if !s.config.SecurityEnabled || !s.config.DuplicateXIDCheck {
		return
	}
	
	s.xidCacheMutex.Lock()
	defer s.xidCacheMutex.Unlock()
	
	now := time.Now()
	cleanedXIDs := 0
	
	for xid, timestamp := range s.xidCache {
		if now.Sub(timestamp) > 1*time.Minute { // 1분 이상 된 XID 삭제
			delete(s.xidCache, xid)
			cleanedXIDs++
		}
	}
	
	if s.verbose && cleanedXIDs > 0 {
		fmt.Printf("[CLEANUP] %d개 만료된 XID 정리됨\n", cleanedXIDs)
	}
}

// 만료된 IP 임대 정리
func (s *DHCPServer) cleanupExpiredIPs() {
	cleaned := s.ipPool.CleanupExpired(s.config.LeaseTime)
	
	if s.verbose && cleaned > 0 {
		fmt.Printf("[CLEANUP] %d개 만료된 IP 임대 정리됨\n", cleaned)
	}
}

// 서버 실행 상태 확인
func (s *DHCPServer) isRunning() bool {
	s.runMutex.RLock()
	defer s.runMutex.RUnlock()
	return s.running
}

// 서버 중지 (개선됨)
func (s *DHCPServer) Stop() {
	s.runMutex.Lock()
	defer s.runMutex.Unlock()
	
	if !s.running {
		return
	}
	
	s.running = false
	
	// 워커 풀 중지
	if s.workerPool != nil {
		s.workerPool.Stop()
	}
	
	// 연결 종료
	if s.conn != nil {
		s.conn.Close()
	}
	
	// 보안 로거 종료
	if s.securityLogger != nil {
		s.securityLogger.Close()
	}
	
	fmt.Println("\nDHCP 서버가 정상적으로 종료되었습니다.")
}

// 최종 통계 출력 (확장됨)
func (s *DHCPServer) PrintFinalStats() {
	fmt.Printf("\n%s\n", strings.Repeat("=", 80))
	fmt.Printf("DHCP 서버 최종 통계 (보안 강화 및 성능 최적화)\n")
	fmt.Printf("%s\n", strings.Repeat("=", 80))
	
	uptime := time.Since(s.stats.StartTime)
	discoverRx := atomic.LoadInt64(&s.stats.DiscoverReceived)
	offerTx := atomic.LoadInt64(&s.stats.OfferSent)
	requestRx := atomic.LoadInt64(&s.stats.RequestReceived)
	ackTx := atomic.LoadInt64(&s.stats.AckSent)
	nakTx := atomic.LoadInt64(&s.stats.NakSent)
	
	// 기본 통계
	fmt.Printf("%-25s %15v\n", "가동 시간:", uptime.Truncate(time.Second))
	fmt.Printf("%-25s %15d\n", "처리된 DISCOVER:", discoverRx)
	fmt.Printf("%-25s %15d\n", "전송된 OFFER:", offerTx)
	fmt.Printf("%-25s %15d\n", "처리된 REQUEST:", requestRx)
	fmt.Printf("%-25s %15d\n", "전송된 ACK:", ackTx)
	fmt.Printf("%-25s %15d\n", "전송된 NAK:", nakTx)
	
	if uptime > 0 {
		rps := float64(discoverRx+requestRx) / uptime.Seconds()
		fmt.Printf("%-25s %14.1f req/s\n", "평균 RPS:", rps)
	}
	
	// 보안 통계
	securityBlocked := atomic.LoadInt64(&s.stats.SecurityBlocked)
	rateLimited := atomic.LoadInt64(&s.stats.RateLimited)
	invalidMACs := atomic.LoadInt64(&s.stats.InvalidMACs)
	duplicateXIDs := atomic.LoadInt64(&s.stats.DuplicateXIDs)
	
	if s.config.SecurityEnabled && securityBlocked > 0 {
		fmt.Printf("\n%s\n", strings.Repeat("-", 80))
		fmt.Printf("보안 통계\n")
		fmt.Printf("%s\n", strings.Repeat("-", 80))
		fmt.Printf("%-25s %15d\n", "총 보안 차단:", securityBlocked)
		if rateLimited > 0 {
			fmt.Printf("%-25s %15d\n", "Rate Limit 차단:", rateLimited)
		}
		if invalidMACs > 0 {
			fmt.Printf("%-25s %15d\n", "잘못된 MAC:", invalidMACs)
		}
		if duplicateXIDs > 0 {
			fmt.Printf("%-25s %15d\n", "중복 XID:", duplicateXIDs)
		}
	}
	
	// 성능 통계
	poolHits := atomic.LoadInt64(&s.stats.PacketPoolHits)
	poolMisses := atomic.LoadInt64(&s.stats.PacketPoolMisses)
	workerJobs := atomic.LoadInt64(&s.stats.WorkerPoolJobs)
	
	if s.config.PacketPoolEnabled && (poolHits > 0 || workerJobs > 0) {
		fmt.Printf("\n%s\n", strings.Repeat("-", 80))
		fmt.Printf("성능 최적화 통계\n")
		fmt.Printf("%s\n", strings.Repeat("-", 80))
		
		if poolHits > 0 || poolMisses > 0 {
			total := poolHits + poolMisses
			hitRate := float64(poolHits) / float64(total) * 100
			fmt.Printf("%-25s %15d\n", "캐시 Hit:", poolHits)
			fmt.Printf("%-25s %15d\n", "캐시 Miss:", poolMisses)
			fmt.Printf("%-25s %14.1f%%\n", "캐시 Hit Rate:", hitRate)
		}
		
		if workerJobs > 0 {
			fmt.Printf("%-25s %15d\n", "워커 처리 작업:", workerJobs)
			
			workerDropped := atomic.LoadInt64(&s.stats.WorkerPoolDropped)
			if workerDropped > 0 {
				fmt.Printf("%-25s %15d\n", "워커 드롭 작업:", workerDropped)
				dropRate := float64(workerDropped) / float64(workerJobs+workerDropped) * 100
				fmt.Printf("%-25s %14.1f%%\n", "워커 드롭률:", dropRate)
			}
		}
		
		memoryMB := atomic.LoadInt64(&s.memoryUsage) / 1024 / 1024
		if memoryMB > 0 {
			fmt.Printf("%-25s %12dMB\n", "총 메모리 사용량:", memoryMB)
		}
	}
	
	// IP 풀 최종 상태
	total, available, leased, utilizationPct := s.ipPool.GetStats()
	fmt.Printf("\n%s\n", strings.Repeat("-", 80))
	fmt.Printf("IP 풀 최종 상태\n")
	fmt.Printf("%s\n", strings.Repeat("-", 80))
	fmt.Printf("%-25s %15d\n", "총 IP 수:", total)
	fmt.Printf("%-25s %15d\n", "임대된 IP:", leased)
	fmt.Printf("%-25s %15d\n", "사용 가능 IP:", available)
	fmt.Printf("%-25s %14.1f%%\n", "최종 사용률:", utilizationPct)
	
	// 에러 통계
	parseErrors := atomic.LoadInt64(&s.stats.ParseErrors)
	poolExhausted := atomic.LoadInt64(&s.stats.PoolExhausted)
	invalidRequests := atomic.LoadInt64(&s.stats.InvalidRequests)
	
	if parseErrors > 0 || poolExhausted > 0 || invalidRequests > 0 {
		fmt.Printf("\n%s\n", strings.Repeat("-", 80))
		fmt.Printf("에러 통계\n")
		fmt.Printf("%s\n", strings.Repeat("-", 80))
		if parseErrors > 0 {
			fmt.Printf("%-25s %15d\n", "파싱 오류:", parseErrors)
		}
		if poolExhausted > 0 {
			fmt.Printf("%-25s %15d\n", "IP 풀 고갈:", poolExhausted)
		}
		if invalidRequests > 0 {
			fmt.Printf("%-25s %15d\n", "잘못된 요청:", invalidRequests)
		}
	}
	
	// 세션 통계
	s.sessionMutex.RLock()
	activeSessions := len(s.sessions)
	s.sessionMutex.RUnlock()
	
	if activeSessions > 0 {
		fmt.Printf("\n%-25s %15d\n", "활성 세션 수:", activeSessions)
	}
}

func main() {
	// 명령행 플래그 정의 (확장됨)
	var (
		listenIP     = flag.String("listen", "0.0.0.0", "서버 바인딩 IP 주소")
		listenPort   = flag.Int("port", 67, "서버 바인딩 포트")
		startIP      = flag.String("start-ip", "192.168.100.10", "IP 풀 시작 주소")
		endIP        = flag.String("end-ip", "192.168.100.250", "IP 풀 종료 주소")
		subnetMask   = flag.String("subnet-mask", "255.255.255.0", "서브넷 마스크")
		gateway      = flag.String("gateway", "192.168.100.1", "기본 게이트웨이")
		dns1         = flag.String("dns1", "8.8.8.8", "첫 번째 DNS 서버")
		dns2         = flag.String("dns2", "8.8.4.4", "두 번째 DNS 서버")
		domain       = flag.String("domain", "example.com", "도메인 이름")
		leaseTime    = flag.Duration("lease-time", 24*time.Hour, "IP 임대 시간")
		offerTimeout = flag.Duration("offer-timeout", 30*time.Second, "Offer 타임아웃")
		
		// 성능 제한 옵션
		maxConcurrent = flag.Int("max-concurrent", 1000, "최대 동시 처리 수")
		responseDelay = flag.Duration("response-delay", 0, "응답 지연 시뮬레이션")
		dropRate      = flag.Float64("drop-rate", 0.0, "패킷 드롭률 (0.0-1.0)")
		
		// Relay Agent 옵션
		supportRelay = flag.Bool("relay", true, "Relay Agent 지원")
		maxHops      = flag.Int("max-hops", 4, "최대 허용 hop count")
		
		// 보안 옵션 (새로 추가)
		enableSecurity     = flag.Bool("security", true, "보안 기능 활성화")
		enableRateLimit    = flag.Bool("rate-limit", true, "Rate limiting 활성화")
		maxReqPerMin       = flag.Int("max-req-per-min", 100, "IP별 분당 최대 요청 수")
		globalRateLimit    = flag.Int64("global-rate-limit", 1000, "글로벌 분당 최대 요청 수")
		enableMACValidation = flag.Bool("mac-validation", true, "MAC 주소 검증")
		enableXIDCheck     = flag.Bool("xid-check", true, "중복 XID 검사")
		enableIPSpoofCheck = flag.Bool("ip-spoof-check", true, "IP 스푸핑 검사")
		securityLogFile    = flag.String("security-log", "", "보안 이벤트 로그 파일")
		
		// 성능 옵션 (새로 추가)
		enablePacketPool   = flag.Bool("packet-pool", true, "패킷 풀링 활성화")
		workerPoolSize     = flag.Int("worker-pool-size", 0, "워커 풀 크기 (0은 CPU 코어 수 * 2)")
		workerQueueSize    = flag.Int("worker-queue-size", 1000, "워커 큐 크기")
		enableMemOptim     = flag.Bool("mem-optim", true, "메모리 최적화")
		enableCache        = flag.Bool("cache", true, "패킷 캐싱 활성화")
		cleanupInterval    = flag.Duration("cleanup-interval", 5*time.Minute, "정리 작업 간격")
		
		// 표시 옵션
		verbose   = flag.Bool("verbose", false, "상세 로그 출력")
		liveStats = flag.Bool("live", false, "실시간 통계 대시보드")
	)
	flag.Parse()
	
	// 워커 풀 크기 기본값 설정
	if *workerPoolSize == 0 {
		*workerPoolSize = runtime.NumCPU() * 2
	}
	
	// 설정 생성 및 검증
	config := NewServerConfig()
	config.ListenIP = *listenIP
	config.ListenPort = *listenPort
	
	config.StartIP = net.ParseIP(*startIP)
	config.EndIP = net.ParseIP(*endIP)
	config.SubnetMask = net.ParseIP(*subnetMask)
	config.Gateway = net.ParseIP(*gateway)
	config.DNSServers = []net.IP{net.ParseIP(*dns1), net.ParseIP(*dns2)}
	config.DomainName = *domain
	config.LeaseTime = *leaseTime
	config.OfferTimeout = *offerTimeout
	
	config.MaxConcurrent = *maxConcurrent
	config.ResponseDelay = *responseDelay
	config.DropRate = *dropRate
	config.SupportRelay = *supportRelay
	config.MaxHops = uint8(*maxHops)
	
	// 보안 설정
	config.SecurityEnabled = *enableSecurity
	config.RateLimitEnabled = *enableRateLimit
	config.MaxRequestsPerMin = *maxReqPerMin
	config.GlobalRateLimit = *globalRateLimit
	config.MACValidation = *enableMACValidation
	config.DuplicateXIDCheck = *enableXIDCheck
	config.IPSpoofingCheck = *enableIPSpoofCheck
	config.SecurityLogFile = *securityLogFile
	
	// 성능 설정
	config.PacketPoolEnabled = *enablePacketPool
	config.WorkerPoolSize = *workerPoolSize
	config.WorkerQueueSize = *workerQueueSize
	config.MemoryOptimization = *enableMemOptim
	config.CacheEnabled = *enableCache
	config.CleanupInterval = *cleanupInterval
	
	// 입력 검증
	if config.StartIP == nil || config.EndIP == nil {
		log.Fatal("올바른 IP 주소를 입력하세요")
	}
	if ipToUint32(config.StartIP) > ipToUint32(config.EndIP) {
		log.Fatal("시작 IP가 종료 IP보다 클 수 없습니다")
	}
	if config.SubnetMask == nil {
		log.Fatal("올바른 서브넷 마스크를 입력하세요")
	}
	if config.Gateway == nil {
		log.Fatal("올바른 게이트웨이 주소를 입력하세요")
	}
	if *dropRate < 0.0 || *dropRate > 1.0 {
		log.Fatal("드롭률은 0.0과 1.0 사이여야 합니다")
	}
	if *maxReqPerMin < 1 || *maxReqPerMin > 10000 {
		log.Fatal("분당 최대 요청 수는 1-10000 범위여야 합니다")
	}
	if *globalRateLimit < 1 || *globalRateLimit > 100000 {
		log.Fatal("글로벌 레이트 리미트는 1-100000 범위여야 합니다")
	}
	if *workerPoolSize < 1 || *workerPoolSize > 1000 {
		log.Fatal("워커 풀 크기는 1-1000 범위여야 합니다")
	}
	if *workerQueueSize < 10 || *workerQueueSize > 10000 {
		log.Fatal("워커 큐 크기는 10-10000 범위여야 합니다")
	}
	if *maxHops < 1 || *maxHops > 16 {
		log.Fatal("최대 hop count는 1-16 범위여야 합니다")
	}
	
	// DNS 서버 검증
	for i, dns := range config.DNSServers {
		if dns == nil {
			log.Fatalf("DNS 서버 %d가 올바르지 않습니다", i+1)
		}
	}
	
	// IP 풀 크기 확인
	poolSize := ipToUint32(config.EndIP) - ipToUint32(config.StartIP) + 1
	if poolSize < 10 {
		log.Fatal("IP 풀 크기가 너무 작습니다 (최소 10개)")
	}
	if poolSize > 65536 {
		log.Fatal("IP 풀 크기가 너무 큽니다 (최대 65536개)")
	}
	
	// 서버 생성
	server := NewDHCPServer(config)
	server.verbose = *verbose
	server.showLiveStats = *liveStats
	
	// 시그널 핸들링
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	
	// 설정 요약 출력
	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Printf("DHCP 서버 설정 요약\n")
	fmt.Printf("%s\n", strings.Repeat("=", 70))
	fmt.Printf("서버 주소:           %s:%d\n", config.ListenIP, config.ListenPort)
	fmt.Printf("IP 풀:              %s - %s (%d개)\n", 
		config.StartIP.String(), config.EndIP.String(), poolSize)
	fmt.Printf("서브넷 마스크:        %s\n", config.SubnetMask.String())
	fmt.Printf("게이트웨이:          %s\n", config.Gateway.String())
	fmt.Printf("DNS 서버:           %s, %s\n", 
		config.DNSServers[0].String(), config.DNSServers[1].String())
	fmt.Printf("도메인:             %s\n", config.DomainName)
	fmt.Printf("임대 시간:           %v\n", config.LeaseTime)
	fmt.Printf("Offer 타임아웃:      %v\n", config.OfferTimeout)
	
	if config.SecurityEnabled {
		fmt.Printf("\n%s보안 설정%s\n", ANSI_BOLD, ANSI_RESET)
		if config.RateLimitEnabled {
			fmt.Printf("Rate Limiting:      활성화 (%d req/min/IP, 글로벌: %d req/min)\n", 
				config.MaxRequestsPerMin, config.GlobalRateLimit)
		}
		if config.MACValidation {
			fmt.Printf("MAC 검증:          활성화\n")
		}
		if config.DuplicateXIDCheck {
			fmt.Printf("중복 XID 검사:      활성화\n")
		}
		if config.IPSpoofingCheck {
			fmt.Printf("IP 스푸핑 검사:     활성화\n")
		}
		if config.SecurityLogFile != "" {
			fmt.Printf("보안 로그:          %s\n", config.SecurityLogFile)
		}
	}
	
	if config.PacketPoolEnabled {
		fmt.Printf("\n%s성능 최적화 설정%s\n", ANSI_BOLD, ANSI_RESET)
		fmt.Printf("패킷 풀링:          활성화\n")
		fmt.Printf("워커 풀:           %d개 워커 (큐: %d)\n", 
			config.WorkerPoolSize, config.WorkerQueueSize)
		if config.MemoryOptimization {
			fmt.Printf("메모리 최적화:      활성화\n")
		}
		if config.CacheEnabled {
			fmt.Printf("패킷 캐싱:          활성화\n")
		}
		fmt.Printf("정리 간격:          %v\n", config.CleanupInterval)
	}
	
	if config.SupportRelay {
		fmt.Printf("\nRelay Agent:        지원 (최대 %d hops)\n", config.MaxHops)
	}
	
	if config.DropRate > 0 || config.ResponseDelay > 0 {
		fmt.Printf("\n%s시뮬레이션 설정%s\n", ANSI_BOLD, ANSI_RESET)
		if config.DropRate > 0 {
			fmt.Printf("패킷 드롭률:        %.1f%%\n", config.DropRate*100)
		}
		if config.ResponseDelay > 0 {
			fmt.Printf("응답 지연:          %v\n", config.ResponseDelay)
		}
	}
	
	fmt.Printf("\n시스템 정보:        CPU %d코어, 워커 %d개\n", 
		runtime.NumCPU(), config.WorkerPoolSize)
	
	if *liveStats {
		fmt.Printf("모니터링 모드:      실시간 대시보드\n")
	} else if *verbose {
		fmt.Printf("로깅 모드:         상세 로그\n")
	}
	
	fmt.Printf("%s\n", strings.Repeat("=", 70))
	
	// 서버 시작
	fmt.Printf("\n🚀 DHCP 서버를 시작합니다...\n\n")
	err := server.Start()
	if err != nil {
		log.Fatalf("서버 시작 실패: %v", err)
	}
	
	// 시작 완료 메시지
	if *liveStats {
		fmt.Printf("📊 실시간 대시보드가 곧 시작됩니다...\n")
		time.Sleep(2 * time.Second)
	} else {
		fmt.Printf("✅ 서버가 성공적으로 시작되었습니다!\n")
		fmt.Printf("📝 DHCP 요청을 처리할 준비가 완료되었습니다.\n\n")
		
		if *verbose {
			fmt.Printf("상세 로그 모드가 활성화되었습니다.\n")
		}
		
		fmt.Printf("종료하려면 Ctrl+C를 누르세요.\n")
		fmt.Printf("%s\n", strings.Repeat("-", 70))
	}
	
	// 종료 신호 대기
	<-sigChan
	
	fmt.Printf("\n\n종료 신호를 받았습니다. 서버를 정리 중...\n")
	
	// 서버 중지
	server.Stop()
	
	// 최종 통계 출력 (live 모드가 아닐 때만)
	if !*liveStats {
		server.PrintFinalStats()
	}
	
	fmt.Printf("\n✅ 서버가 안전하게 종료되었습니다.\n")
}
