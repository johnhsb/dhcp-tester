package main

import (
	"bytes"
	"encoding/binary"
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
	DHCPRelayAgentInfo    = 82  // Relay Agent Information Option
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
	TestModeSimulation TestMode = iota  // 시뮬레이션 모드 (권한 불필요)
	TestModeRealistic                   // 실제 모드 (root 권한 권장)
	TestModeBroadcast                   // 브로드캐스트 모드 (root 권한 필요)
)

// DHCP 패킷 구조체
type DHCPPacket struct {
	Op      uint8    // 1 = BOOTREQUEST, 2 = BOOTREPLY
	HType   uint8    // Hardware type (1 = Ethernet)
	HLen    uint8    // Hardware address length (6 for MAC)
	Hops    uint8    // Number of hops
	Xid     uint32   // Transaction ID
	Secs    uint16   // Seconds elapsed
	Flags   uint16   // Flags
	Ciaddr  [4]byte  // Client IP address
	Yiaddr  [4]byte  // Your IP address
	Siaddr  [4]byte  // Server IP address
	Giaddr  [4]byte  // Gateway IP address
	Chaddr  [16]byte // Client hardware address
	Sname   [64]byte // Server name
	File    [128]byte // Boot file name
	Options []byte   // Options
}

// 테스트 결과 구조체
type TestResult struct {
	ClientID      string
	Success       bool
	ResponseTime  time.Duration
	Error         string
	Timestamp     time.Time
	RelayUsed     bool
	
	// DHCP 과정 상세 정보
	DiscoverTime  time.Duration  // Discover 전송 시간
	OfferTime     time.Duration  // Offer 수신 시간
	RequestTime   time.Duration  // Request 전송 시간
	AckTime       time.Duration  // ACK 수신 시간
	OfferedIP     string         // 제공받은 IP
	ServerID      string         // DHCP 서버 ID
}

// Relay Agent 설정 구조체
type RelayConfig struct {
	Enabled      bool
	RelayIP      string    // Relay Agent의 IP (giaddr에 설정됨)
	CircuitID    string    // Option 82 Circuit ID
	RemoteID     string    // Option 82 Remote ID
	HopCount     uint8     // 현재 hop count
	MaxHops      uint8     // 최대 허용 hop count (기본값: 4)
}

// 통계 정보 구조체
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
	RelayTests  int64  // Relay Agent를 사용한 테스트 수
}

// 실시간 통계 구조체
type LiveStats struct {
	// 패킷 카운터 (atomic)
	DiscoverSent    int64
	OfferReceived   int64
	RequestSent     int64
	AckReceived     int64
	
	// 응답 시간 누적 (atomic으로는 float64 처리가 복잡하므로 mutex 사용)
	mutex           sync.RWMutex
	DiscoverOfferTimes []time.Duration
	RequestAckTimes    []time.Duration
	
	// 에러 카운터
	TimeoutErrors   int64
	ParsingErrors   int64
	NetworkErrors   int64
}

// DHCP 테스터 구조체
type DHCPTester struct {
	serverIP     string
	serverPort   int
	clientPort   int
	timeout      time.Duration
	results      []TestResult
	resultsMutex sync.Mutex
	relayConfig  *RelayConfig
	testMode     TestMode
	verbose      bool
	showLiveStats bool  // 실시간 통계 표시 여부
	liveStats    *LiveStats
	
	// 통계 카운터 (atomic 연산용)
	totalCount   int64
	successCount int64
	failureCount int64
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

// 새로운 DHCP 테스터 생성
func NewDHCPTester(serverIP string, serverPort int, timeout time.Duration) *DHCPTester {
	return &DHCPTester{
		serverIP:   serverIP,
		serverPort: serverPort,
		clientPort: 68,
		timeout:    timeout,
		results:    make([]TestResult, 0),
		testMode:   TestModeSimulation,
		relayConfig: &RelayConfig{
			Enabled:  false,
			MaxHops:  4,
		},
		liveStats: &LiveStats{
			DiscoverOfferTimes: make([]time.Duration, 0),
			RequestAckTimes:    make([]time.Duration, 0),
		},
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

// 실시간 대시보드 출력
func (dt *DHCPTester) printLiveDashboard(numClients int, elapsedTime time.Duration) {
	fmt.Print(ANSI_CURSOR_HOME)
	
	// 헤더
	fmt.Printf("%s%s╔══════════════════════════════════════════════════════════════════════╗%s\n", ANSI_BOLD, ANSI_CYAN, ANSI_RESET)
	fmt.Printf("%s%s║                    DHCP 서버 성능 테스트 실시간 모니터                     ║%s\n", ANSI_BOLD, ANSI_CYAN, ANSI_RESET)
	fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════════════╝%s\n", ANSI_BOLD, ANSI_CYAN, ANSI_RESET)
	fmt.Println()
	
	// 기본 정보
	fmt.Printf("%s테스트 설정%s\n", ANSI_BOLD, ANSI_RESET)
	fmt.Printf("  서버: %s%s:%d%s", ANSI_YELLOW, dt.serverIP, dt.serverPort, ANSI_RESET)
	if dt.relayConfig.Enabled {
		fmt.Printf("  (Relay: %s%s%s)", ANSI_GREEN, dt.relayConfig.RelayIP, ANSI_RESET)
	}
	fmt.Println()
	fmt.Printf("  클라이언트: %s%d%s, 경과시간: %s%v%s\n\n", ANSI_YELLOW, numClients, ANSI_RESET, ANSI_YELLOW, elapsedTime.Truncate(time.Second), ANSI_RESET)
	
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
	
	fmt.Printf("%s│%s                                                                    %s%s│%s\n", ANSI_BLUE, ANSI_RESET, ANSI_BLUE, ANSI_RESET)
	fmt.Printf("%s│%s  평균 응답시간:                                                    %s%s│%s\n", ANSI_BLUE, ANSI_RESET, ANSI_BLUE, ANSI_RESET)
	fmt.Printf("%s│%s    Discover → Offer: %s%10v%s      Request → ACK: %s%10v%s    %s%s│%s\n", 
		ANSI_BLUE, ANSI_RESET, ANSI_YELLOW, avgDO, ANSI_RESET, ANSI_YELLOW, avgRA, ANSI_RESET, ANSI_BLUE, ANSI_RESET)
	
	fmt.Printf("%s%s└──────────────────────────────────────────────────────────────────────┘%s\n", ANSI_BOLD, ANSI_BLUE, ANSI_RESET)
	fmt.Println()
	
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
		fmt.Printf("  완료율: %s%.1f completions/sec%s\n", ANSI_GREEN, rps, ANSI_RESET)
		
		if success > 0 {
			successRps := float64(success) / elapsedTime.Seconds()
			fmt.Printf("  성공율: %s%.1f successful/sec%s\n", ANSI_GREEN, successRps, ANSI_RESET)
		}
		fmt.Println()
	}
	
	fmt.Printf("%s%s[ESC 또는 Ctrl+C로 중단]%s", ANSI_BOLD, ANSI_WHITE, ANSI_RESET)
}

// Relay Agent 설정
func (dt *DHCPTester) SetRelayConfig(config *RelayConfig) {
	dt.relayConfig = config
}

// Verbose 모드 설정
func (dt *DHCPTester) SetVerbose(verbose bool) {
	dt.verbose = verbose
}

// 실시간 통계 모드 설정
func (dt *DHCPTester) SetLiveStats(enabled bool) {
	dt.showLiveStats = enabled
}

// 실시간 통계 업데이트
func (dt *DHCPTester) updateLiveStats(stage string, responseTime time.Duration, errorType string) {
	switch stage {
	case "discover":
		atomic.AddInt64(&dt.liveStats.DiscoverSent, 1)
	case "offer":
		atomic.AddInt64(&dt.liveStats.OfferReceived, 1)
		dt.liveStats.mutex.Lock()
		dt.liveStats.DiscoverOfferTimes = append(dt.liveStats.DiscoverOfferTimes, responseTime)
		// 메모리 절약을 위해 최근 1000개만 유지
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
		// 메모리 절약을 위해 최근 1000개만 유지
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
		}
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

// Option 82 (Relay Agent Information) 생성
func createRelayAgentOption(circuitID, remoteID string) []byte {
	if circuitID == "" && remoteID == "" {
		return nil
	}
	
	var suboptions []byte
	
	// Circuit ID sub-option
	if circuitID != "" {
		circuitIDBytes := []byte(circuitID)
		suboptions = append(suboptions, RelayAgentCircuitID)
		suboptions = append(suboptions, byte(len(circuitIDBytes)))
		suboptions = append(suboptions, circuitIDBytes...)
	}
	
	// Remote ID sub-option
	if remoteID != "" {
		remoteIDBytes := []byte(remoteID)
		suboptions = append(suboptions, RelayAgentRemoteID)
		suboptions = append(suboptions, byte(len(remoteIDBytes)))
		suboptions = append(suboptions, remoteIDBytes...)
	}
	
	// Option 82 헤더 추가
	option82 := []byte{DHCPRelayAgentInfo, byte(len(suboptions))}
	option82 = append(option82, suboptions...)
	
	return option82
}

// MAC 주소 생성
func generateMACAddress() [6]byte {
	mac := [6]byte{}
	mac[0] = 0x02 // 로컬 관리 비트 설정
	for i := 1; i < 6; i++ {
		mac[i] = byte(rand.Intn(256))
	}
	return mac
}

// DHCP Discover 패킷 생성 (Relay Agent 지원)
func createDiscoverPacket(xid uint32, clientMAC [6]byte, relayConfig *RelayConfig) []byte {
	packet := make([]byte, 240) // 기본 DHCP 헤더 크기
	
	// DHCP 헤더 설정
	packet[0] = 1                                    // Op: BOOTREQUEST
	packet[1] = 1                                    // HType: Ethernet
	packet[2] = 6                                    // HLen: MAC length
	
	// Relay Agent가 활성화된 경우 hops 설정
	if relayConfig != nil && relayConfig.Enabled {
		packet[3] = relayConfig.HopCount              // Hops
	} else {
		packet[3] = 0                                 // Hops
	}
	
	binary.BigEndian.PutUint32(packet[4:8], xid)    // Transaction ID
	binary.BigEndian.PutUint16(packet[8:10], 0)     // Secs
	binary.BigEndian.PutUint16(packet[10:12], 0)    // Flags
	// Ciaddr는 0으로 유지
	// Yiaddr는 0으로 유지
	// Siaddr는 0으로 유지
	
	// Giaddr 설정 (Relay Agent IP)
	if relayConfig != nil && relayConfig.Enabled && relayConfig.RelayIP != "" {
		relayIPBytes, err := ipToBytes(relayConfig.RelayIP)
		if err == nil {
			copy(packet[24:28], relayIPBytes[:])
		}
	}
	
	copy(packet[28:34], clientMAC[:])               // Client MAC address
	
	// Magic Cookie 추가
	packet = append(packet, 0x63, 0x82, 0x53, 0x63)
	
	// DHCP 옵션 추가
	// Message Type (Discover)
	packet = append(packet, DHCPMessageType, 1, DHCPDiscover)
	
	// Client Identifier
	packet = append(packet, DHCPClientID, 7, 1) // 옵션 코드, 길이, 하드웨어 타입
	packet = append(packet, clientMAC[:]...)
	
	// Relay Agent Information (Option 82) 추가
	if relayConfig != nil && relayConfig.Enabled {
		option82 := createRelayAgentOption(relayConfig.CircuitID, relayConfig.RemoteID)
		if option82 != nil {
			packet = append(packet, option82...)
		}
	}
	
	// End option
	packet = append(packet, DHCPEnd)
	
	return packet
}

// DHCP Request 패킷 생성 (Relay Agent 지원)
func createRequestPacket(xid uint32, clientMAC [6]byte, requestedIP, serverIP uint32, relayConfig *RelayConfig) []byte {
	packet := make([]byte, 240)
	
	// DHCP 헤더 설정
	packet[0] = 1
	packet[1] = 1
	packet[2] = 6
	
	// Relay Agent가 활성화된 경우 hops 설정
	if relayConfig != nil && relayConfig.Enabled {
		packet[3] = relayConfig.HopCount
	} else {
		packet[3] = 0
	}
	
	binary.BigEndian.PutUint32(packet[4:8], xid)
	binary.BigEndian.PutUint16(packet[8:10], 0)
	binary.BigEndian.PutUint16(packet[10:12], 0)
	
	// Giaddr 설정 (Relay Agent IP)
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
	// Message Type (Request)
	packet = append(packet, DHCPMessageType, 1, DHCPRequest)
	
	// Requested IP Address
	packet = append(packet, DHCPRequestedIP, 4)
	reqIPBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(reqIPBytes, requestedIP)
	packet = append(packet, reqIPBytes...)
	
	// Server Identifier
	packet = append(packet, DHCPServerID, 4)
	serverIPBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(serverIPBytes, serverIP)
	packet = append(packet, serverIPBytes...)
	
	// Client Identifier
	packet = append(packet, DHCPClientID, 7, 1)
	packet = append(packet, clientMAC[:]...)
	
	// Relay Agent Information (Option 82) 추가
	if relayConfig != nil && relayConfig.Enabled {
		option82 := createRelayAgentOption(relayConfig.CircuitID, relayConfig.RemoteID)
		if option82 != nil {
			packet = append(packet, option82...)
		}
	}
	
	// End option
	packet = append(packet, DHCPEnd)
	
	return packet
}

// DHCP 패킷 파싱
func parseDHCPPacket(data []byte) (*DHCPPacket, error) {
	if len(data) < 240 {
		return nil, fmt.Errorf("패킷이 너무 짧습니다")
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

// 서버 ID 추출
func getServerID(options []byte) (uint32, error) {
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
		
		if optionCode == DHCPServerID && optionLength == 4 && i+6 <= len(options) {
			return binary.BigEndian.Uint32(options[i+2:i+6]), nil
		}
		
		i += 2 + optionLength
	}
	return 0, fmt.Errorf("서버 ID를 찾을 수 없습니다")
}

// 단일 클라이언트 테스트 (완전한 DHCP 4-way handshake + 실시간 통계)
func (dt *DHCPTester) testSingleClient(clientID string) TestResult {
	overallStart := time.Now()
	result := TestResult{
		ClientID:  clientID,
		Timestamp: overallStart,
		RelayUsed: dt.relayConfig.Enabled,
	}
	
	if dt.verbose {
		fmt.Printf("[%s] DHCP 4-way handshake 시작\n", clientID)
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
		if dt.verbose {
			fmt.Printf("[%s] Relay Agent 모드: %s (hops: %d)\n", clientID, dt.relayConfig.RelayIP, dt.relayConfig.HopCount)
		}
	}
	
	// UDP 연결 생성
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", dt.serverIP, dt.serverPort), dt.timeout)
	if err != nil {
		result.Error = fmt.Sprintf("연결 실패: %v", err)
		dt.updateLiveStats("error", 0, "network")
		atomic.AddInt64(&dt.failureCount, 1)
		return result
	}
	defer conn.Close()
	
	// 타임아웃 설정
	conn.SetDeadline(time.Now().Add(dt.timeout))
	
	// 클라이언트 정보 생성
	xid := rand.Uint32()
	clientMAC := generateMACAddress()
	
	if dt.verbose {
		fmt.Printf("[%s] Transaction ID: 0x%08X, MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
			clientID, xid, clientMAC[0], clientMAC[1], clientMAC[2], clientMAC[3], clientMAC[4], clientMAC[5])
	}
	
	// === 1단계: DHCP Discover 전송 ===
	discoverStart := time.Now()
	discoverPacket := createDiscoverPacket(xid, clientMAC, dt.relayConfig)
	_, err = conn.Write(discoverPacket)
	if err != nil {
		result.Error = fmt.Sprintf("Discover 전송 실패: %v", err)
		dt.updateLiveStats("error", 0, "network")
		atomic.AddInt64(&dt.failureCount, 1)
		return result
	}
	result.DiscoverTime = time.Since(discoverStart)
	dt.updateLiveStats("discover", 0, "")
	
	if dt.verbose {
		fmt.Printf("[%s] ➤ DHCP Discover 전송 완료 (%v)\n", clientID, result.DiscoverTime)
	}
	
	// === 2단계: DHCP Offer 수신 ===
	offerStart := time.Now()
	buffer := make([]byte, 1500)
	n, err := conn.Read(buffer)
	if err != nil {
		result.Error = fmt.Sprintf("Offer 수신 실패: %v", err)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			dt.updateLiveStats("error", 0, "timeout")
		} else {
			dt.updateLiveStats("error", 0, "network")
		}
		atomic.AddInt64(&dt.failureCount, 1)
		return result
	}
	result.OfferTime = time.Since(offerStart)
	
	offerPacket, err := parseDHCPPacket(buffer[:n])
	if err != nil {
		result.Error = fmt.Sprintf("Offer 파싱 실패: %v", err)
		dt.updateLiveStats("error", 0, "parsing")
		atomic.AddInt64(&dt.failureCount, 1)
		return result
	}
	
	if offerPacket.Xid != xid {
		result.Error = "잘못된 Transaction ID (Offer)"
		dt.updateLiveStats("error", 0, "parsing")
		atomic.AddInt64(&dt.failureCount, 1)
		return result
	}
	
	// Discover-Offer 시간 계산 (Discover 전송 후 Offer 수신까지)
	discoverOfferTime := time.Since(discoverStart)
	dt.updateLiveStats("offer", discoverOfferTime, "")
	
	// Relay Agent를 사용하는 경우 giaddr 검증
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
	
	messageType, err := getMessageType(offerPacket.Options)
	if err != nil || messageType != DHCPOffer {
		result.Error = "DHCP Offer가 아닙니다"
		dt.updateLiveStats("error", 0, "parsing")
		atomic.AddInt64(&dt.failureCount, 1)
		return result
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
		fmt.Printf("[%s] ◀ DHCP Offer 수신 완료 (%v) - IP: %s, 서버: %s\n", 
			clientID, result.OfferTime, result.OfferedIP, result.ServerID)
	}
	
	// === 3단계: DHCP Request 전송 ===
	requestStart := time.Now()
	requestPacket := createRequestPacket(xid, clientMAC, offeredIP, serverID, dt.relayConfig)
	_, err = conn.Write(requestPacket)
	if err != nil {
		result.Error = fmt.Sprintf("Request 전송 실패: %v", err)
		dt.updateLiveStats("error", 0, "network")
		atomic.AddInt64(&dt.failureCount, 1)
		return result
	}
	result.RequestTime = time.Since(requestStart)
	dt.updateLiveStats("request", 0, "")
	
	if dt.verbose {
		fmt.Printf("[%s] ➤ DHCP Request 전송 완료 (%v) - 요청 IP: %s\n", 
			clientID, result.RequestTime, result.OfferedIP)
	}
	
	// === 4단계: DHCP ACK 수신 ===
	ackStart := time.Now()
	n, err = conn.Read(buffer)
	if err != nil {
		result.Error = fmt.Sprintf("ACK 수신 실패: %v", err)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			dt.updateLiveStats("error", 0, "timeout")
		} else {
			dt.updateLiveStats("error", 0, "network")
		}
		atomic.AddInt64(&dt.failureCount, 1)
		return result
	}
	result.AckTime = time.Since(ackStart)
	
	ackPacket, err := parseDHCPPacket(buffer[:n])
	if err != nil {
		result.Error = fmt.Sprintf("ACK 파싱 실패: %v", err)
		dt.updateLiveStats("error", 0, "parsing")
		atomic.AddInt64(&dt.failureCount, 1)
		return result
	}
	
	if ackPacket.Xid != xid {
		result.Error = "잘못된 Transaction ID (ACK)"
		dt.updateLiveStats("error", 0, "parsing")
		atomic.AddInt64(&dt.failureCount, 1)
		return result
	}
	
	messageType, err = getMessageType(ackPacket.Options)
	if err != nil || messageType != DHCPAck {
		result.Error = "DHCP ACK가 아닙니다"
		dt.updateLiveStats("error", 0, "parsing")
		atomic.AddInt64(&dt.failureCount, 1)
		return result
	}
	
	// Request-ACK 시간 계산 (Request 전송 후 ACK 수신까지)
	requestAckTime := time.Since(requestStart)
	dt.updateLiveStats("ack", requestAckTime, "")
	
	if dt.verbose {
		fmt.Printf("[%s] ◀ DHCP ACK 수신 완료 (%v) - IP 할당 성공!\n", 
			clientID, result.AckTime)
	}
	
	// === 성공: 전체 과정 완료 ===
	result.Success = true
	result.ResponseTime = time.Since(overallStart)
	atomic.AddInt64(&dt.successCount, 1)
	
	if dt.verbose {
		fmt.Printf("[%s] ✅ DHCP 4-way handshake 완료 (총 시간: %v)\n", clientID, result.ResponseTime)
		fmt.Printf("[%s]    단계별 시간: Discover=%v, Offer=%v, Request=%v, ACK=%v\n",
			clientID, result.DiscoverTime, result.OfferTime, result.RequestTime, result.AckTime)
		fmt.Printf("[%s]    응답 시간: D-O=%v, R-A=%v\n", clientID, discoverOfferTime, requestAckTime)
		fmt.Println()
	}
	
	return result
}

// 성능 테스트 실행 (실시간 모니터링 지원)
func (dt *DHCPTester) RunPerformanceTest(numClients int, concurrency int, showProgress bool) *Statistics {
	if dt.showLiveStats {
		// 실시간 모니터링 모드
		return dt.runTestWithLiveStats(numClients, concurrency)
	} else {
		// 기존 진행률 표시 모드
		return dt.runTestWithProgressBar(numClients, concurrency, showProgress)
	}
}

// 실시간 통계 모니터링과 함께 테스트 실행
func (dt *DHCPTester) runTestWithLiveStats(numClients int, concurrency int) *Statistics {
	fmt.Printf("DHCP 서버 성능 테스트 시작 (실시간 모니터링 모드)\n")
	fmt.Printf("대상 서버: %s:%d\n", dt.serverIP, dt.serverPort)
	fmt.Printf("총 클라이언트: %d, 동시 실행: %d\n", numClients, concurrency)
	fmt.Printf("실시간 대시보드를 시작합니다...\n\n")
	
	time.Sleep(2 * time.Second) // 사용자가 메시지를 읽을 시간
	
	// 터미널 초기화
	initTerminal()
	defer restoreTerminal()
	
	startTime := time.Now()
	
	// 결과 채널과 작업 채널 생성
	resultChan := make(chan TestResult, numClients)
	workChan := make(chan string, numClients)
	
	// 작업 큐에 클라이언트 ID 추가
	for i := 0; i < numClients; i++ {
		workChan <- fmt.Sprintf("client_%05d", i+1)
	}
	close(workChan)
	
	// 워커 고루틴 시작
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
	
	// 실시간 대시보드 업데이트 고루틴
	var dashboardWG sync.WaitGroup
	dashboardWG.Add(1)
	done := make(chan bool)
	
	go func() {
		defer dashboardWG.Done()
		ticker := time.NewTicker(200 * time.Millisecond) // 5fps 업데이트
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
	
	// 결과 저장
	for result := range resultChan {
		dt.resultsMutex.Lock()
		dt.results = append(dt.results, result)
		dt.resultsMutex.Unlock()
	}
	
	dashboardWG.Wait()
	
	// 최종 대시보드 표시
	dt.printLiveDashboard(numClients, time.Since(startTime))
	
	fmt.Printf("\n\n%s테스트 완료!%s\n", ANSI_BOLD+ANSI_GREEN, ANSI_RESET)
	
	totalTime := time.Since(startTime)
	return dt.calculateStatistics(totalTime)
}

// 기존 진행률 표시로 테스트 실행
func (dt *DHCPTester) runTestWithProgressBar(numClients int, concurrency int, showProgress bool) *Statistics {
	fmt.Printf("DHCP 서버 성능 테스트 시작\n")
	fmt.Printf("대상 서버: %s:%d\n", dt.serverIP, dt.serverPort)
	fmt.Printf("총 클라이언트: %d\n", numClients)
	fmt.Printf("동시 실행 수: %d\n", concurrency)
	fmt.Printf("타임아웃: %v\n", dt.timeout)
	
	// Relay Agent 정보 표시
	if dt.relayConfig.Enabled {
		fmt.Printf("Relay Agent: 활성화\n")
		fmt.Printf("  - Relay IP: %s\n", dt.relayConfig.RelayIP)
		fmt.Printf("  - Hop Count: %d\n", dt.relayConfig.HopCount)
		fmt.Printf("  - Max Hops: %d\n", dt.relayConfig.MaxHops)
		if dt.relayConfig.CircuitID != "" {
			fmt.Printf("  - Circuit ID: %s\n", dt.relayConfig.CircuitID)
		}
		if dt.relayConfig.RemoteID != "" {
			fmt.Printf("  - Remote ID: %s\n", dt.relayConfig.RemoteID)
		}
	} else {
		fmt.Printf("Relay Agent: 비활성화 (직접 통신)\n")
	}
	
	fmt.Printf("%s\n", strings.Repeat("-", 60))
	
	startTime := time.Now()
	
	// 결과 채널과 작업 채널 생성
	resultChan := make(chan TestResult, numClients)
	workChan := make(chan string, numClients)
	
	// 작업 큐에 클라이언트 ID 추가
	for i := 0; i < numClients; i++ {
		workChan <- fmt.Sprintf("client_%05d", i+1)
	}
	close(workChan)
	
	// 워커 고루틴 시작
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
					
					fmt.Printf("\r진행상황: %d/%d (성공: %d, 실패: %d) [%.1f%%]",
						completed, numClients, success, failure,
						float64(completed)/float64(numClients)*100)
				}
			}
		}()
	}
	
	// 결과 수집
	go func() {
		wg.Wait()
		close(resultChan)
	}()
	
	// 결과 저장
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

// 통계 계산
func (dt *DHCPTester) calculateStatistics(totalTime time.Duration) *Statistics {
	stats := &Statistics{
		TotalRequests:  int64(len(dt.results)),
		ErrorCounts:    make(map[string]int64),
	}
	
	var responseTimes []time.Duration
	var discoverTimes, offerTimes, requestTimes, ackTimes []time.Duration
	
	for _, result := range dt.results {
		if result.RelayUsed {
			stats.RelayTests++
		}
		
		if result.Success {
			stats.SuccessfulRequests++
			responseTimes = append(responseTimes, result.ResponseTime)
			
			// DHCP 단계별 시간 수집
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
	
	stats.SuccessRate = float64(stats.SuccessfulRequests) / float64(stats.TotalRequests) * 100
	stats.TotalTime = totalTime
	stats.RequestsPerSecond = float64(stats.TotalRequests) / totalTime.Seconds()
	
	if len(responseTimes) > 0 {
		sort.Slice(responseTimes, func(i, j int) bool {
			return responseTimes[i] < responseTimes[j]
		})
		
		stats.MinResponseTime = responseTimes[0]
		stats.MaxResponseTime = responseTimes[len(responseTimes)-1]
		
		// 평균 계산
		var total time.Duration
		for _, rt := range responseTimes {
			total += rt
		}
		stats.AvgResponseTime = total / time.Duration(len(responseTimes))
		
		// 백분위수 계산
		stats.MedianResponseTime = responseTimes[len(responseTimes)/2]
		stats.P95ResponseTime = responseTimes[int(float64(len(responseTimes))*0.95)]
		stats.P99ResponseTime = responseTimes[int(float64(len(responseTimes))*0.99)]
	}
	
	return stats
}

// 통계 출력
func (stats *Statistics) PrintReport() {
	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Printf("DHCP 서버 성능 테스트 결과 (완전한 4-way handshake)\n")
	fmt.Printf("%s\n", strings.Repeat("=", 70))
	fmt.Printf("각 클라이언트가 수행한 과정: Discover → Offer → Request → ACK\n")
	fmt.Printf("%s\n", strings.Repeat("-", 70))
	fmt.Printf("총 요청 수:          %10d\n", stats.TotalRequests)
	fmt.Printf("성공 요청 수:        %10d\n", stats.SuccessfulRequests)
	fmt.Printf("실패 요청 수:        %10d\n", stats.FailedRequests)
	fmt.Printf("성공률:             %9.1f%%\n", stats.SuccessRate)
	fmt.Printf("총 테스트 시간:      %10v\n", stats.TotalTime)
	fmt.Printf("초당 완료 수:        %9.1f completions/s\n", stats.RequestsPerSecond)
	
	// Relay Agent 통계
	if stats.RelayTests > 0 {
		fmt.Printf("Relay 테스트 수:     %10d\n", stats.RelayTests)
		fmt.Printf("직접 테스트 수:      %10d\n", stats.TotalRequests - stats.RelayTests)
	}
	
	if stats.SuccessfulRequests > 0 {
		fmt.Printf("\n%s\n", strings.Repeat("-", 70))
		fmt.Printf("완전한 DHCP 협상 시간 통계 (Discover~ACK 전체 과정)\n")
		fmt.Printf("%s\n", strings.Repeat("-", 70))
		fmt.Printf("최소 협상 시간:      %10v\n", stats.MinResponseTime)
		fmt.Printf("최대 협상 시간:      %10v\n", stats.MaxResponseTime)
		fmt.Printf("평균 협상 시간:      %10v\n", stats.AvgResponseTime)
		fmt.Printf("중간값 협상 시간:    %10v\n", stats.MedianResponseTime)
		fmt.Printf("95퍼센타일:         %10v\n", stats.P95ResponseTime)
		fmt.Printf("99퍼센타일:         %10v\n", stats.P99ResponseTime)
		
		fmt.Printf("\n💡 참고: 위 시간은 각 클라이언트가 IP 주소를 완전히 획득하는데\n")
		fmt.Printf("   걸린 전체 시간입니다 (4단계 모두 포함)\n")
	}
	
	if stats.FailedRequests > 0 {
		fmt.Printf("\n%s\n", strings.Repeat("-", 70))
		fmt.Printf("실패 원인 분석\n")
		fmt.Printf("%s\n", strings.Repeat("-", 70))
		for error, count := range stats.ErrorCounts {
			fmt.Printf("%-50s: %d건\n", error, count)
		}
	}
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
		verbose     = flag.Bool("verbose", false, "상세 DHCP 과정 출력 (각 클라이언트별 4-way handshake)")
		liveStats   = flag.Bool("live", false, "실시간 대시보드 모니터링 (curses 스타일)")
		seed        = flag.Int64("seed", 0, "랜덤 시드 (0은 현재 시간)")
		
		// Relay Agent 관련 플래그
		relayEnabled  = flag.Bool("relay", false, "DHCP Relay Agent 모드 활성화")
		relayIP       = flag.String("relay-ip", "", "Relay Agent IP 주소 (giaddr)")
		relayCircuitID = flag.String("circuit-id", "", "Relay Agent Circuit ID (Option 82)")
		relayRemoteID  = flag.String("remote-id", "", "Relay Agent Remote ID (Option 82)")
		relayHops      = flag.Int("hops", 1, "Relay Agent Hop Count")
		relayMaxHops   = flag.Int("max-hops", 4, "최대 허용 Hop Count")
		
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
	
	// 포트 68 바인딩 테스트 (권한 확인용)
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
	
	// 테스터 생성
	tester := NewDHCPTester(*serverIP, *serverPort, *timeout)
	
	// 모드 설정
	tester.SetVerbose(*verbose)
	tester.SetLiveStats(*liveStats)
	
	// 모드 안내 메시지
	if *liveStats {
		fmt.Printf("📊 실시간 대시보드 모드: DHCP 4-way handshake 과정을 실시간으로 모니터링합니다\n")
		fmt.Printf("   각 단계별 패킷 수와 D-O, R-A 평균 응답시간을 실시간 표시합니다\n\n")
	} else if *verbose {
		fmt.Printf("🔍 Verbose 모드: 각 클라이언트의 DHCP 4-way handshake 과정을 상세히 표시합니다\n")
		fmt.Printf("   Discover → Offer → Request → ACK 순서로 진행됩니다\n\n")
	}
	
	// Live 모드와 Verbose 모드 동시 사용 방지
	if *liveStats && *verbose {
		fmt.Printf("⚠️  Live 모드와 Verbose 모드는 동시에 사용할 수 없습니다. Live 모드를 우선합니다.\n")
		tester.SetVerbose(false)
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
		
		fmt.Printf("DHCP Relay Agent 모드로 실행합니다.\n")
		fmt.Printf("Relay IP: %s, Hops: %d, Max Hops: %d\n", 
			*relayIP, *relayHops, *relayMaxHops)
		if *relayCircuitID != "" {
			fmt.Printf("Circuit ID: %s\n", *relayCircuitID)
		}
		if *relayRemoteID != "" {
			fmt.Printf("Remote ID: %s\n", *relayRemoteID)
		}
		fmt.Println()
	}
	
	// 테스트 실행
	stats := tester.RunPerformanceTest(*numClients, *concurrency, *showProgress)
	
	// 결과 출력
	stats.PrintReport()
}
