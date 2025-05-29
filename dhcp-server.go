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
	"os/signal"
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

// IP 주소 풀 엔트리
type IPPoolEntry struct {
	IP        net.IP
	Available bool
	LeaseTime time.Time
	ClientMAC [6]byte
	ClientID  string
}

// 클라이언트 세션 정보
type ClientSession struct {
	TransactionID uint32
	ClientMAC     [6]byte
	ClientID      string
	OfferedIP     net.IP
	OfferTime     time.Time
	State         string // "offered", "leased", "expired"
	RelayIP       net.IP
	CircuitID     string
	RemoteID      string
}

// 서버 통계
type ServerStats struct {
	// 패킷 카운터 (atomic)
	DiscoverReceived int64
	OfferSent       int64
	RequestReceived int64
	AckSent         int64
	NakSent         int64
	
	// 성능 지표
	mutex           sync.RWMutex
	ProcessingTimes []time.Duration
	
	// 에러 카운터
	ParseErrors     int64
	PoolExhausted   int64
	InvalidRequests int64
	
	StartTime       time.Time
}

// DHCP 서버 구조체
type DHCPServer struct {
	config       *ServerConfig
	ipPool       []*IPPoolEntry
	poolMutex    sync.RWMutex
	sessions     map[uint32]*ClientSession
	sessionMutex sync.RWMutex
	stats        *ServerStats
	running      bool
	runMutex     sync.RWMutex
	
	conn         *net.UDPConn
	verbose      bool
	showLiveStats bool
}

// 서버 설정
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
	DropRate         float64  // 0.0-1.0, 패킷 드롭 시뮬레이션
	
	// Relay Agent 지원
	SupportRelay     bool
	MaxHops          uint8
}

// 기본 서버 설정
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
	}
}

// 새로운 DHCP 서버 생성
func NewDHCPServer(config *ServerConfig) *DHCPServer {
	server := &DHCPServer{
		config:   config,
		sessions: make(map[uint32]*ClientSession),
		stats: &ServerStats{
			StartTime:       time.Now(),
			ProcessingTimes: make([]time.Duration, 0),
		},
		running: false,
	}
	
	// IP 풀 초기화
	server.initIPPool()
	
	return server
}

// IP 풀 초기화
func (s *DHCPServer) initIPPool() {
	s.poolMutex.Lock()
	defer s.poolMutex.Unlock()
	
	start := ipToUint32(s.config.StartIP)
	end := ipToUint32(s.config.EndIP)
	
	s.ipPool = make([]*IPPoolEntry, 0, end-start+1)
	
	for ip := start; ip <= end; ip++ {
		entry := &IPPoolEntry{
			IP:        uint32ToIP(ip),
			Available: true,
		}
		s.ipPool = append(s.ipPool, entry)
	}
	
	fmt.Printf("IP 풀 초기화 완료: %s - %s (%d개 주소)\n", 
		s.config.StartIP.String(), s.config.EndIP.String(), len(s.ipPool))
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

// 사용 가능한 IP 주소 할당
func (s *DHCPServer) allocateIP(clientMAC [6]byte, clientID string) net.IP {
	s.poolMutex.Lock()
	defer s.poolMutex.Unlock()
	
	// 기존에 할당된 IP가 있는지 확인
	for _, entry := range s.ipPool {
		if !entry.Available && bytes.Equal(entry.ClientMAC[:], clientMAC[:]) {
			if time.Since(entry.LeaseTime) < s.config.LeaseTime {
				return entry.IP
			}
			// 임대 시간 만료됨
			entry.Available = true
		}
	}
	
	// 새로운 IP 할당
	for _, entry := range s.ipPool {
		if entry.Available {
			entry.Available = false
			entry.ClientMAC = clientMAC
			entry.ClientID = clientID
			entry.LeaseTime = time.Now()
			return entry.IP
		}
	}
	
	// 풀 고갈
	atomic.AddInt64(&s.stats.PoolExhausted, 1)
	return nil
}

// IP 주소 해제
func (s *DHCPServer) releaseIP(ip net.IP) {
	s.poolMutex.Lock()
	defer s.poolMutex.Unlock()
	
	for _, entry := range s.ipPool {
		if entry.IP.Equal(ip) {
			entry.Available = true
			entry.ClientMAC = [6]byte{}
			entry.ClientID = ""
			break
		}
	}
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

// DHCP 응답 패킷 생성
func (s *DHCPServer) createResponsePacket(request *DHCPPacket, msgType uint8, offeredIP net.IP, relayAgentInfo []byte) []byte {
	packet := make([]byte, 240)
	
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
	
	return packet
}

// DHCP Discover 처리
func (s *DHCPServer) handleDiscover(packet *DHCPPacket, clientAddr *net.UDPAddr) {
	atomic.AddInt64(&s.stats.DiscoverReceived, 1)
	
	if s.verbose {
		fmt.Printf("[DISCOVER] Transaction ID: 0x%08X, Client: %02x:%02x:%02x:%02x:%02x:%02x\n",
			packet.Xid, packet.Chaddr[0], packet.Chaddr[1], packet.Chaddr[2],
			packet.Chaddr[3], packet.Chaddr[4], packet.Chaddr[5])
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
	clientMAC := [6]byte{}
	copy(clientMAC[:], packet.Chaddr[:6])
	
	// IP 주소 할당
	offeredIP := s.allocateIP(clientMAC, clientID)
	if offeredIP == nil {
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
	
	// 세션 정보 저장
	session := &ClientSession{
		TransactionID: packet.Xid,
		ClientMAC:     clientMAC,
		ClientID:      clientID,
		OfferedIP:     offeredIP,
		OfferTime:     time.Now(),
		State:         "offered",
		CircuitID:     circuitID,
		RemoteID:      remoteID,
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
	
	if s.verbose {
		fmt.Printf("[OFFER] IP: %s → Transaction ID: 0x%08X\n", offeredIP.String(), packet.Xid)
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

// DHCP Request 처리
func (s *DHCPServer) handleRequest(packet *DHCPPacket, clientAddr *net.UDPAddr) {
	atomic.AddInt64(&s.stats.RequestReceived, 1)
	
	if s.verbose {
		fmt.Printf("[REQUEST] Transaction ID: 0x%08X\n", packet.Xid)
	}
	
	// 드롭 시뮬레이션
	if s.config.DropRate > 0 && rand.Float64() < s.config.DropRate {
		if s.verbose {
			fmt.Printf("[REQUEST] 패킷 드롭 시뮬레이션\n")
		}
		return
	}
	
	// 세션 확인
	s.sessionMutex.RLock()
	session, exists := s.sessions[packet.Xid]
	s.sessionMutex.RUnlock()
	
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
		s.releaseIP(session.OfferedIP)
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
	s.sessionMutex.Unlock()
	
	atomic.AddInt64(&s.stats.AckSent, 1)
	
	if s.verbose {
		fmt.Printf("[ACK] IP: %s → Transaction ID: 0x%08X\n", session.OfferedIP.String(), packet.Xid)
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

// 패킷 처리
func (s *DHCPServer) handlePacket(data []byte, clientAddr *net.UDPAddr) {
	start := time.Now()
	
	packet, err := parseDHCPPacket(data)
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

// 서버 시작
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
	if s.config.DropRate > 0 {
		fmt.Printf("패킷 드롭 시뮬레이션: %.1f%%\n", s.config.DropRate*100)
	}
	if s.config.ResponseDelay > 0 {
		fmt.Printf("응답 지연 시뮬레이션: %v\n", s.config.ResponseDelay)
	}
	fmt.Println(strings.Repeat("-", 60))
	
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

// 서버 메인 루프
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
		
		// 고루틴으로 패킷 처리 (동시 처리)
		go s.handlePacket(buffer[:n], clientAddr)
	}
}

// 실시간 통계 루프
func (s *DHCPServer) liveStatsLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	for s.isRunning() {
		select {
		case <-ticker.C:
			s.printLiveStats()
		}
	}
}

// 실시간 통계 출력
func (s *DHCPServer) printLiveStats() {
	// 터미널 클리어 및 상단으로 이동
	fmt.Print("\033[2J\033[H")
	
	// 헤더
	fmt.Printf("%s╔════════════════════════════════════════════════════════════════════════╗%s\n", "\033[1;36m", "\033[0m")
	fmt.Printf("%s║                        DHCP 서버 실시간 모니터링                          ║%s\n", "\033[1;36m", "\033[0m")
	fmt.Printf("%s╚════════════════════════════════════════════════════════════════════════╝%s\n", "\033[1;36m", "\033[0m")
	fmt.Println()
	
	// 서버 정보
	uptime := time.Since(s.stats.StartTime)
	fmt.Printf("%s서버 정보%s\n", "\033[1m", "\033[0m")
	fmt.Printf("  주소: %s%s:%d%s", "\033[33m", s.config.ListenIP, s.config.ListenPort, "\033[0m")
	if s.config.SupportRelay {
		fmt.Printf("  (Relay 지원)")
	}
	fmt.Println()
	fmt.Printf("  가동 시간: %s%v%s\n", "\033[33m", uptime.Truncate(time.Second), "\033[0m")
	fmt.Printf("  IP 풀: %s%s - %s%s (%d개)\n\n", "\033[33m", s.config.StartIP, s.config.EndIP, "\033[0m", len(s.ipPool))
	
	// DHCP 메시지 통계
	discoverRx := atomic.LoadInt64(&s.stats.DiscoverReceived)
	offerTx := atomic.LoadInt64(&s.stats.OfferSent)
	requestRx := atomic.LoadInt64(&s.stats.RequestReceived)
	ackTx := atomic.LoadInt64(&s.stats.AckSent)
	nakTx := atomic.LoadInt64(&s.stats.NakSent)
	
	fmt.Printf("%s%s┌─ DHCP 메시지 통계 ──────────────────────────────────────────────────────┐%s\n", "\033[1m", "\033[34m", "\033[0m")
	fmt.Printf("%s│%s  수신: DISCOVER %s%8d%s    REQUEST %s%8d%s                         %s%s│%s\n", 
		"\033[34m", "\033[0m", "\033[37m", discoverRx, "\033[0m", "\033[37m", requestRx, "\033[0m", "\033[34m", "\033[0m")
	fmt.Printf("%s│%s  전송: OFFER    %s%8d%s    ACK     %s%8d%s    NAK %s%8d%s     %s%s│%s\n", 
		"\033[34m", "\033[0m", "\033[37m", offerTx, "\033[0m", "\033[37m", ackTx, "\033[0m", "\033[37m", nakTx, "\033[0m", "\033[34m", "\033[0m")
	fmt.Printf("%s%s└────────────────────────────────────────────────────────────────────────┘%s\n", "\033[1m", "\033[34m", "\033[0m")
	fmt.Println()
	
	// IP 풀 상태
	s.poolMutex.RLock()
	availableIPs := 0
	leasedIPs := 0
	for _, entry := range s.ipPool {
		if entry.Available {
			availableIPs++
		} else {
			leasedIPs++
		}
	}
	s.poolMutex.RUnlock()
	
	utilizationRate := float64(leasedIPs) / float64(len(s.ipPool)) * 100
	
	fmt.Printf("%sIP 풀 상태%s\n", "\033[1m", "\033[0m")
	fmt.Printf("  사용 중: %s%d%s, 사용 가능: %s%d%s, 사용률: %s%.1f%%%s\n", 
		"\033[32m", leasedIPs, "\033[0m", "\033[36m", availableIPs, "\033[0m", "\033[33m", utilizationRate, "\033[0m")
	
	// 사용률 바
	barWidth := 50
	filledWidth := int(utilizationRate / 100.0 * float64(barWidth))
	fmt.Print("  [")
	for i := 0; i < barWidth; i++ {
		if i < filledWidth {
			fmt.Printf("%s█%s", "\033[32m", "\033[0m")
		} else {
			fmt.Print("░")
		}
	}
	fmt.Printf("] %.1f%%\n\n", utilizationRate)
	
	// 성능 지표
	if uptime > 0 {
		rps := float64(discoverRx+requestRx) / uptime.Seconds()
		fmt.Printf("%s성능 지표%s\n", "\033[1m", "\033[0m")
		fmt.Printf("  평균 RPS: %s%.1f requests/sec%s\n", "\033[32m", rps, "\033[0m")
		
		// 평균 처리 시간
		s.stats.mutex.RLock()
		if len(s.stats.ProcessingTimes) > 0 {
			var total time.Duration
			for _, t := range s.stats.ProcessingTimes {
				total += t
			}
			avgProcessing := total / time.Duration(len(s.stats.ProcessingTimes))
			fmt.Printf("  평균 처리 시간: %s%v%s\n", "\033[32m", avgProcessing, "\033[0m")
		}
		s.stats.mutex.RUnlock()
	}
	
	// 에러 통계
	parseErrors := atomic.LoadInt64(&s.stats.ParseErrors)
	poolExhausted := atomic.LoadInt64(&s.stats.PoolExhausted)
	invalidRequests := atomic.LoadInt64(&s.stats.InvalidRequests)
	
	if parseErrors > 0 || poolExhausted > 0 || invalidRequests > 0 {
		fmt.Printf("\n%s에러 통계%s\n", "\033[1m", "\033[0m")
		if parseErrors > 0 {
			fmt.Printf("  파싱 오류: %s%d%s  ", "\033[31m", parseErrors, "\033[0m")
		}
		if poolExhausted > 0 {
			fmt.Printf("  풀 고갈: %s%d%s  ", "\033[31m", poolExhausted, "\033[0m")
		}
		if invalidRequests > 0 {
			fmt.Printf("  잘못된 요청: %s%d%s  ", "\033[31m", invalidRequests, "\033[0m")
		}
		fmt.Println()
	}
	
	fmt.Printf("\n%s%s[Ctrl+C로 종료]%s", "\033[1m", "\033[37m", "\033[0m")
}

// 세션 정리 루프
func (s *DHCPServer) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for s.isRunning() {
		select {
		case <-ticker.C:
			s.cleanupExpiredSessions()
		}
	}
}

// 만료된 세션 정리
func (s *DHCPServer) cleanupExpiredSessions() {
	s.sessionMutex.Lock()
	defer s.sessionMutex.Unlock()
	
	now := time.Now()
	for xid, session := range s.sessions {
		if session.State == "offered" && now.Sub(session.OfferTime) > s.config.OfferTimeout {
			// Offer 타임아웃된 세션 정리
			s.releaseIP(session.OfferedIP)
			delete(s.sessions, xid)
		} else if session.State == "leased" && now.Sub(session.OfferTime) > s.config.LeaseTime {
			// 임대 시간 만료된 세션 정리
			s.releaseIP(session.OfferedIP)
			delete(s.sessions, xid)
		}
	}
}

// 서버 실행 상태 확인
func (s *DHCPServer) isRunning() bool {
	s.runMutex.RLock()
	defer s.runMutex.RUnlock()
	return s.running
}

// 서버 중지
func (s *DHCPServer) Stop() {
	s.runMutex.Lock()
	defer s.runMutex.Unlock()
	
	if !s.running {
		return
	}
	
	s.running = false
	if s.conn != nil {
		s.conn.Close()
	}
	
	fmt.Println("\nDHCP 서버가 정상적으로 종료되었습니다.")
}

// 최종 통계 출력
func (s *DHCPServer) PrintFinalStats() {
	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Printf("DHCP 서버 최종 통계\n")
	fmt.Printf("%s\n", strings.Repeat("=", 70))
	
	uptime := time.Since(s.stats.StartTime)
	discoverRx := atomic.LoadInt64(&s.stats.DiscoverReceived)
	offerTx := atomic.LoadInt64(&s.stats.OfferSent)
	requestRx := atomic.LoadInt64(&s.stats.RequestReceived)
	ackTx := atomic.LoadInt64(&s.stats.AckSent)
	nakTx := atomic.LoadInt64(&s.stats.NakSent)
	
	fmt.Printf("가동 시간:           %v\n", uptime.Truncate(time.Second))
	fmt.Printf("처리된 DISCOVER:     %d\n", discoverRx)
	fmt.Printf("전송된 OFFER:        %d\n", offerTx)
	fmt.Printf("처리된 REQUEST:      %d\n", requestRx)
	fmt.Printf("전송된 ACK:          %d\n", ackTx)
	fmt.Printf("전송된 NAK:          %d\n", nakTx)
	
	if uptime > 0 {
		rps := float64(discoverRx+requestRx) / uptime.Seconds()
		fmt.Printf("평균 RPS:           %.1f requests/sec\n", rps)
	}
	
	// IP 풀 최종 상태
	s.poolMutex.RLock()
	leasedCount := 0
	for _, entry := range s.ipPool {
		if !entry.Available {
			leasedCount++
		}
	}
	s.poolMutex.RUnlock()
	
	fmt.Printf("최종 IP 사용률:      %.1f%% (%d/%d)\n", 
		float64(leasedCount)/float64(len(s.ipPool))*100, leasedCount, len(s.ipPool))
	
	// 에러 통계
	parseErrors := atomic.LoadInt64(&s.stats.ParseErrors)
	poolExhausted := atomic.LoadInt64(&s.stats.PoolExhausted)
	invalidRequests := atomic.LoadInt64(&s.stats.InvalidRequests)
	
	if parseErrors > 0 || poolExhausted > 0 || invalidRequests > 0 {
		fmt.Printf("\n에러 통계:\n")
		if parseErrors > 0 {
			fmt.Printf("  파싱 오류:         %d\n", parseErrors)
		}
		if poolExhausted > 0 {
			fmt.Printf("  IP 풀 고갈:        %d\n", poolExhausted)
		}
		if invalidRequests > 0 {
			fmt.Printf("  잘못된 요청:       %d\n", invalidRequests)
		}
	}
}

func main() {
	// 명령행 플래그 정의
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
		
		// 표시 옵션
		verbose   = flag.Bool("verbose", false, "상세 로그 출력")
		liveStats = flag.Bool("live", false, "실시간 통계 대시보드")
		
		// Relay Agent 옵션
		supportRelay = flag.Bool("relay", true, "Relay Agent 지원")
		maxHops      = flag.Int("max-hops", 4, "최대 허용 hop count")
	)
	flag.Parse()
	
	// 설정 생성
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
	
	// 입력 검증
	if config.StartIP == nil || config.EndIP == nil {
		log.Fatal("올바른 IP 주소를 입력하세요")
	}
	if ipToUint32(config.StartIP) > ipToUint32(config.EndIP) {
		log.Fatal("시작 IP가 종료 IP보다 클 수 없습니다")
	}
	if *dropRate < 0.0 || *dropRate > 1.0 {
		log.Fatal("드롭률은 0.0과 1.0 사이여야 합니다")
	}
	
	// 서버 생성
	server := NewDHCPServer(config)
	server.verbose = *verbose
	server.showLiveStats = *liveStats
	
	// 시그널 핸들링
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	
	// 서버 시작
	err := server.Start()
	if err != nil {
		log.Fatalf("서버 시작 실패: %v", err)
	}
	
	// 종료 신호 대기
	<-sigChan
	
	// 서버 중지
	server.Stop()
	
	// 최종 통계 출력 (live 모드가 아닐 때만)
	if !*liveStats {
		server.PrintFinalStats()
	}
}
