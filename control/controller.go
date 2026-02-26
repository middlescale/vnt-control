package control

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
	"vnt-control/config"
	"vnt-control/protocol"
	"vnt-control/protocol/pb"
	"vnt-control/util"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

type Controller struct {
	nc  NetworkControl
	cfg *config.Config
	mu  sync.Mutex
}

type PunchSessionState string

const (
	PunchSessionCreated    PunchSessionState = "created"
	PunchSessionDispatch   PunchSessionState = "dispatching"
	PunchSessionInProgress PunchSessionState = "in_progress"
	PunchSessionSuccess    PunchSessionState = "success"
	PunchSessionFailed     PunchSessionState = "failed"
	PunchSessionTimeout    PunchSessionState = "timeout"
	PunchSessionCanceled   PunchSessionState = "canceled"
)

type PunchSession struct {
	SessionID   uint64
	Source      uint32
	Target      uint32
	Attempt     uint32
	State       PunchSessionState
	RequestedAt int64
	LastReason  string
	Ack         map[uint32]bool
	Results     map[uint32]*pb.PunchResult
}

var supportedHandshakeCapabilities = map[string]struct{}{
	"udp_endpoint_report_v1": {},
	"punch_coord_v1":        {},
}

func NewController(cfg *config.Config) *Controller {
	return &Controller{
		nc: NetworkControl{
			VirtualNetwork: *NewExpireMap[string, *NetworkInfo](7 * 24 * time.Hour),
			IPSessions:     *NewExpireMap[IpSessionKey, net.Addr](24 * time.Hour),
			CipherSessions: *NewExpireMap[string, struct{}](24 * time.Hour),
			PunchSessions:  *NewExpireMap[string, *PunchSession](10 * time.Minute),
			PunchPairCooldown: *NewExpireMap[string, struct{}](20 * time.Second),
		},
		cfg: cfg,
	}
}

func (c *Controller) Stop() {
	c.nc.VirtualNetwork.Stop()
	c.nc.IPSessions.Stop()
	c.nc.CipherSessions.Stop()
	c.nc.PunchSessions.Stop()
	c.nc.PunchPairCooldown.Stop()
}

func (c *Controller) HandleHandshakePacket(reqPacket *protocol.Packet) (*protocol.Packet, error) {
	log.Debugf("收到客户端 HandshakeRequest Packet: %s", reqPacket.DebugString())
	var req pb.HandshakeRequest
	if err := proto.Unmarshal(reqPacket.Payload, &req); err != nil {
		log.Errorf("HandshakeRequest unmarshal error: %v", err)
		return nil, err
	}

	if req.GetSecret() {
		log.Infof("handsshake request no need secret, ignored")
	}

	rsp := &pb.HandshakeResponse{
		Version:      "goversion-1.0.0",
		Secret:       false,
		Capabilities: negotiateHandshakeCapabilities(req.GetCapabilities()),
	}
	playload, err := proto.Marshal(rsp)
	if err != nil {
		log.Errorf("HandshakeResponse marshal error: %v", err)
		return nil, err
	}

	rspPacket := &protocol.Packet{
		Ver:       protocol.V2,
		Proto:     protocol.ProtocolService,
		AppProto:  protocol.AppProtoHandshakeResponse,
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     reqPacket.DstIP,
		DstIP:     reqPacket.SrcIP,
		Gateway:   true,
		Payload:   playload,
	}

	// 目前不处理 handshake的加密算法

	return rspPacket, nil
}

func (c *Controller) HandleRegistrationPacket(request *protocol.Packet, remoteAddr net.Addr) (*protocol.Packet, error) {
	respPacket, _, err := c.HandleRegistrationPacketWithVirtualIP(request, remoteAddr)
	return respPacket, err
}

func (c *Controller) HandleRegistrationPacketWithVirtualIP(request *protocol.Packet, remoteAddr net.Addr) (*protocol.Packet, uint32, error) {
	log.Debugf("收到客户端 RegistrationRequest Packet: %s", request.DebugString())
	var registration pb.RegistrationRequest
	if err := proto.Unmarshal(request.Payload, &registration); err != nil {
		log.Errorf("RegistrationRequest unmarshal error: %v", err)
		return nil, 0, err
	}
	if err := validateRegistrationRequest(&registration); err != nil {
		log.Errorf("RegistrationRequest validate error: %v", err)
		return nil, 0, err
	}

	domain := registration.GetToken()
	if c.cfg.Domain != "" && domain != c.cfg.Domain {
		return nil, 0, fmt.Errorf("RegistrationRequest domain %s mismatch config domain %s", domain, c.cfg.Domain)
	}

	raddrStr := remoteAddr.String()
	host, portStr, err := net.SplitHostPort(raddrStr)
	if err != nil {
		return nil, 0, fmt.Errorf("Failed to parse remote address: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil, 0, fmt.Errorf("invalid remote port: %q", portStr)
	}
	pubPort := uint32(port)

	registrationResp := &pb.RegistrationResponse{
		PublicPort: pubPort,
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			registrationResp.PublicIp = util.IpToUint32(ip4)
		} else {
			registrationResp.PublicIpv6 = ip.To16()
		}
	}
	netmask, err := c.parseNetmask()
	if err != nil {
		return nil, 0, err
	}
	registrationResp.VirtualGateway = util.IpToUint32(c.cfg.Gateway)
	registrationResp.VirtualNetmask = util.MaskToUint32(netmask)

	c.mu.Lock()
	defer c.mu.Unlock()

	netInfo, netInfoExist := c.nc.VirtualNetwork.Get(domain)
	if !netInfoExist {
		netInfo = NewNetworkInfo(domain, netmask, net.IP(c.cfg.Gateway))
		c.nc.VirtualNetwork.Set(domain, netInfo)
	}
	virtualIP, oldIP, err := c.nc.generateIP(
		netInfo,
		registration.GetVirtualIp(),
		registration.GetDeviceId(),
		registration.GetAllowIpChange(),
	)
	if err != nil {
		return nil, 0, err
	}
	if oldIP != 0 && oldIP != virtualIP {
		delete(netInfo.Clients, oldIP)
		c.nc.IPSessions.Delete(NewIpSessionKey(domain, util.Uint32ToIP(oldIP)))
	}
	clientInfo := netInfo.Clients[virtualIP]
	now := time.Now().Unix()
	clientInfo.DeviceId = registration.GetDeviceId()
	clientInfo.Name = registration.GetName()
	clientInfo.Version = registration.GetVersion()
	clientInfo.ControlOnline = true
	clientInfo.ControlLastSeen = now
	clientInfo.DataPlaneReachable = false
	clientInfo.DataPlaneLastSeen = 0
	clientInfo.VirtualIp = virtualIP
	clientInfo.Address = remoteAddr
	clientInfo.ClientSecret = registration.GetClientSecret()
	clientInfo.ClientSecretHash = append(clientInfo.ClientSecretHash[:0], registration.GetClientSecretHash()...)
	clientInfo.Wireguard = false
	clientInfo.LastJoin = now
	netInfo.Clients[virtualIP] = clientInfo
	c.nc.IPSessions.Delete(NewIpSessionKey(domain, util.Uint32ToIP(virtualIP)))
	c.nc.TouchCipherSession(remoteAddr)
	netInfo.Epoch++
	registrationResp.VirtualIp = virtualIP
	registrationResp.Epoch = uint32(netInfo.Epoch)
	registrationResp.DeviceInfoList = buildDeviceInfoList(netInfo.Clients, virtualIP)

	respBytes, err := proto.Marshal(registrationResp)
	if err != nil {
		return nil, 0, fmt.Errorf("RegistrationResponse marshal error: %v", err)
	}

	respPacket := &protocol.Packet{
		Ver:       protocol.V2,
		Proto:     protocol.ProtocolService,
		AppProto:  protocol.AppProtoRegistrationResponse,
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     request.DstIP,
		DstIP:     request.SrcIP,
		Gateway:   true,
		Payload:   respBytes,
	}

	return respPacket, virtualIP, nil
}

func (c *Controller) HandlePullDeviceListPacket(request *protocol.Packet) (*protocol.Packet, error) {
	selfIP := util.IpToUint32(request.SrcIP)
	deviceList, ok := c.nc.DeviceListByIP(selfIP)
	if !ok {
		return nil, fmt.Errorf("client %s not registered", request.SrcIP)
	}
	payload, err := proto.Marshal(deviceList)
	if err != nil {
		return nil, fmt.Errorf("DeviceList marshal error: %v", err)
	}
	return &protocol.Packet{
		Ver:       protocol.V2,
		Proto:     protocol.ProtocolService,
		AppProto:  protocol.AppProtoPushDeviceList,
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     request.DstIP,
		DstIP:     request.SrcIP,
		Gateway:   true,
		Payload:   payload,
	}, nil
}

func (c *Controller) HandleClientStatusInfoPacket(request *protocol.Packet) error {
	var status pb.ClientStatusInfo
	if err := proto.Unmarshal(request.Payload, &status); err != nil {
		return fmt.Errorf("ClientStatusInfo unmarshal error: %v", err)
	}
	srcIP := util.IpToUint32(request.SrcIP)
	if status.GetSource() != 0 && status.GetSource() != srcIP {
		return fmt.Errorf("client status source mismatch: %d != %d", status.GetSource(), srcIP)
	}
	now := time.Now().Unix()
	clientStatus := &ClientStatusInfo{
		P2PList:        make([]net.IP, 0, len(status.GetP2PList())),
		PublicIPList:   make([]net.IP, 0, len(status.GetPublicIpList())),
		PublicUDPPorts: make([]uint16, 0, len(status.GetPublicUdpPorts())),
		LocalUDPPorts:  make([]uint16, 0, len(status.GetLocalUdpPorts())),
		UpStream:       status.GetUpStream(),
		DownStream:     status.GetDownStream(),
		IsCone:         status.GetNatType() == pb.PunchNatType_Cone,
		UpdateTime:     now,
	}
	for _, item := range status.GetP2PList() {
		clientStatus.P2PList = append(clientStatus.P2PList, util.Uint32ToIP(item.GetNextIp()))
	}
	for _, ip := range status.GetPublicIpList() {
		clientStatus.PublicIPList = append(clientStatus.PublicIPList, util.Uint32ToIP(ip))
	}
	for _, port := range status.GetPublicUdpPorts() {
		if port <= 65535 {
			clientStatus.PublicUDPPorts = append(clientStatus.PublicUDPPorts, uint16(port))
		}
	}
	for _, port := range status.GetLocalUdpPorts() {
		if port <= 65535 {
			clientStatus.LocalUDPPorts = append(clientStatus.LocalUDPPorts, uint16(port))
		}
	}
	reachable := len(clientStatus.P2PList) > 0
	c.nc.VirtualNetwork.mutex.Lock()
	defer c.nc.VirtualNetwork.mutex.Unlock()
	for _, network := range c.nc.VirtualNetwork.data {
		client, ok := network.Clients[srcIP]
		if !ok {
			continue
		}
		client.ControlOnline = true
		client.ControlLastSeen = now
		client.DataPlaneReachable = reachable
		if reachable {
			client.DataPlaneLastSeen = now
		}
		client.ClientStatus = clientStatus
		network.Clients[srcIP] = client
		return nil
	}
	return fmt.Errorf("client %s not registered", request.SrcIP)
}

func (c *Controller) BuildPunchStartPacketsFromStatus(request *protocol.Packet) ([]*protocol.Packet, error) {
	srcIP := util.IpToUint32(request.SrcIP)
	c.nc.VirtualNetwork.mutex.RLock()
	defer c.nc.VirtualNetwork.mutex.RUnlock()
	for _, network := range c.nc.VirtualNetwork.data {
		srcClient, ok := network.Clients[srcIP]
		if !ok || !srcClient.ControlOnline || srcClient.ClientStatus == nil {
			continue
		}
		for targetIP, targetClient := range network.Clients {
			if targetIP == srcIP || !targetClient.ControlOnline || targetClient.ClientStatus == nil {
				continue
			}
			pairKey := punchPairKey(srcIP, targetIP)
			if _, cooling := c.nc.PunchPairCooldown.Get(pairKey); cooling {
				return nil, nil
			}
			sourceEndpoints := buildPunchEndpoints(srcClient.ClientStatus)
			targetEndpoints := buildPunchEndpoints(targetClient.ClientStatus)
			if len(sourceEndpoints) == 0 || len(targetEndpoints) == 0 {
				return nil, nil
			}
			sessionID := uint64(time.Now().UnixNano())
			attempt := uint32(1)
			now := time.Now()
			session := &PunchSession{
				SessionID:   sessionID,
				Source:      srcIP,
				Target:      targetIP,
				Attempt:     attempt,
				State:       PunchSessionDispatch,
				RequestedAt: now.Unix(),
				Ack:         make(map[uint32]bool),
				Results:     make(map[uint32]*pb.PunchResult),
			}
			c.nc.PunchSessions.Set(punchSessionKey(sessionID, attempt), session)
			c.nc.PunchPairCooldown.Set(pairKey, struct{}{})
			deadline := now.Add(5 * time.Second).UnixMilli()
			sourceStart := &pb.PunchStart{
				SessionId:      sessionID,
				Source:         srcIP,
				Target:         targetIP,
				PeerEndpoints:  targetEndpoints,
				Attempt:        attempt,
				TimeoutMs:      3000,
				DeadlineUnixMs: deadline,
			}
			targetStart := &pb.PunchStart{
				SessionId:      sessionID,
				Source:         targetIP,
				Target:         srcIP,
				PeerEndpoints:  sourceEndpoints,
				Attempt:        attempt,
				TimeoutMs:      3000,
				DeadlineUnixMs: deadline,
			}
			sourcePayload, err := proto.Marshal(sourceStart)
			if err != nil {
				return nil, fmt.Errorf("PunchStart source marshal error: %v", err)
			}
			targetPayload, err := proto.Marshal(targetStart)
			if err != nil {
				return nil, fmt.Errorf("PunchStart target marshal error: %v", err)
			}
			return []*protocol.Packet{
				{
					Ver:       protocol.V2,
					Proto:     protocol.ProtocolService,
					AppProto:  protocol.AppProtoPunchStart,
					SourceTTL: protocol.MAX_TTL,
					TTL:       protocol.MAX_TTL,
					SrcIP:     request.DstIP,
					DstIP:     util.Uint32ToIP(srcIP),
					Gateway:   true,
					Payload:   sourcePayload,
				},
				{
					Ver:       protocol.V2,
					Proto:     protocol.ProtocolService,
					AppProto:  protocol.AppProtoPunchStart,
					SourceTTL: protocol.MAX_TTL,
					TTL:       protocol.MAX_TTL,
					SrcIP:     request.DstIP,
					DstIP:     util.Uint32ToIP(targetIP),
					Gateway:   true,
					Payload:   targetPayload,
				},
			}, nil
		}
	}
	return nil, nil
}

func (c *Controller) HandlePunchRequestPacket(request *protocol.Packet) (*protocol.Packet, error) {
	var req pb.PunchRequest
	if err := proto.Unmarshal(request.Payload, &req); err != nil {
		return nil, fmt.Errorf("PunchRequest unmarshal error: %v", err)
	}
	sourceIP := util.IpToUint32(request.SrcIP)
	if req.GetSource() != 0 && req.GetSource() != sourceIP {
		return nil, fmt.Errorf("punch request source mismatch: %d != %d", req.GetSource(), sourceIP)
	}
	if req.GetSessionId() == 0 || req.GetAttempt() == 0 {
		return nil, fmt.Errorf("invalid punch request, session_id and attempt must be non-zero")
	}
	if _, ok := c.nc.FindClientByVirtualIP(req.GetTarget()); !ok {
		return nil, fmt.Errorf("punch target %s not registered", util.Uint32ToIP(req.GetTarget()))
	}
	now := time.Now().Unix()
	session := &PunchSession{
		SessionID:   req.GetSessionId(),
		Source:      sourceIP,
		Target:      req.GetTarget(),
		Attempt:     req.GetAttempt(),
		State:       PunchSessionDispatch,
		RequestedAt: now,
		Ack:         map[uint32]bool{sourceIP: true},
		Results:     make(map[uint32]*pb.PunchResult),
	}
	c.nc.PunchSessions.Set(punchSessionKey(req.GetSessionId(), req.GetAttempt()), session)
	ack := &pb.PunchAck{
		SessionId: req.GetSessionId(),
		Source:    sourceIP,
		Attempt:   req.GetAttempt(),
		Accepted:  true,
	}
	payload, err := proto.Marshal(ack)
	if err != nil {
		return nil, fmt.Errorf("PunchAck marshal error: %v", err)
	}
	return &protocol.Packet{
		Ver:       protocol.V2,
		Proto:     protocol.ProtocolService,
		AppProto:  protocol.AppProtoPunchAck,
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     request.DstIP,
		DstIP:     request.SrcIP,
		Gateway:   true,
		Payload:   payload,
	}, nil
}

func (c *Controller) BuildPunchStartPackets(request *protocol.Packet) ([]*protocol.Packet, error) {
	var req pb.PunchRequest
	if err := proto.Unmarshal(request.Payload, &req); err != nil {
		return nil, fmt.Errorf("PunchRequest unmarshal error: %v", err)
	}
	sourceIP := util.IpToUint32(request.SrcIP)
	if req.GetSource() != 0 && req.GetSource() != sourceIP {
		return nil, fmt.Errorf("punch request source mismatch: %d != %d", req.GetSource(), sourceIP)
	}
	if req.GetSessionId() == 0 || req.GetAttempt() == 0 {
		return nil, fmt.Errorf("invalid punch request, session_id and attempt must be non-zero")
	}
	if _, ok := c.nc.FindClientByVirtualIP(sourceIP); !ok {
		return nil, fmt.Errorf("punch source %s not registered", util.Uint32ToIP(sourceIP))
	}
	if _, ok := c.nc.FindClientByVirtualIP(req.GetTarget()); !ok {
		return nil, fmt.Errorf("punch target %s not registered", util.Uint32ToIP(req.GetTarget()))
	}
	sourceStart := &pb.PunchStart{
		SessionId:      req.GetSessionId(),
		Source:         sourceIP,
		Target:         req.GetTarget(),
		PeerEndpoints:  req.GetTargetEndpoints(),
		Attempt:        req.GetAttempt(),
		TimeoutMs:      req.GetTimeoutMs(),
		DeadlineUnixMs: req.GetDeadlineUnixMs(),
	}
	targetStart := &pb.PunchStart{
		SessionId:      req.GetSessionId(),
		Source:         req.GetTarget(),
		Target:         sourceIP,
		PeerEndpoints:  req.GetSourceEndpoints(),
		Attempt:        req.GetAttempt(),
		TimeoutMs:      req.GetTimeoutMs(),
		DeadlineUnixMs: req.GetDeadlineUnixMs(),
	}
	sourcePayload, err := proto.Marshal(sourceStart)
	if err != nil {
		return nil, fmt.Errorf("PunchStart source marshal error: %v", err)
	}
	targetPayload, err := proto.Marshal(targetStart)
	if err != nil {
		return nil, fmt.Errorf("PunchStart target marshal error: %v", err)
	}
	return []*protocol.Packet{
		{
			Ver:       protocol.V2,
			Proto:     protocol.ProtocolService,
			AppProto:  protocol.AppProtoPunchStart,
			SourceTTL: protocol.MAX_TTL,
			TTL:       protocol.MAX_TTL,
			SrcIP:     request.DstIP,
			DstIP:     util.Uint32ToIP(sourceIP),
			Gateway:   true,
			Payload:   sourcePayload,
		},
		{
			Ver:       protocol.V2,
			Proto:     protocol.ProtocolService,
			AppProto:  protocol.AppProtoPunchStart,
			SourceTTL: protocol.MAX_TTL,
			TTL:       protocol.MAX_TTL,
			SrcIP:     request.DstIP,
			DstIP:     util.Uint32ToIP(req.GetTarget()),
			Gateway:   true,
			Payload:   targetPayload,
		},
	}, nil
}

func (c *Controller) HandlePunchAckPacket(request *protocol.Packet) error {
	var ack pb.PunchAck
	if err := proto.Unmarshal(request.Payload, &ack); err != nil {
		return fmt.Errorf("PunchAck unmarshal error: %v", err)
	}
	key := punchSessionKey(ack.GetSessionId(), ack.GetAttempt())
	session, ok := c.nc.PunchSessions.Get(key)
	if !ok {
		return fmt.Errorf("punch session not found: %s", key)
	}
	source := util.IpToUint32(request.SrcIP)
	if ack.GetSource() != 0 && ack.GetSource() != source {
		return fmt.Errorf("punch ack source mismatch: %d != %d", ack.GetSource(), source)
	}
	session.Ack[source] = ack.GetAccepted()
	if !ack.GetAccepted() {
		session.State = PunchSessionFailed
		session.LastReason = ack.GetReason()
	} else if len(session.Ack) >= 2 {
		session.State = PunchSessionInProgress
	}
	c.nc.PunchSessions.Set(key, session)
	return nil
}

func (c *Controller) HandlePunchResultPacket(request *protocol.Packet) error {
	var result pb.PunchResult
	if err := proto.Unmarshal(request.Payload, &result); err != nil {
		return fmt.Errorf("PunchResult unmarshal error: %v", err)
	}
	key := punchSessionKey(result.GetSessionId(), result.GetAttempt())
	session, ok := c.nc.PunchSessions.Get(key)
	if !ok {
		return fmt.Errorf("punch session not found: %s", key)
	}
	source := util.IpToUint32(request.SrcIP)
	if result.GetSource() != 0 && result.GetSource() != source {
		return fmt.Errorf("punch result source mismatch: %d != %d", result.GetSource(), source)
	}
	session.Results[source] = &result
	switch result.GetCode() {
	case pb.PunchResultCode_PunchResultSuccess:
		session.State = PunchSessionSuccess
	case pb.PunchResultCode_PunchResultTimeout:
		session.State = PunchSessionTimeout
	case pb.PunchResultCode_PunchResultCanceled:
		session.State = PunchSessionCanceled
	default:
		session.State = PunchSessionFailed
	}
	session.LastReason = result.GetReason()
	c.nc.PunchSessions.Set(key, session)
	return nil
}

func (c *Controller) HandlePunchCancelPacket(request *protocol.Packet) error {
	var cancel pb.PunchCancel
	if err := proto.Unmarshal(request.Payload, &cancel); err != nil {
		return fmt.Errorf("PunchCancel unmarshal error: %v", err)
	}
	key := punchSessionKey(cancel.GetSessionId(), cancel.GetAttempt())
	session, ok := c.nc.PunchSessions.Get(key)
	if !ok {
		return fmt.Errorf("punch session not found: %s", key)
	}
	session.State = PunchSessionCanceled
	session.LastReason = cancel.GetReason()
	c.nc.PunchSessions.Set(key, session)
	return nil
}

func (c *Controller) HandleControlPacket(request *protocol.Packet, remoteAddr net.Addr) (*protocol.Packet, error) {
	switch protocol.ControlProtocol(request.AppProto) {
	case protocol.ControlPing:
		pingTime, _, err := protocol.ParsePingPayload(request.Payload)
		if err != nil {
			return nil, err
		}
		epoch := c.nc.TouchClientByIP(request.SrcIP)
		payload := protocol.BuildPingPayload(pingTime, epoch)
		return &protocol.Packet{
			Ver:       protocol.V2,
			Proto:     protocol.ProtocolControl,
			AppProto:  protocol.AppProtocol(protocol.ControlPong),
			SourceTTL: protocol.MAX_TTL,
			TTL:       protocol.MAX_TTL,
			SrcIP:     request.DstIP,
			DstIP:     request.SrcIP,
			Gateway:   true,
			Payload:   payload,
		}, nil
	case protocol.ControlAddrRequest:
		payload, err := protocol.BuildAddrPayloadByAddr(remoteAddr)
		if err != nil {
			return nil, err
		}
		return &protocol.Packet{
			Ver:       protocol.V2,
			Proto:     protocol.ProtocolControl,
			AppProto:  protocol.AppProtocol(protocol.ControlAddrResponse),
			SourceTTL: protocol.MAX_TTL,
			TTL:       protocol.MAX_TTL,
			SrcIP:     request.DstIP,
			DstIP:     request.SrcIP,
			Gateway:   true,
			Payload:   payload,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported control protocol: %d", request.AppProto)
	}
}

func punchSessionKey(sessionID uint64, attempt uint32) string {
	return fmt.Sprintf("%d:%d", sessionID, attempt)
}

func punchPairKey(a, b uint32) string {
	if a < b {
		return fmt.Sprintf("%d-%d", a, b)
	}
	return fmt.Sprintf("%d-%d", b, a)
}

func buildPunchEndpoints(status *ClientStatusInfo) []*pb.PunchEndpoint {
	if status == nil || len(status.PublicIPList) == 0 || len(status.PublicUDPPorts) == 0 {
		return nil
	}
	endpoints := make([]*pb.PunchEndpoint, 0, len(status.PublicIPList)*len(status.PublicUDPPorts))
	for _, ip := range status.PublicIPList {
		ipv4 := ip.To4()
		if ipv4 == nil {
			continue
		}
		ipv4u := util.IpToUint32(ipv4)
		for _, port := range status.PublicUDPPorts {
			if port == 0 {
				continue
			}
			endpoints = append(endpoints, &pb.PunchEndpoint{
				Ip:   ipv4u,
				Port: uint32(port),
				Tcp:  false,
			})
		}
	}
	return endpoints
}

type NetworkControl struct {
	//
	VirtualNetwork ExpireMap[string, *NetworkInfo]
	// 用来做地址分配和回收
	IPSessions ExpireMap[IpSessionKey, net.Addr]
	// 链路上的加密会话上下文占位（按远端地址跟踪）
	CipherSessions ExpireMap[string, struct{}]
	// 打洞会话状态（session_id + attempt）
	PunchSessions ExpireMap[string, *PunchSession]
	// 打洞触发冷却（pair key）
	PunchPairCooldown ExpireMap[string, struct{}]
}

// IpSessionKey is a comparable key for IPSessions.
// Use string fields because net.IP (a []byte) is not comparable.
type IpSessionKey struct {
	ID string // domain
	IP string // use net.IP.String()
}

// compile-time check: ensure IpSessionKey is comparable (map key). If IpSessionKey contains
// a non-comparable field (e.g. slice), this will fail to compile.
var _ map[IpSessionKey]struct{} = nil

// NewIpSessionKey builds an IpSessionKey from an id and net.IP.
func NewIpSessionKey(id string, ip net.IP) IpSessionKey {
	return IpSessionKey{
		ID: id,
		IP: ip.String(),
	}
}

func (c *Controller) parseNetmask() (net.IPMask, error) {
	ip := net.ParseIP(c.cfg.Netmask)
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("invalid netmask %q", c.cfg.Netmask)
	}
	return net.IPMask(ip.To4()), nil
}

func validateRegistrationRequest(reg *pb.RegistrationRequest) error {
	if reg.GetToken() == "" || len(reg.GetToken()) > 128 {
		return fmt.Errorf("token length error")
	}
	if reg.GetDeviceId() == "" || len(reg.GetDeviceId()) > 128 {
		return fmt.Errorf("device_id length error")
	}
	if reg.GetName() == "" || len(reg.GetName()) > 128 {
		return fmt.Errorf("name length error")
	}
	if len(reg.GetClientSecretHash()) > 128 {
		return fmt.Errorf("client_secret_hash length error")
	}
	return nil
}

func validateRequestedIP(virtualIP uint32, gateway net.IP, netmask net.IPMask) error {
	requested := util.Uint32ToIP(virtualIP)
	if gateway.Equal(requested) {
		return fmt.Errorf("client requested virtual ip is gateway ip")
	}
	networkIP := util.IpToUint32(gateway) & util.MaskToUint32(netmask)
	mask := util.MaskToUint32(netmask)
	broadcast := networkIP | ^mask
	first := networkIP + 1
	last := broadcast - 1
	if virtualIP < first || virtualIP > last {
		return fmt.Errorf("virtual ip %s out of network range", requested)
	}
	return nil
}

func findClientIPByDeviceID(clients map[uint32]ClientInfo, deviceID string) uint32 {
	for ip, info := range clients {
		if info.DeviceId == deviceID {
			return ip
		}
	}
	return 0
}

func buildDeviceInfoList(clients map[uint32]ClientInfo, selfIP uint32) []*pb.DeviceInfo {
	deviceList := make([]*pb.DeviceInfo, 0, len(clients))
	for ip, info := range clients {
		if ip == selfIP {
			continue
		}
		item := &pb.DeviceInfo{
			Name:             info.Name,
			VirtualIp:        ip,
			ClientSecret:     info.ClientSecret,
			Wireguard:        info.Wireguard,
			ClientSecretHash: nil,
		}
		if info.ControlOnline {
			item.DeviceStatus = 0
			item.ClientSecretHash = append(item.ClientSecretHash, info.ClientSecretHash...)
		} else {
			item.DeviceStatus = 1
		}
		deviceList = append(deviceList, item)
	}
	return deviceList
}

func negotiateHandshakeCapabilities(requested []string) []string {
	if len(requested) == 0 {
		return nil
	}
	negotiated := make([]string, 0, len(requested))
	for _, capability := range requested {
		if _, ok := supportedHandshakeCapabilities[capability]; ok {
			negotiated = append(negotiated, capability)
		}
	}
	return negotiated
}

func (nc *NetworkControl) generateIP(
	network *NetworkInfo,
	requestedIP uint32,
	deviceID string,
	allowIPChange bool,
) (virtualIP uint32, oldIP uint32, err error) {
	oldIP = findClientIPByDeviceID(network.Clients, deviceID)
	if requestedIP != 0 {
		if err = validateRequestedIP(requestedIP, network.Gateway, network.Netmask); err != nil {
			return 0, oldIP, err
		}
		if current, ok := network.Clients[requestedIP]; ok && current.DeviceId != deviceID {
			if !allowIPChange {
				return 0, oldIP, fmt.Errorf("virtual ip %s already in use", util.Uint32ToIP(requestedIP))
			}
			requestedIP = 0
		}
	}
	if requestedIP != 0 {
		return requestedIP, oldIP, nil
	}
	if oldIP != 0 {
		return oldIP, oldIP, nil
	}
	networkIP := util.IpToUint32(network.Gateway) & util.MaskToUint32(network.Netmask)
	mask := util.MaskToUint32(network.Netmask)
	broadcast := networkIP | ^mask
	gatewayIP := util.IpToUint32(network.Gateway)

	// first and last usable (exclude network and broadcast)
	first := networkIP + 1
	last := broadcast - 1
	if first > last {
		return 0, 0, fmt.Errorf("no available virtual ips")
	}
	for ip := first; ip <= last; ip++ {
		if ip == gatewayIP {
			continue
		}
		if client, occupied := network.Clients[ip]; occupied {
			if !client.ControlOnline {
				key := NewIpSessionKey(network.Group, util.Uint32ToIP(ip))
				if _, reserved := nc.IPSessions.Get(key); !reserved {
					delete(network.Clients, ip)
				} else {
					continue
				}
			} else {
				continue
			}
		}
		candidate := util.Uint32ToIP(ip)
		key := NewIpSessionKey(network.Group, candidate)
		if _, occupied := nc.IPSessions.Get(key); !occupied {
			addr := &net.IPAddr{IP: candidate}
			nc.IPSessions.Set(key, addr)
			return ip, 0, nil
		}
	}
	return 0, 0, fmt.Errorf("no available virtual ips")
}

func (nc *NetworkControl) TouchClientByIP(srcIP net.IP) uint16 {
	ip := util.IpToUint32(srcIP)
	nc.VirtualNetwork.mutex.Lock()
	defer nc.VirtualNetwork.mutex.Unlock()
	now := time.Now().Unix()
	for _, network := range nc.VirtualNetwork.data {
		if client, ok := network.Clients[ip]; ok {
			client.ControlOnline = true
			client.ControlLastSeen = now
			network.Clients[ip] = client
			return uint16(network.Epoch)
		}
	}
	return 0
}

func (c *Controller) TouchCipherSession(remoteAddr net.Addr) {
	c.nc.TouchCipherSession(remoteAddr)
}

func (nc *NetworkControl) TouchCipherSession(remoteAddr net.Addr) {
	if remoteAddr == nil {
		return
	}
	nc.CipherSessions.Set(remoteAddr.String(), struct{}{})
}

func (c *Controller) LeaveByRemoteAddr(remoteAddr net.Addr) {
	c.nc.LeaveByRemoteAddr(remoteAddr)
}

func (nc *NetworkControl) LeaveByRemoteAddr(remoteAddr net.Addr) {
	if remoteAddr == nil {
		return
	}
	addr := remoteAddr.String()
	nc.CipherSessions.Delete(addr)
	now := time.Now().Unix()
	nc.VirtualNetwork.mutex.Lock()
	defer nc.VirtualNetwork.mutex.Unlock()
	for _, network := range nc.VirtualNetwork.data {
		changed := false
		for ip, client := range network.Clients {
			if client.Address == nil || client.Address.String() != addr || !client.ControlOnline {
				continue
			}
			client.ControlOnline = false
			client.ControlLastSeen = now
			network.Clients[ip] = client
			nc.IPSessions.Set(NewIpSessionKey(network.Group, util.Uint32ToIP(ip)), remoteAddr)
			changed = true
		}
		if changed {
			network.Epoch++
		}
	}
}

func (nc *NetworkControl) DeviceListByIP(selfIP uint32) (*pb.DeviceList, bool) {
	nc.VirtualNetwork.mutex.RLock()
	defer nc.VirtualNetwork.mutex.RUnlock()
	for _, network := range nc.VirtualNetwork.data {
		if _, ok := network.Clients[selfIP]; !ok {
			continue
		}
		return &pb.DeviceList{
			Epoch:          uint32(network.Epoch),
			DeviceInfoList: buildDeviceInfoList(network.Clients, selfIP),
		}, true
	}
	return nil, false
}

func (nc *NetworkControl) FindClientByVirtualIP(virtualIP uint32) (ClientInfo, bool) {
	nc.VirtualNetwork.mutex.RLock()
	defer nc.VirtualNetwork.mutex.RUnlock()
	for _, network := range nc.VirtualNetwork.data {
		client, ok := network.Clients[virtualIP]
		if ok {
			return client, true
		}
	}
	return ClientInfo{}, false
}

func (nc *NetworkControl) UpdateClientByVirtualIP(virtualIP uint32, update func(*ClientInfo)) bool {
	nc.VirtualNetwork.mutex.Lock()
	defer nc.VirtualNetwork.mutex.Unlock()
	for _, network := range nc.VirtualNetwork.data {
		client, ok := network.Clients[virtualIP]
		if !ok {
			continue
		}
		update(&client)
		network.Clients[virtualIP] = client
		return true
	}
	return false
}

func (nc *NetworkControl) FindPunchSession(sessionID uint64, attempt uint32) (*PunchSession, bool) {
	return nc.PunchSessions.Get(punchSessionKey(sessionID, attempt))
}

// ExpireMap now accepts a key type K (must be comparable) and value type T.
type ExpireMap[K comparable, T any] struct {
	data       map[K]T
	expiration map[K]int64 // unixNano deadline per key; 0 means no expiry
	mutex      sync.RWMutex
	ttl        int64 // default ttl in nanoseconds; 0 means no default expiry
	stopCh     chan struct{}
}

// NewExpireMap creates an ExpireMap. defaultTTL == 0 means entries do not expire by default.
func NewExpireMap[K comparable, T any](defaultTTL time.Duration) *ExpireMap[K, T] {
	em := &ExpireMap[K, T]{
		data:       make(map[K]T),
		expiration: make(map[K]int64),
		ttl:        int64(defaultTTL),
		stopCh:     make(chan struct{}),
	}
	go em.janitor()
	return em
}

// Set stores value. Uses the map's default TTL provided in NewExpireMap; if default TTL == 0 the key does not expire.
func (e *ExpireMap[K, T]) Set(key K, value T) {
	var deadline int64
	if e.ttl > 0 {
		deadline = time.Now().Add(time.Duration(e.ttl)).UnixNano()
	} else {
		deadline = 0
	}

	e.mutex.Lock()
	e.data[key] = value
	if deadline == 0 {
		delete(e.expiration, key)
	} else {
		e.expiration[key] = deadline
	}
	e.mutex.Unlock()
}

// Get returns the value and true if present and not expired.
func (e *ExpireMap[K, T]) Get(key K) (T, bool) {
	e.mutex.RLock()
	deadline, hasExp := e.expiration[key]
	val, ok := e.data[key]
	e.mutex.RUnlock()

	if !ok {
		var zero T
		return zero, false
	}
	if hasExp && deadline > 0 && time.Now().UnixNano() > deadline {
		// expired; remove it
		e.mutex.Lock()
		delete(e.data, key)
		delete(e.expiration, key)
		e.mutex.Unlock()
		var zero T
		return zero, false
	}
	return val, true
}

// Delete removes a key immediately.
func (e *ExpireMap[K, T]) Delete(key K) {
	e.mutex.Lock()
	delete(e.data, key)
	delete(e.expiration, key)
	e.mutex.Unlock()
}

// Stop stops the janitor goroutine. After Stop, the map still usable but automatic cleanup stops.
func (e *ExpireMap[K, T]) Stop() {
	select {
	case <-e.stopCh:
		// already closed
	default:
		close(e.stopCh)
	}
}

// janitor periodically scans and removes expired entries.
func (e *ExpireMap[K, T]) janitor() {
	// choose a reasonable interval
	interval := time.Second
	if e.ttl > 0 {
		d := time.Duration(e.ttl) / 4
		if d > 0 && d < interval {
			interval = d
		}
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now().UnixNano()
			e.mutex.Lock()
			for k, dl := range e.expiration {
				if dl > 0 && now > dl {
					delete(e.expiration, k)
					delete(e.data, k)
				}
			}
			e.mutex.Unlock()
		case <-e.stopCh:
			return
		}
	}
}
