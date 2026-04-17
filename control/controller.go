package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sdl-control/config"
	"sdl-control/protocol"
	"sdl-control/protocol/pb"
	"sdl-control/util"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

type Controller struct {
	nc  NetworkControl
	um  *UserManager
	gs  *JSONGatewayStore
	cfg *config.Config
	mu  sync.Mutex

	authChallengeMu sync.Mutex
	authChallenges  map[string]deviceAuthChallengeState
	handshakeCaps   map[string][]string

	gatewayMu    sync.RWMutex
	gatewayNodes map[string]GatewayNodeInfo
	gatewayAllow map[string]string
	gatewaySeen  map[string]GatewayNodeInfo
	gatewayNonce map[string]map[string]int64

	debugMu                  sync.Mutex
	debugCollectSeq          uint64
	debugWatchSeq            uint64
	pendingDebugCollect      map[uint64]chan DebugCollectResult
	pendingDebugWatchStart   map[uint64]chan DebugWatchStartResult
	pendingDebugWatchStop    map[uint64]chan DebugWatchStopResult
	latestDebugCollect       map[string]DebugCollectResult
	debugStore               *DebugSnapshotStore
	activeDebugWatches       map[uint64]DebugWatchSession
	activeDebugWatchByDevice map[string]uint64
}

type GatewayNodeInfo struct {
	GatewayID      string
	Endpoint       string
	Capabilities   []string
	Channels       []*pb.GatewayChannel
	DefaultChannel pb.GatewayChannelKind
	UDPKeyID       string
	UDPPublicKey   []byte
	UpdatedAt      time.Time
}

type deviceAuthChallengeState struct {
	UserID         string
	GroupName      string
	DeviceID       string
	Ticket         string
	DevicePubKey   []byte
	Nonce          []byte
	ExpireAt       time.Time
	ReauthRequired bool
}

type GatewayAdminView struct {
	GatewayID     string   `json:"gateway_id"`
	Endpoint      string   `json:"endpoint"`
	Approved      bool     `json:"approved"`
	Default       bool     `json:"default"`
	Reported      bool     `json:"reported"`
	Alive         bool     `json:"alive"`
	Capabilities  []string `json:"capabilities,omitempty"`
	UpdatedAtUnix int64    `json:"updated_at_unix,omitempty"`
}

type DeviceAdminView struct {
	UserID             string `json:"user_id"`
	Group              string `json:"group"`
	Name               string `json:"name"`
	DeviceID           string `json:"device_id"`
	VirtualIP          string `json:"virtual_ip"`
	ControlOnline      bool   `json:"control_online"`
	DataPlaneReachable bool   `json:"data_plane_reachable"`
	AuthedAtUnix       int64  `json:"authed_at_unix,omitempty"`
	AuthExpireAtUnix   int64  `json:"auth_expire_at_unix,omitempty"`
	AuthExpired        bool   `json:"auth_expired,omitempty"`
	UpdatedAtUnix      int64  `json:"updated_at_unix,omitempty"`
}

const maxPunchAttemptsPerPair = 3
const gatewayNodeLease = 90 * time.Second
const deviceAuthChallengeTTL = 60 * time.Second
const gatewayReportFreshnessWindow = 2 * time.Minute
const punchStatusFreshSnapshotWindow = 2 * time.Second

type PunchSessionState string

const (
	PunchSessionScheduled PunchSessionState = "scheduled"
	PunchSessionSending   PunchSessionState = "sending"
	PunchSessionWaiting   PunchSessionState = "waiting"
	PunchSessionSuccess   PunchSessionState = "success"
	PunchSessionFailed    PunchSessionState = "failed"
	PunchSessionTimeout   PunchSessionState = "timeout"
)

type PunchSession struct {
	SessionID       uint64
	Source          uint32
	Target          uint32
	SourceOwner     uint64
	TargetOwner     uint64
	Attempt         uint32
	AttemptBudget   uint32
	DeadlineUnixMs  int64
	TriggerReason   string
	SelectionPolicy string
	State           PunchSessionState
	RequestedAt     int64
	LastReason      string
	RelayFallback   bool
	Ack             map[uint32]bool
	Results         map[uint32]*pb.PunchResult
}

type PunchRetryState struct {
	Attempt           uint32
	NextAllowedUnixMs int64
}

var supportedHandshakeCapabilities = map[string]struct{}{
	"udp_endpoint_report_v1": {},
	"punch_coord_v1":         {},
	"gateway_ticket_v1":      {},
}

const capabilityUDPEndpointReportV1 = "udp_endpoint_report_v1"

func NewController(cfg *config.Config) (*Controller, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	um := newUserManagerFromStore()
	gatewayAllow, gatewayStore := newGatewayApprovalStateFromStore()
	return &Controller{
		nc: NetworkControl{
			VirtualNetwork:    *NewExpireMap[string, *NetworkInfo](7 * 24 * time.Hour),
			IPSessions:        *NewExpireMap[IpSessionKey, net.Addr](24 * time.Hour),
			PunchSessions:     *NewExpireMap[string, *PunchSession](10 * time.Minute),
			PunchPairCooldown: *NewExpireMap[string, struct{}](20 * time.Second),
			PunchPairRetry:    *NewExpireMap[string, PunchRetryState](30 * time.Minute),
		},
		um:                       um,
		gs:                       gatewayStore,
		cfg:                      cfg,
		authChallenges:           make(map[string]deviceAuthChallengeState),
		handshakeCaps:            make(map[string][]string),
		gatewayNodes:             make(map[string]GatewayNodeInfo),
		gatewayAllow:             gatewayAllow,
		gatewaySeen:              make(map[string]GatewayNodeInfo),
		gatewayNonce:             make(map[string]map[string]int64),
		pendingDebugCollect:      make(map[uint64]chan DebugCollectResult),
		pendingDebugWatchStart:   make(map[uint64]chan DebugWatchStartResult),
		pendingDebugWatchStop:    make(map[uint64]chan DebugWatchStopResult),
		latestDebugCollect:       make(map[string]DebugCollectResult),
		debugStore:               newDebugSnapshotStore(cfg),
		activeDebugWatches:       make(map[uint64]DebugWatchSession),
		activeDebugWatchByDevice: make(map[string]uint64),
	}, nil
}

func newUserManagerFromStore() *UserManager {
	path := os.Getenv("UM_STORE_JSON_PATH")
	if path == "" {
		path = "./data/um.json"
	}
	um, err := NewUserManagerWithStore(NewJSONUMStore(path))
	if err != nil {
		log.Warnf("load user manager from json failed (%s): %v; fallback to memory", path, err)
		return NewUserManager()
	}
	return um
}

func newGatewayApprovalStateFromStore() (map[string]string, *JSONGatewayStore) {
	path := os.Getenv("GATEWAY_STORE_JSON_PATH")
	if path == "" {
		path = "./data/gateways.json"
	}
	store := NewJSONGatewayStore(path)
	snapshot, err := store.Load()
	if err != nil {
		log.Warnf("load gateway approval store failed (%s): %v; fallback to memory", path, err)
		return map[string]string{}, store
	}
	approved := make(map[string]string, len(snapshot.Approved))
	for gatewayID, endpoint := range snapshot.Approved {
		gatewayID = strings.TrimSpace(gatewayID)
		endpoint = strings.TrimSpace(endpoint)
		if gatewayID == "" || endpoint == "" {
			continue
		}
		approved[gatewayID] = endpoint
	}
	return approved, store
}

func newDebugSnapshotStore(cfg *config.Config) *DebugSnapshotStore {
	path := strings.TrimSpace(os.Getenv("DEBUG_COLLECT_DIR"))
	if path == "" && cfg != nil {
		path = strings.TrimSpace(cfg.DebugCollectDir)
	}
	if path == "" {
		path = "./data/debug-collect"
	}
	keepPerDevice := 20
	if cfg != nil && cfg.DebugCollectKeepPerDevice > 0 {
		keepPerDevice = cfg.DebugCollectKeepPerDevice
	}
	if value := strings.TrimSpace(os.Getenv("DEBUG_COLLECT_KEEP_PER_DEVICE")); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			keepPerDevice = parsed
		}
	}
	return NewDebugSnapshotStore(path, keepPerDevice)
}

func (c *Controller) persistGatewayApprovalLocked() {
	if c.gs == nil {
		return
	}
	snapshot := GatewayStoreSnapshot{
		Approved: make(map[string]string, len(c.gatewayAllow)),
	}
	for gatewayID, endpoint := range c.gatewayAllow {
		gatewayID = strings.TrimSpace(gatewayID)
		endpoint = strings.TrimSpace(endpoint)
		if gatewayID == "" || endpoint == "" {
			continue
		}
		snapshot.Approved[gatewayID] = endpoint
	}
	if err := c.gs.Save(snapshot); err != nil {
		log.Warnf("persist gateway approval store failed: %v", err)
	}
}

func (c *Controller) Stop() {
	c.nc.VirtualNetwork.Stop()
	c.nc.IPSessions.Stop()
	c.nc.PunchSessions.Stop()
	c.nc.PunchPairCooldown.Stop()
	c.nc.PunchPairRetry.Stop()
}

func (c *Controller) HandleHandshakePacket(reqPacket *protocol.Packet, remoteAddr net.Addr) (*protocol.Packet, error) {
	log.Debugf("收到客户端 HandshakeRequest Packet: %s", reqPacket.DebugString())
	var req pb.HandshakeRequest
	if err := proto.Unmarshal(reqPacket.Payload, &req); err != nil {
		log.Errorf("HandshakeRequest unmarshal error: %v", err)
		return nil, err
	}
	negotiatedCapabilities := negotiateHandshakeCapabilities(req.GetCapabilities())
	c.setPendingHandshakeCapabilities(remoteAddr, negotiatedCapabilities)

	rsp := &pb.HandshakeResponse{
		Version:      "goversion-1.0.0",
		Capabilities: negotiatedCapabilities,
	}
	playload, err := proto.Marshal(rsp)
	if err != nil {
		log.Errorf("HandshakeResponse marshal error: %v", err)
		return nil, err
	}

	rspPacket := &protocol.Packet{
		Ver:       protocol.V3,
		Proto:     protocol.ProtocolService,
		AppProto:  protocol.AppProtoHandshakeResponse,
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     reqPacket.DstIP,
		DstIP:     reqPacket.SrcIP,
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
	gateway, netmask, err := c.resolveGroupNetworkConfig(domain)
	if err != nil {
		return nil, 0, err
	}
	if err := c.UMCheckAuthedDevice(domain, registration.GetDeviceId(), registration.GetDevicePubKey()); err != nil {
		c.clearStaleClientStateByDeviceID(domain, registration.GetDeviceId())
		return nil, 0, fmt.Errorf("device %s auth check failed for group %s: %w", registration.GetDeviceId(), domain, err)
	}
	displayName := sanitizeDNSHostnameLabel(registration.GetName(), registration.GetDeviceId())
	if existing, ok := c.UMGetAuthedDevice(domain, registration.GetDeviceId()); ok {
		if persisted := strings.TrimSpace(existing.DisplayName); persisted != "" {
			displayName = sanitizeDNSHostnameLabel(persisted, registration.GetDeviceId())
		}
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
	negotiatedCapabilities := c.consumeHandshakeCapabilities(remoteAddr)
	if !hasCapability(negotiatedCapabilities, capabilityUDPEndpointReportV1) {
		return nil, 0, fmt.Errorf("client %v missing required handshake capability %q", remoteAddr, capabilityUDPEndpointReportV1)
	}

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
	registrationResp.VirtualGateway = util.IpToUint32(gateway)
	registrationResp.VirtualNetmask = util.MaskToUint32(netmask)
	registrationResp.DnsProfile = c.BuildClientDNSProfile(domain)

	c.mu.Lock()
	defer c.mu.Unlock()

	netInfo, netInfoExist := c.nc.VirtualNetwork.Get(domain)
	if !netInfoExist {
		netInfo = NewNetworkInfo(domain, netmask, net.IP(gateway), c.reservedServiceIPs(domain))
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
		netInfo.DeleteClient(oldIP)
		c.nc.IPSessions.Delete(NewIpSessionKey(domain, util.Uint32ToIP(oldIP)))
	}
	clientInfo := netInfo.Clients[virtualIP]
	now := time.Now().Unix()
	clientInfo.DeviceId = registration.GetDeviceId()
	clientInfo.Name = displayName
	clientInfo.Version = registration.GetVersion()
	clientInfo.Capabilities = negotiatedCapabilities
	clientInfo.RegistrationEpoch++
	clientInfo.ControlOnline = true
	clientInfo.ControlLastSeen = now
	clientInfo.DataPlaneReachable = false
	clientInfo.DataPlaneLastSeen = 0
	clientInfo.VirtualIp = virtualIP
	clientInfo.Address = remoteAddr
	clientInfo.DevicePubKey = append(clientInfo.DevicePubKey[:0], registration.GetDevicePubKey()...)
	clientInfo.OnlineKxPub = append(clientInfo.OnlineKxPub[:0], registration.GetOnlineKxPub()...)
	clientInfo.LastJoin = now
	netInfo.UpsertClient(virtualIP, clientInfo)
	c.nc.IPSessions.Delete(NewIpSessionKey(domain, util.Uint32ToIP(virtualIP)))
	// Reset punch retry state for all pairs involving this client so re-registering
	// clients start fresh (attempt counter is not shared across registration epochs).
	for peerIP := range netInfo.Clients {
		if peerIP == virtualIP {
			continue
		}
		for _, key := range []string{punchPairKey(virtualIP, peerIP), punchPairKey(peerIP, virtualIP)} {
			c.nc.PunchPairRetry.Delete(key)
			c.nc.PunchPairCooldown.Delete(key)
		}
	}
	netInfo.Epoch++
	registrationResp.VirtualIp = virtualIP
	registrationResp.GatewayAccessGrant = c.buildGatewayAccessGrant(virtualIP, registration.GetDeviceId())
	registrationResp.Epoch = uint32(netInfo.Epoch)
	registrationResp.RegistrationEpoch = clientInfo.RegistrationEpoch
	registrationResp.DeviceInfoList = buildDeviceInfoList(netInfo.Clients, virtualIP)

	respBytes, err := proto.Marshal(registrationResp)
	if err != nil {
		return nil, 0, fmt.Errorf("RegistrationResponse marshal error: %v", err)
	}

	respPacket := &protocol.Packet{
		Ver:       protocol.V3,
		Proto:     protocol.ProtocolService,
		AppProto:  protocol.AppProtoRegistrationResponse,
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     request.DstIP,
		DstIP:     request.SrcIP,
		Payload:   respBytes,
	}

	return respPacket, virtualIP, nil
}

func (c *Controller) HandleDeviceRenamePacket(request *protocol.Packet) (*protocol.Packet, uint32, error) {
	var req pb.DeviceRenameRequest
	if err := proto.Unmarshal(request.Payload, &req); err != nil {
		return nil, 0, err
	}
	deviceID := strings.TrimSpace(req.GetDeviceId())
	newName, err := normalizeRenameName(req.GetNewName())
	if err != nil {
		resp, packetErr := c.buildServicePacket(request, protocol.AppProtoDeviceRenameResponse, &pb.DeviceRenameResponse{
			RequestId: req.GetRequestId(),
			Ok:        false,
			Reason:    err.Error(),
		})
		return resp, 0, packetErr
	}
	if deviceID == "" {
		resp, err := c.buildServicePacket(request, protocol.AppProtoDeviceRenameResponse, &pb.DeviceRenameResponse{
			RequestId: req.GetRequestId(),
			Ok:        false,
			Reason:    "device_id is empty",
		})
		return resp, 0, err
	}
	srcIP := util.IpToUint32(request.SrcIP)
	groupName := ""
	c.nc.VirtualNetwork.mutex.RLock()
	for _, network := range c.nc.VirtualNetwork.data {
		client, ok := network.Clients[srcIP]
		if !ok {
			continue
		}
		if client.DeviceId != deviceID {
			c.nc.VirtualNetwork.mutex.RUnlock()
			resp, err := c.buildServicePacket(request, protocol.AppProtoDeviceRenameResponse, &pb.DeviceRenameResponse{
				RequestId: req.GetRequestId(),
				Ok:        false,
				Reason:    "device mismatch",
			})
			return resp, 0, err
		}
		groupName = network.Group
		break
	}
	c.nc.VirtualNetwork.mutex.RUnlock()
	if groupName == "" {
		resp, err := c.buildServicePacket(request, protocol.AppProtoDeviceRenameResponse, &pb.DeviceRenameResponse{
			RequestId: req.GetRequestId(),
			Ok:        false,
			Reason:    "device not registered",
		})
		return resp, 0, err
	}
	changedIP, err := c.applyDeviceRename(groupName, deviceID, newName)
	if err != nil {
		resp, packetErr := c.buildServicePacket(request, protocol.AppProtoDeviceRenameResponse, &pb.DeviceRenameResponse{
			RequestId: req.GetRequestId(),
			Ok:        false,
			Reason:    err.Error(),
		})
		return resp, 0, packetErr
	}
	resp, err := c.buildServicePacket(request, protocol.AppProtoDeviceRenameResponse, &pb.DeviceRenameResponse{
		RequestId:   req.GetRequestId(),
		Ok:          true,
		AppliedName: newName,
	})
	return resp, changedIP, err
}

func (c *Controller) clearStaleClientStateByDeviceID(domain, deviceID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	netInfo, ok := c.nc.VirtualNetwork.Get(domain)
	if !ok {
		return
	}
	changed := false
	now := time.Now().Unix()
	for virtualIP, clientInfo := range netInfo.Clients {
		if clientInfo.DeviceId != deviceID {
			continue
		}
		if !clientInfo.ControlOnline && clientInfo.ClientStatus == nil && !clientInfo.DataPlaneReachable {
			continue
		}
		clientInfo.ControlOnline = false
		clientInfo.ControlLastSeen = now
		clientInfo.DataPlaneReachable = false
		clientInfo.DataPlaneLastSeen = 0
		clientInfo.ClientStatus = nil
		netInfo.UpsertClient(virtualIP, clientInfo)
		c.nc.IPSessions.Set(NewIpSessionKey(domain, util.Uint32ToIP(virtualIP)), clientInfo.Address)
		changed = true
	}
	if changed {
		netInfo.Epoch++
	}
}

func (c *Controller) BuildRegistrationErrorPacket(request *protocol.Packet, err error) (*protocol.Packet, error) {
	code := uint32(1)
	reason := "registration failed"
	if err != nil {
		reason = err.Error()
		switch {
		case strings.Contains(reason, "expect <group>.<domain>"),
			strings.Contains(reason, "not configured in domains"):
			code = 1001
		case strings.Contains(reason, "not authed"):
			code = 1002
		case strings.Contains(reason, "unmarshal"),
			strings.Contains(reason, "validate"):
			code = 1003
		default:
			code = 1999
		}
	}
	resp := &pb.RegistrationResponse{
		ErrorCode:    code,
		ErrorMessage: reason,
	}
	payload, marshalErr := proto.Marshal(resp)
	if marshalErr != nil {
		return nil, fmt.Errorf("RegistrationResponse(error) marshal error: %v", marshalErr)
	}
	return &protocol.Packet{
		Ver:       protocol.V3,
		Proto:     protocol.ProtocolService,
		AppProto:  protocol.AppProtoRegistrationResponse,
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     request.DstIP,
		DstIP:     request.SrcIP,
		Payload:   payload,
	}, nil
}

func (c *Controller) HandlePullDeviceListPacket(request *protocol.Packet) (*protocol.Packet, error) {
	selfIP := util.IpToUint32(request.SrcIP)
	deviceList, ok := c.nc.DeviceListByIP(selfIP)
	if !ok {
		return c.buildDisconnectPacket(request), nil
	}
	payload, err := proto.Marshal(deviceList)
	if err != nil {
		return nil, fmt.Errorf("DeviceList marshal error: %v", err)
	}
	return &protocol.Packet{
		Ver:       protocol.V3,
		Proto:     protocol.ProtocolService,
		AppProto:  protocol.AppProtoPushDeviceList,
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     request.DstIP,
		DstIP:     request.SrcIP,
		Payload:   payload,
	}, nil
}

func (c *Controller) BuildPushDeviceListPacketsForPeerChange(changedIP uint32) ([]*protocol.Packet, error) {
	c.nc.VirtualNetwork.mutex.RLock()
	defer c.nc.VirtualNetwork.mutex.RUnlock()

	for _, network := range c.nc.VirtualNetwork.data {
		changedClient, ok := network.Clients[changedIP]
		if !ok {
			continue
		}
		if !changedClient.ControlOnline {
			return nil, nil
		}
		packets := make([]*protocol.Packet, 0, len(network.Clients))
		for targetIP, targetClient := range network.Clients {
			if targetIP == changedIP || !targetClient.ControlOnline {
				continue
			}
			push := &pb.DeviceList{
				Epoch:          uint32(network.Epoch),
				DeviceInfoList: buildDeviceInfoList(network.Clients, targetIP),
			}
			payload, err := proto.Marshal(push)
			if err != nil {
				return nil, fmt.Errorf("DeviceList marshal error: %v", err)
			}
			packets = append(packets, &protocol.Packet{
				Ver:       protocol.V3,
				Proto:     protocol.ProtocolService,
				AppProto:  protocol.AppProtoPushDeviceList,
				SourceTTL: protocol.MAX_TTL,
				TTL:       protocol.MAX_TTL,
				SrcIP:     net.ParseIP("0.0.0.1"),
				DstIP:     util.Uint32ToIP(targetIP),
				Payload:   payload,
			})
		}
		return packets, nil
	}
	return nil, nil
}

func (c *Controller) BuildDeviceRenameNotifyPacket(
	targetIP uint32,
	requestID uint64,
	appliedName string,
) (*protocol.Packet, error) {
	if targetIP == 0 {
		return nil, nil
	}
	resp := &pb.DeviceRenameResponse{
		RequestId:   requestID,
		Ok:          true,
		AppliedName: appliedName,
	}
	payload, err := proto.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("DeviceRenameResponse marshal error: %v", err)
	}
	return &protocol.Packet{
		Ver:       protocol.V3,
		Proto:     protocol.ProtocolService,
		AppProto:  protocol.AppProtoDeviceRenameResponse,
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     net.ParseIP("0.0.0.1"),
		DstIP:     util.Uint32ToIP(targetIP),
		Payload:   payload,
	}, nil
}

func (c *Controller) buildDisconnectPacket(request *protocol.Packet) *protocol.Packet {
	return &protocol.Packet{
		Ver:       protocol.V3,
		Proto:     protocol.ProtocolError,
		AppProto:  protocol.AppProtocol(2),
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     request.DstIP,
		DstIP:     request.SrcIP,
	}
}

func (c *Controller) HandleDeviceAuthPacket(request *protocol.Packet) (*protocol.Packet, error) {
	var req pb.DeviceAuthRequest
	if err := proto.Unmarshal(request.Payload, &req); err != nil {
		return nil, err
	}
	groupName, err := c.UMValidateDeviceAuth(req.GetUserId(), req.GetGroup(), req.GetDeviceId(), req.GetTicket())
	if err != nil {
		ack := &pb.DeviceAuthAck{
			Ok:       false,
			Reason:   err.Error(),
			UserId:   req.GetUserId(),
			Group:    req.GetGroup(),
			DeviceId: req.GetDeviceId(),
		}
		return c.buildServicePacket(request, protocol.AppProtoDeviceAuthAck, ack)
	}
	if len(req.GetDevicePubKey()) == 0 {
		ack := &pb.DeviceAuthAck{
			Ok:       false,
			Reason:   "device public key is empty",
			UserId:   req.GetUserId(),
			Group:    req.GetGroup(),
			DeviceId: req.GetDeviceId(),
		}
		return c.buildServicePacket(request, protocol.AppProtoDeviceAuthAck, ack)
	}
	reauthRequired := false
	if existing, ok := c.UMGetAuthedDevice(groupName, req.GetDeviceId()); ok {
		if existing.PubKeyHex != toPubKeyHex(req.GetDevicePubKey(), "ed25519") {
			reauthRequired = true
		}
	}
	challenge, err := c.newDeviceAuthChallenge(req.GetUserId(), groupName, req.GetDeviceId(), req.GetTicket(), req.GetDevicePubKey(), reauthRequired)
	if err != nil {
		return nil, err
	}
	return c.buildServicePacket(request, protocol.AppProtoDeviceAuthChallenge, challenge)
}

func (c *Controller) HandleDeviceAuthProofPacket(request *protocol.Packet) (*protocol.Packet, error) {
	var req pb.DeviceAuthProof
	if err := proto.Unmarshal(request.Payload, &req); err != nil {
		return nil, err
	}
	challenge, ok := c.consumeDeviceAuthChallenge(req.GetChallengeId())
	if !ok || time.Now().After(challenge.ExpireAt) {
		ack := &pb.DeviceAuthAck{
			Ok:       false,
			Reason:   "challenge_expired",
			DeviceId: req.GetDeviceId(),
		}
		return c.buildServicePacket(request, protocol.AppProtoDeviceAuthAck, ack)
	}
	if challenge.DeviceID != req.GetDeviceId() || !bytes.Equal(challenge.DevicePubKey, req.GetDevicePubKey()) {
		ack := &pb.DeviceAuthAck{
			Ok:             false,
			Reason:         "device_key_mismatch",
			DeviceId:       req.GetDeviceId(),
			ReauthRequired: challenge.ReauthRequired,
		}
		return c.buildServicePacket(request, protocol.AppProtoDeviceAuthAck, ack)
	}
	if !ed25519.Verify(ed25519.PublicKey(req.GetDevicePubKey()), buildDeviceAuthSignedPayload(req.GetChallengeId(), challenge.Nonce, req.GetDeviceId(), req.GetDevicePubKey()), req.GetSignature()) {
		ack := &pb.DeviceAuthAck{
			Ok:             false,
			Reason:         "invalid_signature",
			DeviceId:       req.GetDeviceId(),
			ReauthRequired: challenge.ReauthRequired,
		}
		return c.buildServicePacket(request, protocol.AppProtoDeviceAuthAck, ack)
	}
	record, err := c.UMAuthDevice(challenge.UserID, challenge.GroupName, challenge.DeviceID, challenge.Ticket, challenge.DevicePubKey)
	if err != nil {
		ack := &pb.DeviceAuthAck{
			Ok:             false,
			Reason:         err.Error(),
			UserId:         challenge.UserID,
			Group:          challenge.GroupName,
			DeviceId:       challenge.DeviceID,
			ReauthRequired: challenge.ReauthRequired,
		}
		return c.buildServicePacket(request, protocol.AppProtoDeviceAuthAck, ack)
	}
	ack := &pb.DeviceAuthAck{
		Ok:               true,
		UserId:           record.UserID,
		Group:            record.GroupName,
		DeviceId:         record.DeviceID,
		AuthExpireUnixMs: record.AuthExpireAt.UnixMilli(),
		ReauthRequired:   challenge.ReauthRequired,
	}
	return c.buildServicePacket(request, protocol.AppProtoDeviceAuthAck, ack)
}

func (c *Controller) HandleRefreshGatewayGrantPacket(request *protocol.Packet) (*protocol.Packet, error) {
	var req pb.RefreshGatewayGrantRequest
	if err := proto.Unmarshal(request.Payload, &req); err != nil {
		return nil, err
	}
	if req.GetVirtualIp() == 0 {
		return nil, fmt.Errorf("refresh gateway grant virtual_ip is empty")
	}
	if req.GetDeviceId() == "" {
		return nil, fmt.Errorf("refresh gateway grant device_id is empty")
	}
	if srcIP := request.SrcIP.To4(); srcIP == nil || util.IpToUint32(srcIP) != req.GetVirtualIp() {
		return nil, fmt.Errorf("refresh gateway grant source mismatch")
	}
	if !c.clientOwnsVirtualIP(req.GetVirtualIp(), req.GetDeviceId()) {
		return nil, fmt.Errorf("refresh gateway grant device mismatch")
	}

	resp := &pb.RefreshGatewayGrantResponse{
		HasUpdate: true,
		Reason:    "refreshed",
	}
	if grant := c.buildGatewayAccessGrant(req.GetVirtualIp(), req.GetDeviceId()); grant != nil {
		resp.GatewayAccessGrant = grant
	} else {
		resp.HasUpdate = false
		resp.Reason = "no gateway available"
	}
	payload, err := proto.Marshal(resp)
	if err != nil {
		return nil, err
	}
	return &protocol.Packet{
		Ver:       protocol.V3,
		Proto:     protocol.ProtocolService,
		AppProto:  protocol.AppProtoRefreshGatewayGrantResponse,
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     request.DstIP,
		DstIP:     request.SrcIP,
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
		P2PList:            make([]net.IP, 0, len(status.GetP2PList())),
		PublicUDPEndpoints: make([]*net.UDPAddr, 0, len(status.GetPublicUdpEndpoints())),
		LocalUDPPorts:      make([]uint16, 0, len(status.GetLocalUdpPorts())),
		UpStream:           status.GetUpStream(),
		DownStream:         status.GetDownStream(),
		IsCone:             status.GetNatType() == pb.PunchNatType_Cone,
		PunchTriggerReason: status.GetPunchTriggerReason().String(),
		UpdateTime:         now,
	}
	for _, item := range status.GetP2PList() {
		clientStatus.P2PList = append(clientStatus.P2PList, util.Uint32ToIP(item.GetNextIp()))
	}
	for _, endpoint := range status.GetPublicUdpEndpoints() {
		if endpoint.GetPort() == 0 || endpoint.GetPort() > 65535 {
			continue
		}
		var ip net.IP
		if endpoint.GetIp() != 0 {
			ip = util.Uint32ToIP(endpoint.GetIp())
		} else if len(endpoint.GetIpv6()) == net.IPv6len {
			ip = append(net.IP(nil), endpoint.GetIpv6()...)
		}
		if ip == nil {
			continue
		}
		clientStatus.PublicUDPEndpoints = append(clientStatus.PublicUDPEndpoints, &net.UDPAddr{
			IP:   ip,
			Port: int(endpoint.GetPort()),
		})
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
		clientStatus.RegistrationEpoch = client.RegistrationEpoch
		client.ControlOnline = true
		client.ControlLastSeen = now
		client.DataPlaneReachable = reachable
		if reachable {
			client.DataPlaneLastSeen = now
		}
		client.ClientStatus = clientStatus
		network.UpsertClient(srcIP, client)
		return nil
	}
	return fmt.Errorf("client %s not registered", request.SrcIP)
}

func (c *Controller) BuildPunchStartPacketsFromStatus(request *protocol.Packet) ([]*protocol.Packet, error) {
	srcIP := util.IpToUint32(request.SrcIP)
	now := time.Now()
	nowMs := now.UnixMilli()
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
			if clientsHaveMutualP2PPath(srcClient, srcIP, targetClient, targetIP) {
				continue
			}
			if !clientsHaveFreshPunchSnapshot(srcClient, targetClient, now) {
				continue
			}
			pairKey := punchPairKey(srcIP, targetIP)
			if !c.nc.PunchPairCooldown.SetIfAbsent(pairKey, struct{}{}) {
				continue
			}
			retryState, hasRetry := c.nc.PunchPairRetry.Get(pairKey)
			if hasRetry {
				if retryState.Attempt >= maxPunchAttemptsPerPair {
					c.nc.PunchPairCooldown.Delete(pairKey)
					continue
				}
				if nowMs < retryState.NextAllowedUnixMs {
					c.nc.PunchPairCooldown.Delete(pairKey)
					continue
				}
			}
			sourceEndpoints := buildPunchEndpoints(srcClient)
			targetEndpoints := buildPunchEndpoints(targetClient)
			if len(sourceEndpoints) == 0 || len(targetEndpoints) == 0 {
				c.nc.PunchPairCooldown.Delete(pairKey)
				continue
			}
			sessionID := uint64(time.Now().UnixNano())
			attempt := uint32(1)
			attemptBudget := uint32(maxPunchAttemptsPerPair)
			if hasRetry {
				attempt = retryState.Attempt + 1
			}
			deadline := now.Add(5 * time.Second).UnixMilli()
			triggerReason := pb.PunchTriggerReason_PunchTriggerStatusUpdate
			if srcClient.ClientStatus != nil {
				if parsed, ok := pb.PunchTriggerReason_value[srcClient.ClientStatus.PunchTriggerReason]; ok {
					triggerReason = pb.PunchTriggerReason(parsed)
				}
			}
			selectionPolicy := pb.PunchEndpointSelectionPolicy_PunchEndpointSelectionAll
			session := &PunchSession{
				SessionID:       sessionID,
				Source:          srcIP,
				Target:          targetIP,
				SourceOwner:     srcClient.RegistrationEpoch,
				TargetOwner:     targetClient.RegistrationEpoch,
				Attempt:         attempt,
				AttemptBudget:   attemptBudget,
				DeadlineUnixMs:  deadline,
				TriggerReason:   triggerReason.String(),
				SelectionPolicy: selectionPolicy.String(),
				State:           PunchSessionScheduled,
				RequestedAt:     now.Unix(),
				Ack:             make(map[uint32]bool),
				Results:         make(map[uint32]*pb.PunchResult),
			}
			c.supersedeOlderPunchSessions(session)
			c.nc.PunchSessions.Set(punchSessionKey(sessionID, attempt), session)
			sourceStart := &pb.PunchStart{
				SessionId:               sessionID,
				Source:                  srcIP,
				Target:                  targetIP,
				SourceOwner:             srcClient.RegistrationEpoch,
				TargetOwner:             targetClient.RegistrationEpoch,
				PeerEndpoints:           targetEndpoints,
				Attempt:                 attempt,
				TimeoutMs:               3000,
				DeadlineUnixMs:          deadline,
				TriggerReason:           triggerReason,
				AttemptBudget:           attemptBudget,
				EndpointSelectionPolicy: selectionPolicy,
			}
			targetStart := &pb.PunchStart{
				SessionId:               sessionID,
				Source:                  targetIP,
				Target:                  srcIP,
				SourceOwner:             targetClient.RegistrationEpoch,
				TargetOwner:             srcClient.RegistrationEpoch,
				PeerEndpoints:           sourceEndpoints,
				Attempt:                 attempt,
				TimeoutMs:               3000,
				DeadlineUnixMs:          deadline,
				TriggerReason:           triggerReason,
				AttemptBudget:           attemptBudget,
				EndpointSelectionPolicy: selectionPolicy,
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
					Ver:       protocol.V3,
					Proto:     protocol.ProtocolService,
					AppProto:  protocol.AppProtoPunchStart,
					SourceTTL: protocol.MAX_TTL,
					TTL:       protocol.MAX_TTL,
					SrcIP:     request.DstIP,
					DstIP:     util.Uint32ToIP(srcIP),
					Payload:   sourcePayload,
				},
				{
					Ver:       protocol.V3,
					Proto:     protocol.ProtocolService,
					AppProto:  protocol.AppProtoPunchStart,
					SourceTTL: protocol.MAX_TTL,
					TTL:       protocol.MAX_TTL,
					SrcIP:     request.DstIP,
					DstIP:     util.Uint32ToIP(targetIP),
					Payload:   targetPayload,
				},
			}, nil
		}
	}
	return nil, nil
}

func clientReportsDirectPeer(client ClientInfo, peerIP uint32) bool {
	if client.ClientStatus == nil {
		return false
	}
	peer := util.Uint32ToIP(peerIP)
	for _, ip := range client.ClientStatus.P2PList {
		if ip != nil && ip.Equal(peer) {
			return true
		}
	}
	return false
}

func clientsHaveMutualP2PPath(srcClient ClientInfo, srcIP uint32, targetClient ClientInfo, targetIP uint32) bool {
	return clientReportsDirectPeer(srcClient, targetIP) && clientReportsDirectPeer(targetClient, srcIP)
}

func clientsHaveFreshPunchSnapshot(srcClient ClientInfo, targetClient ClientInfo, now time.Time) bool {
	if srcClient.ClientStatus == nil || targetClient.ClientStatus == nil {
		return false
	}
	if srcClient.ClientStatus.RegistrationEpoch != srcClient.RegistrationEpoch ||
		targetClient.ClientStatus.RegistrationEpoch != targetClient.RegistrationEpoch {
		return false
	}
	if srcClient.ClientStatus.UpdateTime < srcClient.LastJoin || targetClient.ClientStatus.UpdateTime < targetClient.LastJoin {
		return false
	}
	newestJoin := srcClient.LastJoin
	if targetClient.LastJoin > newestJoin {
		newestJoin = targetClient.LastJoin
	}
	if newestJoin == 0 {
		return true
	}
	// Always enforce the minimum settle window after registration.
	// A fresh snapshot alone is not sufficient — we must wait for the full settle
	// window so that both sides have had time to update their endpoint info.
	return now.Unix()-newestJoin >= int64(punchStatusFreshSnapshotWindow/time.Second)
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
	sourceClient, ok := c.nc.FindClientByVirtualIP(sourceIP)
	if !ok {
		return nil, fmt.Errorf("punch source %s not registered", util.Uint32ToIP(sourceIP))
	}
	targetClient, ok := c.nc.FindClientByVirtualIP(req.GetTarget())
	if !ok {
		return nil, fmt.Errorf("punch target %s not registered", util.Uint32ToIP(req.GetTarget()))
	}
	now := time.Now().Unix()
	session := &PunchSession{
		SessionID:       req.GetSessionId(),
		Source:          sourceIP,
		Target:          req.GetTarget(),
		SourceOwner:     sourceClient.RegistrationEpoch,
		TargetOwner:     targetClient.RegistrationEpoch,
		Attempt:         req.GetAttempt(),
		AttemptBudget:   req.GetAttemptBudget(),
		DeadlineUnixMs:  req.GetDeadlineUnixMs(),
		TriggerReason:   req.GetTriggerReason().String(),
		SelectionPolicy: req.GetEndpointSelectionPolicy().String(),
		State:           PunchSessionScheduled,
		RequestedAt:     now,
		Ack:             map[uint32]bool{sourceIP: true},
		Results:         make(map[uint32]*pb.PunchResult),
	}
	if session.DeadlineUnixMs == 0 {
		session.DeadlineUnixMs = time.Now().Add(5 * time.Second).UnixMilli()
	}
	if session.AttemptBudget == 0 {
		session.AttemptBudget = maxPunchAttemptsPerPair
	}
	c.supersedeOlderPunchSessions(session)
	c.nc.PunchSessions.Set(punchSessionKey(req.GetSessionId(), req.GetAttempt()), session)
	ack := &pb.PunchAck{
		SessionId:   req.GetSessionId(),
		Source:      sourceIP,
		Attempt:     req.GetAttempt(),
		Accepted:    true,
		Phase:       pb.PunchSessionPhase_PunchPhaseScheduled,
		SourceOwner: session.SourceOwner,
		TargetOwner: session.TargetOwner,
	}
	payload, err := proto.Marshal(ack)
	if err != nil {
		return nil, fmt.Errorf("PunchAck marshal error: %v", err)
	}
	return &protocol.Packet{
		Ver:       protocol.V3,
		Proto:     protocol.ProtocolService,
		AppProto:  protocol.AppProtoPunchAck,
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     request.DstIP,
		DstIP:     request.SrcIP,
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
	sourceClient, ok := c.nc.FindClientByVirtualIP(sourceIP)
	if !ok {
		return nil, fmt.Errorf("punch source %s not registered", util.Uint32ToIP(sourceIP))
	}
	targetClient, ok := c.nc.FindClientByVirtualIP(req.GetTarget())
	if !ok {
		return nil, fmt.Errorf("punch target %s not registered", util.Uint32ToIP(req.GetTarget()))
	}
	sourceStart := &pb.PunchStart{
		SessionId:               req.GetSessionId(),
		Source:                  sourceIP,
		Target:                  req.GetTarget(),
		SourceOwner:             sourceClient.RegistrationEpoch,
		TargetOwner:             targetClient.RegistrationEpoch,
		PeerEndpoints:           req.GetTargetEndpoints(),
		Attempt:                 req.GetAttempt(),
		TimeoutMs:               req.GetTimeoutMs(),
		DeadlineUnixMs:          req.GetDeadlineUnixMs(),
		TriggerReason:           req.GetTriggerReason(),
		AttemptBudget:           req.GetAttemptBudget(),
		EndpointSelectionPolicy: req.GetEndpointSelectionPolicy(),
	}
	targetStart := &pb.PunchStart{
		SessionId:               req.GetSessionId(),
		Source:                  req.GetTarget(),
		Target:                  sourceIP,
		SourceOwner:             targetClient.RegistrationEpoch,
		TargetOwner:             sourceClient.RegistrationEpoch,
		PeerEndpoints:           req.GetSourceEndpoints(),
		Attempt:                 req.GetAttempt(),
		TimeoutMs:               req.GetTimeoutMs(),
		DeadlineUnixMs:          req.GetDeadlineUnixMs(),
		TriggerReason:           req.GetTriggerReason(),
		AttemptBudget:           req.GetAttemptBudget(),
		EndpointSelectionPolicy: req.GetEndpointSelectionPolicy(),
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
			Ver:       protocol.V3,
			Proto:     protocol.ProtocolService,
			AppProto:  protocol.AppProtoPunchStart,
			SourceTTL: protocol.MAX_TTL,
			TTL:       protocol.MAX_TTL,
			SrcIP:     request.DstIP,
			DstIP:     util.Uint32ToIP(sourceIP),
			Payload:   sourcePayload,
		},
		{
			Ver:       protocol.V3,
			Proto:     protocol.ProtocolService,
			AppProto:  protocol.AppProtoPunchStart,
			SourceTTL: protocol.MAX_TTL,
			TTL:       protocol.MAX_TTL,
			SrcIP:     request.DstIP,
			DstIP:     util.Uint32ToIP(req.GetTarget()),
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
	if session.Ack == nil {
		session.Ack = make(map[uint32]bool)
	}
	if session.Results == nil {
		session.Results = make(map[uint32]*pb.PunchResult)
	}
	pairKey := punchPairKey(session.Source, session.Target)
	if !punchPacketOwnersMatchSession(session, source, ack.GetSourceOwner(), ack.GetTargetOwner()) {
		log.Debugf(
			"ignoring punch ack with mismatched packet owners session_id=%d attempt=%d pair=%s packet_source=%s source_owner=%d target_owner=%d",
			session.SessionID,
			session.Attempt,
			pairKey,
			request.SrcIP,
			ack.GetSourceOwner(),
			ack.GetTargetOwner(),
		)
		return nil
	}
	if !c.punchSessionOwnerMatches(session) {
		log.Debugf(
			"ignoring stale punch ack due to owner mismatch session_id=%d attempt=%d pair=%s",
			session.SessionID,
			session.Attempt,
			pairKey,
		)
		return nil
	}
	peer := punchPeerIP(session, source)
	if !ack.GetAccepted() {
		log.Infof(
			"PunchAck detail src=%s dst=%s session_id=%d attempt=%d accepted=%v phase=%s reason=%q",
			request.SrcIP,
			formatPunchIP(peer),
			ack.GetSessionId(),
			ack.GetAttempt(),
			ack.GetAccepted(),
			ack.GetPhase().String(),
			ack.GetReason(),
		)
	} else {
		log.Debugf(
			"PunchAck detail src=%s dst=%s session_id=%d attempt=%d accepted=%v phase=%s reason=%q",
			request.SrcIP,
			formatPunchIP(peer),
			ack.GetSessionId(),
			ack.GetAttempt(),
			ack.GetAccepted(),
			ack.GetPhase().String(),
			ack.GetReason(),
		)
	}
	session.Ack[source] = ack.GetAccepted()
	if !ack.GetAccepted() {
		session.State = PunchSessionFailed
		session.LastReason = ack.GetReason()
		session.RelayFallback = true
		if c.isLatestPunchSessionForPair(session) {
			c.nc.PunchPairCooldown.Delete(pairKey)
			c.updatePunchRetryState(pairKey, session.State)
		} else {
			log.Debugf("ignoring stale punch ack pair update for session_id=%d attempt=%d pair=%s", session.SessionID, session.Attempt, pairKey)
		}
	} else if len(session.Ack) >= 2 {
		session.State = PunchSessionWaiting
	} else {
		session.State = punchSessionStateFromPhase(ack.GetPhase())
		if session.State == PunchSessionScheduled {
			session.State = PunchSessionSending
		}
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
	if session.Ack == nil {
		session.Ack = make(map[uint32]bool)
	}
	if session.Results == nil {
		session.Results = make(map[uint32]*pb.PunchResult)
	}
	if !punchPacketOwnersMatchSession(session, source, result.GetSourceOwner(), result.GetTargetOwner()) {
		log.Debugf(
			"ignoring punch result with mismatched packet owners session_id=%d attempt=%d pair=%s packet_source=%s source_owner=%d target_owner=%d",
			session.SessionID,
			session.Attempt,
			punchPairKey(session.Source, session.Target),
			request.SrcIP,
			result.GetSourceOwner(),
			result.GetTargetOwner(),
		)
		return nil
	}
	if !c.punchSessionOwnerMatches(session) {
		log.Debugf(
			"ignoring stale punch result due to owner mismatch session_id=%d attempt=%d pair=%s",
			session.SessionID,
			session.Attempt,
			punchPairKey(session.Source, session.Target),
		);
		return nil
	}
	peer := punchPeerIP(session, source)
	if result.GetCode() == pb.PunchResultCode_PunchResultSuccess {
		log.Debugf(
			"PunchResult detail src=%s dst=%s session_id=%d attempt=%d phase=%s code=%s reason=%q selected_endpoint=%s",
			request.SrcIP,
			formatPunchIP(peer),
			result.GetSessionId(),
			result.GetAttempt(),
			result.GetPhase().String(),
			result.GetCode().String(),
			result.GetReason(),
			formatPunchEndpoint(result.GetSelectedEndpoint()),
		)
	} else {
		log.Infof(
			"PunchResult detail src=%s dst=%s session_id=%d attempt=%d phase=%s code=%s reason=%q selected_endpoint=%s",
			request.SrcIP,
			formatPunchIP(peer),
			result.GetSessionId(),
			result.GetAttempt(),
			result.GetPhase().String(),
			result.GetCode().String(),
			result.GetReason(),
			formatPunchEndpoint(result.GetSelectedEndpoint()),
		)
	}
	session.Results[source] = &result
	session.LastReason = result.GetReason()
	if len(session.Results) < 2 {
		session.State = PunchSessionWaiting
		c.nc.PunchSessions.Set(key, session)
		return nil
	}
	pairKey := punchPairKey(session.Source, session.Target)
	success := true
	timeout := false
	lastReason := session.LastReason
	for _, item := range session.Results {
		if item == nil {
			success = false
			continue
		}
		if item.GetReason() != "" {
			lastReason = item.GetReason()
		}
		switch item.GetCode() {
		case pb.PunchResultCode_PunchResultSuccess:
		case pb.PunchResultCode_PunchResultTimeout, pb.PunchResultCode_PunchResultNoResponse:
			success = false
			timeout = true
		default:
			success = false
		}
	}
	session.LastReason = lastReason
	if success {
		session.State = PunchSessionSuccess
		session.RelayFallback = false
	} else if timeout {
		session.State = PunchSessionTimeout
		session.RelayFallback = true
	} else {
		session.State = PunchSessionFailed
		session.RelayFallback = true
	}
	if c.isLatestPunchSessionForPair(session) {
		// Only delete the cooldown for failures/timeouts so rapid re-punch is prevented.
		// On success, let the 20s TTL expire naturally; the successful P2P route is now
		// in place and we don't want a follow-up status event to trigger a fresh punch
		// that would tear it down via clear_direct_paths.
		if !success {
			c.nc.PunchPairCooldown.Delete(pairKey)
		}
		c.updatePunchRetryState(pairKey, session.State)
	} else {
		log.Debugf("ignoring stale punch result pair update for session_id=%d attempt=%d pair=%s", session.SessionID, session.Attempt, pairKey)
	}
	c.nc.PunchSessions.Set(key, session)
	return nil
}

func (c *Controller) ReconcilePunchSessions(nowUnixMs int64) {
	c.nc.PunchSessions.mutex.Lock()
	defer c.nc.PunchSessions.mutex.Unlock()
	for key, session := range c.nc.PunchSessions.data {
		if session == nil {
			continue
		}
		if (session.State == PunchSessionScheduled || session.State == PunchSessionSending || session.State == PunchSessionWaiting) &&
			session.DeadlineUnixMs > 0 && nowUnixMs > session.DeadlineUnixMs {
			session.State = PunchSessionTimeout
			if session.LastReason == "" {
				session.LastReason = "deadline exceeded"
			}
			session.RelayFallback = true
			c.nc.PunchSessions.data[key] = session
			pairKey := punchPairKey(session.Source, session.Target)
			if !c.punchSessionOwnerMatches(session) {
				log.Debugf("ignoring stale punch timeout due to owner mismatch session_id=%d attempt=%d pair=%s", session.SessionID, session.Attempt, pairKey)
				continue
			}
			if hasNewerPunchSessionForPairLocked(c.nc.PunchSessions.data, session) {
				log.Debugf("ignoring stale punch timeout pair update for session_id=%d attempt=%d pair=%s", session.SessionID, session.Attempt, pairKey)
				continue
			}
			// Unblock future punches by releasing the cooldown. The retry-state increment
			// (attempt counter / backoff) is managed by HandlePunchResultPacket when both
			// clients' results arrive, which avoids double-counting here.
			c.nc.PunchPairCooldown.Delete(pairKey)
			if len(session.Results) < 2 {
				// Fallback: no client results arrived yet (e.g. client crashed mid-punch).
				// Update retry state so the next attempt uses the correct backoff.
				c.updatePunchRetryState(pairKey, session.State)
			}
		}
	}
}

func (c *Controller) HandleControlPacket(request *protocol.Packet, remoteAddr net.Addr) (*protocol.Packet, error) {
	switch protocol.ControlProtocol(request.AppProto) {
	case protocol.ControlPing:
		pingTime, _, err := protocol.ParsePingPayload(request.Payload)
		if err != nil {
			return nil, err
		}
		epoch := c.nc.TouchClientByIP(request.SrcIP)
		if epoch == 0 {
			return c.buildDisconnectPacket(request), nil
		}
		payload := protocol.BuildPingPayload(pingTime, epoch)
		return &protocol.Packet{
			Ver:       protocol.V3,
			Proto:     protocol.ProtocolControl,
			AppProto:  protocol.AppProtocol(protocol.ControlPong),
			SourceTTL: protocol.MAX_TTL,
			TTL:       protocol.MAX_TTL,
			SrcIP:     request.DstIP,
			DstIP:     request.SrcIP,
			Payload:   payload,
		}, nil
	case protocol.ControlAddrRequest:
		payload, err := protocol.BuildAddrPayloadByAddr(remoteAddr)
		if err != nil {
			return nil, err
		}
		return &protocol.Packet{
			Ver:       protocol.V3,
			Proto:     protocol.ProtocolControl,
			AppProto:  protocol.AppProtocol(protocol.ControlAddrResponse),
			SourceTTL: protocol.MAX_TTL,
			TTL:       protocol.MAX_TTL,
			SrcIP:     request.DstIP,
			DstIP:     request.SrcIP,
			Payload:   payload,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported control protocol: %d", request.AppProto)
	}
}

func punchSessionKey(sessionID uint64, attempt uint32) string {
	return fmt.Sprintf("%d:%d", sessionID, attempt)
}

func (c *Controller) isLatestPunchSessionForPair(session *PunchSession) bool {
	c.nc.PunchSessions.mutex.RLock()
	defer c.nc.PunchSessions.mutex.RUnlock()
	return !hasNewerPunchSessionForPairLocked(c.nc.PunchSessions.data, session)
}

func (c *Controller) supersedeOlderPunchSessions(session *PunchSession) {
	if session == nil {
		return
	}
	pairKey := punchPairKey(session.Source, session.Target)
	c.nc.PunchSessions.mutex.Lock()
	defer c.nc.PunchSessions.mutex.Unlock()
	for key, existing := range c.nc.PunchSessions.data {
		if existing == nil || punchPairKey(existing.Source, existing.Target) != pairKey {
			continue
		}
		if existing.SessionID == session.SessionID && existing.Attempt == session.Attempt {
			continue
		}
		if existing.State == PunchSessionSuccess ||
			existing.State == PunchSessionFailed ||
			existing.State == PunchSessionTimeout {
			continue
		}
		existing.State = PunchSessionFailed
		existing.LastReason = "superseded by new attempt"
		existing.RelayFallback = true
		c.nc.PunchSessions.data[key] = existing
	}
}

func (c *Controller) punchSessionOwnerMatches(session *PunchSession) bool {
	if session == nil {
		return false
	}
	if session.SourceOwner == 0 && session.TargetOwner == 0 {
		return true
	}
	sourceClient, ok := c.nc.FindClientByVirtualIP(session.Source)
	if !ok || sourceClient.RegistrationEpoch != session.SourceOwner {
		return false
	}
	targetClient, ok := c.nc.FindClientByVirtualIP(session.Target)
	if !ok || targetClient.RegistrationEpoch != session.TargetOwner {
		return false
	}
	return true
}

func punchPacketOwnersMatchSession(session *PunchSession, source uint32, sourceOwner uint64, targetOwner uint64) bool {
	if session == nil {
		return false
	}
	if sourceOwner == 0 && targetOwner == 0 {
		return true
	}
	expectedSourceOwner, expectedTargetOwner, ok := punchSessionOwnersForSource(session, source)
	if !ok {
		return false
	}
	return sourceOwner == expectedSourceOwner && targetOwner == expectedTargetOwner
}

func punchSessionOwnersForSource(session *PunchSession, source uint32) (uint64, uint64, bool) {
	if session == nil {
		return 0, 0, false
	}
	switch source {
	case session.Source:
		return session.SourceOwner, session.TargetOwner, true
	case session.Target:
		return session.TargetOwner, session.SourceOwner, true
	default:
		return 0, 0, false
	}
}

func hasNewerPunchSessionForPairLocked(data map[string]*PunchSession, session *PunchSession) bool {
	if session == nil {
		return false
	}
	pairKey := punchPairKey(session.Source, session.Target)
	for _, candidate := range data {
		if candidate == nil || punchPairKey(candidate.Source, candidate.Target) != pairKey {
			continue
		}
		if candidate.SessionID == session.SessionID && candidate.Attempt == session.Attempt {
			continue
		}
		// Terminal sessions (from a prior punch series that succeeded/failed/timed out)
		// must not be treated as newer; after a reconnection the new series resets to
		// attempt=1 and a stale attempt=N terminal session would incorrectly supersede it.
		if candidate.State == PunchSessionSuccess ||
			candidate.State == PunchSessionFailed ||
			candidate.State == PunchSessionTimeout {
			continue
		}
		if candidate.Attempt > session.Attempt {
			return true
		}
		if candidate.Attempt == session.Attempt {
			if candidate.RequestedAt > session.RequestedAt {
				return true
			}
			if candidate.RequestedAt == session.RequestedAt && candidate.SessionID > session.SessionID {
				return true
			}
		}
	}
	return false
}

func punchPairKey(a, b uint32) string {
	if a < b {
		return fmt.Sprintf("%d-%d", a, b)
	}
	return fmt.Sprintf("%d-%d", b, a)
}

func retryBackoffDuration(attempt uint32) time.Duration {
	if attempt == 0 {
		return 0
	}
	shift := attempt
	if shift > 5 {
		shift = 5
	}
	d := time.Duration(1<<shift) * time.Second
	if d > 30*time.Second {
		return 30 * time.Second
	}
	return d
}

func punchSessionStateFromPhase(phase pb.PunchSessionPhase) PunchSessionState {
	switch phase {
	case pb.PunchSessionPhase_PunchPhaseScheduled, pb.PunchSessionPhase_PunchPhaseUnknown:
		return PunchSessionScheduled
	case pb.PunchSessionPhase_PunchPhaseSending:
		return PunchSessionSending
	case pb.PunchSessionPhase_PunchPhaseWaiting:
		return PunchSessionWaiting
	case pb.PunchSessionPhase_PunchPhaseSuccess:
		return PunchSessionSuccess
	case pb.PunchSessionPhase_PunchPhaseTimeout:
		return PunchSessionTimeout
	case pb.PunchSessionPhase_PunchPhaseFailed:
		return PunchSessionFailed
	default:
		return PunchSessionFailed
	}
}

func (c *Controller) updatePunchRetryState(pairKey string, status PunchSessionState) {
	switch status {
	case PunchSessionSuccess:
		c.nc.PunchPairRetry.Delete(pairKey)
	case PunchSessionFailed, PunchSessionTimeout:
		state, _ := c.nc.PunchPairRetry.Get(pairKey)
		state.Attempt++
		state.NextAllowedUnixMs = time.Now().Add(retryBackoffDuration(state.Attempt)).UnixMilli()
		c.nc.PunchPairRetry.Set(pairKey, state)
	}
}

func buildPunchEndpoints(client ClientInfo) []*pb.PunchEndpoint {
	status := client.ClientStatus
	if status == nil {
		return nil
	}
	endpoints := make([]*pb.PunchEndpoint, 0, len(status.PublicUDPEndpoints)+len(status.LocalUDPPorts))
	seen := make(map[string]struct{})
	appendEndpoint := func(ip net.IP, port uint16) {
		if port == 0 {
			return
		}
		if ip == nil {
			return
		}
		var endpoint *pb.PunchEndpoint
		if ipv4 := ip.To4(); ipv4 != nil {
			endpoint = &pb.PunchEndpoint{
				Ip:   util.IpToUint32(ipv4),
				Port: uint32(port),
				Tcp:  false,
			}
		} else if ipv6 := ip.To16(); len(ipv6) == net.IPv6len {
			endpoint = &pb.PunchEndpoint{
				Ipv6: append([]byte(nil), ipv6...),
				Port: uint32(port),
				Tcp:  false,
			}
		} else {
			return
		}
		key := ip.String() + ":" + strconv.Itoa(int(port))
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		endpoints = append(endpoints, endpoint)
	}
	for _, endpoint := range status.PublicUDPEndpoints {
		if endpoint == nil {
			continue
		}
		appendEndpoint(endpoint.IP, uint16(endpoint.Port))
	}
	if udpAddr, ok := client.Address.(*net.UDPAddr); ok && shouldIncludeLocalUDPCandidates(udpAddr.IP) {
		for _, port := range status.LocalUDPPorts {
			appendEndpoint(udpAddr.IP, port)
		}
	}
	return endpoints
}

func punchPeerIP(session *PunchSession, source uint32) uint32 {
	if session == nil {
		return 0
	}
	switch source {
	case session.Source:
		return session.Target
	case session.Target:
		return session.Source
	default:
		return 0
	}
}

func formatPunchIP(ip uint32) string {
	if ip == 0 {
		return "-"
	}
	return util.Uint32ToIP(ip).String()
}

func formatPunchEndpoint(endpoint *pb.PunchEndpoint) string {
	if endpoint == nil {
		return "-"
	}
	protoName := "udp"
	if endpoint.GetTcp() {
		protoName = "tcp"
	}
	if ipv6 := net.IP(endpoint.GetIpv6()); len(ipv6) > 0 {
		return fmt.Sprintf("[%s]:%d/%s", ipv6.String(), endpoint.GetPort(), protoName)
	}
	if endpoint.GetIp() == 0 {
		return fmt.Sprintf("-:%d/%s", endpoint.GetPort(), protoName)
	}
	return fmt.Sprintf("%s:%d/%s", util.Uint32ToIP(endpoint.GetIp()), endpoint.GetPort(), protoName)
}

func shouldIncludeLocalUDPCandidates(ip net.IP) bool {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return false
	}
	return !ipv4.IsGlobalUnicast() || ipv4.IsPrivate()
}

func (c *Controller) setPendingHandshakeCapabilities(remoteAddr net.Addr, capabilities []string) {
	if remoteAddr == nil {
		return
	}
	c.mu.Lock()
	c.handshakeCaps[remoteAddr.String()] = append([]string(nil), capabilities...)
	c.mu.Unlock()
}

func (c *Controller) consumeHandshakeCapabilities(remoteAddr net.Addr) []string {
	if remoteAddr == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	key := remoteAddr.String()
	capabilities := append([]string(nil), c.handshakeCaps[key]...)
	delete(c.handshakeCaps, key)
	return capabilities
}

func hasCapability(capabilities []string, capability string) bool {
	for _, item := range capabilities {
		if item == capability {
			return true
		}
	}
	return false
}

type NetworkControl struct {
	//
	VirtualNetwork ExpireMap[string, *NetworkInfo]
	// 用来做地址分配和回收
	IPSessions ExpireMap[IpSessionKey, net.Addr]
	// 打洞会话状态（session_id + attempt）
	PunchSessions ExpireMap[string, *PunchSession]
	// 打洞触发冷却（pair key）
	PunchPairCooldown ExpireMap[string, struct{}]
	// 打洞重试状态（pair key）
	PunchPairRetry ExpireMap[string, PunchRetryState]
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

func parseNetmask(netmask string) (net.IPMask, error) {
	ip := net.ParseIP(netmask)
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("invalid netmask %q", netmask)
	}
	return net.IPMask(ip.To4()), nil
}

func (c *Controller) resolveGroupNetworkConfig(group string) (net.IP, net.IPMask, error) {
	if len(c.cfg.Domains) > 0 {
		domainName, groupName, ok := matchDomainAndGroup(group, c.cfg.Domains)
		if !ok {
			return nil, nil, fmt.Errorf("group %s not configured in domains (expect <group>.<domain>)", group)
		}
		dc := c.cfg.Domains[domainName]
		gc, ok := dc.Groups[groupName]
		if !ok {
			return nil, nil, fmt.Errorf("group %s not configured under domain %s", groupName, domainName)
		}
		mask, err := parseNetmask(gc.Netmask)
		if err != nil {
			return nil, nil, err
		}
		return gc.Gateway, mask, nil
	}
	if len(c.cfg.Groups) > 0 {
		gc, ok := c.cfg.Groups[group]
		if !ok {
			return nil, nil, fmt.Errorf("group %s not configured", group)
		}
		mask, err := parseNetmask(gc.Netmask)
		if err != nil {
			return nil, nil, err
		}
		return gc.Gateway, mask, nil
	}
	if c.cfg.Domain != "" && group != c.cfg.Domain {
		return nil, nil, fmt.Errorf("RegistrationRequest domain %s mismatch config domain %s", group, c.cfg.Domain)
	}
	mask, err := parseNetmask(c.cfg.Netmask)
	if err != nil {
		return nil, nil, err
	}
	return c.cfg.Gateway, mask, nil
}

func (c *Controller) HandleGatewayReportPacket(packet *protocol.Packet) (*protocol.Packet, error) {
	var req pb.GatewayReportRequest
	if err := proto.Unmarshal(packet.Payload, &req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.GetGatewayId()) == "" {
		return nil, fmt.Errorf("gateway_id is required")
	}
	if len(req.GetGatewayChannels()) == 0 {
		return nil, fmt.Errorf("gateway_channels is required")
	}
	if req.GetReportUnixMs() == 0 {
		return nil, fmt.Errorf("report_unix_ms is required")
	}
	primaryEndpoint := primaryGatewayEndpoint(req.GetGatewayChannels())
	if primaryEndpoint == "" {
		return nil, fmt.Errorf("gateway_channels must include at least one valid addr")
	}
	now := time.Now()
	if err := c.authenticateGatewayReport(&req, now); err != nil {
		return c.buildGatewayReportAck(packet, &pb.GatewayReportAck{
			Ok:           false,
			Reason:       err.Error(),
			GatewayId:    req.GetGatewayId(),
			ExpireUnixMs: now.Add(2 * time.Minute).UnixMilli(),
		})
	}
	c.recordGatewaySeen(GatewayNodeInfo{
		GatewayID:      req.GetGatewayId(),
		Endpoint:       primaryEndpoint,
		Capabilities:   append([]string{}, req.GetCapabilities()...),
		Channels:       cloneGatewayChannels(req.GetGatewayChannels()),
		DefaultChannel: normalizeGatewayChannelKind(req.GetDefaultGatewayChannel()),
		UDPKeyID:       strings.TrimSpace(req.GetGatewayUdpKeyId()),
		UDPPublicKey:   append([]byte(nil), req.GetGatewayUdpPublicKey()...),
		UpdatedAt:      now,
	})
	if !c.isGatewayAllowed(req.GetGatewayId(), primaryEndpoint) {
		return c.buildGatewayReportAck(packet, &pb.GatewayReportAck{
			Ok:           false,
			Reason:       "gateway not approved",
			GatewayId:    req.GetGatewayId(),
			ExpireUnixMs: now.Add(2 * time.Minute).UnixMilli(),
		})
	}
	c.RegisterGatewayNodeWithTransport(
		req.GetGatewayId(),
		req.GetCapabilities(),
		req.GetGatewayChannels(),
		req.GetDefaultGatewayChannel(),
		req.GetGatewayUdpKeyId(),
		req.GetGatewayUdpPublicKey(),
	)

	ack := &pb.GatewayReportAck{
		Ok:           true,
		Reason:       "ok",
		GatewayId:    req.GetGatewayId(),
		ExpireUnixMs: now.Add(2 * time.Minute).UnixMilli(),
	}
	return c.buildGatewayReportAck(packet, ack)
}

func (c *Controller) authenticateGatewayReport(req *pb.GatewayReportRequest, now time.Time) error {
	if len(req.GetNonce()) == 0 {
		return fmt.Errorf("nonce is required")
	}
	if len(req.GetSignature()) == 0 {
		return fmt.Errorf("signature is required")
	}
	proofBytes, err := marshalGatewayReportProof(req)
	if err != nil {
		return fmt.Errorf("invalid_gateway_report_proof: %w", err)
	}
	gatewayID := strings.TrimSpace(req.GetGatewayId())
	mac := hmac.New(sha256.New, []byte(c.cfg.GatewayTicketSecret))
	if _, err := mac.Write(proofBytes); err != nil {
		return fmt.Errorf("invalid_gateway_report_proof: %w", err)
	}
	if !hmac.Equal(mac.Sum(nil), req.GetSignature()) {
		return fmt.Errorf("invalid_signature")
	}
	return c.validateGatewayReplayWindow(gatewayID, req.GetReportUnixMs(), req.GetNonce(), now)
}

func marshalGatewayReportProof(req *pb.GatewayReportRequest) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(&pb.GatewayReportProof{
		GatewayId:             req.GetGatewayId(),
		Capabilities:          append([]string{}, req.GetCapabilities()...),
		ReportUnixMs:          req.GetReportUnixMs(),
		Nonce:                 append([]byte(nil), req.GetNonce()...),
		GatewayChannels:       cloneGatewayChannels(req.GetGatewayChannels()),
		DefaultGatewayChannel: req.GetDefaultGatewayChannel(),
		GatewayUdpPublicKey:   append([]byte(nil), req.GetGatewayUdpPublicKey()...),
		GatewayUdpKeyId:       req.GetGatewayUdpKeyId(),
	})
}

func (c *Controller) validateGatewayReplayWindow(gatewayID string, reportUnixMs int64, nonce []byte, now time.Time) error {
	reportTime := time.UnixMilli(reportUnixMs)
	if now.Sub(reportTime) > gatewayReportFreshnessWindow || reportTime.Sub(now) > gatewayReportFreshnessWindow {
		return fmt.Errorf("stale_report_timestamp")
	}
	nonceKey := hex.EncodeToString(nonce)
	expireAt := reportTime.Add(gatewayReportFreshnessWindow).UnixMilli()
	if expireAt < now.UnixMilli() {
		expireAt = now.Add(gatewayReportFreshnessWindow).UnixMilli()
	}
	c.gatewayMu.Lock()
	defer c.gatewayMu.Unlock()
	cache := c.gatewayNonce[gatewayID]
	if cache == nil {
		cache = make(map[string]int64)
		c.gatewayNonce[gatewayID] = cache
	}
	nowUnixMs := now.UnixMilli()
	for key, nonceExpireAt := range cache {
		if nonceExpireAt <= nowUnixMs {
			delete(cache, key)
		}
	}
	if _, ok := cache[nonceKey]; ok {
		return fmt.Errorf("replayed_nonce")
	}
	cache[nonceKey] = expireAt
	return nil
}

func (c *Controller) buildGatewayReportAck(packet *protocol.Packet, ack *pb.GatewayReportAck) (*protocol.Packet, error) {
	payload, err := proto.Marshal(ack)
	if err != nil {
		return nil, err
	}
	return &protocol.Packet{
		Ver:       protocol.V3,
		Proto:     protocol.ProtocolService,
		AppProto:  protocol.AppProtoGatewayReportAck,
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     packet.DstIP,
		DstIP:     packet.SrcIP,
		Payload:   payload,
	}, nil
}

func (c *Controller) ApproveGatewayNode(gatewayID, endpoint string) {
	c.gatewayMu.Lock()
	c.gatewayAllow[gatewayID] = endpoint
	c.persistGatewayApprovalLocked()
	c.gatewayMu.Unlock()
}

func (c *Controller) ApproveGatewayNodeByID(gatewayID string) error {
	c.gatewayMu.Lock()
	defer c.gatewayMu.Unlock()
	gatewayID = strings.TrimSpace(gatewayID)
	if gatewayID == "" {
		return fmt.Errorf("gateway_id is required")
	}
	if gatewayID == strings.TrimSpace(c.cfg.DefaultGatewayID) {
		return nil
	}
	if endpoint, ok := c.gatewayAllow[gatewayID]; ok && strings.TrimSpace(endpoint) != "" {
		return nil
	}
	seen, ok := c.gatewaySeen[gatewayID]
	if !ok || strings.TrimSpace(seen.Endpoint) == "" {
		return fmt.Errorf("gateway %s has no pending report", gatewayID)
	}
	c.gatewayAllow[gatewayID] = seen.Endpoint
	c.persistGatewayApprovalLocked()
	return nil
}

func (c *Controller) ListGateways() []GatewayAdminView {
	c.gatewayMu.RLock()
	defer c.gatewayMu.RUnlock()
	now := time.Now()
	byID := map[string]GatewayAdminView{}
	defaultID := strings.TrimSpace(c.cfg.DefaultGatewayID)
	if defaultID != "" {
		item := GatewayAdminView{
			GatewayID: defaultID,
			Approved:  true,
			Default:   true,
		}
		if endpoint, ok := c.gatewayAllow[defaultID]; ok {
			item.Endpoint = endpoint
		}
		byID[defaultID] = item
	}
	for gatewayID, endpoint := range c.gatewayAllow {
		item := byID[gatewayID]
		item.GatewayID = gatewayID
		item.Endpoint = endpoint
		item.Approved = true
		if gatewayID == defaultID {
			item.Default = true
		}
		byID[gatewayID] = item
	}
	for gatewayID, seen := range c.gatewaySeen {
		item, ok := byID[gatewayID]
		if !ok {
			item = GatewayAdminView{
				GatewayID: gatewayID,
				Endpoint:  seen.Endpoint,
			}
		}
		if strings.TrimSpace(item.Endpoint) == "" {
			item.Endpoint = seen.Endpoint
		}
		item.Reported = true
		item.Alive = now.Sub(seen.UpdatedAt) <= gatewayNodeLease
		item.Capabilities = append([]string{}, seen.Capabilities...)
		item.UpdatedAtUnix = seen.UpdatedAt.Unix()
		byID[gatewayID] = item
	}
	for gatewayID, item := range byID {
		if node, ok := c.gatewayNodes[gatewayID]; ok && (strings.TrimSpace(item.Endpoint) == "" || strings.TrimSpace(node.Endpoint) == strings.TrimSpace(item.Endpoint)) {
			item.Endpoint = node.Endpoint
			item.Reported = true
			item.Alive = now.Sub(node.UpdatedAt) <= gatewayNodeLease
			item.Capabilities = append([]string{}, node.Capabilities...)
			item.UpdatedAtUnix = node.UpdatedAt.Unix()
			byID[gatewayID] = item
		}
	}
	result := make([]GatewayAdminView, 0, len(byID))
	for _, item := range byID {
		result = append(result, item)
	}
	return result
}

func (c *Controller) ListDevices(userID string) []DeviceAdminView {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil
	}
	records := c.um.ListAuthedDevicesByUser(userID)
	if len(records) == 0 {
		return nil
	}
	deviceByGroupDevice := make(map[string]DeviceAdminView, len(records))
	for _, record := range records {
		name := strings.TrimSpace(record.DisplayName)
		if name == "" {
			name = record.DeviceID
		}
		deviceByGroupDevice[record.GroupName+"\x00"+record.DeviceID] = DeviceAdminView{
			UserID:           record.UserID,
			Group:            record.GroupName,
			Name:             name,
			DeviceID:         record.DeviceID,
			AuthedAtUnix:     record.AuthedAt.Unix(),
			AuthExpireAtUnix: record.AuthExpireAt.Unix(),
			AuthExpired:      !record.AuthExpireAt.IsZero() && time.Now().After(record.AuthExpireAt),
			UpdatedAtUnix:    record.AuthedAt.Unix(),
		}
	}

	c.nc.VirtualNetwork.mutex.RLock()
	defer c.nc.VirtualNetwork.mutex.RUnlock()

	for _, network := range c.nc.VirtualNetwork.data {
		for ip, client := range network.Clients {
			key := network.Group + "\x00" + client.DeviceId
			device, ok := deviceByGroupDevice[key]
			if !ok {
				continue
			}
			updatedAt := client.ControlLastSeen
			if client.DataPlaneLastSeen > updatedAt {
				updatedAt = client.DataPlaneLastSeen
			}
			if client.LastJoin > updatedAt {
				updatedAt = client.LastJoin
			}
			if strings.TrimSpace(client.Name) != "" {
				device.Name = client.Name
			}
			device.Group = network.Group
			device.VirtualIP = util.Uint32ToIP(ip).String()
			device.ControlOnline = client.ControlOnline
			device.DataPlaneReachable = client.DataPlaneReachable
			if updatedAt > device.UpdatedAtUnix {
				device.UpdatedAtUnix = updatedAt
			}
			deviceByGroupDevice[key] = device
		}
	}

	devices := make([]DeviceAdminView, 0, len(deviceByGroupDevice))
	for _, device := range deviceByGroupDevice {
		devices = append(devices, device)
	}
	sort.Slice(devices, func(i, j int) bool {
		if devices[i].Group != devices[j].Group {
			return devices[i].Group < devices[j].Group
		}
		if devices[i].UserID != devices[j].UserID {
			return devices[i].UserID < devices[j].UserID
		}
		if devices[i].Name != devices[j].Name {
			return devices[i].Name < devices[j].Name
		}
		if devices[i].VirtualIP != devices[j].VirtualIP {
			return devices[i].VirtualIP < devices[j].VirtualIP
		}
		return devices[i].DeviceID < devices[j].DeviceID
	})
	return devices
}

func (c *Controller) isGatewayAllowed(gatewayID, endpoint string) bool {
	c.gatewayMu.RLock()
	defer c.gatewayMu.RUnlock()
	if strings.TrimSpace(gatewayID) == strings.TrimSpace(c.cfg.DefaultGatewayID) {
		return true
	}
	allowedEndpoint, ok := c.gatewayAllow[gatewayID]
	return ok && strings.TrimSpace(allowedEndpoint) == strings.TrimSpace(endpoint)
}

func (c *Controller) RegisterGatewayNode(gatewayID, endpoint string, capabilities []string, _ string, _ []byte) {
	c.RegisterGatewayNodeWithTransport(
		gatewayID,
		capabilities,
		[]*pb.GatewayChannel{{
			Kind:       pb.GatewayChannelKind_GATEWAY_CHANNEL_QUIC,
			Addr:       "quic://" + strings.TrimSpace(endpoint),
			ServerName: gatewayServerName(endpoint),
		}},
		pb.GatewayChannelKind_GATEWAY_CHANNEL_UNKNOWN,
		"",
		nil,
	)
}

func (c *Controller) RegisterGatewayNodeWithTransport(
	gatewayID string,
	capabilities []string,
	channels []*pb.GatewayChannel,
	defaultChannel pb.GatewayChannelKind,
	udpKeyID string,
	udpPublicKey []byte,
) {
	c.gatewayMu.Lock()
	endpoint := primaryGatewayEndpoint(channels)
	c.gatewayAllow[gatewayID] = endpoint
	normalizedChannels := cloneGatewayChannels(channels)
	if len(normalizedChannels) == 0 && strings.TrimSpace(endpoint) != "" {
		normalizedChannels = []*pb.GatewayChannel{{
			Kind:       pb.GatewayChannelKind_GATEWAY_CHANNEL_QUIC,
			Addr:       "quic://" + strings.TrimSpace(endpoint),
			ServerName: gatewayServerName(endpoint),
		}}
	}
	c.gatewayNodes[gatewayID] = GatewayNodeInfo{
		GatewayID:      gatewayID,
		Endpoint:       endpoint,
		Capabilities:   append([]string{}, capabilities...),
		Channels:       normalizedChannels,
		DefaultChannel: normalizeGatewayChannelKind(defaultChannel),
		UDPKeyID:       strings.TrimSpace(udpKeyID),
		UDPPublicKey:   append([]byte(nil), udpPublicKey...),
		UpdatedAt:      time.Now(),
	}
	delete(c.gatewaySeen, gatewayID)
	c.persistGatewayApprovalLocked()
	c.gatewayMu.Unlock()
}

func (c *Controller) recordGatewaySeen(info GatewayNodeInfo) {
	c.gatewayMu.Lock()
	c.gatewaySeen[info.GatewayID] = info
	c.gatewayMu.Unlock()
}

func (c *Controller) buildGatewayAccessGrant(virtualIP uint32, deviceID string) *pb.GatewayAccessGrant {
	c.gatewayMu.RLock()
	defer c.gatewayMu.RUnlock()
	now := time.Now()
	defaultID := strings.TrimSpace(c.cfg.DefaultGatewayID)
	if defaultID == "" {
		return nil
	}
	var picked *GatewayNodeInfo
	if node, ok := c.gatewayNodes[defaultID]; ok && now.Sub(node.UpdatedAt) <= gatewayNodeLease {
		n := node
		picked = &n
	} else if endpoint, ok := c.gatewayAllow[defaultID]; ok && strings.TrimSpace(endpoint) != "" {
		picked = &GatewayNodeInfo{
			GatewayID: defaultID,
			Endpoint:  endpoint,
		}
	}
	if picked == nil {
		return nil
	}
	expire := time.Now().Add(2 * time.Minute)
	sessionID := uint64(time.Now().UnixNano())
	leaseSecs := uint32(60)
	graceSecs := uint32(30)
	ticket, err := newGatewayTicket(
		c.cfg.GatewayTicketSecret,
		deviceID,
		virtualIP,
		sessionID,
		1,
		[]string{picked.GatewayID},
		"",
		expire.UnixMilli(),
		leaseSecs,
		graceSecs,
	)
	if err != nil {
		log.Warnf("build gateway ticket failed: %v", err)
		return nil
	}
	grantChannels := cloneGatewayChannels(picked.Channels)
	if len(grantChannels) == 0 && strings.TrimSpace(picked.Endpoint) != "" {
		grantChannels = []*pb.GatewayChannel{{
			Kind:       pb.GatewayChannelKind_GATEWAY_CHANNEL_QUIC,
			Addr:       "quic://" + strings.TrimSpace(picked.Endpoint),
			ServerName: gatewayServerName(picked.Endpoint),
		}}
	}
	defaultChannel := normalizeGatewayChannelKind(picked.DefaultChannel)
	if defaultChannel == pb.GatewayChannelKind_GATEWAY_CHANNEL_UNKNOWN {
		if hasGatewayChannelKind(grantChannels, pb.GatewayChannelKind_GATEWAY_CHANNEL_UDP) {
			defaultChannel = pb.GatewayChannelKind_GATEWAY_CHANNEL_UDP
		} else {
			defaultChannel = pb.GatewayChannelKind_GATEWAY_CHANNEL_QUIC
		}
	}
	return &pb.GatewayAccessGrant{
		Ticket:                []byte(ticket),
		TicketExpireUnixMs:    expire.UnixMilli(),
		SessionId:             sessionID,
		PolicyRev:             1,
		GatewayCapabilities:   append([]string{}, picked.Capabilities...),
		LeaseSecs:             leaseSecs,
		GraceSecs:             graceSecs,
		GatewayChannels:       cloneGatewayChannels(grantChannels),
		DefaultGatewayChannel: defaultChannel,
		GatewayUdpPublicKey:   append([]byte(nil), picked.UDPPublicKey...),
		GatewayUdpKeyId:       picked.UDPKeyID,
	}
}

func cloneGatewayChannels(channels []*pb.GatewayChannel) []*pb.GatewayChannel {
	if len(channels) == 0 {
		return nil
	}
	cloned := make([]*pb.GatewayChannel, 0, len(channels))
	for _, channel := range channels {
		if channel == nil {
			continue
		}
		addr := strings.TrimSpace(channel.GetAddr())
		if addr == "" {
			continue
		}
		cloned = append(cloned, &pb.GatewayChannel{
			Kind:       normalizeGatewayChannelKind(channel.GetKind()),
			Addr:       addr,
			ServerName: strings.TrimSpace(channel.GetServerName()),
		})
	}
	return cloned
}

func normalizeGatewayChannelKind(kind pb.GatewayChannelKind) pb.GatewayChannelKind {
	switch kind {
	case pb.GatewayChannelKind_GATEWAY_CHANNEL_UDP, pb.GatewayChannelKind_GATEWAY_CHANNEL_QUIC:
		return kind
	default:
		return pb.GatewayChannelKind_GATEWAY_CHANNEL_UNKNOWN
	}
}

func hasGatewayChannelKind(channels []*pb.GatewayChannel, kind pb.GatewayChannelKind) bool {
	for _, channel := range channels {
		if channel != nil && normalizeGatewayChannelKind(channel.GetKind()) == kind {
			return true
		}
	}
	return false
}

func primaryGatewayEndpoint(channels []*pb.GatewayChannel) string {
	for _, channel := range channels {
		if channel == nil {
			continue
		}
		addr := strings.TrimSpace(channel.GetAddr())
		switch normalizeGatewayChannelKind(channel.GetKind()) {
		case pb.GatewayChannelKind_GATEWAY_CHANNEL_UDP:
			if strings.HasPrefix(addr, "udp://") {
				endpoint := strings.TrimPrefix(addr, "udp://")
				if endpoint != "" {
					return endpoint
				}
			}
		case pb.GatewayChannelKind_GATEWAY_CHANNEL_QUIC:
			if strings.HasPrefix(addr, "quic://") {
				endpoint := strings.TrimPrefix(addr, "quic://")
				if endpoint != "" {
					return endpoint
				}
			}
		}
	}
	return ""
}

func gatewayServerName(endpoint string) string {
	host := endpoint
	if h, _, err := net.SplitHostPort(endpoint); err == nil {
		host = h
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "gateway.middlescale.net"
	}
	return host
}

func newGatewayTicket(
	secret string,
	deviceID string,
	virtualIP uint32,
	sessionID uint64,
	policyRevision uint64,
	gatewayIDs []string,
	gatewayGroupID string,
	expireUnixMs int64,
	leaseCapSecs uint32,
	graceCapSecs uint32,
) ([]byte, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	nowMs := time.Now().UnixMilli()
	claims := &pb.GatewayTicketClaims{
		TicketId:        fmt.Sprintf("%x", buf),
		DeviceId:        deviceID,
		VirtualIp:       virtualIP,
		SessionId:       sessionID,
		PolicyRevision:  policyRevision,
		GatewayIds:      append([]string{}, gatewayIDs...),
		GatewayGroupId:  gatewayGroupID,
		IssuedAtUnixMs:  nowMs,
		NotBeforeUnixMs: nowMs - 5_000,
		ExpireUnixMs:    expireUnixMs,
		LeaseCapSecs:    leaseCapSecs,
		GraceCapSecs:    graceCapSecs,
	}
	claimsBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(claims)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(secret) == "" {
		return nil, fmt.Errorf("gateway ticket secret is required")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	if _, err := mac.Write(claimsBytes); err != nil {
		return nil, err
	}
	ticket := &pb.SignedGatewayTicket{
		Alg:       "hmac-sha256",
		Claims:    claimsBytes,
		Signature: mac.Sum(nil),
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(ticket)
}

func matchDomainAndGroup(token string, domains map[string]config.DomainConfig) (string, string, bool) {
	bestDomain := ""
	for domain := range domains {
		suffix := "." + domain
		if strings.HasSuffix(token, suffix) && len(domain) > len(bestDomain) {
			bestDomain = domain
		}
	}
	if bestDomain == "" {
		return "", "", false
	}
	group := strings.TrimSuffix(token, "."+bestDomain)
	group = strings.TrimSpace(group)
	if group == "" {
		return "", "", false
	}
	return bestDomain, group, true
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
	if len(reg.GetDevicePubKey()) == 0 {
		return fmt.Errorf("device_pub_key is empty")
	}
	return nil
}

func (c *Controller) buildServicePacket(request *protocol.Packet, appProto protocol.AppProtocol, msg proto.Message) (*protocol.Packet, error) {
	payload, err := proto.Marshal(msg)
	if err != nil {
		return nil, err
	}
	return &protocol.Packet{
		Ver:       protocol.V3,
		Proto:     protocol.ProtocolService,
		AppProto:  appProto,
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     request.DstIP,
		DstIP:     request.SrcIP,
		Payload:   payload,
	}, nil
}

func (c *Controller) newDeviceAuthChallenge(userID, groupName, deviceID, ticket string, devicePubKey []byte, reauthRequired bool) (*pb.DeviceAuthChallenge, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	challengeIDBytes := make([]byte, 16)
	if _, err := rand.Read(challengeIDBytes); err != nil {
		return nil, err
	}
	challengeID := fmt.Sprintf("%x", challengeIDBytes)
	challenge := deviceAuthChallengeState{
		UserID:         userID,
		GroupName:      groupName,
		DeviceID:       deviceID,
		Ticket:         ticket,
		DevicePubKey:   append([]byte(nil), devicePubKey...),
		Nonce:          nonce,
		ExpireAt:       time.Now().Add(deviceAuthChallengeTTL),
		ReauthRequired: reauthRequired,
	}
	c.authChallengeMu.Lock()
	defer c.authChallengeMu.Unlock()
	now := time.Now()
	for id, state := range c.authChallenges {
		if now.After(state.ExpireAt) {
			delete(c.authChallenges, id)
		}
	}
	c.authChallenges[challengeID] = challenge
	return &pb.DeviceAuthChallenge{
		ChallengeId:    challengeID,
		Nonce:          append([]byte(nil), nonce...),
		ExpireUnixMs:   challenge.ExpireAt.UnixMilli(),
		ReauthRequired: reauthRequired,
	}, nil
}

func (c *Controller) consumeDeviceAuthChallenge(challengeID string) (deviceAuthChallengeState, bool) {
	c.authChallengeMu.Lock()
	defer c.authChallengeMu.Unlock()
	challenge, ok := c.authChallenges[challengeID]
	if ok {
		delete(c.authChallenges, challengeID)
	}
	return challenge, ok
}

func buildDeviceAuthSignedPayload(challengeID string, nonce []byte, deviceID string, devicePubKey []byte) []byte {
	buf := make([]byte, 0, len(challengeID)+len(nonce)+len(deviceID)+len(devicePubKey)+16)
	appendLenPrefixed(&buf, []byte(challengeID))
	appendLenPrefixed(&buf, nonce)
	appendLenPrefixed(&buf, []byte(deviceID))
	appendLenPrefixed(&buf, devicePubKey)
	return buf
}

func appendLenPrefixed(buf *[]byte, data []byte) {
	var lenBuf [4]byte
	lenBuf[0] = byte(len(data) >> 24)
	lenBuf[1] = byte(len(data) >> 16)
	lenBuf[2] = byte(len(data) >> 8)
	lenBuf[3] = byte(len(data))
	*buf = append(*buf, lenBuf[:]...)
	*buf = append(*buf, data...)
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

func (c *Controller) reservedServiceIPs(group string) map[uint32]string {
	reserved := make(map[uint32]string)
	if ip := strings.TrimSpace(c.resolveDNSServiceIP(group)); ip != "" {
		parsed := net.ParseIP(ip)
		if parsed != nil && parsed.To4() != nil {
			reserved[util.IpToUint32(parsed)] = "dns_service_ip"
		}
	}
	return reserved
}

func (c *Controller) resolveDNSServiceIP(group string) string {
	group = strings.ToLower(strings.TrimSpace(group))
	switch {
	case len(c.cfg.Domains) > 0:
		domainName, groupName, ok := matchDomainAndGroup(group, c.cfg.Domains)
		if !ok {
			return ""
		}
		gc := c.cfg.Domains[domainName].Groups[groupName]
		if strings.TrimSpace(gc.DNSServiceIP) != "" {
			return strings.TrimSpace(gc.DNSServiceIP)
		}
		return strings.TrimSpace(c.cfg.DNSServiceIP)
	case len(c.cfg.Groups) > 0:
		gc, ok := c.cfg.Groups[group]
		if !ok {
			return ""
		}
		if strings.TrimSpace(gc.DNSServiceIP) != "" {
			return strings.TrimSpace(gc.DNSServiceIP)
		}
		return strings.TrimSpace(c.cfg.DNSServiceIP)
	default:
		return strings.TrimSpace(c.cfg.DNSServiceIP)
	}
}

func (c *Controller) clientOwnsVirtualIP(virtualIP uint32, deviceID string) bool {
	c.nc.VirtualNetwork.mutex.RLock()
	defer c.nc.VirtualNetwork.mutex.RUnlock()
	for _, network := range c.nc.VirtualNetwork.data {
		if client, ok := network.Clients[virtualIP]; ok {
			return client.DeviceId == deviceID
		}
	}
	return false
}

func buildDeviceInfoList(clients map[uint32]ClientInfo, selfIP uint32) []*pb.DeviceInfo {
	deviceList := make([]*pb.DeviceInfo, 0, len(clients))
	for ip, info := range clients {
		if ip == selfIP {
			continue
		}
		item := &pb.DeviceInfo{
			Name:              info.Name,
			VirtualIp:         ip,
			DeviceId:          info.DeviceId,
			DevicePubKey:      append([]byte(nil), info.DevicePubKey...),
			OnlineKxPub:       append([]byte(nil), info.OnlineKxPub...),
			RegistrationEpoch: info.RegistrationEpoch,
		}
		if info.ControlOnline {
			item.DeviceStatus = 0
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
	oldIP = network.FindClientIPByDeviceID(deviceID)
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
		if _, reserved := network.ReservedIPs[ip]; reserved {
			continue
		}
		if client, occupied := network.Clients[ip]; occupied {
			if !client.ControlOnline {
				key := NewIpSessionKey(network.Group, util.Uint32ToIP(ip))
				if _, reserved := nc.IPSessions.Get(key); !reserved {
					network.DeleteClient(ip)
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
			network.UpsertClient(ip, client)
			return uint16(network.Epoch)
		}
	}
	return 0
}

func (c *Controller) LeaveByRemoteAddr(remoteAddr net.Addr) {
	c.nc.LeaveByRemoteAddr(remoteAddr)
}

func (nc *NetworkControl) LeaveByRemoteAddr(remoteAddr net.Addr) {
	if remoteAddr == nil {
		return
	}
	addr := remoteAddr.String()
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
			network.UpsertClient(ip, client)
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

func (nc *NetworkControl) FindClientByDeviceID(groupName string, deviceID string) (ClientInfo, bool) {
	nc.VirtualNetwork.mutex.RLock()
	defer nc.VirtualNetwork.mutex.RUnlock()
	network, ok := nc.VirtualNetwork.data[groupName]
	if !ok {
		return ClientInfo{}, false
	}
	virtualIP := network.FindClientIPByDeviceID(deviceID)
	if virtualIP == 0 {
		return ClientInfo{}, false
	}
	client, ok := network.Clients[virtualIP]
	if !ok {
		return ClientInfo{}, false
	}
	return client, true
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
		network.UpsertClient(virtualIP, client)
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

// SetIfAbsent stores value only when the key is missing or expired.
func (e *ExpireMap[K, T]) SetIfAbsent(key K, value T) bool {
	var deadline int64
	if e.ttl > 0 {
		deadline = time.Now().Add(time.Duration(e.ttl)).UnixNano()
	}

	e.mutex.Lock()
	defer e.mutex.Unlock()

	if currentDeadline, hasExp := e.expiration[key]; hasExp && currentDeadline > 0 && time.Now().UnixNano() > currentDeadline {
		delete(e.data, key)
		delete(e.expiration, key)
	}
	if _, exists := e.data[key]; exists {
		return false
	}
	e.data[key] = value
	if deadline == 0 {
		delete(e.expiration, key)
	} else {
		e.expiration[key] = deadline
	}
	return true
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
