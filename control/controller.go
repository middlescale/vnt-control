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

func NewController(cfg *config.Config) *Controller {
	return &Controller{
		nc: NetworkControl{
			VirtualNetwork: *NewExpireMap[string, *NetworkInfo](7 * 24 * time.Hour),
			IpSession:      *NewExpireMap[IpSessionKey, net.Addr](24 * time.Hour),
		},
		cfg: cfg,
	}
}

func (c *Controller) Stop() {
	c.nc.VirtualNetwork.Stop()
	c.nc.IpSession.Stop()
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
		Version: "goversion-1.0.0",
		Secret:  false,
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
	log.Debugf("收到客户端 RegistrationRequest Packet: %s", request.DebugString())
	var registration pb.RegistrationRequest
	if err := proto.Unmarshal(request.Payload, &registration); err != nil {
		log.Errorf("RegistrationRequest unmarshal error: %v", err)
		return nil, err
	}
	if err := validateRegistrationRequest(&registration); err != nil {
		log.Errorf("RegistrationRequest validate error: %v", err)
		return nil, err
	}

	domain := registration.GetToken()
	if c.cfg.Domain != "" && domain != c.cfg.Domain {
		return nil, fmt.Errorf("RegistrationRequest domain %s mismatch config domain %s", domain, c.cfg.Domain)
	}

	raddrStr := remoteAddr.String()
	host, portStr, err := net.SplitHostPort(raddrStr)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse remote address: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid remote port: %q", portStr)
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
		return nil, err
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
	oldIP := findClientIPByDeviceID(netInfo.Clients, registration.GetDeviceId())
	requestedIP := registration.GetVirtualIp()
	if requestedIP != 0 {
		if err := validateRequestedIP(requestedIP, c.cfg.Gateway, netmask); err != nil {
			return nil, err
		}
		if current, ok := netInfo.Clients[requestedIP]; ok && current.DeviceId != registration.GetDeviceId() {
			if !registration.GetAllowIpChange() {
				return nil, fmt.Errorf("virtual ip %s already in use", util.Uint32ToIP(requestedIP))
			}
			requestedIP = 0
		}
	}
	virtualIP := requestedIP
	if virtualIP == 0 {
		if oldIP != 0 {
			virtualIP = oldIP
		} else {
			ip := c.nc.generateIP(domain, c.cfg.Gateway, netmask)
			if ip == nil {
				return nil, fmt.Errorf("no available virtual ips")
			}
			virtualIP = util.IpToUint32(ip)
		}
	}
	if oldIP != 0 && oldIP != virtualIP {
		delete(netInfo.Clients, oldIP)
		c.nc.IpSession.Delete(NewIpSessionKey(domain, util.Uint32ToIP(oldIP)))
	}
	clientInfo := netInfo.Clients[virtualIP]
	now := time.Now().Unix()
	clientInfo.DeviceId = registration.GetDeviceId()
	clientInfo.Name = registration.GetName()
	clientInfo.Version = registration.GetVersion()
	clientInfo.Online = true
	clientInfo.VirtualIp = virtualIP
	clientInfo.Address = remoteAddr
	clientInfo.ClientSecret = registration.GetClientSecret()
	clientInfo.ClientSecretHash = append(clientInfo.ClientSecretHash[:0], registration.GetClientSecretHash()...)
	clientInfo.Wireguard = false
	clientInfo.LastJoin = now
	clientInfo.LastSeen = now
	netInfo.Clients[virtualIP] = clientInfo
	c.nc.IpSession.Set(NewIpSessionKey(domain, util.Uint32ToIP(virtualIP)), remoteAddr)
	netInfo.Epoch++
	registrationResp.VirtualIp = virtualIP
	registrationResp.Epoch = uint32(netInfo.Epoch)
	registrationResp.DeviceInfoList = buildDeviceInfoList(netInfo.Clients, virtualIP)

	respBytes, err := proto.Marshal(registrationResp)
	if err != nil {
		return nil, fmt.Errorf("RegistrationResponse marshal error: %v", err)
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

	return respPacket, nil
}

type NetworkControl struct {
	//
	VirtualNetwork ExpireMap[string, *NetworkInfo]
	// 用来做地址分配和回收
	IpSession ExpireMap[IpSessionKey, net.Addr]
}

// IpSessionKey is a comparable key for IpSession.
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
		if info.Online {
			item.DeviceStatus = 0
			item.ClientSecretHash = append(item.ClientSecretHash, info.ClientSecretHash...)
		} else {
			item.DeviceStatus = 1
		}
		deviceList = append(deviceList, item)
	}
	return deviceList
}

func (nc *NetworkControl) generateIP(domain string, gateway net.IP, netmask net.IPMask) net.IP {
	networkIP := util.IpToUint32(gateway) & util.MaskToUint32(netmask)
	mask := util.MaskToUint32(netmask)
	broadcast := networkIP | ^mask
	gatewayIP := util.IpToUint32(gateway)

	// first and last usable (exclude network and broadcast)
	first := networkIP + 1
	last := broadcast - 1
	if first > last {
		return nil
	}

	for ip := first; ip <= last; ip++ {
		if ip == gatewayIP {
			continue
		}
		candidate := util.Uint32ToIP(ip)
		key := NewIpSessionKey(domain, candidate)
		if _, occupied := nc.IpSession.Get(key); !occupied {
			addr := &net.IPAddr{IP: candidate}
			nc.IpSession.Set(key, addr)
			return candidate
		}
	}
	return nil
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
