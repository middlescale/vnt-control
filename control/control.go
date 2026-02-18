package control

import (
	"errors"
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

type Control struct {
	nc  NetworkControl
	cfg *config.Config
}

func NewControl(cfg *config.Config) *Control {
	return &Control{
		nc: NetworkControl{
			VirtualNetwork: *NewExpireMap[string, *NetworkInfo](7 * 24 * time.Hour),
			IpSession:      *NewExpireMap[IpSessionKey, net.Addr](24 * time.Hour),
		},
		cfg: cfg,
	}
}

func (c *Control) Stop() {
	c.nc.VirtualNetwork.Stop()
	c.nc.IpSession.Stop()
}

func (c *Control) HandleHandshakePacket(reqPacket *protocol.Packet) (*protocol.Packet, error) {
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
		SrcIP:     net.IP(c.cfg.Gateway),
		DstIP:     reqPacket.SrcIP,
		Gateway:   true,
		Payload:   playload,
	}

	// 目前不处理 handshake的加密算法

	return rspPacket, nil
}

func (c *Control) HandleRegistrationPacket(request *protocol.Packet, remoteAddr net.Addr) (*protocol.Packet, error) {
	log.Debugf("收到客户端 RegistrationRequest Packet: %s", request.DebugString())
	var registration pb.RegistrationRequest
	if err := proto.Unmarshal(request.Payload, &registration); err != nil {
		log.Errorf("RegistrationRequest unmarshal error: %v", err)
		return nil, err
	}

	if registration.GetToken() == "" {
		log.Errorf("RegistrationRequest missing token(domain name), ignoring: %+v", request)
		return nil, errors.New("RegistrationRequest missing token(domain name)")
	}
	if registration.GetDeviceId() == "" || registration.GetName() == "" {
		log.Errorf("RegistrationRequest missing device_id or name, ignoring: %+v", request)
		return nil, errors.New("RegistrationRequest missing device_id or name")
	}

	domain := registration.GetToken()
	if domain != c.cfg.Domain {
		return nil, fmt.Errorf("RegistrationRequest domain %s mismatch config domain %s", domain, c.cfg.Domain)
	}

	// 解析 remote address，区分 IPv4/IPv6 并提取 port（确保两者不会同时存在）
	raddrStr := remoteAddr.String()
	host, portStr, err := net.SplitHostPort(raddrStr)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse remote address: %v", err)
	}

	// handling virtual network assignment
	_, netInfoExist := c.nc.VirtualNetwork.Get(domain)
	if !netInfoExist {
		newNetInfo := NewNetworkInfo(domain, net.IPMask(c.cfg.Netmask), net.IP(c.cfg.Gateway))
		c.nc.VirtualNetwork.Set(domain, newNetInfo)
	}
	if registration.GetVirtualIp() != 0 {
		virtualIP := util.Uint32ToIP(registration.GetVirtualIp())
		if c.cfg.Gateway.Equal(virtualIP) {
			return nil, fmt.Errorf("Client requested virtual IP is gateway IP, ignoring assignment")
		}
	}

	port, _ := strconv.Atoi(portStr)
	pubPort := uint32(port)

	registrationResp := &pb.RegistrationResponse{
		PublicPort: pubPort,
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			registrationResp.PublicIp = uint32(ip4[3]) | uint32(ip4[2])<<8 | uint32(ip4[1])<<16 | uint32(ip4[0])<<24
		} else {
			registrationResp.PublicIpv6 = []byte(ip.String())
		}
	}
	registrationResp.VirtualGateway = util.IpToUint32(c.cfg.Gateway)
	registrationResp.VirtualNetmask = util.IpToUint32(net.IP(c.cfg.Netmask))

	ip := c.nc.generateIP(domain, c.cfg.Gateway, net.IPMask(c.cfg.Netmask))
	if ip == nil {
		return nil, fmt.Errorf("No available virtual IPs")
	}
	registrationResp.VirtualIp = util.IpToUint32(ip)

	respBytes, err := proto.Marshal(registrationResp)
	if err != nil {
		return nil, fmt.Errorf("RegistrationResponse marshal error: %v", err)
	}

	respPacket := &protocol.Packet{
		Ver:      protocol.V2,
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoRegistrationResponse,
		Payload:  respBytes,
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
