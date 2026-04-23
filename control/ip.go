package control

import "net"

type NetworkInfo struct {
	Group               string
	Netmask             net.IPMask
	Gateway             net.IP
	Epoch               uint64
	Clients             map[uint32]ClientInfo
	ClientIPsByDeviceID map[string]uint32
	ReservedIPs         map[uint32]string
}

func NewNetworkInfo(group string, netmask net.IPMask, gateway net.IP, reservedIPs map[uint32]string) *NetworkInfo {
	if reservedIPs == nil {
		reservedIPs = make(map[uint32]string)
	}
	return &NetworkInfo{
		Group:               group,
		Netmask:             netmask,
		Gateway:             gateway,
		Clients:             make(map[uint32]ClientInfo), // key: virtual IP
		ClientIPsByDeviceID: make(map[string]uint32),
		ReservedIPs:         reservedIPs,
	}
}

func (n *NetworkInfo) UpsertClient(ip uint32, client ClientInfo) {
	if existing, ok := n.Clients[ip]; ok && existing.DeviceId != "" && existing.DeviceId != client.DeviceId {
		if mappedIP, ok := n.ClientIPsByDeviceID[existing.DeviceId]; ok && mappedIP == ip {
			delete(n.ClientIPsByDeviceID, existing.DeviceId)
		}
	}
	n.Clients[ip] = client
	if client.DeviceId != "" {
		n.ClientIPsByDeviceID[client.DeviceId] = ip
	}
}

func (n *NetworkInfo) DeleteClient(ip uint32) {
	client, ok := n.Clients[ip]
	if !ok {
		return
	}
	delete(n.Clients, ip)
	if client.DeviceId != "" {
		if mappedIP, ok := n.ClientIPsByDeviceID[client.DeviceId]; ok && mappedIP == ip {
			delete(n.ClientIPsByDeviceID, client.DeviceId)
		}
	}
}

func (n *NetworkInfo) FindClientIPByDeviceID(deviceID string) uint32 {
	if deviceID == "" {
		return 0
	}
	return n.ClientIPsByDeviceID[deviceID]
}

type ClientInfo struct {
	DeviceId           string
	Name               string
	ControlOnline      bool
	ControlLastSeen    int64 // Unix时间戳 (timestamp)
	DataPlaneReachable bool
	DataPlaneLastSeen  int64 // Unix时间戳 (timestamp)
	Version            string
	Capabilities       []string

	VirtualIp uint32 // 虚拟IP，IPv4大端表示
	Address   net.Addr

	DevicePubKey []byte
	OnlineKxPub  []byte

	LastJoin int64 // Unix时间戳 (timestamp)

	ClientStatus *ClientStatusInfo // 只有 DataPlaneReachable 时才有值
}

type ClientStatusInfo struct {
	P2PList            []net.IP
	PublicUDPEndpoints []*net.UDPAddr
	LocalUDPEndpoints  []*net.UDPAddr
	UpStream           uint64
	DownStream         uint64
	IsCone             bool
	PunchTriggerReason string
	UpdateTime         int64 // Unix时间戳 (timestamp)
}
