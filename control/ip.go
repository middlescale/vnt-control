package control

import "net"

type NetworkInfo struct {
	Group       string
	Netmask     net.IPMask
	Gateway     net.IP
	Epoch       uint64
	Clients     map[uint32]ClientInfo
	ReservedIPs map[uint32]string
}

func NewNetworkInfo(group string, netmask net.IPMask, gateway net.IP, reservedIPs map[uint32]string) *NetworkInfo {
	if reservedIPs == nil {
		reservedIPs = make(map[uint32]string)
	}
	return &NetworkInfo{
		Group:       group,
		Netmask:     netmask,
		Gateway:     gateway,
		Clients:     make(map[uint32]ClientInfo), // key: virtual IP
		ReservedIPs: reservedIPs,
	}
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
	Wireguard    bool

	LastJoin int64 // Unix时间戳 (timestamp)

	ClientStatus *ClientStatusInfo // 只有 DataPlaneReachable 时才有值
}

type ClientStatusInfo struct {
	P2PList        []net.IP
	PublicIPList   []net.IP
	PublicUDPPorts []uint16
	LocalUDPPorts  []uint16
	UpStream       uint64
	DownStream     uint64
	IsCone         bool
	UpdateTime     int64 // Unix时间戳 (timestamp)
}
