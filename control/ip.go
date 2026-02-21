package control

import "net"

type NetworkInfo struct {
	Group   string
	Netmask net.IPMask
	Gateway net.IP
	Epoch   uint64
	Clients map[uint32]ClientInfo
}

func NewNetworkInfo(group string, netmask net.IPMask, gateway net.IP) *NetworkInfo {
	return &NetworkInfo{
		Group:   group,
		Netmask: netmask,
		Gateway: gateway,
		Clients: make(map[uint32]ClientInfo), // key: virtual IP
	}
}

type ClientInfo struct {
	DeviceId string
	Name     string
	Online   bool
	Version  string

	VirtualIp uint32 // 虚拟IP，IPv4大端表示
	Address   net.Addr

	ClientSecret     bool
	ClientSecretHash []byte
	Wireguard        bool

	LastJoin int64 // Unix时间戳 (timestamp)
	LastSeen int64 // Unix时间戳 (timestamp)

	ClientStatus *ClientStatusInfo // 只有 Online 时才有值
}

type ClientStatusInfo struct {
	P2PList    []net.IP
	UpStream   uint64
	DownStream uint64
	IsCone     bool
	UpdateTime int64 // Unix时间戳 (timestamp)
}
