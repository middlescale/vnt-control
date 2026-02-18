package util

import (
	"encoding/binary"
	"net"
)

func IpToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip4)
}

func Uint32ToIP(v uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, v)
	return ip
}

func MaskToUint32(mask net.IPMask) uint32 {
	if len(mask) >= 4 {
		// take last 4 bytes for IPv4 masks (also works if mask is 4 bytes)
		return binary.BigEndian.Uint32(mask[len(mask)-4:])
	}
	return 0
}
