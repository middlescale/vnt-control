package protocol

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
)

type ControlProtocol uint8

const (
	ControlPing          ControlProtocol = 1
	ControlPong          ControlProtocol = 2
	ControlPunchRequest  ControlProtocol = 3
	ControlPunchResponse ControlProtocol = 4
	ControlAddrRequest   ControlProtocol = 5
	ControlAddrResponse  ControlProtocol = 6
)

func ParsePingPayload(payload []byte) (time uint16, epoch uint16, err error) {
	if len(payload) < 4 {
		return 0, 0, fmt.Errorf("invalid ping payload length: %d", len(payload))
	}
	return binary.BigEndian.Uint16(payload[:2]), binary.BigEndian.Uint16(payload[2:4]), nil
}

func BuildPingPayload(time uint16, epoch uint16) []byte {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint16(payload[:2], time)
	binary.BigEndian.PutUint16(payload[2:4], epoch)
	return payload
}

func ParseAddrPayload(payload []byte) (net.IP, uint16, error) {
	if len(payload) < 6 {
		return nil, 0, fmt.Errorf("invalid addr payload length: %d", len(payload))
	}
	ip := net.IPv4(payload[0], payload[1], payload[2], payload[3]).To4()
	port := binary.BigEndian.Uint16(payload[4:6])
	return ip, port, nil
}

func BuildAddrPayloadByAddr(remoteAddr net.Addr) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse remote addr: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid remote port: %q", portStr)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("invalid remote host: %q", host)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		ip4 = net.IPv4zero
	}
	payload := make([]byte, 6)
	copy(payload[:4], ip4)
	binary.BigEndian.PutUint16(payload[4:6], uint16(port))
	return payload, nil
}
