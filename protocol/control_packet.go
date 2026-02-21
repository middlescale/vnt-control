package protocol

import (
	"encoding/binary"
	"fmt"
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
