package protocol

import (
	"errors"
	"fmt"
	"net"
)

/*
	0                                            15                                              31
	0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5  6  7  8  9  0  1

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|e |s |x |u|   版本(4) |      协议(8)          |      app协议(8)        | source_ttl(4) | ttl(4) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                          源ip地址(32)                                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                          目的ip地址(32)                                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                           数据体                                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
注：e为是否加密标志，s为服务端通信包标志，x扩展标志，u未使用
*/
type Packet struct {
	Ver       Version     // 版本，4位
	Proto     Protocol    // 协议，8位
	AppProto  AppProtocol // 应用协议，8位
	SourceTTL uint8       // 初始TTL，4位
	TTL       uint8       // 生存时间，4位
	SrcIP     net.IP      // 源IP地址，IPv4
	DstIP     net.IP      // 目的IP地址，IPv4
	Payload   []byte      // 数据体
	Gateway   bool
}

const (
	PacketHeaderSize = 12 // 没加密的头 12字节
	MAX_TTL          = 0b1111
)

type Version uint8

const (
	V2             Version = 2
	VersionUnknown Version = 255
)

func VersionFromUint8(val uint8) Version {
	switch val {
	case 2:
		return V2
	default:
		return VersionUnknown
	}
}

func (v Version) ToUint8() uint8 {
	return uint8(v)
}

type Protocol uint8

const (
	ProtocolService   Protocol = 1
	ProtocolError     Protocol = 2
	ProtocolControl   Protocol = 3
	ProtocolIpTurn    Protocol = 4
	ProtocolOtherTurn Protocol = 5
	ProtocolUnknown   Protocol = 255
)

func ProtocolFromUint8(val uint8) Protocol {
	switch val {
	case 1:
		return ProtocolService
	case 2:
		return ProtocolError
	case 3:
		return ProtocolControl
	case 4:
		return ProtocolIpTurn
	case 5:
		return ProtocolOtherTurn
	default:
		return ProtocolUnknown
	}
}

func (p Protocol) ToUint8() uint8 {
	return uint8(p)
}

type AppProtocol uint8

const (
	AppProtoRegistrationRequest     AppProtocol = 1
	AppProtoRegistrationResponse    AppProtocol = 2
	AppProtoPullDeviceList          AppProtocol = 3
	AppProtoPushDeviceList          AppProtocol = 4
	AppProtoHandshakeRequest        AppProtocol = 5
	AppProtoHandshakeResponse       AppProtocol = 6
	AppProtoSecretHandshakeRequest  AppProtocol = 7
	AppProtoSecretHandshakeResponse AppProtocol = 8
	AppProtoClientStatusInfo        AppProtocol = 9
	AppProtoPunchRequest            AppProtocol = 10
	AppProtoPunchAck                AppProtocol = 11
	AppProtoPunchStart              AppProtocol = 12
	AppProtoPunchResult             AppProtocol = 13
	AppProtoUnknown                 AppProtocol = 255
)

func AppProtocolFromUint8(val uint8) AppProtocol {
	switch val {
	case 1:
		return AppProtoRegistrationRequest
	case 2:
		return AppProtoRegistrationResponse
	case 3:
		return AppProtoPullDeviceList
	case 4:
		return AppProtoPushDeviceList
	case 5:
		return AppProtoHandshakeRequest
	case 6:
		return AppProtoHandshakeResponse
	case 7:
		return AppProtoSecretHandshakeRequest
	case 8:
		return AppProtoSecretHandshakeResponse
	case 9:
		return AppProtoClientStatusInfo
	case 10:
		return AppProtoPunchRequest
	case 11:
		return AppProtoPunchAck
	case 12:
		return AppProtoPunchStart
	case 13:
		return AppProtoPunchResult
	default:
		return AppProtoUnknown
	}
}

func (p AppProtocol) ToUint8() uint8 {
	return uint8(p)
}

var ErrInvalidPacket = errors.New("invalid packet")

func NewPacket(ver, proto, appProto, sourceTTL, ttl uint8, srcIP, dstIP net.IP, payload []byte) *Packet {
	return &Packet{
		Ver:       VersionFromUint8(ver),
		Proto:     ProtocolFromUint8(proto),
		AppProto:  AppProtocolFromUint8(appProto),
		SourceTTL: sourceTTL,
		TTL:       ttl,
		SrcIP:     srcIP.To4(),
		DstIP:     dstIP.To4(),
		Payload:   payload,
	}
}

func (p *Packet) Marshal() []byte {
	buf := make([]byte, PacketHeaderSize+len(p.Payload))
	buf[0] = (V2.ToUint8() & 0x0F) // 版本占4位
	buf[1] = p.Proto.ToUint8()
	buf[2] = p.AppProto.ToUint8()
	buf[3] = ((p.SourceTTL & 0x0F) << 4) | (p.TTL & 0x0F) // SourceTTL和TTL各占4位

	// 源IP地址
	copy(buf[4:8], p.SrcIP.To4())
	// 目的IP地址
	copy(buf[8:12], p.DstIP.To4())

	// 数据体
	copy(buf[PacketHeaderSize:], p.Payload)

	if p.Gateway {
		buf[0] |= 0x40 // 0b0100
	} else {
		buf[0] &= 0xBF // 0b1011
	}

	return buf
}

func Unmarshal(data []byte) (*Packet, error) {
	if len(data) < PacketHeaderSize {
		return nil, ErrInvalidPacket
	}

	p := &Packet{}
	p.Ver = VersionFromUint8(data[0] & 0x0F)
	p.Gateway = (data[0] & 0x40) != 0
	p.Proto = ProtocolFromUint8(data[1])
	p.AppProto = AppProtocolFromUint8(data[2])
	p.SourceTTL = (data[3] >> 4) & 0x0F
	p.TTL = data[3] & 0x0F
	p.SrcIP = net.IPv4(data[4], data[5], data[6], data[7])
	p.DstIP = net.IPv4(data[8], data[9], data[10], data[11])

	p.Payload = make([]byte, len(data)-PacketHeaderSize)
	copy(p.Payload, data[PacketHeaderSize:])

	return p, nil
}

func (p *Packet) DebugString() string {
	return "Packet{" +
		"Ver=" + fmt.Sprintf("%d", p.Ver) + ", " +
		"Proto=" + fmt.Sprintf("%d", p.Proto) + ", " +
		"AppProto=" + fmt.Sprintf("%d", p.AppProto) + ", " +
		"SourceTTL=" + fmt.Sprintf("%d", p.SourceTTL) + ", " +
		"TTL=" + fmt.Sprintf("%d", p.TTL) + ", " +
		"SrcIP=" + p.SrcIP.String() + ", " +
		"DstIP=" + p.DstIP.String() + ", " +
		"PayloadLen=" + fmt.Sprintf("%d", len(p.Payload)) +
		", Gateway=" + fmt.Sprintf("%t", p.Gateway) +
		"}"
}

func (p *Packet) SetGatewayFlag(isGateway bool) {
	p.Gateway = isGateway
}
