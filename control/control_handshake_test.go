package control

import (
	"net"
	"testing"
	"vnt-control/config"
	"vnt-control/protocol"
	"vnt-control/protocol/pb"

	"google.golang.org/protobuf/proto"
)

func TestHandleHandshakePacketSuccess(t *testing.T) {
	cfg := &config.Config{
		Gateway: net.ParseIP("10.26.0.1"),
		Domain:  "ms.net",
		Netmask: "255.255.255.0",
	}
	ctrl := NewController(cfg)
	defer ctrl.Stop()

	req := &pb.HandshakeRequest{
		Version: "test-client",
		Secret:  true,
	}
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal handshake request failed: %v", err)
	}
	srcIP := net.ParseIP("10.26.0.2")
	reqPacket := &protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoHandshakeRequest,
		SrcIP:    srcIP,
		DstIP:    net.ParseIP("0.0.0.1"),
		Gateway:  true,
		Payload:  payload,
	}

	respPacket, err := ctrl.HandleHandshakePacket(reqPacket)
	if err != nil {
		t.Fatalf("HandleHandshakePacket failed: %v", err)
	}
	if respPacket.Ver != protocol.V2 {
		t.Fatalf("unexpected version: %v", respPacket.Ver)
	}
	if respPacket.Proto != protocol.ProtocolService {
		t.Fatalf("unexpected proto: %v", respPacket.Proto)
	}
	if respPacket.AppProto != protocol.AppProtoHandshakeResponse {
		t.Fatalf("unexpected app proto: %v", respPacket.AppProto)
	}
	if respPacket.SourceTTL != protocol.MAX_TTL {
		t.Fatalf("unexpected source ttl: %v", respPacket.SourceTTL)
	}
	if respPacket.TTL != protocol.MAX_TTL {
		t.Fatalf("unexpected ttl: %v", respPacket.TTL)
	}
	if !respPacket.Gateway {
		t.Fatalf("expected gateway packet")
	}
	if !respPacket.SrcIP.Equal(reqPacket.DstIP) {
		t.Fatalf("unexpected source ip: %v", respPacket.SrcIP)
	}
	if !respPacket.DstIP.Equal(srcIP) {
		t.Fatalf("unexpected destination ip: %v", respPacket.DstIP)
	}

	var resp pb.HandshakeResponse
	if err := proto.Unmarshal(respPacket.Payload, &resp); err != nil {
		t.Fatalf("unmarshal handshake response failed: %v", err)
	}
	if resp.GetVersion() != "goversion-1.0.0" {
		t.Fatalf("unexpected response version: %s", resp.GetVersion())
	}
	if resp.GetSecret() {
		t.Fatalf("expected secret=false")
	}
}

func TestHandleHandshakePacketInvalidPayload(t *testing.T) {
	cfg := &config.Config{
		Gateway: net.ParseIP("10.26.0.1"),
		Domain:  "ms.net",
		Netmask: "255.255.255.0",
	}
	ctrl := NewController(cfg)
	defer ctrl.Stop()

	reqPacket := &protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoHandshakeRequest,
		SrcIP:    net.ParseIP("10.26.0.2"),
		Gateway:  true,
		Payload:  []byte{0x01, 0x02},
	}

	if _, err := ctrl.HandleHandshakePacket(reqPacket); err == nil {
		t.Fatalf("expected error for invalid payload")
	}
}
