package control

import (
	"net"
	"testing"
	"vnt-control/protocol"
	"vnt-control/protocol/pb"
	"vnt-control/util"
)

func TestHandleControlPacketPingPong(t *testing.T) {
	ctrl := newTestController()
	defer ctrl.Stop()

	resp := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	ok := ctrl.nc.UpdateClientByVirtualIP(resp.GetVirtualIp(), func(client *ClientInfo) {
		client.ControlOnline = false
		client.ControlLastSeen = 1
	})
	if !ok {
		t.Fatalf("client not found")
	}
	timeVal := uint16(1234)
	req := &protocol.Packet{
		Ver:       protocol.V2,
		Proto:     protocol.ProtocolControl,
		AppProto:  protocol.AppProtocol(protocol.ControlPing),
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     util.Uint32ToIP(resp.GetVirtualIp()),
		DstIP:     util.Uint32ToIP(resp.GetVirtualGateway()),
		Gateway:   true,
		Payload:   protocol.BuildPingPayload(timeVal, 0),
	}
	rs, err := ctrl.HandleControlPacket(req, &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	if err != nil {
		t.Fatalf("HandleControlPacket failed: %v", err)
	}
	if rs.Proto != protocol.ProtocolControl || rs.AppProto != protocol.AppProtocol(protocol.ControlPong) {
		t.Fatalf("unexpected control response proto/app: %v/%v", rs.Proto, rs.AppProto)
	}
	rt, epoch, err := protocol.ParsePingPayload(rs.Payload)
	if err != nil {
		t.Fatalf("invalid pong payload: %v", err)
	}
	if rt != timeVal {
		t.Fatalf("unexpected pong time: %d", rt)
	}
	if epoch != uint16(resp.GetEpoch()) {
		t.Fatalf("unexpected pong epoch: %d", epoch)
	}
	updated, ok := ctrl.nc.FindClientByVirtualIP(resp.GetVirtualIp())
	if !ok {
		t.Fatalf("client not found")
	}
	if !updated.ControlOnline {
		t.Fatalf("client should be marked online on ping")
	}
	if updated.ControlLastSeen <= 1 {
		t.Fatalf("client last_seen was not refreshed")
	}
}

func TestHandleControlPacketInvalidPingPayload(t *testing.T) {
	ctrl := newTestController()
	defer ctrl.Stop()
	_, err := ctrl.HandleControlPacket(&protocol.Packet{
		Proto:    protocol.ProtocolControl,
		AppProto: protocol.AppProtocol(protocol.ControlPing),
		Payload:  []byte{0x01},
	}, &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	if err == nil {
		t.Fatalf("expected invalid ping payload error")
	}
}

func TestHandleControlPacketAddrRequest(t *testing.T) {
	ctrl := newTestController()
	defer ctrl.Stop()
	req := &protocol.Packet{
		Ver:       protocol.V2,
		Proto:     protocol.ProtocolControl,
		AppProto:  protocol.AppProtocol(protocol.ControlAddrRequest),
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     net.IPv4(10, 0, 0, 2),
		DstIP:     net.IPv4(10, 0, 0, 1),
		Gateway:   true,
	}
	rs, err := ctrl.HandleControlPacket(req, &net.UDPAddr{IP: net.ParseIP("2.3.4.5"), Port: 4567})
	if err != nil {
		t.Fatalf("HandleControlPacket addr request failed: %v", err)
	}
	if rs.AppProto != protocol.AppProtocol(protocol.ControlAddrResponse) {
		t.Fatalf("unexpected app proto: %v", rs.AppProto)
	}
	ip, port, err := protocol.ParseAddrPayload(rs.Payload)
	if err != nil {
		t.Fatalf("invalid addr payload: %v", err)
	}
	if !ip.Equal(net.IPv4(2, 3, 4, 5)) || port != 4567 {
		t.Fatalf("unexpected addr response: %v:%d", ip, port)
	}
}

func newBaseRegisterReq(deviceID, name string) *pb.RegistrationRequest {
	return &pb.RegistrationRequest{
		Token:    "ms.net",
		DeviceId: deviceID,
		Name:     name,
	}
}
