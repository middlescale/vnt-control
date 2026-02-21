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
	netInfo, ok := ctrl.nc.VirtualNetwork.Get("ms.net")
	if !ok {
		t.Fatalf("network not found")
	}
	client := netInfo.Clients[resp.GetVirtualIp()]
	client.Online = false
	client.LastSeen = 1
	netInfo.Clients[resp.GetVirtualIp()] = client
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
	rs, err := ctrl.HandleControlPacket(req)
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
	updated := netInfo.Clients[resp.GetVirtualIp()]
	if !updated.Online {
		t.Fatalf("client should be marked online on ping")
	}
	if updated.LastSeen <= 1 {
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
	})
	if err == nil {
		t.Fatalf("expected invalid ping payload error")
	}
}

func newBaseRegisterReq(deviceID, name string) *pb.RegistrationRequest {
	return &pb.RegistrationRequest{
		Token:    "ms.net",
		DeviceId: deviceID,
		Name:     name,
	}
}
