package control

import (
	"net"
	"testing"
	"vnt-control/config"
	"vnt-control/protocol"
	"vnt-control/protocol/pb"
	"vnt-control/util"

	"google.golang.org/protobuf/proto"
)

func TestHandleRegistrationPacketConflictAndAllowIpChange(t *testing.T) {
	ctrl := newTestController()
	defer ctrl.Stop()

	resp1 := mustRegister(t, ctrl, &pb.RegistrationRequest{
		Token:    "ms.net",
		DeviceId: "dev-a",
		Name:     "node-a",
	}, &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 3456})
	if resp1.GetVirtualIp() == 0 {
		t.Fatalf("virtual ip should not be zero")
	}
	if resp1.GetEpoch() != 1 {
		t.Fatalf("unexpected epoch: %d", resp1.GetEpoch())
	}
	if len(resp1.GetDeviceInfoList()) != 0 {
		t.Fatalf("unexpected device list length: %d", len(resp1.GetDeviceInfoList()))
	}
	if resp1.GetPublicIp() != util.IpToUint32(net.ParseIP("1.2.3.4")) {
		t.Fatalf("unexpected public ip: %d", resp1.GetPublicIp())
	}
	if resp1.GetPublicPort() != 3456 {
		t.Fatalf("unexpected public port: %d", resp1.GetPublicPort())
	}

	_, err := ctrl.HandleRegistrationPacket(newRegistrationPacket(t, &pb.RegistrationRequest{
		Token:         "ms.net",
		DeviceId:      "dev-b",
		Name:          "node-b",
		VirtualIp:     resp1.GetVirtualIp(),
		AllowIpChange: false,
	}), &net.UDPAddr{IP: net.ParseIP("5.6.7.8"), Port: 7788})
	if err == nil {
		t.Fatalf("expected conflict error")
	}

	resp2 := mustRegister(t, ctrl, &pb.RegistrationRequest{
		Token:         "ms.net",
		DeviceId:      "dev-b",
		Name:          "node-b",
		VirtualIp:     resp1.GetVirtualIp(),
		AllowIpChange: true,
	}, &net.UDPAddr{IP: net.ParseIP("5.6.7.8"), Port: 7788})
	if resp2.GetVirtualIp() == resp1.GetVirtualIp() {
		t.Fatalf("allow_ip_change should allocate a different ip")
	}
	if resp2.GetEpoch() != 2 {
		t.Fatalf("unexpected epoch after second registration: %d", resp2.GetEpoch())
	}
	if len(resp2.GetDeviceInfoList()) != 1 {
		t.Fatalf("unexpected device list length: %d", len(resp2.GetDeviceInfoList()))
	}
}

func TestHandleRegistrationPacketReuseSameDeviceIP(t *testing.T) {
	ctrl := newTestController()
	defer ctrl.Stop()

	resp1 := mustRegister(t, ctrl, &pb.RegistrationRequest{
		Token:    "ms.net",
		DeviceId: "dev-a",
		Name:     "node-a",
	}, &net.UDPAddr{IP: net.ParseIP("10.10.10.10"), Port: 10000})
	resp2 := mustRegister(t, ctrl, &pb.RegistrationRequest{
		Token:    "ms.net",
		DeviceId: "dev-a",
		Name:     "node-a-updated",
	}, &net.UDPAddr{IP: net.ParseIP("10.10.10.11"), Port: 10001})

	if resp1.GetVirtualIp() != resp2.GetVirtualIp() {
		t.Fatalf("same device should reuse virtual ip: %d != %d", resp1.GetVirtualIp(), resp2.GetVirtualIp())
	}
	if resp2.GetEpoch() != 2 {
		t.Fatalf("unexpected epoch after re-register: %d", resp2.GetEpoch())
	}
}

func TestHandleRegistrationPacketInvalidRequestedIP(t *testing.T) {
	ctrl := newTestController()
	defer ctrl.Stop()

	_, err := ctrl.HandleRegistrationPacket(newRegistrationPacket(t, &pb.RegistrationRequest{
		Token:     "ms.net",
		DeviceId:  "dev-a",
		Name:      "node-a",
		VirtualIp: util.IpToUint32(net.ParseIP("10.27.0.1")),
	}), &net.UDPAddr{IP: net.ParseIP("9.9.9.9"), Port: 9999})
	if err == nil {
		t.Fatalf("expected invalid requested ip error")
	}
}

func newTestController() *Controller {
	return NewController(&config.Config{
		Gateway: net.ParseIP("10.26.0.1"),
		Domain:  "ms.net",
		Netmask: "255.255.255.0",
	})
}

func mustRegister(t *testing.T, ctrl *Controller, req *pb.RegistrationRequest, remoteAddr net.Addr) *pb.RegistrationResponse {
	t.Helper()
	respPacket, err := ctrl.HandleRegistrationPacket(newRegistrationPacket(t, req), remoteAddr)
	if err != nil {
		t.Fatalf("HandleRegistrationPacket failed: %v", err)
	}
	var resp pb.RegistrationResponse
	if err := proto.Unmarshal(respPacket.Payload, &resp); err != nil {
		t.Fatalf("unmarshal registration response failed: %v", err)
	}
	if resp.GetVirtualGateway() != util.IpToUint32(net.ParseIP("10.26.0.1")) {
		t.Fatalf("unexpected virtual gateway: %d", resp.GetVirtualGateway())
	}
	if resp.GetVirtualNetmask() != util.IpToUint32(net.ParseIP("255.255.255.0")) {
		t.Fatalf("unexpected virtual netmask: %d", resp.GetVirtualNetmask())
	}
	return &resp
}

func newRegistrationPacket(t *testing.T, req *pb.RegistrationRequest) *protocol.Packet {
	t.Helper()
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal registration request failed: %v", err)
	}
	return &protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoRegistrationRequest,
		SrcIP:    net.ParseIP("10.26.0.2"),
		Gateway:  true,
		Payload:  payload,
	}
}
