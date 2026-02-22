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

func TestHandlePullDeviceListPacket(t *testing.T) {
	ctrl := newTestController()
	defer ctrl.Stop()
	resp1 := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	resp2 := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})
	req := &protocol.Packet{
		Ver:       protocol.V2,
		Proto:     protocol.ProtocolService,
		AppProto:  protocol.AppProtoPullDeviceList,
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     util.Uint32ToIP(resp2.GetVirtualIp()),
		DstIP:     util.Uint32ToIP(resp2.GetVirtualGateway()),
		Gateway:   true,
	}
	rs, err := ctrl.HandlePullDeviceListPacket(req)
	if err != nil {
		t.Fatalf("HandlePullDeviceListPacket failed: %v", err)
	}
	if rs.AppProto != protocol.AppProtoPushDeviceList {
		t.Fatalf("unexpected app proto: %v", rs.AppProto)
	}
	var list pb.DeviceList
	if err := proto.Unmarshal(rs.Payload, &list); err != nil {
		t.Fatalf("unmarshal device list failed: %v", err)
	}
	if list.GetEpoch() != resp2.GetEpoch() {
		t.Fatalf("unexpected epoch: %d", list.GetEpoch())
	}
	if len(list.GetDeviceInfoList()) != 1 || list.GetDeviceInfoList()[0].GetVirtualIp() != resp1.GetVirtualIp() {
		t.Fatalf("unexpected device list response: %+v", list.GetDeviceInfoList())
	}
}

func TestHandleClientStatusInfoPacket(t *testing.T) {
	ctrl := newTestController()
	defer ctrl.Stop()
	resp := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	status := &pb.ClientStatusInfo{
		Source:     resp.GetVirtualIp(),
		UpStream:   10,
		DownStream: 20,
		NatType:    pb.PunchNatType_Cone,
		P2PList: []*pb.RouteItem{
			{NextIp: util.IpToUint32(net.ParseIP("10.26.0.3"))},
		},
	}
	payload, err := proto.Marshal(status)
	if err != nil {
		t.Fatalf("marshal client status failed: %v", err)
	}
	err = ctrl.HandleClientStatusInfoPacket(&protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoClientStatusInfo,
		SrcIP:    util.Uint32ToIP(resp.GetVirtualIp()),
		Payload:  payload,
	})
	if err != nil {
		t.Fatalf("HandleClientStatusInfoPacket failed: %v", err)
	}
	client, ok := ctrl.nc.FindClientByVirtualIP(resp.GetVirtualIp())
	if !ok {
		t.Fatalf("client not found")
	}
	if client.ClientStatus == nil || !client.ClientStatus.IsCone || client.ClientStatus.UpStream != 10 || client.ClientStatus.DownStream != 20 {
		t.Fatalf("unexpected client status: %+v", client.ClientStatus)
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
	virtualIP := resp.GetVirtualIp()
	virtualGateway := resp.GetVirtualGateway()
	virtualNetmask := resp.GetVirtualNetmask()
	if virtualIP&virtualNetmask != virtualGateway&virtualNetmask {
		t.Fatalf("virtual ip %s is not in gateway/netmask network", util.Uint32ToIP(virtualIP))
	}
	broadcast := (virtualGateway & virtualNetmask) | ^virtualNetmask
	if virtualIP == virtualGateway || virtualIP == broadcast {
		t.Fatalf("virtual ip should not be gateway/broadcast: %s", util.Uint32ToIP(virtualIP))
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
