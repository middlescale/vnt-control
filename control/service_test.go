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
		Version:      "test-client",
		Secret:       true,
		Capabilities: []string{"udp_endpoint_report_v1", "punch_coord_v1", "unknown_cap"},
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
	if len(resp.GetCapabilities()) != 2 || resp.GetCapabilities()[0] != "udp_endpoint_report_v1" || resp.GetCapabilities()[1] != "punch_coord_v1" {
		t.Fatalf("unexpected capabilities: %v", resp.GetCapabilities())
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

func TestHandleHandshakePacketUnsupportedCapabilities(t *testing.T) {
	ctrl := newTestController()
	defer ctrl.Stop()
	req := &pb.HandshakeRequest{
		Version:      "test-client",
		Secret:       false,
		Capabilities: []string{"unknown_cap_a", "unknown_cap_b"},
	}
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal handshake request failed: %v", err)
	}
	respPacket, err := ctrl.HandleHandshakePacket(&protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoHandshakeRequest,
		SrcIP:    net.ParseIP("10.26.0.2"),
		DstIP:    net.ParseIP("0.0.0.1"),
		Gateway:  true,
		Payload:  payload,
	})
	if err != nil {
		t.Fatalf("HandleHandshakePacket failed: %v", err)
	}
	var resp pb.HandshakeResponse
	if err := proto.Unmarshal(respPacket.Payload, &resp); err != nil {
		t.Fatalf("unmarshal handshake response failed: %v", err)
	}
	if len(resp.GetCapabilities()) != 0 {
		t.Fatalf("expected empty negotiated capabilities, got: %v", resp.GetCapabilities())
	}
}

func TestPunchCoordProtoContractRoundTrip(t *testing.T) {
	req := &pb.PunchRequest{
		SessionId:     1001,
		Source:        util.IpToUint32(net.ParseIP("10.26.0.2")),
		Target:        util.IpToUint32(net.ParseIP("10.26.0.3")),
		SourceNatType: pb.PunchNatType_Cone,
		TargetNatType: pb.PunchNatType_Symmetric,
		SourceEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("1.1.1.1")), Port: 5000, Tcp: false},
		},
		TargetEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("2.2.2.2")), Port: 6000, Tcp: false},
		},
		Attempt:        1,
		TimeoutMs:      2000,
		DeadlineUnixMs: 10000,
	}
	buf, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal punch request failed: %v", err)
	}
	var decoded pb.PunchRequest
	if err := proto.Unmarshal(buf, &decoded); err != nil {
		t.Fatalf("unmarshal punch request failed: %v", err)
	}
	if decoded.GetSessionId() != req.GetSessionId() || decoded.GetAttempt() != req.GetAttempt() || decoded.GetTimeoutMs() != req.GetTimeoutMs() || decoded.GetDeadlineUnixMs() != req.GetDeadlineUnixMs() || len(decoded.GetSourceEndpoints()) != 1 || len(decoded.GetTargetEndpoints()) != 1 {
		t.Fatalf("unexpected decoded punch request: %+v", decoded)
	}
	if decoded.GetSourceNatType() != pb.PunchNatType_Cone || decoded.GetTargetNatType() != pb.PunchNatType_Symmetric {
		t.Fatalf("unexpected decoded nat types: source=%v target=%v", decoded.GetSourceNatType(), decoded.GetTargetNatType())
	}
	ack := &pb.PunchAck{
		SessionId: req.GetSessionId(),
		Source:    req.GetTarget(),
		Attempt:   req.GetAttempt(),
		Accepted:  true,
	}
	ackBuf, err := proto.Marshal(ack)
	if err != nil {
		t.Fatalf("marshal punch ack failed: %v", err)
	}
	var ackDecoded pb.PunchAck
	if err := proto.Unmarshal(ackBuf, &ackDecoded); err != nil {
		t.Fatalf("unmarshal punch ack failed: %v", err)
	}
	if !ackDecoded.GetAccepted() || ackDecoded.GetSessionId() != req.GetSessionId() || ackDecoded.GetAttempt() != req.GetAttempt() {
		t.Fatalf("unexpected decoded punch ack: %+v", ackDecoded)
	}
	result := &pb.PunchResult{
		SessionId: req.GetSessionId(),
		Source:    req.GetSource(),
		Target:    req.GetTarget(),
		Attempt:   req.GetAttempt(),
		Code:      pb.PunchResultCode(99),
		Reason:    "compat-enum",
		SelectedEndpoint: &pb.PunchEndpoint{
			Ip:   req.GetSourceEndpoints()[0].GetIp(),
			Port: req.GetSourceEndpoints()[0].GetPort(),
		},
	}
	resultBuf, err := proto.Marshal(result)
	if err != nil {
		t.Fatalf("marshal punch result failed: %v", err)
	}
	var resultDecoded pb.PunchResult
	if err := proto.Unmarshal(resultBuf, &resultDecoded); err != nil {
		t.Fatalf("unmarshal punch result failed: %v", err)
	}
	if resultDecoded.GetCode() != pb.PunchResultCode(99) || resultDecoded.GetSelectedEndpoint() == nil || resultDecoded.GetSelectedEndpoint().GetPort() != req.GetSourceEndpoints()[0].GetPort() {
		t.Fatalf("unexpected decoded punch result: %+v", resultDecoded)
	}
}

func TestPunchSessionLifecycleHandlers(t *testing.T) {
	ctrl := newTestController()
	defer ctrl.Stop()
	srcReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	dstReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})
	req := &pb.PunchRequest{
		SessionId: 2001,
		Source:    srcReg.GetVirtualIp(),
		Target:    dstReg.GetVirtualIp(),
		Attempt:   1,
		SourceEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("8.8.8.8")), Port: 30001},
		},
		TargetEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("9.9.9.9")), Port: 30002},
		},
	}
	reqPayload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal punch request failed: %v", err)
	}
	resp, err := ctrl.HandlePunchRequestPacket(&protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoPunchRequest,
		SrcIP:    util.Uint32ToIP(srcReg.GetVirtualIp()),
		DstIP:    util.Uint32ToIP(srcReg.GetVirtualGateway()),
		Gateway:  true,
		Payload:  reqPayload,
	})
	if err != nil {
		t.Fatalf("HandlePunchRequestPacket failed: %v", err)
	}
	if resp.AppProto != protocol.AppProtoPunchAck {
		t.Fatalf("unexpected punch request response app proto: %v", resp.AppProto)
	}
	session, ok := ctrl.nc.FindPunchSession(req.GetSessionId(), req.GetAttempt())
	if !ok || session.State != PunchSessionDispatch {
		t.Fatalf("unexpected session after request: %+v", session)
	}

	ack := &pb.PunchAck{
		SessionId: req.GetSessionId(),
		Source:    dstReg.GetVirtualIp(),
		Attempt:   req.GetAttempt(),
		Accepted:  true,
	}
	ackPayload, err := proto.Marshal(ack)
	if err != nil {
		t.Fatalf("marshal punch ack failed: %v", err)
	}
	if err := ctrl.HandlePunchAckPacket(&protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoPunchAck,
		SrcIP:    util.Uint32ToIP(dstReg.GetVirtualIp()),
		Payload:  ackPayload,
	}); err != nil {
		t.Fatalf("HandlePunchAckPacket failed: %v", err)
	}
	session, ok = ctrl.nc.FindPunchSession(req.GetSessionId(), req.GetAttempt())
	if !ok || session.State != PunchSessionInProgress {
		t.Fatalf("unexpected session after ack: %+v", session)
	}

	result := &pb.PunchResult{
		SessionId: req.GetSessionId(),
		Source:    dstReg.GetVirtualIp(),
		Target:    srcReg.GetVirtualIp(),
		Attempt:   req.GetAttempt(),
		Code:      pb.PunchResultCode_PunchResultSuccess,
		Reason:    "ok",
	}
	resultPayload, err := proto.Marshal(result)
	if err != nil {
		t.Fatalf("marshal punch result failed: %v", err)
	}
	if err := ctrl.HandlePunchResultPacket(&protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoPunchResult,
		SrcIP:    util.Uint32ToIP(dstReg.GetVirtualIp()),
		Payload:  resultPayload,
	}); err != nil {
		t.Fatalf("HandlePunchResultPacket failed: %v", err)
	}
	session, ok = ctrl.nc.FindPunchSession(req.GetSessionId(), req.GetAttempt())
	if !ok || session.State != PunchSessionSuccess {
		t.Fatalf("unexpected session after result: %+v", session)
	}
}

func TestBuildPunchStartPackets(t *testing.T) {
	ctrl := newTestController()
	defer ctrl.Stop()
	srcReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	dstReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})
	req := &pb.PunchRequest{
		SessionId: 3001,
		Source:    srcReg.GetVirtualIp(),
		Target:    dstReg.GetVirtualIp(),
		Attempt:   1,
		TimeoutMs: 2500,
		SourceEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("8.8.8.8")), Port: 3333},
		},
		TargetEndpoints: []*pb.PunchEndpoint{
			{Ip: util.IpToUint32(net.ParseIP("9.9.9.9")), Port: 4444},
		},
	}
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal punch request failed: %v", err)
	}
	packets, err := ctrl.BuildPunchStartPackets(&protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoPunchRequest,
		SrcIP:    util.Uint32ToIP(srcReg.GetVirtualIp()),
		DstIP:    util.Uint32ToIP(srcReg.GetVirtualGateway()),
		Gateway:  true,
		Payload:  payload,
	})
	if err != nil {
		t.Fatalf("BuildPunchStartPackets failed: %v", err)
	}
	if len(packets) != 2 {
		t.Fatalf("expected 2 punch start packets, got %d", len(packets))
	}
	first := packets[0]
	if first.AppProto != protocol.AppProtoPunchStart || !first.DstIP.Equal(util.Uint32ToIP(srcReg.GetVirtualIp())) {
		t.Fatalf("unexpected first punch start packet: %+v", first)
	}
	second := packets[1]
	if second.AppProto != protocol.AppProtoPunchStart || !second.DstIP.Equal(util.Uint32ToIP(dstReg.GetVirtualIp())) {
		t.Fatalf("unexpected second punch start packet: %+v", second)
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
		Source:         resp.GetVirtualIp(),
		UpStream:       10,
		DownStream:     20,
		NatType:        pb.PunchNatType_Cone,
		PublicIpList:   []uint32{util.IpToUint32(net.ParseIP("8.8.8.8"))},
		PublicUdpPorts: []uint32{54321},
		LocalUdpPorts:  []uint32{12345},
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
	if len(client.ClientStatus.PublicIPList) != 1 || !client.ClientStatus.PublicIPList[0].Equal(net.ParseIP("8.8.8.8")) {
		t.Fatalf("unexpected public ip list: %+v", client.ClientStatus.PublicIPList)
	}
	if len(client.ClientStatus.PublicUDPPorts) != 1 || client.ClientStatus.PublicUDPPorts[0] != 54321 {
		t.Fatalf("unexpected public udp ports: %+v", client.ClientStatus.PublicUDPPorts)
	}
	if len(client.ClientStatus.LocalUDPPorts) != 1 || client.ClientStatus.LocalUDPPorts[0] != 12345 {
		t.Fatalf("unexpected local udp ports: %+v", client.ClientStatus.LocalUDPPorts)
	}
	if !client.DataPlaneReachable {
		t.Fatalf("data plane should be reachable when p2p list is non-empty")
	}
}

func TestHandleClientStatusInfoPacketNoP2PRoute(t *testing.T) {
	ctrl := newTestController()
	defer ctrl.Stop()
	resp := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	status := &pb.ClientStatusInfo{
		Source:     resp.GetVirtualIp(),
		UpStream:   10,
		DownStream: 20,
		NatType:    pb.PunchNatType_Symmetric,
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
	if client.DataPlaneReachable {
		t.Fatalf("data plane should be unreachable when p2p list is empty")
	}
}

func TestLeaveByRemoteAddrMarksControlOffline(t *testing.T) {
	ctrl := newTestController()
	defer ctrl.Stop()
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111}
	resp := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), remoteAddr)
	ctrl.LeaveByRemoteAddr(remoteAddr)
	client, ok := ctrl.nc.FindClientByVirtualIP(resp.GetVirtualIp())
	if !ok {
		t.Fatalf("client not found")
	}
	if client.ControlOnline {
		t.Fatalf("control should be offline after leave")
	}
}

func TestGenerateIPReusesOfflineIPAfterSessionExpiry(t *testing.T) {
	ctrl := newTestController()
	defer ctrl.Stop()
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111}
	resp1 := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), remoteAddr)
	ctrl.LeaveByRemoteAddr(remoteAddr)
	ctrl.nc.IPSessions.Delete(NewIpSessionKey("ms.net", util.Uint32ToIP(resp1.GetVirtualIp())))
	resp2 := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})
	if resp2.GetVirtualIp() != resp1.GetVirtualIp() {
		t.Fatalf("expected reuse ip %v, got %v", resp1.GetVirtualIp(), resp2.GetVirtualIp())
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
