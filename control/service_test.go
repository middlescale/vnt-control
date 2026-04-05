package control

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sdl-control/config"
	"sdl-control/protocol"
	"sdl-control/protocol/pb"
	"sdl-control/util"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
)

const testGatewayTicketSecret = "test-gateway-ticket-secret"

func TestHandleHandshakePacketSuccess(t *testing.T) {
	cfg := &config.Config{
		Gateway:             net.ParseIP("10.26.0.1"),
		Domain:              "ms.net",
		Netmask:             "255.255.255.0",
		DefaultGatewayID:    "gw-default",
		GatewayTicketSecret: testGatewayTicketSecret,
	}
	ctrl := newControllerWithConfig(t, cfg)
	defer ctrl.Stop()

	req := &pb.HandshakeRequest{
		Version:      "test-client",
		Capabilities: []string{"udp_endpoint_report_v1", "punch_coord_v1", "gateway_ticket_v1", "unknown_cap"},
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
	if respPacket.Ver != protocol.V3 {
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
	if len(resp.GetCapabilities()) != 3 || resp.GetCapabilities()[0] != "udp_endpoint_report_v1" || resp.GetCapabilities()[1] != "punch_coord_v1" || resp.GetCapabilities()[2] != "gateway_ticket_v1" {
		t.Fatalf("unexpected capabilities: %v", resp.GetCapabilities())
	}
}

func TestHandleHandshakePacketInvalidPayload(t *testing.T) {
	cfg := &config.Config{
		Gateway:             net.ParseIP("10.26.0.1"),
		Domain:              "ms.net",
		Netmask:             "255.255.255.0",
		DefaultGatewayID:    "gw-default",
		GatewayTicketSecret: testGatewayTicketSecret,
	}
	ctrl := newControllerWithConfig(t, cfg)
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
	ctrl := newTestController(t)
	defer ctrl.Stop()
	req := &pb.HandshakeRequest{
		Version:      "test-client",
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
	ctrl := newTestController(t)
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
	if session.RelayFallback {
		t.Fatalf("success session should not require relay fallback")
	}
}

func TestBuildPunchStartPackets(t *testing.T) {
	ctrl := newTestController(t)
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

func TestHandlePunchAckAndResultInitializeSessionMaps(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()

	srcIP := util.IpToUint32(net.ParseIP("10.26.0.2"))
	dstIP := util.IpToUint32(net.ParseIP("10.26.0.3"))
	sessionID := uint64(4001)
	attempt := uint32(1)
	key := punchSessionKey(sessionID, attempt)
	ctrl.nc.PunchSessions.Set(key, &PunchSession{
		SessionID:      sessionID,
		Source:         srcIP,
		Target:         dstIP,
		Attempt:        attempt,
		DeadlineUnixMs: time.Now().Add(5 * time.Second).UnixMilli(),
		State:          PunchSessionDispatch,
		RequestedAt:    time.Now().Unix(),
	})

	ackPayload, err := proto.Marshal(&pb.PunchAck{
		SessionId: sessionID,
		Source:    dstIP,
		Attempt:   attempt,
		Accepted:  true,
	})
	if err != nil {
		t.Fatalf("marshal punch ack failed: %v", err)
	}
	if err := ctrl.HandlePunchAckPacket(&protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoPunchAck,
		SrcIP:    util.Uint32ToIP(dstIP),
		Payload:  ackPayload,
	}); err != nil {
		t.Fatalf("HandlePunchAckPacket failed: %v", err)
	}

	resultPayload, err := proto.Marshal(&pb.PunchResult{
		SessionId: sessionID,
		Source:    dstIP,
		Target:    srcIP,
		Attempt:   attempt,
		Code:      pb.PunchResultCode_PunchResultSuccess,
		Reason:    "ok",
	})
	if err != nil {
		t.Fatalf("marshal punch result failed: %v", err)
	}
	if err := ctrl.HandlePunchResultPacket(&protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoPunchResult,
		SrcIP:    util.Uint32ToIP(dstIP),
		Payload:  resultPayload,
	}); err != nil {
		t.Fatalf("HandlePunchResultPacket failed: %v", err)
	}

	session, ok := ctrl.nc.FindPunchSession(sessionID, attempt)
	if !ok {
		t.Fatalf("session not found")
	}
	if session.Ack == nil || session.Results == nil {
		t.Fatalf("session maps not initialized: %+v", session)
	}
	if !session.Ack[dstIP] {
		t.Fatalf("ack not recorded for %d", dstIP)
	}
	if session.Results[dstIP] == nil {
		t.Fatalf("result not recorded for %d", dstIP)
	}
}

func TestBuildPunchStartPacketsFromStatus(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	srcReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	dstReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})
	srcStatus := &pb.ClientStatusInfo{
		Source:         srcReg.GetVirtualIp(),
		NatType:        pb.PunchNatType_Cone,
		PublicIpList:   []uint32{util.IpToUint32(net.ParseIP("8.8.8.8"))},
		PublicUdpPorts: []uint32{30001},
		LocalUdpPorts:  []uint32{1111},
	}
	dstStatus := &pb.ClientStatusInfo{
		Source:         dstReg.GetVirtualIp(),
		NatType:        pb.PunchNatType_Cone,
		PublicIpList:   []uint32{util.IpToUint32(net.ParseIP("9.9.9.9"))},
		PublicUdpPorts: []uint32{30002},
		LocalUdpPorts:  []uint32{2222},
	}
	srcPayload, err := proto.Marshal(srcStatus)
	if err != nil {
		t.Fatalf("marshal src status failed: %v", err)
	}
	dstPayload, err := proto.Marshal(dstStatus)
	if err != nil {
		t.Fatalf("marshal dst status failed: %v", err)
	}
	if err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()), Payload: srcPayload}); err != nil {
		t.Fatalf("update src status failed: %v", err)
	}
	if err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(dstReg.GetVirtualIp()), Payload: dstPayload}); err != nil {
		t.Fatalf("update dst status failed: %v", err)
	}
	startPackets, err := ctrl.BuildPunchStartPacketsFromStatus(&protocol.Packet{
		Proto:   protocol.ProtocolService,
		SrcIP:   util.Uint32ToIP(srcReg.GetVirtualIp()),
		DstIP:   util.Uint32ToIP(srcReg.GetVirtualGateway()),
		Gateway: true,
	})
	if err != nil {
		t.Fatalf("BuildPunchStartPacketsFromStatus failed: %v", err)
	}
	if len(startPackets) != 2 {
		t.Fatalf("expected 2 start packets, got %d", len(startPackets))
	}
	var start pb.PunchStart
	if err := proto.Unmarshal(startPackets[0].Payload, &start); err != nil {
		t.Fatalf("unmarshal punch start failed: %v", err)
	}
	var foundPublic, foundLocal bool
	for _, ep := range start.GetPeerEndpoints() {
		switch {
		case ep.GetIp() == util.IpToUint32(net.ParseIP("9.9.9.9")) && ep.GetPort() == 30002:
			foundPublic = true
		case ep.GetIp() == util.IpToUint32(net.ParseIP("1.1.1.2")) && ep.GetPort() == 2222:
			foundLocal = true
		}
	}
	if !foundPublic || !foundLocal {
		t.Fatalf("expected public and local endpoints in punch start, got %+v", start.GetPeerEndpoints())
	}
	next, err := ctrl.BuildPunchStartPacketsFromStatus(&protocol.Packet{
		Proto: protocol.ProtocolService,
		SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()),
		DstIP: util.Uint32ToIP(srcReg.GetVirtualGateway()),
	})
	if err != nil {
		t.Fatalf("second BuildPunchStartPacketsFromStatus failed: %v", err)
	}
	if len(next) != 0 {
		t.Fatalf("expected cooldown to suppress immediate re-trigger, got %d packets", len(next))
	}
}

func TestReconcilePunchSessionsTimeoutMarksFallback(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	sessionID := uint64(9001)
	attempt := uint32(1)
	key := punchSessionKey(sessionID, attempt)
	ctrl.nc.PunchSessions.Set(key, &PunchSession{
		SessionID:      sessionID,
		Source:         util.IpToUint32(net.ParseIP("10.26.0.2")),
		Target:         util.IpToUint32(net.ParseIP("10.26.0.3")),
		Attempt:        attempt,
		DeadlineUnixMs: time.Now().Add(-time.Second).UnixMilli(),
		State:          PunchSessionInProgress,
		RequestedAt:    time.Now().Unix(),
		Ack:            map[uint32]bool{},
		Results:        map[uint32]*pb.PunchResult{},
		RelayFallback:  false,
	})
	ctrl.ReconcilePunchSessions(time.Now().UnixMilli())
	session, ok := ctrl.nc.FindPunchSession(sessionID, attempt)
	if !ok {
		t.Fatalf("session not found")
	}
	if session.State != PunchSessionTimeout {
		t.Fatalf("expected timeout state, got %s", session.State)
	}
	if !session.RelayFallback {
		t.Fatalf("timeout session should require relay fallback")
	}
	pairKey := punchPairKey(session.Source, session.Target)
	retry, ok := ctrl.nc.PunchPairRetry.Get(pairKey)
	if !ok {
		t.Fatalf("retry state not found after timeout")
	}
	if retry.Attempt != 1 {
		t.Fatalf("unexpected retry attempt: %d", retry.Attempt)
	}
	if retry.NextAllowedUnixMs <= time.Now().UnixMilli() {
		t.Fatalf("expected backoff window in future, got %d", retry.NextAllowedUnixMs)
	}
}

func TestBuildPunchStartPacketsFromStatusHonorsRetryPolicy(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	srcReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	dstReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})
	srcStatus := &pb.ClientStatusInfo{
		Source:         srcReg.GetVirtualIp(),
		NatType:        pb.PunchNatType_Cone,
		PublicIpList:   []uint32{util.IpToUint32(net.ParseIP("8.8.8.8"))},
		PublicUdpPorts: []uint32{30001},
	}
	dstStatus := &pb.ClientStatusInfo{
		Source:         dstReg.GetVirtualIp(),
		NatType:        pb.PunchNatType_Cone,
		PublicIpList:   []uint32{util.IpToUint32(net.ParseIP("9.9.9.9"))},
		PublicUdpPorts: []uint32{30002},
	}
	srcPayload, err := proto.Marshal(srcStatus)
	if err != nil {
		t.Fatalf("marshal src status failed: %v", err)
	}
	dstPayload, err := proto.Marshal(dstStatus)
	if err != nil {
		t.Fatalf("marshal dst status failed: %v", err)
	}
	if err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()), Payload: srcPayload}); err != nil {
		t.Fatalf("update src status failed: %v", err)
	}
	if err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(dstReg.GetVirtualIp()), Payload: dstPayload}); err != nil {
		t.Fatalf("update dst status failed: %v", err)
	}
	pairKey := punchPairKey(srcReg.GetVirtualIp(), dstReg.GetVirtualIp())
	ctrl.nc.PunchPairRetry.Set(pairKey, PunchRetryState{
		Attempt:           maxPunchAttemptsPerPair,
		NextAllowedUnixMs: 0,
	})
	packets, err := ctrl.BuildPunchStartPacketsFromStatus(&protocol.Packet{
		Proto: protocol.ProtocolService,
		SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()),
		DstIP: util.Uint32ToIP(srcReg.GetVirtualGateway()),
	})
	if err != nil {
		t.Fatalf("BuildPunchStartPacketsFromStatus failed: %v", err)
	}
	if len(packets) != 0 {
		t.Fatalf("expected max retry suppression, got %d packets", len(packets))
	}
	ctrl.nc.PunchPairRetry.Set(pairKey, PunchRetryState{
		Attempt:           1,
		NextAllowedUnixMs: time.Now().Add(2 * time.Second).UnixMilli(),
	})
	packets, err = ctrl.BuildPunchStartPacketsFromStatus(&protocol.Packet{
		Proto: protocol.ProtocolService,
		SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()),
		DstIP: util.Uint32ToIP(srcReg.GetVirtualGateway()),
	})
	if err != nil {
		t.Fatalf("BuildPunchStartPacketsFromStatus failed: %v", err)
	}
	if len(packets) != 0 {
		t.Fatalf("expected backoff suppression, got %d packets", len(packets))
	}
}

func TestFailedRegistrationClearsStalePunchCandidateState(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()

	srcReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	dstReq := newBaseRegisterReq("dev-b", "node-b")
	dstRemote := &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222}
	dstReg := mustRegister(t, ctrl, dstReq, dstRemote)

	srcStatus := &pb.ClientStatusInfo{
		Source:         srcReg.GetVirtualIp(),
		NatType:        pb.PunchNatType_Cone,
		PublicIpList:   []uint32{util.IpToUint32(net.ParseIP("8.8.8.8"))},
		PublicUdpPorts: []uint32{30001},
		LocalUdpPorts:  []uint32{1111},
	}
	dstStatus := &pb.ClientStatusInfo{
		Source:         dstReg.GetVirtualIp(),
		NatType:        pb.PunchNatType_Cone,
		PublicIpList:   []uint32{util.IpToUint32(net.ParseIP("9.9.9.9"))},
		PublicUdpPorts: []uint32{30002},
		LocalUdpPorts:  []uint32{2222},
	}
	srcPayload, err := proto.Marshal(srcStatus)
	if err != nil {
		t.Fatalf("marshal src status failed: %v", err)
	}
	dstPayload, err := proto.Marshal(dstStatus)
	if err != nil {
		t.Fatalf("marshal dst status failed: %v", err)
	}
	if err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()), Payload: srcPayload}); err != nil {
		t.Fatalf("update src status failed: %v", err)
	}
	if err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(dstReg.GetVirtualIp()), Payload: dstPayload}); err != nil {
		t.Fatalf("update dst status failed: %v", err)
	}

	delete(ctrl.um.authedDevices, "ms.net|dev-b")
	if _, _, err := ctrl.HandleRegistrationPacketWithVirtualIP(newRegistrationPacket(t, dstReq), dstRemote); err == nil {
		t.Fatalf("expected registration auth failure")
	}

	packets, err := ctrl.BuildPunchStartPacketsFromStatus(&protocol.Packet{
		Proto: protocol.ProtocolService,
		SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()),
		DstIP: util.Uint32ToIP(srcReg.GetVirtualGateway()),
	})
	if err != nil {
		t.Fatalf("BuildPunchStartPacketsFromStatus failed: %v", err)
	}
	if len(packets) != 0 {
		t.Fatalf("expected stale unauthenticated peer to be excluded from punch, got %d packets", len(packets))
	}
}

func TestListDevicesIncludesOnlineState(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()

	userA, err := ctrl.UMCreateUserWithID("user-a", "ms.net", "ms.net")
	if err != nil {
		t.Fatalf("UMCreateUserWithID user-a failed: %v", err)
	}
	userATicket, err := ctrl.UMIssueDeviceTicket(userA.UserID, "ms.net", time.Minute)
	if err != nil {
		t.Fatalf("UMIssueDeviceTicket user-a failed: %v", err)
	}
	if _, err := ctrl.UMAuthDevice(userA.UserID, "ms.net", "dev-a", userATicket.Ticket, []byte("pk-dev-a")); err != nil {
		t.Fatalf("UMAuthDevice user-a failed: %v", err)
	}
	userB, err := ctrl.UMCreateUserWithID("user-b", "ms.net", "ms.net")
	if err != nil {
		t.Fatalf("UMCreateUserWithID user-b failed: %v", err)
	}
	userBTicket, err := ctrl.UMIssueDeviceTicket(userB.UserID, "ms.net", time.Minute)
	if err != nil {
		t.Fatalf("UMIssueDeviceTicket user-b failed: %v", err)
	}
	if _, err := ctrl.UMAuthDevice(userB.UserID, "ms.net", "dev-b", userBTicket.Ticket, []byte("pk-dev-b")); err != nil {
		t.Fatalf("UMAuthDevice user-b failed: %v", err)
	}
	srcReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	dstReg := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})

	srcStatus := &pb.ClientStatusInfo{
		Source:         srcReg.GetVirtualIp(),
		NatType:        pb.PunchNatType_Cone,
		PublicIpList:   []uint32{util.IpToUint32(net.ParseIP("8.8.8.8"))},
		PublicUdpPorts: []uint32{30001},
		LocalUdpPorts:  []uint32{1111},
	}
	srcPayload, err := proto.Marshal(srcStatus)
	if err != nil {
		t.Fatalf("marshal src status failed: %v", err)
	}
	if err := ctrl.HandleClientStatusInfoPacket(&protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoClientStatusInfo, SrcIP: util.Uint32ToIP(srcReg.GetVirtualIp()), Payload: srcPayload}); err != nil {
		t.Fatalf("update src status failed: %v", err)
	}

	devices := ctrl.ListDevices("user-a")
	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devices))
	}
	device := devices[0]
	if device.UserID != "user-a" || device.DeviceID != "dev-a" {
		t.Fatalf("unexpected listed device: %+v", device)
	}
	if device.VirtualIP != util.Uint32ToIP(srcReg.GetVirtualIp()).String() {
		t.Fatalf("unexpected src virtual ip: %+v", device)
	}
	if !device.ControlOnline {
		t.Fatalf("expected src device control-online: %+v", device)
	}
	if other := ctrl.ListDevices("user-b"); len(other) != 1 || other[0].VirtualIP != util.Uint32ToIP(dstReg.GetVirtualIp()).String() || !other[0].ControlOnline {
		t.Fatalf("unexpected user-b device list: %+v", other)
	}
}

func TestHandleRegistrationPacketConflictAndAllowIpChange(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()

	resp1 := mustRegister(t, ctrl, &pb.RegistrationRequest{
		Token:        "ms.net",
		DeviceId:     "dev-a",
		Name:         "node-a",
		DevicePubKey: []byte("pk-dev-a"),
		OnlineKxPub:  testOnlineKxPub("dev-a-v1"),
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
		DevicePubKey:  []byte("pk-dev-b"),
		OnlineKxPub:   testOnlineKxPub("dev-b-v1"),
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
		DevicePubKey:  []byte("pk-dev-b"),
		OnlineKxPub:   testOnlineKxPub("dev-b-v2"),
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
	ctrl := newTestController(t)
	defer ctrl.Stop()

	resp1 := mustRegister(t, ctrl, &pb.RegistrationRequest{
		Token:        "ms.net",
		DeviceId:     "dev-a",
		Name:         "node-a",
		DevicePubKey: []byte("pk-dev-a"),
		OnlineKxPub:  testOnlineKxPub("dev-a-v1"),
	}, &net.UDPAddr{IP: net.ParseIP("10.10.10.10"), Port: 10000})
	resp2 := mustRegister(t, ctrl, &pb.RegistrationRequest{
		Token:        "ms.net",
		DeviceId:     "dev-a",
		Name:         "node-a-updated",
		DevicePubKey: []byte("pk-dev-a"),
		OnlineKxPub:  testOnlineKxPub("dev-a-v2"),
	}, &net.UDPAddr{IP: net.ParseIP("10.10.10.11"), Port: 10001})

	if resp1.GetVirtualIp() != resp2.GetVirtualIp() {
		t.Fatalf("same device should reuse virtual ip: %d != %d", resp1.GetVirtualIp(), resp2.GetVirtualIp())
	}
	if resp2.GetEpoch() != 2 {
		t.Fatalf("unexpected epoch after re-register: %d", resp2.GetEpoch())
	}
}

func TestHandleRegistrationPacketInvalidRequestedIP(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()

	_, err := ctrl.HandleRegistrationPacket(newRegistrationPacket(t, &pb.RegistrationRequest{
		Token:        "ms.net",
		DeviceId:     "dev-a",
		Name:         "node-a",
		VirtualIp:    util.IpToUint32(net.ParseIP("10.27.0.1")),
		DevicePubKey: []byte("pk-dev-a"),
		OnlineKxPub:  testOnlineKxPub("dev-a-v1"),
	}), &net.UDPAddr{IP: net.ParseIP("9.9.9.9"), Port: 9999})
	if err == nil {
		t.Fatalf("expected invalid requested ip error")
	}
}

func TestHandlePullDeviceListPacket(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	resp1 := mustRegister(t, ctrl, newBaseRegisterReq("dev-a", "node-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	resp2 := mustRegister(t, ctrl, newBaseRegisterReq("dev-b", "node-b"), &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 2222})
	req := &protocol.Packet{
		Ver:       protocol.V3,
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
	if list.GetDeviceInfoList()[0].GetDeviceId() != "dev-a" {
		t.Fatalf("unexpected device id in list: %+v", list.GetDeviceInfoList()[0])
	}
	if string(list.GetDeviceInfoList()[0].GetDevicePubKey()) != "pk-dev-a" {
		t.Fatalf("unexpected device pub key in list: %+v", list.GetDeviceInfoList()[0])
	}
	if string(list.GetDeviceInfoList()[0].GetOnlineKxPub()) != string(testOnlineKxPub("dev-a")) {
		t.Fatalf("unexpected online kx pub in list: %+v", list.GetDeviceInfoList()[0])
	}
}

func TestHandleClientStatusInfoPacket(t *testing.T) {
	ctrl := newTestController(t)
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
	ctrl := newTestController(t)
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
	ctrl := newTestController(t)
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
	ctrl := newTestController(t)
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

func TestRegistrationRequiresAuthedDeviceWhenTicketIssued(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	deviceID := fmt.Sprintf("dev-preauth-%d", time.Now().UnixNano())
	user, err := ctrl.UMCreateUser("alice")
	if err != nil {
		t.Fatalf("UMCreateUser failed: %v", err)
	}
	tk, err := ctrl.UMIssueDeviceTicket(user.UserID, "ms.net", time.Minute)
	if err != nil {
		t.Fatalf("UMIssueDeviceTicket failed: %v", err)
	}
	req := newBaseRegisterReq(deviceID, "node-a")
	_, err = ctrl.HandleRegistrationPacket(newRegistrationPacket(t, req), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
	if err == nil {
		t.Fatalf("expected registration rejected before certification")
	}
	if _, err := ctrl.UMAuthDevice(user.UserID, "ms.net", deviceID, tk.Ticket, req.GetDevicePubKey()); err != nil {
		t.Fatalf("UMAuthDevice failed: %v", err)
	}
	_ = mustRegister(t, ctrl, req, &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111})
}

func TestHandleDeviceAuthPacket(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	user, err := ctrl.UMCreateUser("alice")
	if err != nil {
		t.Fatalf("UMCreateUser failed: %v", err)
	}
	tk, err := ctrl.UMIssueDeviceTicket(user.UserID, "ms.net", time.Minute)
	if err != nil {
		t.Fatalf("UMIssueDeviceTicket failed: %v", err)
	}
	req := &pb.DeviceAuthRequest{UserId: user.UserID, Group: "ms.net", DeviceId: "dev-x", Ticket: tk.Ticket, DevicePubKey: []byte("pk-dev-x")}
	b, _ := proto.Marshal(req)
	packet := &protocol.Packet{Proto: protocol.ProtocolService, AppProto: protocol.AppProtoDeviceAuthRequest, SrcIP: net.ParseIP("10.0.0.2"), DstIP: net.ParseIP("0.0.0.1"), Gateway: true, Payload: b}
	resp, err := ctrl.HandleDeviceAuthPacket(packet)
	if err != nil {
		t.Fatalf("HandleDeviceAuthPacket failed: %v", err)
	}
	var challenge pb.DeviceAuthChallenge
	if err := proto.Unmarshal(resp.Payload, &challenge); err != nil {
		t.Fatalf("unmarshal challenge failed: %v", err)
	}
	if challenge.GetChallengeId() == "" || len(challenge.GetNonce()) == 0 {
		t.Fatalf("expected challenge response, got %+v", challenge)
	}
}

func TestGatewayReportAndRegistrationGrant(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	report := newSignedGatewayReport(t, testGatewayTicketSecret, "gw-default", "127.0.0.1:51820", []string{"udp_blind_relay_v1"}, time.Now(), randomGatewayNonce(t))
	packet := newGatewayReportPacket(t, report)
	resp, err := ctrl.HandleGatewayReportPacket(packet)
	if err != nil {
		t.Fatalf("HandleGatewayReportPacket failed: %v", err)
	}
	var ack pb.GatewayReportAck
	if err := proto.Unmarshal(resp.Payload, &ack); err != nil {
		t.Fatalf("unmarshal gateway report ack failed: %v", err)
	}
	if !ack.GetOk() || ack.GetGatewayId() != "gw-default" {
		t.Fatalf("unexpected gateway report ack: %+v", ack)
	}

	regResp := mustRegister(t, ctrl, newBaseRegisterReq("dev-gw-a", "node-gw-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.3"), Port: 3333})
	grant := regResp.GetGatewayAccessGrant()
	if grant == nil {
		t.Fatalf("expected gateway access grant in registration response")
	}
	if len(grant.GetGatewayChannels()) != 1 || grant.GetGatewayChannels()[0].GetAddr() != "quic://127.0.0.1:51820" {
		t.Fatalf("unexpected gateway channels: %+v", grant.GetGatewayChannels())
	}
	if len(grant.GetGatewayCapabilities()) == 0 || grant.GetGatewayCapabilities()[0] != "udp_blind_relay_v1" {
		t.Fatalf("unexpected grant capabilities: %+v", grant.GetGatewayCapabilities())
	}
	if len(grant.GetTicket()) == 0 || grant.GetTicketExpireUnixMs() <= 0 {
		t.Fatalf("expected short-lived ticket in grant: %+v", grant)
	}
	if grant.GetDefaultGatewayChannel() != pb.GatewayChannelKind_GATEWAY_CHANNEL_QUIC {
		t.Fatalf("unexpected default gateway channel: %v", grant.GetDefaultGatewayChannel())
	}
	var ticket pb.SignedGatewayTicket
	if err := proto.Unmarshal(grant.GetTicket(), &ticket); err != nil {
		t.Fatalf("unmarshal signed gateway ticket failed: %v", err)
	}
	if ticket.GetAlg() != "hmac-sha256" {
		t.Fatalf("unexpected ticket alg: %s", ticket.GetAlg())
	}
	if !verifyHMACTicketSignature(testGatewayTicketSecret, &ticket) {
		t.Fatalf("expected HMAC-signed gateway ticket")
	}
}

func TestGatewayReportRejectsInvalidSignature(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	ctrl.ApproveGatewayNode("gw-bad-sig", "127.0.0.1:51820")
	report := newSignedGatewayReport(t, testGatewayTicketSecret, "gw-bad-sig", "127.0.0.1:51820", []string{"udp_blind_relay_v1"}, time.Now(), randomGatewayNonce(t))
	report.Signature[0] ^= 0xff
	resp, err := ctrl.HandleGatewayReportPacket(newGatewayReportPacket(t, report))
	if err != nil {
		t.Fatalf("HandleGatewayReportPacket failed: %v", err)
	}
	var ack pb.GatewayReportAck
	if err := proto.Unmarshal(resp.Payload, &ack); err != nil {
		t.Fatalf("unmarshal gateway report ack failed: %v", err)
	}
	if ack.GetOk() || ack.GetReason() != "invalid_signature" {
		t.Fatalf("expected invalid signature reject, ack=%+v", ack)
	}
}

func TestGatewayReportRequiresApprovalForNonDefaultGateway(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	report := newSignedGatewayReport(t, testGatewayTicketSecret, "gw-denied", "127.0.0.1:51820", []string{"udp_blind_relay_v1"}, time.Now(), randomGatewayNonce(t))
	packet := newGatewayReportPacket(t, report)
	resp, err := ctrl.HandleGatewayReportPacket(packet)
	if err != nil {
		t.Fatalf("HandleGatewayReportPacket failed: %v", err)
	}
	var ack pb.GatewayReportAck
	if err := proto.Unmarshal(resp.Payload, &ack); err != nil {
		t.Fatalf("unmarshal gateway report ack failed: %v", err)
	}
	if ack.GetOk() || ack.GetReason() != "gateway not approved" {
		t.Fatalf("expected gateway report reject without admin approval, ack=%+v", ack)
	}
}

func TestGatewayApproveByIDAfterPendingReport(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	report := newSignedGatewayReport(t, testGatewayTicketSecret, "gw-pending", "127.0.0.1:51821", []string{"udp_blind_relay_v1"}, time.Now(), randomGatewayNonce(t))
	packet := newGatewayReportPacket(t, report)
	resp, err := ctrl.HandleGatewayReportPacket(packet)
	if err != nil {
		t.Fatalf("HandleGatewayReportPacket failed: %v", err)
	}
	var ack pb.GatewayReportAck
	if err := proto.Unmarshal(resp.Payload, &ack); err != nil {
		t.Fatalf("unmarshal gateway report ack failed: %v", err)
	}
	if ack.GetOk() {
		t.Fatalf("expected first report to be pending approval")
	}
	if err := ctrl.ApproveGatewayNodeByID("gw-pending"); err != nil {
		t.Fatalf("ApproveGatewayNodeByID failed: %v", err)
	}
	keepalive := newSignedGatewayReport(t, testGatewayTicketSecret, "gw-pending", "127.0.0.1:51821", []string{"udp_blind_relay_v1"}, time.Now(), randomGatewayNonce(t))
	resp, err = ctrl.HandleGatewayReportPacket(newGatewayReportPacket(t, keepalive))
	if err != nil {
		t.Fatalf("HandleGatewayReportPacket after approve failed: %v", err)
	}
	if err := proto.Unmarshal(resp.Payload, &ack); err != nil {
		t.Fatalf("unmarshal gateway report ack failed: %v", err)
	}
	if !ack.GetOk() {
		t.Fatalf("expected gateway report accepted after approval")
	}
}

func TestGatewayReportAllowsConfiguredDefaultGateway(t *testing.T) {
	ctrl := newControllerWithConfig(t, &config.Config{
		Gateway:             net.ParseIP("10.26.0.1"),
		Domain:              "ms.net",
		Netmask:             "255.255.255.0",
		DefaultGatewayID:    "gw-default",
		GatewayTicketSecret: testGatewayTicketSecret,
	})
	defer ctrl.Stop()
	report := newSignedGatewayReport(t, testGatewayTicketSecret, "gw-default", "gateway.middlescale.net:433", []string{"udp_blind_relay_v1"}, time.Now(), randomGatewayNonce(t))
	packet := newGatewayReportPacket(t, report)
	resp, err := ctrl.HandleGatewayReportPacket(packet)
	if err != nil {
		t.Fatalf("HandleGatewayReportPacket failed: %v", err)
	}
	var ack pb.GatewayReportAck
	if err := proto.Unmarshal(resp.Payload, &ack); err != nil {
		t.Fatalf("unmarshal gateway report ack failed: %v", err)
	}
	if !ack.GetOk() {
		t.Fatalf("expected default gateway auto-allowed, ack=%+v", ack)
	}
}

func TestGatewayGrantIncludesConfiguredCAPem(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "gateway-ca.pem")
	expected := []byte("-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n")
	if err := os.WriteFile(caPath, expected, 0o600); err != nil {
		t.Fatalf("write gateway ca failed: %v", err)
	}
	ctrl := newControllerWithConfig(t, &config.Config{
		Gateway:             net.ParseIP("10.26.0.1"),
		Domain:              "ms.net",
		Netmask:             "255.255.255.0",
		DefaultGatewayID:    "gw-ca",
		GatewayTicketSecret: testGatewayTicketSecret,
		GatewayCAPath:       caPath,
	})
	defer ctrl.Stop()
	ctrl.RegisterGatewayNode("gw-ca", "127.0.0.1:51826", []string{"udp_blind_relay_v1"}, "", nil)

	regResp := mustRegister(t, ctrl, newBaseRegisterReq("dev-ca-a", "node-ca-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.32"), Port: 3232})
	grant := regResp.GetGatewayAccessGrant()
	if grant == nil {
		t.Fatalf("expected gateway access grant in registration response")
	}
	if len(grant.GetGatewayChannels()) != 1 || !bytes.Equal(grant.GetGatewayChannels()[0].GetCaPem(), expected) {
		t.Fatalf("unexpected gateway channel ca pem: %+v", grant.GetGatewayChannels())
	}
}

func TestGatewayApprovalPersistsAcrossControllerRestart(t *testing.T) {
	stateDir := t.TempDir()
	ctrl := newControllerWithStateDir(t, &config.Config{
		Gateway:             net.ParseIP("10.26.0.1"),
		Domain:              "ms.net",
		Netmask:             "255.255.255.0",
		DefaultGatewayID:    "gw-default",
		GatewayTicketSecret: testGatewayTicketSecret,
	}, stateDir)
	report := newSignedGatewayReport(t, testGatewayTicketSecret, "gw-persist", "127.0.0.1:51821", []string{"udp_blind_relay_v1"}, time.Now(), randomGatewayNonce(t))
	resp, err := ctrl.HandleGatewayReportPacket(newGatewayReportPacket(t, report))
	if err != nil {
		t.Fatalf("HandleGatewayReportPacket failed: %v", err)
	}
	var ack pb.GatewayReportAck
	if err := proto.Unmarshal(resp.Payload, &ack); err != nil {
		t.Fatalf("unmarshal gateway report ack failed: %v", err)
	}
	if ack.GetOk() {
		t.Fatalf("expected report to wait for approval")
	}
	if err := ctrl.ApproveGatewayNodeByID("gw-persist"); err != nil {
		t.Fatalf("ApproveGatewayNodeByID failed: %v", err)
	}
	ctrl.Stop()

	reloaded := newControllerWithStateDir(t, &config.Config{
		Gateway:             net.ParseIP("10.26.0.1"),
		Domain:              "ms.net",
		Netmask:             "255.255.255.0",
		DefaultGatewayID:    "gw-default",
		GatewayTicketSecret: testGatewayTicketSecret,
	}, stateDir)
	defer reloaded.Stop()
	if !reloaded.isGatewayAllowed("gw-persist", "127.0.0.1:51821") {
		t.Fatalf("expected approved gateway to persist across restart")
	}
}

func TestGatewaySignedKeepaliveReplayRejected(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	ctrl.ApproveGatewayNode("gw-replay", "127.0.0.1:51822")
	first := newSignedGatewayReport(t, testGatewayTicketSecret, "gw-replay", "127.0.0.1:51822", []string{"udp_blind_relay_v1"}, time.Now(), randomGatewayNonce(t))
	resp, err := ctrl.HandleGatewayReportPacket(newGatewayReportPacket(t, first))
	if err != nil {
		t.Fatalf("first HandleGatewayReportPacket failed: %v", err)
	}
	var ack pb.GatewayReportAck
	if err := proto.Unmarshal(resp.Payload, &ack); err != nil {
		t.Fatalf("unmarshal gateway report ack failed: %v", err)
	}
	if !ack.GetOk() {
		t.Fatalf("expected first report accepted, ack=%+v", ack)
	}
	resp, err = ctrl.HandleGatewayReportPacket(newGatewayReportPacket(t, first))
	if err != nil {
		t.Fatalf("replay HandleGatewayReportPacket failed: %v", err)
	}
	if err := proto.Unmarshal(resp.Payload, &ack); err != nil {
		t.Fatalf("unmarshal replay ack failed: %v", err)
	}
	if ack.GetOk() || ack.GetReason() != "replayed_nonce" {
		t.Fatalf("expected replay rejection, ack=%+v", ack)
	}
}

func TestGatewaySignedKeepaliveRejectsStaleTimestamp(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	ctrl.ApproveGatewayNode("gw-stale", "127.0.0.1:51823")
	first := newSignedGatewayReport(t, testGatewayTicketSecret, "gw-stale", "127.0.0.1:51823", []string{"udp_blind_relay_v1"}, time.Now(), randomGatewayNonce(t))
	if _, err := ctrl.HandleGatewayReportPacket(newGatewayReportPacket(t, first)); err != nil {
		t.Fatalf("first HandleGatewayReportPacket failed: %v", err)
	}
	stale := newSignedGatewayReport(t, testGatewayTicketSecret, "gw-stale", "127.0.0.1:51823", []string{"udp_blind_relay_v1"}, time.Now().Add(-3*gatewayReportFreshnessWindow), randomGatewayNonce(t))
	resp, err := ctrl.HandleGatewayReportPacket(newGatewayReportPacket(t, stale))
	if err != nil {
		t.Fatalf("stale HandleGatewayReportPacket failed: %v", err)
	}
	var ack pb.GatewayReportAck
	if err := proto.Unmarshal(resp.Payload, &ack); err != nil {
		t.Fatalf("unmarshal stale ack failed: %v", err)
	}
	if ack.GetOk() || ack.GetReason() != "stale_report_timestamp" {
		t.Fatalf("expected stale timestamp rejection, ack=%+v", ack)
	}
}

func TestRegistrationSkipsExpiredGatewayLease(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	ctrl.gatewayAllow["gw-default"] = "127.0.0.1:51824"
	ctrl.gatewayNodes["gw-default"] = GatewayNodeInfo{
		GatewayID:    "gw-default",
		Endpoint:     "127.0.0.1:51822",
		Capabilities: []string{"udp_blind_relay_v1"},
		UpdatedAt:    time.Now().Add(-2 * gatewayNodeLease),
	}
	regResp := mustRegister(t, ctrl, newBaseRegisterReq("dev-expired-a", "node-expired-a"), &net.UDPAddr{IP: net.ParseIP("1.1.1.3"), Port: 3333})
	grant := regResp.GetGatewayAccessGrant()
	if grant == nil {
		t.Fatalf("expected gateway access grant in registration response")
	}
	if len(grant.GetGatewayChannels()) == 0 || grant.GetGatewayChannels()[0].GetAddr() != "quic://127.0.0.1:51824" {
		t.Fatalf("expected expired gateway to be skipped")
	}
	if grant.GetGatewayChannels()[0].GetServerName() != "127.0.0.1" {
		t.Fatalf("unexpected gateway server name: %s", grant.GetGatewayChannels()[0].GetServerName())
	}
}

func TestRefreshGatewayGrantPacket(t *testing.T) {
	ctrl := newTestController(t)
	defer ctrl.Stop()
	ctrl.RegisterGatewayNode("gw-default", "127.0.0.1:51820", []string{"udp_blind_relay_v1"}, "", nil)

	regReq := newBaseRegisterReq("dev-refresh-a", "node-refresh-a")
	regResp := mustRegister(t, ctrl, regReq, &net.UDPAddr{IP: net.ParseIP("1.1.1.30"), Port: 3030})
	grant := regResp.GetGatewayAccessGrant()
	if grant == nil {
		t.Fatalf("expected gateway access grant in registration response")
	}

	req := &pb.RefreshGatewayGrantRequest{
		VirtualIp:     regResp.GetVirtualIp(),
		DeviceId:      regReq.GetDeviceId(),
		LastSessionId: grant.GetSessionId(),
		LastPolicyRev: grant.GetPolicyRev(),
	}
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal refresh gateway grant request failed: %v", err)
	}
	respPacket, err := ctrl.HandleRefreshGatewayGrantPacket(&protocol.Packet{
		Ver:       protocol.V3,
		Proto:     protocol.ProtocolService,
		AppProto:  protocol.AppProtoRefreshGatewayGrantRequest,
		SourceTTL: protocol.MAX_TTL,
		TTL:       protocol.MAX_TTL,
		SrcIP:     util.Uint32ToIP(regResp.GetVirtualIp()),
		DstIP:     util.Uint32ToIP(regResp.GetVirtualGateway()),
		Gateway:   true,
		Payload:   payload,
	})
	if err != nil {
		t.Fatalf("HandleRefreshGatewayGrantPacket failed: %v", err)
	}

	var resp pb.RefreshGatewayGrantResponse
	if err := proto.Unmarshal(respPacket.Payload, &resp); err != nil {
		t.Fatalf("unmarshal refresh gateway grant response failed: %v", err)
	}
	if !resp.GetHasUpdate() {
		t.Fatalf("expected refreshed grant, got %+v", resp)
	}
	if resp.GetGatewayAccessGrant() == nil {
		t.Fatalf("expected gateway access grant in refresh response")
	}
}

func TestRegistrationUsesConfiguredGroupNetwork(t *testing.T) {
	ctrl := newControllerWithConfig(t, &config.Config{
		Groups: map[string]config.GroupConfig{
			"g1.net": {Gateway: net.ParseIP("10.26.1.1"), Netmask: "255.255.255.0"},
			"g2.net": {Gateway: net.ParseIP("10.27.0.1"), Netmask: "255.255.0.0"},
		},
		DefaultGatewayID:    "gw-default",
		GatewayTicketSecret: testGatewayTicketSecret,
	})
	defer ctrl.Stop()
	req := newBaseRegisterReq("dev-g1-a", "node-g1-a")
	req.Token = "g1.net"
	resp := mustRegister(t, ctrl, req, &net.UDPAddr{IP: net.ParseIP("1.1.1.10"), Port: 1112})
	if resp.GetVirtualGateway() != util.IpToUint32(net.ParseIP("10.26.1.1")) {
		t.Fatalf("unexpected g1 gateway: %s", util.Uint32ToIP(resp.GetVirtualGateway()))
	}
	if resp.GetVirtualNetmask() != util.IpToUint32(net.ParseIP("255.255.255.0")) {
		t.Fatalf("unexpected g1 netmask: %s", util.Uint32ToIP(resp.GetVirtualNetmask()))
	}
}

func newTestController(t *testing.T) *Controller {
	t.Helper()
	return newControllerWithConfig(t, &config.Config{
		Gateway:             net.ParseIP("10.26.0.1"),
		Domain:              "ms.net",
		Netmask:             "255.255.255.0",
		DefaultGatewayID:    "gw-default",
		GatewayTicketSecret: testGatewayTicketSecret,
	})
}

func newControllerWithConfig(t *testing.T, cfg *config.Config) *Controller {
	t.Helper()
	stateDir := t.TempDir()
	return newControllerWithStateDir(t, cfg, stateDir)
}

func newControllerWithStateDir(t *testing.T, cfg *config.Config, stateDir string) *Controller {
	t.Helper()
	t.Setenv("UM_STORE_JSON_PATH", filepath.Join(stateDir, "um.json"))
	t.Setenv("GATEWAY_STORE_JSON_PATH", filepath.Join(stateDir, "gateways.json"))
	ctrl, err := NewController(cfg)
	if err != nil {
		t.Fatalf("NewController failed: %v", err)
	}
	return ctrl
}

func mustRegister(t *testing.T, ctrl *Controller, req *pb.RegistrationRequest, remoteAddr net.Addr) *pb.RegistrationResponse {
	t.Helper()
	if len(req.GetDevicePubKey()) == 0 {
		req.DevicePubKey = []byte("pk-" + req.GetDeviceId())
	}
	ensureAuthed(t, ctrl, req.GetToken(), req.GetDeviceId(), req.GetDevicePubKey())
	respPacket, err := ctrl.HandleRegistrationPacket(newRegistrationPacket(t, req), remoteAddr)
	if err != nil {
		t.Fatalf("HandleRegistrationPacket failed: %v", err)
	}
	var resp pb.RegistrationResponse
	if err := proto.Unmarshal(respPacket.Payload, &resp); err != nil {
		t.Fatalf("unmarshal registration response failed: %v", err)
	}
	gw, mask, err := ctrl.resolveGroupNetworkConfig(req.GetToken())
	if err != nil {
		t.Fatalf("resolveGroupNetworkConfig failed: %v", err)
	}
	if resp.GetVirtualGateway() != util.IpToUint32(gw) {
		t.Fatalf("unexpected virtual gateway: %d", resp.GetVirtualGateway())
	}
	if resp.GetVirtualNetmask() != util.MaskToUint32(mask) {
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

func randomGatewayNonce(t *testing.T) []byte {
	t.Helper()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("generate gateway nonce failed: %v", err)
	}
	return nonce
}

func newSignedGatewayReport(
	t *testing.T,
	secret string,
	gatewayID string,
	endpoint string,
	capabilities []string,
	reportTime time.Time,
	nonce []byte,
) *pb.GatewayReportRequest {
	t.Helper()
	report := &pb.GatewayReportRequest{
		GatewayId:    gatewayID,
		Capabilities: append([]string{}, capabilities...),
		ReportUnixMs: reportTime.UnixMilli(),
		Nonce:        append([]byte(nil), nonce...),
		GatewayChannels: []*pb.GatewayChannel{{
			Kind:       pb.GatewayChannelKind_GATEWAY_CHANNEL_QUIC,
			Addr:       "quic://" + endpoint,
			ServerName: "127.0.0.1",
		}},
		DefaultGatewayChannel: pb.GatewayChannelKind_GATEWAY_CHANNEL_QUIC,
	}
	signGatewayReportForTest(t, secret, report)
	return report
}

func signGatewayReportForTest(t *testing.T, secret string, report *pb.GatewayReportRequest) {
	t.Helper()
	proofBytes, err := marshalGatewayReportProof(report)
	if err != nil {
		t.Fatalf("marshalGatewayReportProof failed: %v", err)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	if _, err := mac.Write(proofBytes); err != nil {
		t.Fatalf("build gateway report signature failed: %v", err)
	}
	report.Signature = mac.Sum(nil)
}

func verifyHMACTicketSignature(secret string, ticket *pb.SignedGatewayTicket) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	if _, err := mac.Write(ticket.GetClaims()); err != nil {
		return false
	}
	return hmac.Equal(mac.Sum(nil), ticket.GetSignature())
}

func newGatewayReportPacket(t *testing.T, report *pb.GatewayReportRequest) *protocol.Packet {
	t.Helper()
	payload, err := proto.Marshal(report)
	if err != nil {
		t.Fatalf("marshal gateway report failed: %v", err)
	}
	return &protocol.Packet{
		Proto:    protocol.ProtocolService,
		AppProto: protocol.AppProtoGatewayReportRequest,
		SrcIP:    net.ParseIP("10.0.0.2"),
		DstIP:    net.ParseIP("0.0.0.1"),
		Gateway:  true,
		Payload:  payload,
	}
}

func ensureAuthed(t *testing.T, ctrl *Controller, group, deviceID string, devicePubKey []byte) {
	t.Helper()
	if ctrl.UMIsAuthedDevice(group, deviceID) {
		if err := ctrl.UMCheckAuthedDevice(group, deviceID, devicePubKey); err == nil {
			return
		}
	}
	createArgs := []string{fmt.Sprintf("user-%s-%s", group, deviceID)}
	if strings.Contains(group, ".") {
		createArgs = append(createArgs, group)
	}
	user, err := ctrl.UMCreateUser(createArgs[0], createArgs[1:]...)
	if err != nil {
		t.Fatalf("UMCreateUser failed: %v", err)
	}
	tk, err := ctrl.UMIssueDeviceTicket(user.UserID, group, time.Minute)
	if err != nil {
		t.Fatalf("UMIssueDeviceTicket failed: %v", err)
	}
	if _, err = ctrl.UMAuthDevice(user.UserID, group, deviceID, tk.Ticket, devicePubKey); err != nil {
		t.Fatalf("UMAuthDevice failed: %v", err)
	}
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
