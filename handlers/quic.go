package handlers

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sdl-control/control"
	"sdl-control/protocol"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	log "github.com/sirupsen/logrus"
)

type framedSession interface {
	io.Reader
	io.Writer
	io.Closer
}

type sessionStream struct {
	writer io.Writer
	mu     sync.Mutex
}

type streamHub struct {
	mu        sync.RWMutex
	byIP      map[uint32]*sessionStream
	ipsByAddr map[string]map[uint32]struct{}
}

func newStreamHub() *streamHub {
	return &streamHub{
		byIP:      make(map[uint32]*sessionStream),
		ipsByAddr: make(map[string]map[uint32]struct{}),
	}
}

func (h *streamHub) register(remoteAddr net.Addr, virtualIP uint32, writer io.Writer) {
	if remoteAddr == nil || virtualIP == 0 {
		return
	}
	addr := remoteAddr.String()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.byIP[virtualIP] = &sessionStream{writer: writer}
	ips := h.ipsByAddr[addr]
	if ips == nil {
		ips = make(map[uint32]struct{})
		h.ipsByAddr[addr] = ips
	}
	ips[virtualIP] = struct{}{}
}

func (h *streamHub) unregisterRemote(remoteAddr net.Addr) {
	if remoteAddr == nil {
		return
	}
	addr := remoteAddr.String()
	h.mu.Lock()
	defer h.mu.Unlock()
	if ips, ok := h.ipsByAddr[addr]; ok {
		for ip := range ips {
			delete(h.byIP, ip)
		}
		delete(h.ipsByAddr, addr)
	}
}

func (h *streamHub) writeToIP(virtualIP uint32, payload []byte) bool {
	h.mu.RLock()
	target, ok := h.byIP[virtualIP]
	h.mu.RUnlock()
	if !ok {
		return false
	}
	target.mu.Lock()
	defer target.mu.Unlock()
	err := writeFramedWriter(target.writer, payload)
	if err != nil {
		return false
	}
	return true
}

var quicStreams = newStreamHub()

func StartQuicServer(ctx context.Context, ctrl *control.Controller, addr string, tlsConfig *tls.Config) {
	listener, err := quic.ListenAddr(addr, tlsConfig, nil)
	if err != nil {
		log.Fatalf("QUIC listen error: %v", err)
	}
	log.Printf("QUIC server listening on %s", addr)
	for {
		select {
		case <-ctx.Done():
			log.Println("QUIC server shutting down...")
			listener.Close()
			return
		default:
			conn, err := listener.Accept(context.Background())
			if err != nil {
				log.Printf("Accept error: %v", err)
				continue
			}
			go handleSession(ctrl, conn)
		}
	}
}

func handleSession(ctrl *control.Controller, conn *quic.Conn) {
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		log.Printf("Stream error: %v", err)
		return
	}
	defer conn.CloseWithError(0, "")
	serveControlSession(ctrl, conn.RemoteAddr(), stream)
}

func serveControlSession(ctrl *control.Controller, remoteAddr net.Addr, session framedSession) {
	ctrl.TouchCipherSession(remoteAddr)
	defer quicStreams.unregisterRemote(remoteAddr)
	defer ctrl.LeaveByRemoteAddr(remoteAddr)
	defer session.Close()
	buf := make([]byte, 4096)
	frameBuf := make([]byte, 0, 8192)
	lastSweepMs := int64(0)
	for {
		n, err := session.Read(buf)
		if err != nil && !(err == io.EOF && n > 0) {
			if isExpectedSessionReadClose(err) {
				break
			}
			log.Warnf("Read error: %v", err)
			break
		}
		if n > 0 {
			frameBuf = append(frameBuf, buf[:n]...)
		}
		for {
			if len(frameBuf) < 4 {
				break
			}
			frameLen := int(binary.BigEndian.Uint32(frameBuf[:4]))
			if frameLen <= 0 || frameLen > 1<<20 {
				log.Printf("Invalid frame length: %d", frameLen)
				return
			}
			if len(frameBuf) < 4+frameLen {
				break
			}
			packetRaw := append([]byte(nil), frameBuf[4:4+frameLen]...)
			frameBuf = frameBuf[4+frameLen:]
			packet, err := protocol.Unmarshal(packetRaw)
			if err != nil {
				log.Printf("Unmarshal packet error: %v", err)
				continue
			}
			nowMs := time.Now().UnixMilli()
			if nowMs-lastSweepMs >= 1000 {
				ctrl.ReconcilePunchSessions(nowMs)
				lastSweepMs = nowMs
			}

			if packet.Proto == protocol.ProtocolService {
				var respPacket *protocol.Packet
				var err error
				var virtualIP uint32
				var deferredPushPackets []*protocol.Packet

				switch packet.AppProto {
				case protocol.AppProtoHandshakeRequest:
					respPacket, err = ctrl.HandleHandshakePacket(packet, remoteAddr)
					if err != nil {
						log.Errorf("HandleHandshakePacket error: %v", err)
						continue
					}
				case protocol.AppProtoRegistrationRequest:
					respPacket, virtualIP, err = ctrl.HandleRegistrationPacketWithVirtualIP(packet, remoteAddr)
					if err != nil {
						log.Errorf("HandleRegistrationPacket error: %v", err)
						errPacket, packetErr := ctrl.BuildRegistrationErrorPacket(packet, err)
						if packetErr != nil {
							log.Errorf("BuildRegistrationErrorPacket error: %v", packetErr)
							continue
						}
						if writeErr := writeFramedWriter(session, errPacket.Marshal()); writeErr != nil {
							log.Errorf("send registration error packet failed: %v", writeErr)
						}
						continue
					}
					quicStreams.register(remoteAddr, virtualIP, session)
					deferredPushPackets, err = ctrl.BuildPushDeviceListPacketsForPeerChange(virtualIP)
					if err != nil {
						log.Errorf("BuildPushDeviceListPacketsForPeerChange error: %v", err)
						deferredPushPackets = nil
					}
				case protocol.AppProtoPullDeviceList:
					respPacket, err = ctrl.HandlePullDeviceListPacket(packet)
					if err != nil {
						log.Errorf("HandlePullDeviceListPacket error: %v", err)
						continue
					}
				case protocol.AppProtoDeviceAuthRequest:
					respPacket, err = ctrl.HandleDeviceAuthPacket(packet)
					if err != nil {
						log.Errorf("HandleDeviceAuthPacket error: %v", err)
						continue
					}
				case protocol.AppProtoDeviceAuthProof:
					respPacket, err = ctrl.HandleDeviceAuthProofPacket(packet)
					if err != nil {
						log.Errorf("HandleDeviceAuthProofPacket error: %v", err)
						continue
					}
				case protocol.AppProtoGatewayReportRequest:
					respPacket, err = ctrl.HandleGatewayReportPacket(packet)
					if err != nil {
						log.Errorf("HandleGatewayReportPacket error: %v", err)
						continue
					}
				case protocol.AppProtoRefreshGatewayGrantRequest:
					respPacket, err = ctrl.HandleRefreshGatewayGrantPacket(packet)
					if err != nil {
						log.Errorf("HandleRefreshGatewayGrantPacket error: %v", err)
						continue
					}
				case protocol.AppProtoClientStatusInfo:
					err = ctrl.HandleClientStatusInfoPacket(packet)
					if err != nil {
						log.Errorf("HandleClientStatusInfoPacket error: %v", err)
					}
					startPackets, err := ctrl.BuildPunchStartPacketsFromStatus(packet)
					if err != nil {
						log.Errorf("BuildPunchStartPacketsFromStatus error: %v", err)
					} else {
						if len(startPackets) > 0 {
							log.Infof("status-triggered PunchStart packets: %d", len(startPackets))
						}
						for _, push := range startPackets {
							if push == nil || push.DstIP == nil {
								continue
							}
							if !quicStreams.writeToIP(ipToUint32(push.DstIP), push.Marshal()) {
								log.Warnf("status-triggered PunchStart dispatch failed: %s", push.DstIP)
							} else {
								log.Infof("status-triggered PunchStart dispatched: %s", push.DstIP)
							}
						}
					}
					continue
				case protocol.AppProtoPunchRequest:
					respPacket, err = ctrl.HandlePunchRequestPacket(packet)
					if err != nil {
						log.Errorf("HandlePunchRequestPacket error: %v", err)
						continue
					}
					startPackets, err := ctrl.BuildPunchStartPackets(packet)
					if err != nil {
						log.Errorf("BuildPunchStartPackets error: %v", err)
						continue
					}
					for _, push := range startPackets {
						if push == nil || push.DstIP == nil {
							continue
						}
						if !quicStreams.writeToIP(ipToUint32(push.DstIP), push.Marshal()) {
							log.Warnf("PunchStart dispatch failed, peer not available: %s", push.DstIP)
						}
					}
				case protocol.AppProtoPunchAck:
					err = ctrl.HandlePunchAckPacket(packet)
					if err != nil {
						log.Errorf("HandlePunchAckPacket error: %v", err)
					} else {
						log.Infof("PunchAck received from %s", packet.SrcIP)
					}
					continue
				case protocol.AppProtoPunchResult:
					err = ctrl.HandlePunchResultPacket(packet)
					if err != nil {
						log.Errorf("HandlePunchResultPacket error: %v", err)
					}
					continue
				default:
					log.Debugf("忽略非 service处理类型 Packet: %d", packet.AppProto)
					continue
				}
				if respPacket == nil {
					continue
				}
				if err := writeFramedWriter(session, respPacket.Marshal()); err != nil {
					log.Errorf("Write ServiceResponse error: %v", err)
					continue
				}
				for _, push := range deferredPushPackets {
					if push == nil || push.DstIP == nil {
						continue
					}
					if !quicStreams.writeToIP(ipToUint32(push.DstIP), push.Marshal()) {
						log.Warnf("PushDeviceList dispatch failed: %s", push.DstIP)
					} else {
						log.Infof("PushDeviceList dispatched: %s", push.DstIP)
					}
				}
			} else if packet.Proto == protocol.ProtocolControl {
				respPacket, err := ctrl.HandleControlPacket(packet, remoteAddr)
				if err != nil {
					log.Errorf("HandleControlPacket error: %v", err)
					continue
				}
				if respPacket == nil {
					continue
				}
				if err := writeFramedWriter(session, respPacket.Marshal()); err != nil {
					log.Errorf("Write ControlResponse error: %v", err)
				}
			} else {
				log.Infof("忽略非 Service/Control Packet: %s", packet.DebugString())
			}
		}
		if err == io.EOF {
			break
		}

	}
}

func isExpectedSessionReadClose(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "NO_ERROR") ||
		strings.Contains(msg, "Application error 0x0") ||
		strings.Contains(msg, "closed network connection")
}

func writeFramedStream(stream *quic.Stream, payload []byte) error {
	return writeFramedWriter(stream, payload)
}

func writeFramedWriter(writer io.Writer, payload []byte) error {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))
	if _, err := writer.Write(header); err != nil {
		return err
	}
	_, err := writer.Write(payload)
	return err
}

func ipToUint32(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
}
