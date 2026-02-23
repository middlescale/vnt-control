package handlers

import (
	"context"
	"crypto/tls"
	"vnt-control/control"
	"vnt-control/protocol"

	"github.com/quic-go/quic-go"
	log "github.com/sirupsen/logrus"
)

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
	ctrl.TouchCipherSession(conn.RemoteAddr())
	defer ctrl.LeaveByRemoteAddr(conn.RemoteAddr())
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		log.Printf("Stream error: %v", err)
		return
	}
	defer stream.Close()
	buf := make([]byte, 4096)
	for {
		n, err := stream.Read(buf)
		if err != nil {
			log.Printf("Read error: %v", err)
			// 应该 break 吗？
			break
		}
		packet, err := protocol.Unmarshal(buf[:n])
		if err != nil {
			log.Printf("Unmarshal packet error: %v", err)
			continue
		}

		// 目前只处理 Gateway数据，不转发
		if !packet.Gateway {
			log.Infof("忽略非 Gateway Packet: %s", packet.DebugString())
			continue
		}

		// Protocol Service 和 Control 不需要上下文

		if packet.Proto == protocol.ProtocolService {
			var respPacket *protocol.Packet
			var err error

			switch packet.AppProto {

			// handshake
			case protocol.AppProtoHandshakeRequest:
				respPacket, err = ctrl.HandleHandshakePacket(packet)
				if err != nil {
					log.Errorf("HandleHandshakePacket error: %v", err)
					continue
				}

			// registration
			case protocol.AppProtoRegistrationRequest:
				respPacket, err = ctrl.HandleRegistrationPacket(packet, conn.RemoteAddr())
				if err != nil {
					log.Errorf("HandleRegistrationPacket error: %v", err)
					continue
				}
			case protocol.AppProtoPullDeviceList:
				respPacket, err = ctrl.HandlePullDeviceListPacket(packet)
				if err != nil {
					log.Errorf("HandlePullDeviceListPacket error: %v", err)
					continue
				}
			case protocol.AppProtoClientStatusInfo:
				err = ctrl.HandleClientStatusInfoPacket(packet)
				if err != nil {
					log.Errorf("HandleClientStatusInfoPacket error: %v", err)
				}
				continue

			default:
				log.Debugf("忽略非 service处理类型 Packet: %d", packet.AppProto)
				continue
			}
			if respPacket == nil {
				continue
			}
			_, err = stream.Write(respPacket.Marshal())
			if err != nil {
				log.Errorf("Write HandshakeResponse error: %v", err)
			}
		} else if packet.Proto == protocol.ProtocolControl {
			respPacket, err := ctrl.HandleControlPacket(packet, conn.RemoteAddr())
			if err != nil {
				log.Errorf("HandleControlPacket error: %v", err)
				continue
			}
			if respPacket == nil {
				continue
			}
			_, err = stream.Write(respPacket.Marshal())
			if err != nil {
				log.Errorf("Write ControlResponse error: %v", err)
			}
		} else {
			log.Infof("忽略非 Service/Control Packet: %s", packet.DebugString())
		}

	}
}
