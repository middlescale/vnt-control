package handlers

import (
	"context"
	"crypto/tls"
	"net"
	"vnt-control/config"
	"vnt-control/protocol"
	protocol_pb "vnt-control/protocol/pb"

	"github.com/quic-go/quic-go"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

func StartQuicServer(ctx context.Context, addr string, cfg *config.Config, tlsConfig *tls.Config) {
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
			go handleSession(conn, cfg)
		}
	}
}

func handleSession(conn *quic.Conn, cfg *config.Config) {
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
			break
		}
		packet, err := protocol.Unmarshal(buf[:n])
		if err != nil {
			log.Printf("Packet unmarshal error: %v", err)
		} else {
			// 目前 Gateway 和 Control 混在一起，只处理 Gateway数据，不转发
			if !packet.Gateway {
				log.Infof("忽略非 Gateway Packet: %s", packet.DebugString())
			}

			// 只做 Service
			if packet.Proto != protocol.ProtocolService {
				log.Infof("忽略非 service 类型 Packet: %d", packet.Proto)
				continue
			}

			// 只处理 handshake 和 register 类型的 packet
			switch packet.AppProto {
			case protocol.AppProtoHandshakeRequest:
				log.Debugf("收到客户端 HandshakeRequest Packet: %s", packet.DebugString())
				var req protocol_pb.HandshakeRequest
				if err := proto.Unmarshal(packet.Payload, &req); err != nil {
					log.Errorf("HandshakeRequest unmarshal error: %v", err)
					break
				}

				if req.GetSecret() {
					log.Infof("handsshake request no need secret, ignored")
				}

				res := &protocol_pb.HandshakeResponse{
					Version: "goversion-1.0.0",
					Secret:  false,
				}
				resBytes, err := proto.Marshal(res)
				if err != nil {
					log.Errorf("HandshakeResponse marshal error: %v", err)
					break
				}
				// 构造响应 Packet
				respPacket := &protocol.Packet{
					Ver:       protocol.V2,
					Proto:     packet.Proto,
					AppProto:  protocol.AppProtoHandshakeResponse,
					SourceTTL: protocol.MAX_TTL,
					// ttl 不需要设置吗, vnts/ServerPacketHandler 里没有设置
					SrcIP:   net.IP(cfg.Gateway),
					DstIP:   packet.SrcIP,
					Gateway: true,
					Payload: resBytes,
				}

				// 目前不处理 handshake的加密算法

				// 写回响应
				_, err = stream.Write(respPacket.Marshal())
				if err != nil {
					log.Errorf("Write HandshakeResponse error: %v", err)
				}
			case protocol.AppProtoRegistrationRequest, protocol.AppProtoRegistrationResponse,
				protocol.AppProtoHandshakeResponse:
				log.Debugf("收到客户端 Packet: %s", packet.DebugString())
				// TODO: 这里处理 register 类型的 packet
			default:
				log.Debugf("忽略非 handshake/register 类型 Packet: %d", packet.AppProto)
			}
		}
		// 回显数据
		_, err = stream.Write(buf[:n])
		if err != nil {
			log.Printf("Write error: %v", err)
			break
		}
	}
}
