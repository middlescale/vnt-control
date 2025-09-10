package handlers

import (
	"context"
	"crypto/tls"
	"log"

	"github.com/quic-go/quic-go"
)

func StartQuicServer(ctx context.Context, addr string, tlsConfig *tls.Config) {
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
			go handleSession(conn)
		}
	}
}

func handleSession(conn *quic.Conn) {
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
		log.Printf("收到客户端数据: %s", buf[:n])
		// 回显数据
		_, err = stream.Write(buf[:n])
		if err != nil {
			log.Printf("Write error: %v", err)
			break
		}
	}
}
