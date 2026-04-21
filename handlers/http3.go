package handlers

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sdl-control/control"
	"time"

	"github.com/quic-go/quic-go/http3"
	log "github.com/sirupsen/logrus"
)

type http3ControlSession struct {
	reader io.ReadCloser
	stream *http3.Stream
}

func (s *http3ControlSession) Read(p []byte) (int, error) {
	return s.reader.Read(p)
}

func (s *http3ControlSession) Write(p []byte) (int, error) {
	return s.stream.Write(p)
}

func (s *http3ControlSession) Close() error {
	readerErr := s.reader.Close()
	streamErr := s.stream.Close()
	if readerErr != nil {
		return readerErr
	}
	return streamErr
}

func StartHTTP3Server(ctx context.Context, ctrl *control.Controller, addr string, tlsConfig *tls.Config) {
	mux := http.NewServeMux()
	mux.HandleFunc("/control", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		streamer, ok := w.(http3.HTTPStreamer)
		if !ok {
			http.Error(w, "http3 stream takeover not supported", http.StatusInternalServerError)
			return
		}
		stream := streamer.HTTPStream()
		remoteAddr := remoteAddrFromRequest(r)
		serveControlSession(ctrl, remoteAddr, &http3ControlSession{
			reader: r.Body,
			stream: stream,
		})
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok"))
	})

	server := &http3.Server{
		Addr:      addr,
		TLSConfig: cloneTLSConfigForALPN(tlsConfig, "h3"),
		Handler:   mux,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil && err != http.ErrServerClosed {
			log.Warnf("HTTP/3 shutdown error: %v", err)
		}
	}()

	log.Printf("HTTP/3 control server listening on %s", addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTP/3 listen error: %v", err)
	}
}

func remoteAddrFromRequest(r *http.Request) net.Addr {
	if addr, ok := r.Context().Value(http3.RemoteAddrContextKey).(net.Addr); ok && addr != nil {
		return addr
	}
	if udpAddr, err := net.ResolveUDPAddr("udp", r.RemoteAddr); err == nil {
		return udpAddr
	}
	return networkStringAddr{network: "udp", value: r.RemoteAddr}
}
