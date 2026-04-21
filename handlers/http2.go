package handlers

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sdl-control/control"
	"time"

	log "github.com/sirupsen/logrus"
)

type http2ControlSession struct {
	reader  io.ReadCloser
	writer  http.ResponseWriter
	flusher http.Flusher
}

func (s *http2ControlSession) Read(p []byte) (int, error) {
	return s.reader.Read(p)
}

func (s *http2ControlSession) Write(p []byte) (int, error) {
	n, err := s.writer.Write(p)
	if err == nil {
		s.flusher.Flush()
	}
	return n, err
}

func (s *http2ControlSession) Close() error {
	return s.reader.Close()
}

func StartHTTP2Server(ctx context.Context, ctrl *control.Controller, addr string, tlsConfig *tls.Config) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/control", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "stream flush not supported", http.StatusInternalServerError)
			return
		}
		controller := http.NewResponseController(w)
		if err := controller.EnableFullDuplex(); err != nil {
			log.Debugf("EnableFullDuplex not available: %v", err)
		}
		w.Header().Set("content-type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()
		serveControlSession(ctrl, remoteAddrFromTCPRequest(r), &http2ControlSession{
			reader:  r.Body,
			writer:  w,
			flusher: flusher,
		})
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok"))
	})

	serverTLS := cloneTLSConfigForALPN(tlsConfig, "h2", "http/1.1")
	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		TLSConfig:         serverTLS,
		ReadHeaderTimeout: 5 * time.Second,
	}
	listener, err := tls.Listen("tcp", addr, serverTLS)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil && err != http.ErrServerClosed {
			log.Warnf("HTTP/2 shutdown error: %v", err)
		}
	}()
	go func() {
		log.Infof("HTTP/2 control server listening on %s", addr)
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Errorf("HTTP/2 listen error: %v", err)
		}
	}()
	return nil
}

func remoteAddrFromTCPRequest(r *http.Request) net.Addr {
	if tcpAddr, err := net.ResolveTCPAddr("tcp", r.RemoteAddr); err == nil {
		return tcpAddr
	}
	return networkStringAddr{network: "tcp", value: r.RemoteAddr}
}

func cloneTLSConfigForALPN(base *tls.Config, protos ...string) *tls.Config {
	cfg := base.Clone()
	cfg.NextProtos = appendNextProtos(cfg.NextProtos, protos...)
	return cfg
}

func appendNextProtos(existing []string, protos ...string) []string {
	result := append([]string(nil), existing...)
	for _, proto := range protos {
		found := false
		for _, current := range result {
			if current == proto {
				found = true
				break
			}
		}
		if !found {
			result = append(result, proto)
		}
	}
	return result
}

type networkStringAddr struct {
	network string
	value   string
}

func (a networkStringAddr) Network() string { return a.network }
func (a networkStringAddr) String() string  { return a.value }
