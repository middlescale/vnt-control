package main

import (
	"context"
	"crypto/tls"
	"os"
	"os/signal"
	"syscall"
	"vnt-control/handlers"

	"golang.org/x/crypto/acme/autocert"
)

func main() {
	domain := "control.middlescale.net"
	cacheDir := "./cert-cache" // 证书缓存目录

	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
		Cache:      autocert.DirCache(cacheDir),
	}

	tlsConfig := m.TLSConfig()
	tlsConfig.MinVersion = tls.VersionTLS13

	// 信号监听
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		<-sigs
		cancel()
	}()

	handlers.StartQuicServer(ctx, ":4433", tlsConfig)
}
