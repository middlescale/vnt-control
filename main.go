package main

import (
	"context"
	"crypto/tls"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"vnt-control/config"
	"vnt-control/handlers"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	levelStr := os.Getenv("LOG_LEVEL")
	level, err := log.ParseLevel(strings.ToLower(levelStr))
	if err != nil {
		level = log.InfoLevel // 默认 info
	}
	log.SetLevel(level)

	// support overriding config path via CONFIG_PATH env (useful in docker-compose / CI)
	cfgPath := os.Getenv("CONFIG_PATH")
	if cfgPath == "" {
		cfgPath = "config.json"
	}
	log.Infof("Loading config from %s", cfgPath)
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	log.Infof("Config: %+v", cfg)

	// 支持测试模式：如果环境变量 TLS_CERT 和 TLS_KEY 存在，则直接加载本地证书（用于 docker-compose / CI）
	tlsCertPath := os.Getenv("TLS_CERT")
	tlsKeyPath := os.Getenv("TLS_KEY")

	var tlsConfig *tls.Config
	if tlsCertPath != "" && tlsKeyPath != "" {
		log.Infof("Loading TLS cert from env paths: %s, %s", tlsCertPath, tlsKeyPath)
		cert, err := tls.LoadX509KeyPair(tlsCertPath, tlsKeyPath)
		if err != nil {
			log.Fatalf("Failed to load TLS cert/key: %v", err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}
	} else {
		domain := "control.middlescale.net"
		cacheDir := "./cert-cache" // 证书缓存目录

		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(domain),
			Cache:      autocert.DirCache(cacheDir),
		}

		tlsConfig = m.TLSConfig()
		tlsConfig.MinVersion = tls.VersionTLS13
	}

	// 信号监听
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		<-sigs
		cancel()
	}()

	handlers.StartQuicServer(ctx, ":4433", cfg, tlsConfig)
}
