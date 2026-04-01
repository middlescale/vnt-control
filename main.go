package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"os/signal"
	"sdl-control/config"
	"sdl-control/control"
	"sdl-control/handlers"
	"strconv"
	"strings"
	"syscall"

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
		cfgPath = "config/config.json"
	}
	if _, err := os.Stat(cfgPath); err != nil {
		cfgPath = "config.json"
	}
	log.Infof("Loading config from %s", cfgPath)
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	log.Infof(
		"Config loaded: listen_addr=%s default_domain=%s default_gateway_id=%s domains=%d require_client_cert=%t",
		cfg.ListenAddr,
		cfg.EffectiveDefaultDomain(),
		cfg.DefaultGatewayID,
		len(cfg.Domains),
		cfg.RequireClientCert,
	)

	listenAddr := firstNonEmpty(os.Getenv("LISTEN_ADDR"), cfg.ListenAddr)
	if listenAddr == "" {
		listenAddr = ":4433"
	}

	// 支持测试模式：如果环境变量 TLS_CERT 和 TLS_KEY 存在，则直接加载本地证书（用于 docker-compose / CI）
	tlsCertPath := firstNonEmpty(os.Getenv("TLS_CERT"), cfg.TLSCertPath)
	tlsKeyPath := firstNonEmpty(os.Getenv("TLS_KEY"), cfg.TLSKeyPath)
	clientCAPath := firstNonEmpty(os.Getenv("TLS_CLIENT_CA"), cfg.ClientCAPath)
	requireClientCert := cfg.RequireClientCert
	if requireClientCertStr := os.Getenv("TLS_REQUIRE_CLIENT_CERT"); requireClientCertStr != "" {
		parsed, err := strconv.ParseBool(requireClientCertStr)
		if err != nil {
			log.Fatalf("invalid TLS_REQUIRE_CLIENT_CERT value: %v", err)
		}
		requireClientCert = parsed
	}

	var tlsConfig *tls.Config
	var autocertHTTPAddr string
	var autocertHTTPHandler http.Handler
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
		domain := firstNonEmpty(os.Getenv("AUTOCERT_DOMAIN"), cfg.AutoCertDomain, cfg.EffectiveDefaultDomain())
		if domain == "" {
			log.Fatal("AUTOCERT_DOMAIN/domain is required when TLS cert/key are not provided")
		}
		autocertHTTPAddr = firstNonEmpty(os.Getenv("AUTOCERT_HTTP_ADDR"), cfg.AutoCertHTTPAddr)
		if autocertHTTPAddr == "" {
			autocertHTTPAddr = ":80"
		}
		cacheDir := firstNonEmpty(os.Getenv("CERT_CACHE_DIR"), cfg.CertCacheDir)
		if cacheDir == "" {
			cacheDir = "./cert-cache"
		}

		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(domain),
			Cache:      autocert.DirCache(cacheDir),
			Email:      firstNonEmpty(os.Getenv("AUTOCERT_EMAIL"), cfg.AutoCertEmail),
		}

		tlsConfig = m.TLSConfig()
		tlsConfig.MinVersion = tls.VersionTLS13
		autocertHTTPHandler = m.HTTPHandler(nil)
		log.Infof(
			"ACME enabled for domain=%s, http_challenge_addr=%s, cache_dir=%s",
			domain,
			autocertHTTPAddr,
			cacheDir,
		)
	}
	if clientCAPath != "" {
		clientCA, err := os.ReadFile(clientCAPath)
		if err != nil {
			log.Fatalf("failed to read client CA file: %v", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(clientCA) {
			log.Fatal("failed to parse client CA PEM")
		}
		tlsConfig.ClientCAs = caPool
		if requireClientCert {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		}
		log.Infof("Client certificate verification enabled (required=%t)", requireClientCert)
	}

	// 信号监听
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())

	ctrl, err := control.NewController(cfg)
	if err != nil {
		log.Fatalf("create controller failed: %v", err)
	}

	adminSocket := firstNonEmpty(os.Getenv("ADMIN_SOCKET_PATH"), "/tmp/sdl-control-admin.sock")
	if err := handlers.StartAdminUnixServer(ctx, ctrl, adminSocket); err != nil {
		log.Fatalf("start admin unix socket failed: %v", err)
	}
	if autocertHTTPHandler != nil {
		if err := handlers.StartHTTPServer(ctx, autocertHTTPAddr, autocertHTTPHandler); err != nil {
			log.Fatalf("start autocert http challenge server failed: %v", err)
		}
	}
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok"))
	})
	if err := handlers.StartHTTPSServer(ctx, listenAddr, tlsConfig.Clone(), healthMux); err != nil {
		log.Fatalf("start https health server failed: %v", err)
	}

	go func() {
		<-sigs
		cancel()
		ctrl.Stop()
	}()

	handlers.StartHTTP3Server(ctx, ctrl, listenAddr, tlsConfig)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
