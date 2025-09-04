package main

import (
	"log"
	"net/http"
	"vnt-control/handlers"

	"golang.org/x/crypto/acme/autocert"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", handlers.StatusHandler)

	domain := "gateway.middlescale.net"
	cacheDir := "./cert-cache" // 证书缓存目录

	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
		Cache:      autocert.DirCache(cacheDir),
	}

	server := &http.Server{
		Addr:      ":443",
		Handler:   mux,
		TLSConfig: m.TLSConfig(),
	}

	log.Printf("Starting HTTPS server with Let's Encrypt on %s...", server.Addr)
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
