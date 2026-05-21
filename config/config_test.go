package config

import (
	"net"
	"testing"
)

func validConfig() *Config {
	return &Config{
		DefaultGatewayID:    "gw-1",
		GatewayTicketSecret: "secret",
		DNSServiceAddr:      "127.0.0.1:53",
		ListenAddr:          ":443",
		AutoCertHTTPAddr:    ":80",
		DefaultDomain:       "ms.net",
		Domains: map[string]DomainConfig{
			"ms.net": {
				Groups: map[string]GroupConfig{
					"default": {
						Gateway: net.ParseIP("10.26.0.1"),
						Netmask: "255.255.255.0",
					},
				},
			},
		},
	}
}

func TestValidatePassesWithoutDedicatedHTTP3ListenAddr(t *testing.T) {
	cfg := validConfig()

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected config validation to pass without http3_listen_addr, got %v", err)
	}
}
