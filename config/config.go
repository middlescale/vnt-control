package config

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"regexp"
	"strings"
)

// Config 配置结构体
// gateway: IPv4 地址
// netmask: IPv4 子网掩码
// domain: 域名字符串
type Config struct {
	Gateway             net.IP                  `json:"gateway"`
	Domain              string                  `json:"domain"`
	Netmask             string                  `json:"netmask"`
	Groups              map[string]GroupConfig  `json:"groups"`
	DefaultDomain       string                  `json:"default_domain"`
	Domains             map[string]DomainConfig `json:"domains"`
	DefaultGateway      string                  `json:"default_gateway"`
	GatewayTicketSecret string                  `json:"gateway_ticket_secret"`
	ListenAddr          string                  `json:"listen_addr"`
	AutoCertDomain      string                  `json:"autocert_domain"`
	CertCacheDir        string                  `json:"cert_cache_dir"`
	TLSCertPath         string                  `json:"tls_cert_path"`
	TLSKeyPath          string                  `json:"tls_key_path"`
	ClientCAPath        string                  `json:"client_ca_path"`
	RequireClientCert   bool                    `json:"require_client_cert"`
}

type GroupConfig struct {
	Gateway net.IP `json:"gateway"`
	Netmask string `json:"netmask"`
}

type DomainConfig struct {
	Groups map[string]GroupConfig `json:"groups"`
}

func LoadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate 校验配置字段格式
func (c *Config) Validate() error {
	if strings.TrimSpace(c.DefaultGateway) == "" {
		c.DefaultGateway = "gateway.middlescale.net:433"
	}
	if strings.TrimSpace(c.GatewayTicketSecret) == "" {
		c.GatewayTicketSecret = "dev-gateway-ticket-secret-change-me"
	}
	// 域名校验（简单正则，支持主流域名）
	domainRe := regexp.MustCompile(`^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`)
	groupRe := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}$`)
	if len(c.Domains) > 0 {
		if strings.TrimSpace(c.DefaultDomain) == "" {
			c.DefaultDomain = "ms.net"
		}
		if !domainRe.MatchString(c.DefaultDomain) {
			return errors.New("default_domain 必须为合法域名")
		}
		if _, ok := c.Domains[c.DefaultDomain]; !ok {
			return errors.New("default_domain 未在 domains 中配置")
		}
		for domain, dc := range c.Domains {
			if !domainRe.MatchString(domain) {
				return errors.New("domains 的 key 必须为合法域名(FQDN)")
			}
			if len(dc.Groups) == 0 {
				return errors.New("domains.<domain>.groups 不能为空")
			}
			for group, gc := range dc.Groups {
				if !groupRe.MatchString(group) {
					return errors.New("domains.<domain>.groups 的 key 必须为合法 group 名称")
				}
				if err := validateGatewayAndNetmask(gc.Gateway, gc.Netmask); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if len(c.Groups) == 0 {
		if err := validateGatewayAndNetmask(c.Gateway, c.Netmask); err != nil {
			return err
		}
		if !domainRe.MatchString(c.Domain) {
			return errors.New("domain 必须为合法域名")
		}
		return nil
	}
	for group, gc := range c.Groups {
		if !domainRe.MatchString(group) {
			return errors.New("groups 的 key 必须为合法域名")
		}
		if err := validateGatewayAndNetmask(gc.Gateway, gc.Netmask); err != nil {
			return err
		}
	}
	if c.Domain != "" {
		if !domainRe.MatchString(c.Domain) {
			return errors.New("domain 必须为合法域名")
		}
		if err := validateGatewayAndNetmask(c.Gateway, c.Netmask); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) EffectiveDefaultDomain() string {
	if strings.TrimSpace(c.DefaultDomain) != "" {
		return c.DefaultDomain
	}
	if strings.TrimSpace(c.Domain) != "" {
		return c.Domain
	}
	for domain := range c.Domains {
		return domain
	}
	return ""
}

func validateGatewayAndNetmask(gateway net.IP, netmaskStr string) error {
	if gateway == nil || gateway.To4() == nil {
		return errors.New("gateway 必须为合法 IPv4 地址")
	}
	if gateway.To4()[3] == 255 {
		return errors.New("gateway 不能为广播地址")
	}
	if gateway.To4()[0] >= 224 && gateway.To4()[0] <= 239 {
		return errors.New("gateway 不能为组播地址")
	}
	priv := false
	b := gateway.To4()
	switch {
	case b[0] == 10:
		priv = true
	case b[0] == 172 && b[1] >= 16 && b[1] <= 31:
		priv = true
	case b[0] == 192 && b[1] == 168:
		priv = true
	}
	if !priv {
		return errors.New("gateway 不能为公网地址")
	}
	netmask := net.ParseIP(netmaskStr)
	if netmask == nil || netmask.To4() == nil {
		return errors.New("netmask 必须为合法 IPv4 地址")
	}
	mask := netmask.To4()
	val := uint32(mask[0])<<24 | uint32(mask[1])<<16 | uint32(mask[2])<<8 | uint32(mask[3])
	if val == 0 || val == 0xFFFFFFFF {
		return errors.New("netmask 不能为全0或全255")
	}
	foundZero := false
	for i := 31; i >= 0; i-- {
		if (val & (1 << uint(i))) == 0 {
			foundZero = true
		} else if foundZero {
			return errors.New("netmask 必须为连续的1后跟连续的0")
		}
	}
	return nil
}
