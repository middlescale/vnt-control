package config

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"regexp"
)

// Config 配置结构体
// gateway: IPv4 地址
// netmask: IPv4 子网掩码
// domain: 域名字符串
type Config struct {
	Gateway string `json:"gateway"`
	Domain  string `json:"domain"`
	Netmask string `json:"netmask"`
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
	gateway := net.ParseIP(c.Gateway)
	if gateway == nil || gateway.To4() == nil {
		return errors.New("gateway 必须为合法 IPv4 地址")
	}
	// 检查是否为广播地址（最后一段为255）
	if gateway.To4()[3] == 255 {
		return errors.New("gateway 不能为广播地址")
	}
	// 检查是否为组播地址（224.0.0.0/4）
	if gateway.To4()[0] >= 224 && gateway.To4()[0] <= 239 {
		return errors.New("gateway 不能为组播地址")
	}
	// 检查是否为公网地址（排除常见私有网段）
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

	netmask := net.ParseIP(c.Netmask)
	if netmask == nil || netmask.To4() == nil {
		return errors.New("netmask 必须为合法 IPv4 地址")
	}
	// 校验 netmask 是否为标准掩码
	mask := netmask.To4()
	val := uint32(mask[0])<<24 | uint32(mask[1])<<16 | uint32(mask[2])<<8 | uint32(mask[3])
	if val == 0 || val == 0xFFFFFFFF {
		return errors.New("netmask 不能为全0或全255")
	}
	// 检查是否为连续的1后跟连续的0
	var foundZero bool = false
	for i := 31; i >= 0; i-- {
		if (val & (1 << uint(i))) == 0 {
			foundZero = true
		} else if foundZero {
			return errors.New("netmask 必须为连续的1后跟连续的0")
		}
	}

	// 域名校验（简单正则，支持主流域名）
	domainRe := regexp.MustCompile(`^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`)
	if !domainRe.MatchString(c.Domain) {
		return errors.New("domain 必须为合法域名")
	}
	return nil
}
