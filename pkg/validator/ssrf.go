// Package validator SSRF 防护校验
package validator

import (
	"fmt"
	"net"
	"net/url"
)

// CheckSSRF 检查 SSRF 风险
// 阻止访问内网 IP、回环地址、链路本地地址和云元数据端点
func CheckSSRF(host string) error {
	// 解析 IP 地址
	ips, err := net.LookupIP(host)
	if err != nil {
		// DNS 解析失败，拒绝请求以防止 DNS rebinding 攻击
		return fmt.Errorf("DNS lookup failed for %s: %w", host, err)
	}

	for _, ip := range ips {
		// 检查回环地址
		if ip.IsLoopback() {
			return fmt.Errorf("loopback address not allowed: %s", ip)
		}
		// 检查内网 IP (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
		if ip.IsPrivate() {
			return fmt.Errorf("private IP not allowed: %s", ip)
		}
		// 检查链路本地地址 (169.254.0.0/16)
		if ip.IsLinkLocalUnicast() {
			return fmt.Errorf("link-local address not allowed: %s", ip)
		}
		// 检查云元数据地址 (169.254.169.254)
		if ip.String() == "169.254.169.254" {
			return fmt.Errorf("cloud metadata endpoint not allowed")
		}
	}

	return nil
}

// ValidateAPIURL 校验 API URL 是否有效（包含 SSRF 防护）
// 仅 localhost/127.0.0.1 允许 HTTP，其他必须使用 HTTPS
func ValidateAPIURL(apiURL string) error {
	u, err := url.Parse(apiURL)
	if err != nil {
		return fmt.Errorf("invalid API URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("API URL must use HTTP or HTTPS, got: %s", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("API URL must have a valid host")
	}

	host := u.Hostname()
	isLocal := host == "localhost" || host == "127.0.0.1" || host == "::1"

	// HTTP 仅允许 localhost
	if u.Scheme == "http" && !isLocal {
		return fmt.Errorf("HTTP only allowed for localhost, use HTTPS for remote servers")
	}

	// SSRF 防护：检查是否为内网 IP 或云元数据地址
	if !isLocal {
		if err := CheckSSRF(host); err != nil {
			return err
		}
	}

	return nil
}
