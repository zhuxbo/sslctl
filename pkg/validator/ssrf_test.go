package validator

import (
	"testing"
)

func TestCheckSSRF(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		wantErr bool
		desc    string
	}{
		// 回环地址（拒绝）
		{"loopback_v4", "127.0.0.1", true, "IPv4 回环"},
		{"loopback_v6", "::1", true, "IPv6 回环"},

		// 未指定地址（拒绝）
		{"unspecified_v4", "0.0.0.0", true, "IPv4 未指定"},
		{"unspecified_v6", "::", true, "IPv6 未指定"},

		// 内网 IP（拒绝）
		{"private_10", "10.0.0.1", true, "10.0.0.0/8"},
		{"private_10_edge", "10.255.255.255", true, "10.0.0.0/8 边界"},
		{"private_172_16", "172.16.0.1", true, "172.16.0.0/12"},
		{"private_172_31", "172.31.255.255", true, "172.16.0.0/12 边界"},
		{"private_192_168", "192.168.0.1", true, "192.168.0.0/16"},
		{"private_192_168_edge", "192.168.255.255", true, "192.168.0.0/16 边界"},

		// 链路本地地址（拒绝）
		{"link_local", "169.254.1.1", true, "链路本地"},
		{"cloud_metadata", "169.254.169.254", true, "云元数据端点"},

		// IPv4-mapped IPv6 地址（拒绝，验证 Go 标准库正确处理映射地址）
		{"mapped_loopback", "::ffff:127.0.0.1", true, "IPv4-mapped 回环"},
		{"mapped_private_10", "::ffff:10.0.0.1", true, "IPv4-mapped 10.x 内网"},
		{"mapped_private_192", "::ffff:192.168.1.1", true, "IPv4-mapped 192.168.x 内网"},
		{"mapped_link_local", "::ffff:169.254.169.254", true, "IPv4-mapped 云元数据"},
		{"mapped_unspecified", "::ffff:0.0.0.0", true, "IPv4-mapped 未指定"},

		// 公网地址（通过）
		{"public_google", "8.8.8.8", false, "Google DNS"},
		{"public_cloudflare", "1.1.1.1", false, "Cloudflare DNS"},

		// 非内网的 172.x（通过）
		{"non_private_172_15", "172.15.255.255", false, "172.15.x 非内网"},
		{"non_private_172_32", "172.32.0.1", false, "172.32.x 非内网"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckSSRF(tt.host)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckSSRF(%s) error = %v, wantErr %v (%s)", tt.host, err, tt.wantErr, tt.desc)
			}
		})
	}
}

func TestValidateAPIURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
		desc    string
	}{
		// 有效 URL（通过）
		{"https_remote", "https://api.example.com/v1", false, "HTTPS 外网"},
		{"https_with_port", "https://api.example.com:8443/v1", false, "HTTPS 带端口"},
		{"http_localhost", "http://localhost:8080/api", false, "HTTP localhost"},
		{"http_127", "http://127.0.0.1:8080/api", false, "HTTP 127.0.0.1"},
		{"http_ipv6_local", "http://[::1]:8080/api", false, "HTTP [::1]"},

		// 无效 scheme（拒绝）
		{"ftp_scheme", "ftp://example.com", true, "FTP 不允许"},

		// 空 host（拒绝）
		{"empty_host", "https://", true, "空 host"},

		// HTTP 非 localhost（拒绝）
		{"http_remote", "http://api.example.com/v1", true, "HTTP 远程服务器"},
		{"http_public_ip", "http://8.8.8.8/api", true, "HTTP 公网 IP"},

		// HTTPS + 内网 IP（拒绝，SSRF 防护）
		{"https_private_10", "https://10.0.0.1/api", true, "HTTPS 内网 10.x"},
		{"https_private_192", "https://192.168.1.1/api", true, "HTTPS 内网 192.168.x"},

		// localhost 在 isLocal 白名单中，跳过 SSRF 检查（通过）
		{"https_loopback", "https://127.0.0.1/api", false, "127.0.0.1 白名单"},
		{"https_ipv6_local", "https://[::1]/api", false, "::1 白名单"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAPIURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAPIURL(%s) error = %v, wantErr %v (%s)", tt.url, err, tt.wantErr, tt.desc)
			}
		})
	}
}
