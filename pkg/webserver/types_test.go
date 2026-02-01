// Package webserver 类型定义测试
package webserver

import (
	"testing"
)

// TestServerType 测试服务器类型常量
func TestServerType(t *testing.T) {
	tests := []struct {
		serverType ServerType
		want       string
	}{
		{TypeNginx, "nginx"},
		{TypeApache, "apache"},
		{TypeDockerNginx, "docker-nginx"},
		{TypeDockerApache, "docker-apache"},
		{TypeUnknown, "unknown"},
	}

	for _, tt := range tests {
		if string(tt.serverType) != tt.want {
			t.Errorf("ServerType = %s, 期望 %s", tt.serverType, tt.want)
		}
	}
}

// TestSite 测试站点结构
func TestSite(t *testing.T) {
	site := Site{
		Name:            "example.com",
		ServerName:      "example.com",
		ServerAlias:     []string{"www.example.com", "api.example.com"},
		ConfigFile:      "/etc/nginx/sites-enabled/example.conf",
		ListenPorts:     []string{"443 ssl"},
		CertificatePath: "/etc/ssl/certs/example.crt",
		PrivateKeyPath:  "/etc/ssl/private/example.key",
		ChainFile:       "",
		ServerType:      TypeNginx,
		ContainerID:     "",
		ContainerName:   "",
		HostCertPath:    "",
		HostKeyPath:     "",
		VolumeMode:      false,
	}

	if site.Name != "example.com" {
		t.Errorf("Name = %s, 期望 example.com", site.Name)
	}
	if site.ServerType != TypeNginx {
		t.Errorf("ServerType = %s, 期望 nginx", site.ServerType)
	}
	if len(site.ServerAlias) != 2 {
		t.Errorf("ServerAlias 长度 = %d, 期望 2", len(site.ServerAlias))
	}
}

// TestSite_Docker 测试 Docker 站点结构
func TestSite_Docker(t *testing.T) {
	site := Site{
		Name:            "example.com",
		ServerName:      "example.com",
		ConfigFile:      "/etc/nginx/nginx.conf",
		CertificatePath: "/etc/ssl/cert.pem",
		PrivateKeyPath:  "/etc/ssl/key.pem",
		ServerType:      TypeDockerNginx,
		ContainerID:     "abc123def456",
		ContainerName:   "nginx-container",
		HostCertPath:    "/opt/docker/certs/cert.pem",
		HostKeyPath:     "/opt/docker/certs/key.pem",
		VolumeMode:      true,
	}

	if site.ServerType != TypeDockerNginx {
		t.Errorf("ServerType = %s, 期望 docker-nginx", site.ServerType)
	}
	if site.ContainerID != "abc123def456" {
		t.Errorf("ContainerID = %s, 期望 abc123def456", site.ContainerID)
	}
	if !site.VolumeMode {
		t.Error("VolumeMode 应为 true")
	}
}
