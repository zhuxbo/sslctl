package docker

import (
	"testing"
)

// makeTestScanner 创建用于测试的 Scanner（不依赖 Docker）
func makeTestScanner(containerID, containerName string) *Scanner {
	client := NewClient(containerID)
	return &Scanner{
		client:       client,
		scannedFiles: make(map[string]bool),
	}
}

func TestParseConfig_SingleSSLServer(t *testing.T) {
	s := makeTestScanner("abc123", "test-nginx")
	info := &ContainerInfo{ID: "abc123", Name: "test-nginx"}

	config := `
server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    root /var/www/html;
}
`
	sites := s.parseConfig(config, "/etc/nginx/nginx.conf", info)
	if len(sites) != 1 {
		t.Fatalf("expected 1 site, got %d", len(sites))
	}
	site := sites[0]
	if site.ServerName != "example.com" {
		t.Errorf("ServerName = %q, want example.com", site.ServerName)
	}
	if site.CertificatePath != "/etc/nginx/ssl/cert.pem" {
		t.Errorf("CertificatePath = %q", site.CertificatePath)
	}
	if site.PrivateKeyPath != "/etc/nginx/ssl/key.pem" {
		t.Errorf("PrivateKeyPath = %q", site.PrivateKeyPath)
	}
	if site.Webroot != "/var/www/html" {
		t.Errorf("Webroot = %q", site.Webroot)
	}
	if site.ContainerID != "abc123" {
		t.Errorf("ContainerID = %q", site.ContainerID)
	}
}

func TestParseConfig_MultipleServers(t *testing.T) {
	s := makeTestScanner("abc123", "test-nginx")
	info := &ContainerInfo{ID: "abc123", Name: "test-nginx"}

	config := `
server {
    listen 80;
    server_name example.com;
    root /var/www/html;
}

server {
    listen 443 ssl;
    server_name secure.example.com;
    ssl_certificate /ssl/secure.crt;
    ssl_certificate_key /ssl/secure.key;
}

server {
    listen 443 ssl;
    server_name other.example.com;
    ssl_certificate /ssl/other.crt;
    ssl_certificate_key /ssl/other.key;
}
`
	sites := s.parseConfig(config, "/etc/nginx/nginx.conf", info)
	// HTTP-only server 没有 ssl_certificate，应该被过滤
	if len(sites) != 2 {
		t.Fatalf("expected 2 SSL sites, got %d", len(sites))
	}
	if sites[0].ServerName != "secure.example.com" {
		t.Errorf("sites[0].ServerName = %q", sites[0].ServerName)
	}
	if sites[1].ServerName != "other.example.com" {
		t.Errorf("sites[1].ServerName = %q", sites[1].ServerName)
	}
}

func TestParseConfig_ServerName(t *testing.T) {
	s := makeTestScanner("abc123", "test-nginx")
	info := &ContainerInfo{ID: "abc123", Name: "test-nginx"}

	tests := []struct {
		name           string
		config         string
		wantServerName string
		wantAliases    int
	}{
		{
			name: "多域名",
			config: `server {
    listen 443 ssl;
    server_name example.com www.example.com api.example.com;
    ssl_certificate /ssl/cert.pem;
    ssl_certificate_key /ssl/key.pem;
}`,
			wantServerName: "example.com",
			wantAliases:    2,
		},
		{
			name: "通配符域名",
			config: `server {
    listen 443 ssl;
    server_name *.example.com;
    ssl_certificate /ssl/cert.pem;
    ssl_certificate_key /ssl/key.pem;
}`,
			wantServerName: "*.example.com",
			wantAliases:    0,
		},
		{
			name: "下划线（默认服务器）",
			config: `server {
    listen 443 ssl;
    server_name _ default.com;
    ssl_certificate /ssl/cert.pem;
    ssl_certificate_key /ssl/key.pem;
}`,
			wantServerName: "default.com",
			wantAliases:    0,
		},
		{
			name: "通配符优先非通配符",
			config: `server {
    listen 443 ssl;
    server_name *.example.com specific.example.com;
    ssl_certificate /ssl/cert.pem;
    ssl_certificate_key /ssl/key.pem;
}`,
			wantServerName: "specific.example.com",
			wantAliases:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sites := s.parseConfig(tt.config, "/etc/nginx/conf.d/test.conf", info)
			if len(sites) != 1 {
				t.Fatalf("expected 1 site, got %d", len(sites))
			}
			if sites[0].ServerName != tt.wantServerName {
				t.Errorf("ServerName = %q, want %q", sites[0].ServerName, tt.wantServerName)
			}
			if len(sites[0].ServerAlias) != tt.wantAliases {
				t.Errorf("ServerAlias count = %d, want %d, aliases: %v", len(sites[0].ServerAlias), tt.wantAliases, sites[0].ServerAlias)
			}
		})
	}
}

func TestParseConfig_LocationBlock(t *testing.T) {
	s := makeTestScanner("abc123", "test-nginx")
	info := &ContainerInfo{ID: "abc123", Name: "test-nginx"}

	config := `
server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate /ssl/cert.pem;
    ssl_certificate_key /ssl/key.pem;
    root /var/www/html;

    location /static {
        root /var/www/static;
    }
}
`
	sites := s.parseConfig(config, "/etc/nginx/conf.d/test.conf", info)
	if len(sites) != 1 {
		t.Fatalf("expected 1 site, got %d", len(sites))
	}
	// root 应该是 server 级别的 /var/www/html，不是 location 里的
	if sites[0].Webroot != "/var/www/html" {
		t.Errorf("Webroot = %q, want /var/www/html", sites[0].Webroot)
	}
}

func TestParseConfig_NestedBraces(t *testing.T) {
	s := makeTestScanner("abc123", "test-nginx")
	info := &ContainerInfo{ID: "abc123", Name: "test-nginx"}

	config := `
server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate /ssl/cert.pem;
    ssl_certificate_key /ssl/key.pem;

    location / {
        if ($request_method = POST) {
            proxy_pass http://backend;
        }
    }

    location /api {
        proxy_pass http://api;
    }
}
`
	sites := s.parseConfig(config, "/etc/nginx/conf.d/test.conf", info)
	if len(sites) != 1 {
		t.Fatalf("expected 1 site, got %d", len(sites))
	}
	if sites[0].ServerName != "example.com" {
		t.Errorf("ServerName = %q", sites[0].ServerName)
	}
}

func TestParseConfig_CommentedOut(t *testing.T) {
	s := makeTestScanner("abc123", "test-nginx")
	info := &ContainerInfo{ID: "abc123", Name: "test-nginx"}

	config := `
server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate /ssl/cert.pem;
    ssl_certificate_key /ssl/key.pem;
    # ssl_certificate /ssl/old-cert.pem;
    # ssl_certificate_key /ssl/old-key.pem;
}
`
	sites := s.parseConfig(config, "/etc/nginx/conf.d/test.conf", info)
	if len(sites) != 1 {
		t.Fatalf("expected 1 site, got %d", len(sites))
	}
	if sites[0].CertificatePath != "/ssl/cert.pem" {
		t.Errorf("CertificatePath = %q, want /ssl/cert.pem", sites[0].CertificatePath)
	}
}

func TestParseConfig_IncompleteServer(t *testing.T) {
	s := makeTestScanner("abc123", "test-nginx")
	info := &ContainerInfo{ID: "abc123", Name: "test-nginx"}

	// 只有 ssl_certificate 没有 ssl_certificate_key
	config := `
server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate /ssl/cert.pem;
}
`
	sites := s.parseConfig(config, "/etc/nginx/conf.d/test.conf", info)
	if len(sites) != 0 {
		t.Errorf("expected 0 sites for incomplete server, got %d", len(sites))
	}
}

func TestParseConfig_ListenPorts(t *testing.T) {
	s := makeTestScanner("abc123", "test-nginx")
	info := &ContainerInfo{ID: "abc123", Name: "test-nginx"}

	config := `
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name example.com;
    ssl_certificate /ssl/cert.pem;
    ssl_certificate_key /ssl/key.pem;
}
`
	sites := s.parseConfig(config, "/etc/nginx/conf.d/test.conf", info)
	if len(sites) != 1 {
		t.Fatalf("expected 1 site, got %d", len(sites))
	}
	if len(sites[0].ListenPorts) != 2 {
		t.Errorf("ListenPorts count = %d, want 2", len(sites[0].ListenPorts))
	}
}

func TestParseConfig_QuotedPaths(t *testing.T) {
	s := makeTestScanner("abc123", "test-nginx")
	info := &ContainerInfo{ID: "abc123", Name: "test-nginx"}

	config := `
server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate "/ssl/cert.pem";
    ssl_certificate_key '/ssl/key.pem';
}
`
	sites := s.parseConfig(config, "/etc/nginx/conf.d/test.conf", info)
	if len(sites) != 1 {
		t.Fatalf("expected 1 site, got %d", len(sites))
	}
	if sites[0].CertificatePath != "/ssl/cert.pem" {
		t.Errorf("CertificatePath = %q, want /ssl/cert.pem", sites[0].CertificatePath)
	}
	if sites[0].PrivateKeyPath != "/ssl/key.pem" {
		t.Errorf("PrivateKeyPath = %q, want /ssl/key.pem", sites[0].PrivateKeyPath)
	}
}

func TestParseConfig_EmptyContent(t *testing.T) {
	s := makeTestScanner("abc123", "test-nginx")
	info := &ContainerInfo{ID: "abc123", Name: "test-nginx"}

	sites := s.parseConfig("", "/etc/nginx/nginx.conf", info)
	if len(sites) != 0 {
		t.Errorf("expected 0 sites for empty content, got %d", len(sites))
	}
}

func TestValidateContainerPath_Valid(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"simple path", "/etc/nginx/ssl/cert.pem"},
		{"deep path", "/var/www/html/sites/example.com/ssl/fullchain.pem"},
		{"root path", "/cert.pem"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateContainerPath(tt.path); err != nil {
				t.Errorf("validateContainerPath(%q) = %v, want nil", tt.path, err)
			}
		})
	}
}

func TestValidateContainerPath_DangerousChars(t *testing.T) {
	dangerousPaths := []string{
		"/etc/nginx/;rm -rf /",
		"/etc/nginx/&whoami",
		"/etc/nginx/|cat",
		"/etc/nginx/$HOME",
		"/etc/nginx/`id`",
		"/etc/nginx/(subshell)",
		"/etc/nginx/{braces}",
		"/etc/nginx/<redirect",
		"/etc/nginx/>output",
		"/etc/nginx/!negation",
		"/etc/nginx/\ninjection",
		"/etc/nginx/\rreturn",
		"/etc/nginx/'quote",
		"/etc/nginx/\"doublequote",
		"/etc/nginx/\\backslash",
		"/etc/nginx/*.glob",
		"/etc/nginx/?wildcard",
		"/etc/nginx/[bracket]",
	}

	for _, p := range dangerousPaths {
		t.Run(p, func(t *testing.T) {
			if err := validateContainerPath(p); err == nil {
				t.Errorf("validateContainerPath(%q) = nil, want error", p)
			}
		})
	}
}

func TestValidateContainerPath_RelativePath(t *testing.T) {
	if err := validateContainerPath("etc/nginx/cert.pem"); err == nil {
		t.Error("expected error for relative path")
	}
}

func TestValidateContainerPath_Empty(t *testing.T) {
	if err := validateContainerPath(""); err == nil {
		t.Error("expected error for empty path")
	}
}

func TestResolveHostPaths(t *testing.T) {
	client := NewClient("abc123")
	s := &Scanner{
		client:       client,
		scannedFiles: make(map[string]bool),
		mounts: []MountInfo{
			{Type: "bind", Source: "/host/ssl", Destination: "/etc/nginx/ssl", RW: true},
			{Type: "bind", Source: "/host/www", Destination: "/var/www", RW: true},
		},
	}

	site := &SSLSite{
		CertificatePath: "/etc/nginx/ssl/cert.pem",
		PrivateKeyPath:  "/etc/nginx/ssl/key.pem",
		Webroot:         "/var/www/html",
	}

	s.resolveHostPaths(site)

	if site.HostCertPath != "/host/ssl/cert.pem" {
		t.Errorf("HostCertPath = %q, want /host/ssl/cert.pem", site.HostCertPath)
	}
	if site.HostKeyPath != "/host/ssl/key.pem" {
		t.Errorf("HostKeyPath = %q, want /host/ssl/key.pem", site.HostKeyPath)
	}
	if site.HostWebroot != "/host/www/html" {
		t.Errorf("HostWebroot = %q, want /host/www/html", site.HostWebroot)
	}
	if !site.VolumeMode {
		t.Error("expected VolumeMode = true")
	}
}

func TestResolveHostPaths_NoMount(t *testing.T) {
	client := NewClient("abc123")
	s := &Scanner{
		client:       client,
		scannedFiles: make(map[string]bool),
		mounts:       []MountInfo{},
	}

	site := &SSLSite{
		CertificatePath: "/etc/nginx/ssl/cert.pem",
		PrivateKeyPath:  "/etc/nginx/ssl/key.pem",
	}

	s.resolveHostPaths(site)

	if site.HostCertPath != "" {
		t.Errorf("HostCertPath = %q, want empty", site.HostCertPath)
	}
	if site.VolumeMode {
		t.Error("expected VolumeMode = false")
	}
}
