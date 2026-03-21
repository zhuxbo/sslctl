// Package deploy 证书部署命令测试
package deploy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/testdata/certs"
)

// TestDeployToBinding_Nginx 测试 Nginx 部署
func TestDeployToBinding_Nginx(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	testCert, err := certs.GenerateValidCert("example.com", nil)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	binding := &config.SiteBinding{
		ServerName: "example.com",
		ServerType: config.ServerTypeNginx,
		Enabled:    true,
		Paths: config.BindingPaths{
			Certificate: certPath,
			PrivateKey:  keyPath,
		},
		Reload: config.ReloadConfig{
			TestCommand:   "",
			ReloadCommand: "",
		},
	}

	certData := &fetcher.CertData{
		OrderID:          12345,
		Cert:             testCert.CertPEM,
		IntermediateCert: "",
	}

	err = deployToBinding(binding, certData, testCert.KeyPEM, nil)
	if err != nil {
		t.Fatalf("deployToBinding() error = %v", err)
	}

	// 验证证书文件已创建
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("证书文件未创建")
	}

	// 验证私钥文件已创建
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("私钥文件未创建")
	}

	// 验证私钥权限
	info, _ := os.Stat(keyPath)
	if info.Mode().Perm() != 0600 {
		t.Errorf("私钥权限 = %o, 期望 0600", info.Mode().Perm())
	}
}

// TestDeployToBinding_Apache 测试 Apache 部署
func TestDeployToBinding_Apache(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")
	chainPath := filepath.Join(tmpDir, "chain.pem")

	testCert, err := certs.GenerateValidCert("example.com", nil)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	intermediateCert, _ := certs.GenerateValidCert("Intermediate CA", nil)

	binding := &config.SiteBinding{
		ServerName: "example.com",
		ServerType: config.ServerTypeApache,
		Enabled:    true,
		Paths: config.BindingPaths{
			Certificate: certPath,
			PrivateKey:  keyPath,
			ChainFile:   chainPath,
		},
		Reload: config.ReloadConfig{
			TestCommand:   "",
			ReloadCommand: "",
		},
	}

	certData := &fetcher.CertData{
		OrderID:          12345,
		Cert:             testCert.CertPEM,
		IntermediateCert: intermediateCert.CertPEM,
	}

	err = deployToBinding(binding, certData, testCert.KeyPEM, nil)
	if err != nil {
		t.Fatalf("deployToBinding() error = %v", err)
	}

	// 验证所有文件已创建
	for _, path := range []string{certPath, keyPath, chainPath} {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("文件未创建: %s", path)
		}
	}
}

// TestDeployToBinding_UnsupportedType 测试不支持的服务器类型
func TestDeployToBinding_UnsupportedType(t *testing.T) {
	tmpDir := t.TempDir()

	testCert, _ := certs.GenerateValidCert("example.com", nil)

	binding := &config.SiteBinding{
		ServerName: "example.com",
		ServerType: "unsupported",
		Enabled:    true,
		Paths: config.BindingPaths{
			Certificate: filepath.Join(tmpDir, "cert.pem"),
			PrivateKey:  filepath.Join(tmpDir, "key.pem"),
		},
	}

	certData := &fetcher.CertData{
		Cert: testCert.CertPEM,
	}

	err := deployToBinding(binding, certData, testCert.KeyPEM, nil)
	if err == nil {
		t.Error("期望返回错误，但实际成功")
	}
}

// TestDeployToBinding_CreateDirectory 测试目录自动创建
func TestDeployToBinding_CreateDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	nestedDir := filepath.Join(tmpDir, "subdir1", "subdir2")
	certPath := filepath.Join(nestedDir, "cert.pem")
	keyPath := filepath.Join(nestedDir, "key.pem")

	testCert, _ := certs.GenerateValidCert("example.com", nil)

	binding := &config.SiteBinding{
		ServerName: "example.com",
		ServerType: config.ServerTypeNginx,
		Enabled:    true,
		Paths: config.BindingPaths{
			Certificate: certPath,
			PrivateKey:  keyPath,
		},
	}

	certData := &fetcher.CertData{
		Cert: testCert.CertPEM,
	}

	err := deployToBinding(binding, certData, testCert.KeyPEM, nil)
	if err != nil {
		t.Fatalf("deployToBinding() error = %v", err)
	}

	// 验证目录已创建
	if _, err := os.Stat(nestedDir); os.IsNotExist(err) {
		t.Error("嵌套目录未创建")
	}
}

// TestDeployToBinding_DockerNginx 测试 Docker Nginx 部署
func TestDeployToBinding_DockerNginx(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	testCert, _ := certs.GenerateValidCert("example.com", nil)

	binding := &config.SiteBinding{
		ServerName: "example.com",
		ServerType: config.ServerTypeDockerNginx,
		Enabled:    true,
		Paths: config.BindingPaths{
			Certificate: certPath,
			PrivateKey:  keyPath,
		},
	}

	certData := &fetcher.CertData{
		Cert: testCert.CertPEM,
	}

	err := deployToBinding(binding, certData, testCert.KeyPEM, nil)
	if err != nil {
		t.Fatalf("deployToBinding() error = %v", err)
	}

	// 验证文件已创建
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("证书文件未创建")
	}
}

// TestDeployToBinding_DockerApache 测试 Docker Apache 部署
func TestDeployToBinding_DockerApache(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	testCert, _ := certs.GenerateValidCert("example.com", nil)

	binding := &config.SiteBinding{
		ServerName: "example.com",
		ServerType: config.ServerTypeDockerApache,
		Enabled:    true,
		Paths: config.BindingPaths{
			Certificate: certPath,
			PrivateKey:  keyPath,
		},
	}

	certData := &fetcher.CertData{
		Cert: testCert.CertPEM,
	}

	err := deployToBinding(binding, certData, testCert.KeyPEM, nil)
	if err != nil {
		t.Fatalf("deployToBinding() error = %v", err)
	}

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("证书文件未创建")
	}
}

// TestIsApacheType 测试 Apache 类型判断
func TestIsApacheType(t *testing.T) {
	tests := []struct {
		serverType string
		want       bool
	}{
		{config.ServerTypeApache, true},
		{config.ServerTypeDockerApache, true},
		{"apache", true},
		{"docker-apache", true},
		{config.ServerTypeNginx, false},
		{config.ServerTypeDockerNginx, false},
		{"nginx", false},
		{"docker-nginx", false},
		{"unknown", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.serverType, func(t *testing.T) {
			got := isApacheType(tt.serverType)
			if got != tt.want {
				t.Errorf("isApacheType(%q) = %v, want %v", tt.serverType, got, tt.want)
			}
		})
	}
}

// TestBuildBindingFromScanResult 测试从扫描结果构造绑定
func TestBuildBindingFromScanResult(t *testing.T) {
	tmpDir := t.TempDir()
	cfgManager, _ := config.NewConfigManagerWithDir(tmpDir)

	tests := []struct {
		name           string
		site           *config.ScannedSite
		wantServerType string
		wantDocker     bool
		wantChainFile  string // 期望的 ChainFile 值
	}{
		{
			name: "本地 Nginx 站点",
			site: &config.ScannedSite{
				ServerName:      "example.com",
				Source:          "local",
				ConfigFile:      "/etc/nginx/sites-enabled/example.conf",
				CertificatePath: "/etc/ssl/example.com/cert.pem",
				PrivateKeyPath:  "/etc/ssl/example.com/key.pem",
			},
			wantServerType: config.ServerTypeNginx,
			wantDocker:     false,
		},
		{
			name: "本地 Apache 站点（fullchain 模式）",
			site: &config.ScannedSite{
				ServerName:      "apache-site.com",
				Source:          "local",
				ConfigFile:      "/etc/apache2/sites-enabled/apache-site.conf",
				CertificatePath: "/etc/ssl/apache-site.com/cert.pem",
				PrivateKeyPath:  "/etc/ssl/apache-site.com/key.pem",
			},
			wantServerType: config.ServerTypeApache,
			wantDocker:     false,
		},
		{
			name: "本地 Apache 站点（有 ChainFile）",
			site: &config.ScannedSite{
				ServerName:      "apache-chain.com",
				Source:          "local",
				ConfigFile:      "/etc/apache2/sites-enabled/apache-chain.conf",
				CertificatePath: "/etc/ssl/apache-chain.com/cert.pem",
				PrivateKeyPath:  "/etc/ssl/apache-chain.com/key.pem",
				ChainFilePath:   "/etc/ssl/apache-chain.com/chain.pem",
			},
			wantServerType: config.ServerTypeApache,
			wantDocker:     false,
			wantChainFile:  "/etc/ssl/apache-chain.com/chain.pem",
		},
		{
			name: "Docker Nginx 站点",
			site: &config.ScannedSite{
				ServerName:    "docker-site.com",
				Source:        "docker",
				ContainerName: "nginx-container",
				ConfigFile:    "/etc/nginx/conf.d/default.conf",
				HostCertPath:  "/opt/certs/docker-site/cert.pem",
				HostKeyPath:   "/opt/certs/docker-site/key.pem",
				VolumeMode:    true,
			},
			wantServerType: config.ServerTypeDockerNginx,
			wantDocker:     true,
		},
		{
			name: "Docker Apache 站点",
			site: &config.ScannedSite{
				ServerName:    "docker-apache.com",
				Source:        "docker",
				ContainerName: "httpd-container",
				ConfigFile:    "/etc/httpd/conf.d/ssl.conf",
			},
			wantServerType: config.ServerTypeDockerApache,
			wantDocker:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binding := buildBindingFromScanResult(tt.site, cfgManager)

			if binding.ServerType != tt.wantServerType {
				t.Errorf("ServerType = %s, want %s", binding.ServerType, tt.wantServerType)
			}

			if binding.ServerName != tt.site.ServerName {
				t.Errorf("ServerName = %s, want %s", binding.ServerName, tt.site.ServerName)
			}

			if !binding.Enabled {
				t.Error("Enabled should be true")
			}

			if tt.wantDocker && binding.Docker == nil {
				t.Error("Docker info should not be nil")
			}

			if !tt.wantDocker && binding.Docker != nil {
				t.Error("Docker info should be nil for local site")
			}

			// Docker 站点不应设置 Reload 命令（由 Docker deployer 内部处理）
			if tt.wantDocker {
				if binding.Reload.TestCommand != "" || binding.Reload.ReloadCommand != "" {
					t.Errorf("Docker 站点不应设置 Reload 命令, got test=%s reload=%s",
						binding.Reload.TestCommand, binding.Reload.ReloadCommand)
				}
			}

			// ChainFile 应与扫描结果一致
			if binding.Paths.ChainFile != tt.wantChainFile {
				t.Errorf("ChainFile = %s, want %s", binding.Paths.ChainFile, tt.wantChainFile)
			}
		})
	}
}

// TestGetSiteBindingForLocal_ConfigPriority 测试 config.json 优先
func TestGetSiteBindingForLocal_ConfigPriority(t *testing.T) {
	tmpDir := t.TempDir()
	cfgManager, _ := config.NewConfigManagerWithDir(tmpDir)

	// 添加证书配置到 config.json
	cert := &config.CertConfig{
		CertName: "test-cert",
		OrderID:  1,
		Enabled:  true,
		Bindings: []config.SiteBinding{
			{
				ServerName: "config-site.com",
				ServerType: config.ServerTypeNginx,
				Enabled:    true,
				Paths: config.BindingPaths{
					Certificate: "/custom/path/cert.pem",
					PrivateKey:  "/custom/path/key.pem",
				},
			},
		},
	}
	_ = cfgManager.AddCert(cert)

	// 测试从 config.json 获取
	binding, err := getSiteBindingForLocal(cfgManager, "config-site.com")
	if err != nil {
		t.Fatalf("getSiteBindingForLocal() error = %v", err)
	}

	// 应该返回 config.json 中的路径
	if binding.Paths.Certificate != "/custom/path/cert.pem" {
		t.Errorf("Certificate = %s, want /custom/path/cert.pem", binding.Paths.Certificate)
	}
}

// TestGetSiteBindingForLocal_ScanFallback 测试回退到 scan-result.json
func TestGetSiteBindingForLocal_ScanFallback(t *testing.T) {
	tmpDir := t.TempDir()
	cfgManager, _ := config.NewConfigManagerWithDir(tmpDir)

	// 创建 scan-result.json（需要写入系统路径 /opt/sslctl/）
	scanResult := &config.ScanResult{
		Sites: []config.ScannedSite{
			{
				ServerName:      "scan-site.com",
				Source:          "local",
				ConfigFile:      "/etc/nginx/sites-enabled/scan-site.conf",
				CertificatePath: "/etc/ssl/scan-site/cert.pem",
				PrivateKeyPath:  "/etc/ssl/scan-site/key.pem",
			},
		},
	}
	if err := config.SaveScanResult(scanResult); err != nil {
		t.Skipf("跳过测试：无法写入 scan-result.json（需要 root 权限）: %v", err)
	}
	// 清理
	defer func() {
		_ = os.Remove(config.GetScanResultPath())
	}()

	// 测试从 scan-result.json 获取（config.json 中不存在）
	binding, err := getSiteBindingForLocal(cfgManager, "scan-site.com")
	if err != nil {
		t.Fatalf("getSiteBindingForLocal() error = %v", err)
	}

	if binding.ServerName != "scan-site.com" {
		t.Errorf("ServerName = %s, want scan-site.com", binding.ServerName)
	}

	if binding.ServerType != config.ServerTypeNginx {
		t.Errorf("ServerType = %s, want nginx", binding.ServerType)
	}
}

// TestGetSiteBindingForLocal_NotFound 测试站点不存在
func TestGetSiteBindingForLocal_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	cfgManager, _ := config.NewConfigManagerWithDir(tmpDir)

	// 创建空的 scan-result.json
	scanResult := &config.ScanResult{Sites: []config.ScannedSite{}}
	if err := config.SaveScanResult(scanResult); err != nil {
		t.Skipf("跳过测试：无法写入 scan-result.json: %v", err)
	}
	defer func() {
		_ = os.Remove(config.GetScanResultPath())
	}()

	// 测试站点不存在
	_, err := getSiteBindingForLocal(cfgManager, "nonexistent.com")
	if err == nil {
		t.Error("getSiteBindingForLocal() should return error for nonexistent site")
	}
}

// TestGetSiteBindingForLocal_DisabledBinding 测试禁用的绑定
func TestGetSiteBindingForLocal_DisabledBinding(t *testing.T) {
	tmpDir := t.TempDir()
	cfgManager, _ := config.NewConfigManagerWithDir(tmpDir)

	// 添加禁用的绑定
	cert := &config.CertConfig{
		CertName: "test-cert",
		OrderID:  1,
		Enabled:  true,
		Bindings: []config.SiteBinding{
			{
				ServerName: "disabled-site.com",
				ServerType: config.ServerTypeNginx,
				Enabled:    false, // 禁用
				Paths: config.BindingPaths{
					Certificate: "/path/cert.pem",
					PrivateKey:  "/path/key.pem",
				},
			},
		},
	}
	_ = cfgManager.AddCert(cert)

	// 获取绑定（应该成功，但 Enabled=false）
	binding, err := getSiteBindingForLocal(cfgManager, "disabled-site.com")
	if err != nil {
		t.Fatalf("getSiteBindingForLocal() error = %v", err)
	}

	// 验证绑定是禁用状态
	if binding.Enabled {
		t.Error("binding.Enabled should be false")
	}
}

func TestDetectServerType(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name     string
		content  string
		path     string
		isDocker bool
		want     string
	}{
		{
			name:    "Apache VirtualHost 关键词",
			content: "<VirtualHost *:443>\n    ServerName example.com\n</VirtualHost>",
			want:    config.ServerTypeApache,
		},
		{
			name:    "Apache SSLCertificateFile 关键词",
			content: "SSLCertificateFile /etc/ssl/cert.crt",
			want:    config.ServerTypeApache,
		},
		{
			name:    "Nginx server 块关键词",
			content: "server {\n    listen 443 ssl;\n}",
			want:    config.ServerTypeNginx,
		},
		{
			name:    "Nginx ssl_certificate 关键词",
			content: "ssl_certificate /etc/ssl/cert.crt;",
			want:    config.ServerTypeNginx,
		},
		{
			name:     "Docker + Apache",
			content:  "<VirtualHost *:80>\n</VirtualHost>",
			isDocker: true,
			want:     config.ServerTypeDockerApache,
		},
		{
			name:     "Docker + Nginx",
			content:  "server {\n    listen 80;\n}",
			isDocker: true,
			want:     config.ServerTypeDockerNginx,
		},
		{
			name: "路径包含 apache",
			path: "/etc/apache2/sites-enabled/default.conf",
			want: config.ServerTypeApache,
		},
		{
			name: "路径包含 httpd",
			path: "/etc/httpd/conf.d/ssl.conf",
			want: config.ServerTypeApache,
		},
		{
			name: "默认为 Nginx",
			path: "/etc/some/unknown.conf",
			want: config.ServerTypeNginx,
		},
		{
			name:     "Docker 默认为 Docker Nginx",
			path:     "/etc/some/unknown.conf",
			isDocker: true,
			want:     config.ServerTypeDockerNginx,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			site := &config.ScannedSite{}
			if tt.isDocker {
				site.Source = "docker"
			}

			if tt.content != "" {
				confPath := filepath.Join(tmpDir, tt.name+".conf")
				_ = os.WriteFile(confPath, []byte(tt.content), 0644)
				site.ConfigFile = confPath
			} else if tt.path != "" {
				site.ConfigFile = tt.path
			}

			got := detectServerType(site)
			if got != tt.want {
				t.Errorf("detectServerType() = %s, want %s", got, tt.want)
			}
		})
	}
}
