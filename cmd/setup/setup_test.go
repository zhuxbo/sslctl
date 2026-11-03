// Package setup 一键部署命令测试
package setup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zhuxbo/sslctl/pkg/certops"
	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
	"github.com/zhuxbo/sslctl/pkg/matcher"
	"github.com/zhuxbo/sslctl/pkg/webserver"
	"github.com/zhuxbo/sslctl/testdata/certs"
)

// newTestDeployService 构建用于部署测试的 certops 服务（备份目录落在 dir 下）
func newTestDeployService(t *testing.T, dir string) *certops.Service {
	t.Helper()
	cm, err := config.NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	return certops.NewService(cm, logger.NewNopLogger())
}

// TestCreateBinding_Nginx 测试创建 Nginx 绑定
func TestCreateBinding_Nginx(t *testing.T) {
	tmpDir := t.TempDir()
	cfgManager, _ := config.NewConfigManagerWithDir(tmpDir)

	site := &matcher.ScannedSiteInfo{
		ServerName:  "example.com",
		ServerAlias: []string{"www.example.com"},
		ConfigFile:  "/etc/nginx/conf.d/example.conf",
		HasSSL:      true,
		CertPath:    "/etc/ssl/certs/example.pem",
		KeyPath:     "/etc/ssl/private/example.key",
		ServerType:  config.ServerTypeNginx,
	}

	binding := createBinding(site, cfgManager)

	if binding.ServerName != "example.com" {
		t.Errorf("ServerName = %s, want example.com", binding.ServerName)
	}

	if binding.ServerType != config.ServerTypeNginx {
		t.Errorf("ServerType = %s, want nginx", binding.ServerType)
	}

	if !binding.Enabled {
		t.Error("Enabled 应为 true")
	}

	if binding.Paths.Certificate != "/etc/ssl/certs/example.pem" {
		t.Errorf("Certificate = %s", binding.Paths.Certificate)
	}

	if !strings.HasSuffix(binding.Reload.TestCommand, " -t") || !strings.Contains(binding.Reload.TestCommand, "nginx") {
		t.Errorf("TestCommand = %s, 应包含 nginx 和 -t", binding.Reload.TestCommand)
	}

	if !strings.HasSuffix(binding.Reload.ReloadCommand, " -s reload") || !strings.Contains(binding.Reload.ReloadCommand, "nginx") {
		t.Errorf("ReloadCommand = %s, 应包含 nginx 和 -s reload", binding.Reload.ReloadCommand)
	}
}

// TestCreateBinding_NginxUsesScannedExecutable 验证多套 Nginx 共存时，
// 绑定命令使用扫描该站点的实例，而不是再次从 PATH 或其他运行进程中选择。
func TestCreateBinding_NginxUsesScannedExecutable(t *testing.T) {
	tmpDir := t.TempDir()
	cfgManager, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	const scannedExe = `G:\soft\nginx-1.26.3\nginx.exe`
	site := &matcher.ScannedSiteInfo{
		ServerName:     "blait-selector.com",
		ConfigFile:     `G:\soft\nginx-1.26.3\conf\nginx.conf`,
		CertPath:       `G:\soft\nginx-1.26.3\ssl\blait-selector.com.pem`,
		KeyPath:        `G:\soft\nginx-1.26.3\ssl\blait-selector.com.key`,
		ServerType:     config.ServerTypeNginx,
		ExecutablePath: scannedExe,
	}

	binding := createBinding(site, cfgManager)
	if !strings.HasPrefix(binding.Reload.TestCommand, scannedExe+" ") {
		t.Fatalf("TestCommand = %q，应绑定扫描实例 %q", binding.Reload.TestCommand, scannedExe)
	}
	if !strings.HasPrefix(binding.Reload.ReloadCommand, scannedExe+" ") {
		t.Fatalf("ReloadCommand = %q，应绑定扫描实例 %q", binding.Reload.ReloadCommand, scannedExe)
	}
}

// TestHasDeployFailures 验证退出码判定：任一失败/未完成即视为失败。
func TestHasDeployFailures(t *testing.T) {
	tests := []struct {
		name     string
		siteFail int
		certFail int
		needKey  int
		want     bool
	}{
		{"全部成功", 0, 0, 0, false},
		{"部分站点失败", 1, 0, 0, true},
		{"证书失败", 0, 1, 0, true},
		{"需要私钥跳过", 0, 0, 1, true},
		{"多类失败", 2, 1, 3, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasDeployFailures(tt.siteFail, tt.certFail, tt.needKey); got != tt.want {
				t.Errorf("hasDeployFailures(%d,%d,%d) = %v, want %v",
					tt.siteFail, tt.certFail, tt.needKey, got, tt.want)
			}
		})
	}
}

// TestCreateBinding_DockerNginx_Volume 验证 Docker Nginx 站点绑定：
// 证书路径用宿主机挂载路径、命令为 docker exec 容器化命令、Docker 信息为 volume 模式。
func TestCreateBinding_DockerNginx_Volume(t *testing.T) {
	tmpDir := t.TempDir()
	cfgManager, _ := config.NewConfigManagerWithDir(tmpDir)

	site := &matcher.ScannedSiteInfo{
		ServerName:    "docker.example.com",
		ConfigFile:    "/etc/nginx/conf.d/docker.conf",
		HasSSL:        true,
		CertPath:      "/etc/nginx/certs/cert.pem", // 容器内路径
		KeyPath:       "/etc/nginx/certs/key.pem",
		ServerType:    config.ServerTypeDockerNginx,
		ContainerID:   "abc123",
		ContainerName: "nginx-web",
		HostCertPath:  "/opt/docker/certs/cert.pem", // 宿主机挂载路径
		HostKeyPath:   "/opt/docker/certs/key.pem",
		VolumeMode:    true,
	}

	binding := createBinding(site, cfgManager)

	// 证书路径应为宿主机侧挂载路径（而非容器内路径）
	if binding.Paths.Certificate != "/opt/docker/certs/cert.pem" {
		t.Errorf("Certificate = %s, 应为宿主机挂载路径", binding.Paths.Certificate)
	}
	if binding.Paths.PrivateKey != "/opt/docker/certs/key.pem" {
		t.Errorf("PrivateKey = %s, 应为宿主机挂载路径", binding.Paths.PrivateKey)
	}
	// 命令应为容器化 docker exec 命令
	if binding.Reload.TestCommand != "docker exec nginx-web nginx -t" {
		t.Errorf("TestCommand = %q, 应为 docker exec nginx-web nginx -t", binding.Reload.TestCommand)
	}
	if binding.Reload.ReloadCommand != "docker exec nginx-web nginx -s reload" {
		t.Errorf("ReloadCommand = %q, 应为 docker exec nginx-web nginx -s reload", binding.Reload.ReloadCommand)
	}
	// Docker 信息应为 volume 模式
	if binding.Docker == nil || binding.Docker.DeployMode != "volume" || binding.Docker.ContainerName != "nginx-web" {
		t.Errorf("Docker 信息不正确: %+v", binding.Docker)
	}
	// 校验应通过（可安全部署）
	if err := config.ValidateDockerBinding(&binding); err != nil {
		t.Errorf("挂载卷 Docker 绑定应可部署: %v", err)
	}
}

// TestCreateBinding_DockerNginx_NoMount 验证无宿主机挂载路径的 Docker 站点为 copy 模式，
// 已有 HTTPS 路径可通过容器专用流程部署。
func TestCreateBinding_DockerNginx_NoMount(t *testing.T) {
	tmpDir := t.TempDir()
	cfgManager, _ := config.NewConfigManagerWithDir(tmpDir)

	site := &matcher.ScannedSiteInfo{
		ServerName:    "docker2.example.com",
		ConfigFile:    "/etc/nginx/conf.d/docker2.conf",
		HasSSL:        true,
		CertPath:      "/etc/nginx/certs/cert.pem",
		KeyPath:       "/etc/nginx/certs/key.pem",
		ServerType:    config.ServerTypeDockerNginx,
		ContainerName: "nginx-web2",
		VolumeMode:    false, // 无挂载卷
	}

	binding := createBinding(site, cfgManager)

	if binding.Docker == nil || binding.Docker.DeployMode != "copy" {
		t.Errorf("无挂载卷应为 copy 模式: %+v", binding.Docker)
	}
	if err := config.ValidateDockerBinding(&binding); err != nil {
		t.Errorf("已有 HTTPS 的 copy 绑定应可部署: %v", err)
	}
}

// TestCreateBinding_DockerApache_VolumeChainHostPath 验证 Docker Apache 卷模式下证书链使用宿主机路径：
// 此前 createBinding 只取容器内 ChainPath，卷模式会把证书链写到宿主机错误位置。
func TestCreateBinding_DockerApache_VolumeChainHostPath(t *testing.T) {
	tmpDir := t.TempDir()
	cfgManager, _ := config.NewConfigManagerWithDir(tmpDir)

	site := &matcher.ScannedSiteInfo{
		ServerName:    "docker-apache.example.com",
		ConfigFile:    "/etc/apache2/sites/docker.conf",
		HasSSL:        true,
		CertPath:      "/etc/apache2/ssl/cert.pem", // 容器内路径
		KeyPath:       "/etc/apache2/ssl/key.pem",
		ChainPath:     "/etc/apache2/ssl/chain.pem", // 容器内链路径
		ServerType:    config.ServerTypeDockerApache,
		ContainerID:   "def456",
		ContainerName: "apache-web",
		HostCertPath:  "/opt/docker/ssl/cert.pem", // 宿主机挂载路径
		HostKeyPath:   "/opt/docker/ssl/key.pem",
		HostChainPath: "/opt/docker/ssl/chain.pem",
		VolumeMode:    true,
	}

	binding := createBinding(site, cfgManager)

	// 证书链应为宿主机侧挂载路径（而非容器内路径）
	if binding.Paths.ChainFile != "/opt/docker/ssl/chain.pem" {
		t.Errorf("ChainFile = %s, 应为宿主机链路径 /opt/docker/ssl/chain.pem", binding.Paths.ChainFile)
	}
	if binding.Paths.Certificate != "/opt/docker/ssl/cert.pem" {
		t.Errorf("Certificate = %s, 应为宿主机路径", binding.Paths.Certificate)
	}
	if binding.Docker == nil || binding.Docker.DeployMode != "volume" {
		t.Errorf("应为 volume 模式: %+v", binding.Docker)
	}
	if err := config.ValidateDockerBinding(&binding); err != nil {
		t.Errorf("宿主机路径齐全的卷绑定应可部署: %v", err)
	}
}

// TestCreateBinding_Apache 测试创建 Apache 绑定
func TestCreateBinding_Apache(t *testing.T) {
	tmpDir := t.TempDir()
	cfgManager, _ := config.NewConfigManagerWithDir(tmpDir)

	site := &matcher.ScannedSiteInfo{
		ServerName: "example.com",
		ConfigFile: "/etc/apache2/sites-available/example.conf",
		HasSSL:     true,
		CertPath:   "/etc/ssl/certs/example.pem",
		KeyPath:    "/etc/ssl/private/example.key",
		ServerType: config.ServerTypeApache,
	}

	binding := createBinding(site, cfgManager)

	if binding.ServerType != config.ServerTypeApache {
		t.Errorf("ServerType = %s, want apache", binding.ServerType)
	}

	validTestCmds := map[string]bool{
		"apache2ctl -t": true,
		"apachectl -t":  true,
		"httpd -t":      true,
	}
	if !validTestCmds[binding.Reload.TestCommand] {
		t.Errorf("TestCommand = %s, 不在合法命令集合中", binding.Reload.TestCommand)
	}

	validReloadCmds := map[string]bool{
		"apache2ctl graceful": true,
		"apachectl graceful":  true,
		"httpd -k graceful":   true,
	}
	if !validReloadCmds[binding.Reload.ReloadCommand] {
		t.Errorf("ReloadCommand = %s, 不在合法命令集合中", binding.Reload.ReloadCommand)
	}
}

// TestCreateBinding_NoSSL 测试无 SSL 站点创建绑定
func TestCreateBinding_NoSSL(t *testing.T) {
	tmpDir := t.TempDir()
	cfgManager, _ := config.NewConfigManagerWithDir(tmpDir)

	site := &matcher.ScannedSiteInfo{
		ServerName: "example.com",
		ConfigFile: "/etc/nginx/conf.d/example.conf",
		HasSSL:     false,
		CertPath:   "", // 无 SSL 配置
		KeyPath:    "",
		ServerType: config.ServerTypeNginx,
	}

	binding := createBinding(site, cfgManager)

	// 应该使用默认路径
	if binding.Paths.Certificate == "" {
		t.Error("Certificate 路径不应为空")
	}

	if binding.Paths.PrivateKey == "" {
		t.Error("PrivateKey 路径不应为空")
	}
}

// TestDeployCert_Nginx 测试 Nginx 证书部署
func TestDeployCert_Nginx(t *testing.T) {
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

	svc := newTestDeployService(t, tmpDir)
	err = deployToSiteBinding(t.Context(), svc, binding, certData, testCert.KeyPEM)
	if err != nil {
		t.Fatalf("deployCert() error = %v", err)
	}

	// 验证证书文件已创建
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("证书文件未创建")
	}

	// 验证私钥文件已创建
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("私钥文件未创建")
	}
}

// TestDeploySingleBindings_SkipDisabled 验证 SSL 配置安装失败（Enabled=false）的绑定
// 被计为失败且不被部署，而非误报"部署成功"。
// 回归：曾经部署循环不检查 Enabled，导致 SSL 安装失败的站点仍报成功（成功=1, 失败=0）。
func TestDeploySingleBindings_SkipDisabled(t *testing.T) {
	tmpDir := t.TempDir()
	disabledCert := filepath.Join(tmpDir, "disabled", "cert.pem")
	enabledCert := filepath.Join(tmpDir, "enabled", "cert.pem")

	testCert, err := certs.GenerateValidCert("enabled.example.com", nil)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	bindings := []config.SiteBinding{
		{
			ServerName: "disabled.example.com", // 模拟 SSL 配置安装失败被禁用
			ServerType: config.ServerTypeNginx,
			Enabled:    false,
			Paths:      config.BindingPaths{Certificate: disabledCert, PrivateKey: filepath.Join(tmpDir, "disabled", "key.pem")},
		},
		{
			ServerName: "enabled.example.com",
			ServerType: config.ServerTypeNginx,
			Enabled:    true,
			Paths:      config.BindingPaths{Certificate: enabledCert, PrivateKey: filepath.Join(tmpDir, "enabled", "key.pem")},
		},
	}

	certData := &fetcher.CertData{OrderID: 1, Cert: testCert.CertPEM}
	svc := newTestDeployService(t, tmpDir)
	success, failedSites, retryableSites := deploySingleBindings(t.Context(), svc, bindings, certData, testCert.KeyPEM)

	if success != 1 {
		t.Errorf("success = %d, 期望 1（仅 enabled 站点）", success)
	}
	if len(failedSites)+len(retryableSites) != 1 {
		t.Errorf("失败总数 = %d, 期望 1（disabled 站点计为失败）", len(failedSites)+len(retryableSites))
	}
	// 部署前已被禁用的绑定属"已禁用"一类，不进重试列表
	if len(failedSites) != 1 || failedSites[0] != "disabled.example.com" {
		t.Errorf("failedSites = %v, 期望 [disabled.example.com]", failedSites)
	}
	if len(retryableSites) != 0 {
		t.Errorf("retryableSites = %v, 期望空", retryableSites)
	}
	// 禁用的绑定不应被部署：证书文件不应写入
	if _, err := os.Stat(disabledCert); err == nil {
		t.Error("禁用的绑定不应写入证书文件（不应被部署）")
	}
	// 启用的绑定应正常部署
	if _, err := os.Stat(enabledCert); os.IsNotExist(err) {
		t.Error("启用的绑定应写入证书文件")
	}
}

// TestDeployCert_Apache 测试 Apache 证书部署
func TestDeployCert_Apache(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")
	chainPath := filepath.Join(tmpDir, "chain.pem")

	testCert, _ := certs.GenerateValidCert("example.com", nil)
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
	}

	certData := &fetcher.CertData{
		Cert:             testCert.CertPEM,
		IntermediateCert: intermediateCert.CertPEM,
	}

	svc := newTestDeployService(t, tmpDir)
	err := deployToSiteBinding(t.Context(), svc, binding, certData, testCert.KeyPEM)
	if err != nil {
		t.Fatalf("deployCert() error = %v", err)
	}

	// 验证所有文件已创建
	for _, path := range []string{certPath, keyPath, chainPath} {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("文件未创建: %s", path)
		}
	}
}

// TestDeployCert_Apache_Fullchain 测试 Apache fullchain 模式部署（无 ChainFile）
func TestDeployCert_Apache_Fullchain(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	testCert, _ := certs.GenerateValidCert("example.com", nil)
	intermediateCert, _ := certs.GenerateValidCert("Intermediate CA", nil)

	binding := &config.SiteBinding{
		ServerName: "example.com",
		ServerType: config.ServerTypeApache,
		Enabled:    true,
		Paths: config.BindingPaths{
			Certificate: certPath,
			PrivateKey:  keyPath,
			// 不设置 ChainFile — fullchain 模式
		},
	}

	certData := &fetcher.CertData{
		Cert:             testCert.CertPEM,
		IntermediateCert: intermediateCert.CertPEM,
	}

	svc := newTestDeployService(t, tmpDir)
	err := deployToSiteBinding(t.Context(), svc, binding, certData, testCert.KeyPEM)
	if err != nil {
		t.Fatalf("deployCert() error = %v", err)
	}

	// 验证证书文件包含 cert + intermediate（fullchain）
	certData2, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("读取证书文件失败: %v", err)
	}
	certContent := string(certData2)
	if !strings.Contains(certContent, testCert.CertPEM) {
		t.Error("证书文件应包含服务器证书")
	}
	if !strings.Contains(certContent, intermediateCert.CertPEM) {
		t.Error("证书文件应包含中间证书（fullchain 模式）")
	}

	// 不应创建 chain.pem
	chainPath := filepath.Join(tmpDir, "chain.pem")
	if _, err := os.Stat(chainPath); !os.IsNotExist(err) {
		t.Error("fullchain 模式下不应创建独立的 chain.pem")
	}
}

// TestDeployCert_CreateDirectory 测试目录自动创建
func TestDeployCert_CreateDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	nestedDir := filepath.Join(tmpDir, "certs", "example.com")
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

	svc := newTestDeployService(t, tmpDir)
	err := deployToSiteBinding(t.Context(), svc, binding, certData, testCert.KeyPEM)
	if err != nil {
		t.Fatalf("deployCert() error = %v", err)
	}

	// 验证嵌套目录已创建
	if _, err := os.Stat(nestedDir); os.IsNotExist(err) {
		t.Error("嵌套目录未创建")
	}
}

// TestDetectWebServer 测试 Web 服务器检测
func TestDetectWebServer(t *testing.T) {
	// 这个测试依赖系统环境，只验证函数不会 panic
	serverType := webserver.DetectWebServerType()
	t.Logf("检测到的 Web 服务器: %s", serverType)

	// 验证返回值是有效的类型
	validTypes := []string{"nginx", "apache", ""}
	found := false
	for _, vt := range validTypes {
		if serverType == vt {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("DetectWebServerType() = %s, 不是有效类型", serverType)
	}
}

// TestConfirm 测试确认提示（仅验证函数签名）
func TestConfirm(t *testing.T) {
	// confirm 函数需要交互式输入，这里只验证函数存在
	// 实际测试需要模拟 stdin
	_ = confirm
}

// TestScanSites_DockerOnly 复现宿主机未安装 Web 服务、仅 Docker 容器运行 Web 服务的场景。
// 不同服务器中同域名的站点是两个独立部署目标，不能只按域名合并。
func TestScanSites_DockerOnly(t *testing.T) {
	factory := func(serverType webserver.ServerType) (webserver.Scanner, error) {
		switch serverType {
		case webserver.TypeNginx:
			return &staticScanner{
				serverType: webserver.TypeNginx,
				sites: []webserver.Site{{
					ServerName:    "example.com",
					ServerType:    webserver.TypeDockerNginx,
					ContainerID:   "container-id",
					ContainerName: "openresty",
				}},
			}, nil
		case webserver.TypeApache:
			return &staticScanner{
				serverType: webserver.TypeApache,
				sites: []webserver.Site{{
					ServerName:    "example.com",
					ServerType:    webserver.TypeDockerApache,
					ContainerID:   "apache-container-id",
					ContainerName: "apache",
				}},
			}, nil
		default:
			return &staticScanner{serverType: serverType}, nil
		}
	}

	sites := scanSitesWithFactory(logger.NewNopLogger(), factory)
	if len(sites) != 2 {
		t.Fatalf("scanSitesWithFactory() 返回 %d 个站点，期望 2 个", len(sites))
	}
	if sites[0].ServerType != config.ServerTypeDockerNginx {
		t.Fatalf("ServerType = %s，期望 %s", sites[0].ServerType, config.ServerTypeDockerNginx)
	}
	if sites[0].ContainerName != "openresty" {
		t.Fatalf("ContainerName = %s，期望 openresty", sites[0].ContainerName)
	}
	if sites[1].ServerType != config.ServerTypeDockerApache || sites[1].ContainerName != "apache" {
		t.Fatalf("第二个站点 = %+v，期望 Docker Apache 站点", sites[1])
	}
}

func TestSummarizeScannedSites_DockerOnly(t *testing.T) {
	sites := []*matcher.ScannedSiteInfo{
		{ServerType: config.ServerTypeDockerNginx, ContainerName: "openresty"},
		{ServerType: config.ServerTypeDockerNginx, ContainerName: "openresty"},
	}

	environment, serverTypes := summarizeScannedSites(sites)
	if environment != "Docker" {
		t.Fatalf("environment = %q，期望 Docker", environment)
	}
	if len(serverTypes) != 1 || serverTypes[0] != config.ServerTypeDockerNginx {
		t.Fatalf("serverTypes = %v，期望 [%s]", serverTypes, config.ServerTypeDockerNginx)
	}
}

func TestSummarizeScannedSites_Mixed(t *testing.T) {
	sites := []*matcher.ScannedSiteInfo{
		{ServerType: config.ServerTypeNginx},
		{ServerType: config.ServerTypeDockerApache, ContainerName: "apache"},
	}

	environment, serverTypes := summarizeScannedSites(sites)
	if environment != "宿主机 + Docker" {
		t.Fatalf("environment = %q，期望 宿主机 + Docker", environment)
	}
	if len(serverTypes) != 2 || serverTypes[0] != config.ServerTypeNginx || serverTypes[1] != config.ServerTypeDockerApache {
		t.Fatalf("serverTypes = %v，期望 [nginx docker-apache]", serverTypes)
	}
}

func TestDeploymentStatusHint(t *testing.T) {
	want := "\n查看部署状态:\n  sslctl status\n"
	if got := deploymentStatusHint(); got != want {
		t.Fatalf("deploymentStatusHint() = %q，期望 %q", got, want)
	}
}

func TestWebServersNotFoundMessage(t *testing.T) {
	want := "Nginx 和 Apache 服务均未检测到（已检查宿主机和 Docker）"
	if got := webServersNotFoundMessage(); got != want {
		t.Fatalf("webServersNotFoundMessage() = %q，期望 %q", got, want)
	}
}

func TestDeployableSitesNotFoundMessage(t *testing.T) {
	want := "未发现可部署站点"
	if got := deployableSitesNotFoundMessage(); got != want {
		t.Fatalf("deployableSitesNotFoundMessage() = %q，期望 %q", got, want)
	}
}

func TestScanWebServersAndSites_ServerWithoutSites(t *testing.T) {
	factory := func(serverType webserver.ServerType) (webserver.Scanner, error) {
		if serverType == webserver.TypeNginx {
			return &staticScanner{serverType: serverType}, nil
		}
		return &staticScanner{serverType: serverType, scanErr: errors.New("未检测到 Apache")}, nil
	}

	result := scanWebServersAndSitesWithFactory(logger.NewNopLogger(), factory)
	if len(result.ServerTypes) != 1 || result.ServerTypes[0] != config.ServerTypeNginx {
		t.Fatalf("ServerTypes = %v，期望 [nginx]", result.ServerTypes)
	}
	if len(result.Sites) != 0 {
		t.Fatalf("Sites = %+v，期望没有可部署站点", result.Sites)
	}
}

func TestScanSites_OneServerAvailable(t *testing.T) {
	factory := func(serverType webserver.ServerType) (webserver.Scanner, error) {
		if serverType == webserver.TypeNginx {
			return &staticScanner{
				serverType: serverType,
				sites: []webserver.Site{{
					ServerName: "example.com",
					ServerType: webserver.TypeDockerNginx,
				}},
			}, nil
		}
		return &staticScanner{serverType: serverType, scanErr: errors.New("未检测到 Apache")}, nil
	}

	sites := scanSitesWithFactory(logger.NewNopLogger(), factory)
	if len(sites) != 1 || sites[0].ServerType != config.ServerTypeDockerNginx {
		t.Fatalf("sites = %+v，期望仅保留可用的 Docker Nginx 站点", sites)
	}
}

// TestInstallService 测试服务安装（仅验证函数签名）
func TestInstallService(t *testing.T) {
	// installService 需要 root 权限，这里只验证函数存在
	_ = installService
}

// TestInstallSSLConfig_Nginx 测试自动安装 SSL 配置
func TestInstallSSLConfig_Nginx(t *testing.T) {
	tmpDir := t.TempDir()
	cfgManager, _ := config.NewConfigManagerWithDir(tmpDir)
	var capturedTestCommand string
	webserver.RegisterInstaller(webserver.TypeNginx, func(configPath, certPath, keyPath, chainPath, serverName, testCmd string) webserver.Installer {
		capturedTestCommand = testCmd
		return &mockInstaller{configPath: configPath}
	})
	t.Cleanup(func() {
		webserver.RegisterInstaller(webserver.TypeNginx, func(configPath, certPath, keyPath, chainPath, serverName, testCmd string) webserver.Installer {
			return &mockInstaller{configPath: configPath}
		})
	})

	site := &matcher.ScannedSiteInfo{
		ServerName:     "example.com",
		ConfigFile:     "/etc/nginx/conf.d/example.conf",
		HasSSL:         false,
		ServerType:     config.ServerTypeNginx,
		ExecutablePath: filepath.Join(tmpDir, "selected-nginx"),
	}

	result, err := installSSLConfig(site, cfgManager)
	if err != nil {
		t.Fatalf("installSSLConfig() error = %v", err)
	}
	if want := site.ExecutablePath + " -t"; capturedTestCommand != want {
		t.Fatalf("安装器配置测试命令 = %q，期望目标实例 %q", capturedTestCommand, want)
	}

	if !result.Modified {
		t.Error("installSSLConfig() Modified 应为 true")
	}

	if result.BackupPath == "" {
		t.Error("installSSLConfig() BackupPath 不应为空")
	}
}

// TestInstallSSLConfig_Apache 测试 Apache 自动安装 SSL 配置
func TestInstallSSLConfig_Apache(t *testing.T) {
	tmpDir := t.TempDir()
	cfgManager, _ := config.NewConfigManagerWithDir(tmpDir)

	site := &matcher.ScannedSiteInfo{
		ServerName: "example.com",
		ConfigFile: "/etc/apache2/sites-available/example.conf",
		HasSSL:     false,
		ServerType: config.ServerTypeApache,
	}

	result, err := installSSLConfig(site, cfgManager)
	if err != nil {
		t.Fatalf("installSSLConfig() error = %v", err)
	}

	if !result.Modified {
		t.Error("installSSLConfig() Modified 应为 true")
	}
}

// TestMergeSameNameSites 测试同域名站点合并
func TestMergeSameNameSites(t *testing.T) {
	t.Run("80和443分开的server block合并", func(t *testing.T) {
		sites := []*matcher.ScannedSiteInfo{
			{
				ServerName: "example.com",
				ConfigFile: "/etc/nginx/conf.d/example.conf",
				HasSSL:     true,
				CertPath:   "/etc/ssl/cert.pem",
				KeyPath:    "/etc/ssl/key.pem",
				ServerType: "nginx",
			},
			{
				ServerName: "example.com",
				ConfigFile: "/etc/nginx/conf.d/example.conf",
				HasSSL:     false,
				ServerType: "nginx",
				Webroot:    "/var/www/html",
			},
		}

		result := mergeSameNameSites(sites)
		if len(result) != 1 {
			t.Fatalf("合并后应有 1 个站点，实际 %d", len(result))
		}
		if !result[0].HasSSL {
			t.Error("合并后应保留 SSL 状态")
		}
		if result[0].CertPath != "/etc/ssl/cert.pem" {
			t.Errorf("合并后 CertPath = %s，期望 /etc/ssl/cert.pem", result[0].CertPath)
		}
		if result[0].Webroot != "/var/www/html" {
			t.Errorf("合并后应继承 Webroot = /var/www/html，实际 %s", result[0].Webroot)
		}
	})

	t.Run("80在前443在后", func(t *testing.T) {
		sites := []*matcher.ScannedSiteInfo{
			{
				ServerName: "example.com",
				ConfigFile: "/etc/nginx/conf.d/example.conf",
				HasSSL:     false,
				ServerType: "nginx",
				Webroot:    "/var/www/html",
			},
			{
				ServerName: "example.com",
				ConfigFile: "/etc/nginx/conf.d/example.conf",
				HasSSL:     true,
				CertPath:   "/etc/ssl/cert.pem",
				KeyPath:    "/etc/ssl/key.pem",
				ServerType: "nginx",
			},
		}

		result := mergeSameNameSites(sites)
		if len(result) != 1 {
			t.Fatalf("合并后应有 1 个站点，实际 %d", len(result))
		}
		if !result[0].HasSSL {
			t.Error("合并后应保留 SSL 状态")
		}
		if result[0].CertPath != "/etc/ssl/cert.pem" {
			t.Errorf("合并后 CertPath = %s", result[0].CertPath)
		}
		if result[0].Webroot != "/var/www/html" {
			t.Errorf("合并后应继承 Webroot，实际 %s", result[0].Webroot)
		}
	})

	t.Run("不同域名不合并", func(t *testing.T) {
		sites := []*matcher.ScannedSiteInfo{
			{ServerName: "a.com", HasSSL: true, CertPath: "/a.pem", KeyPath: "/a.key", ServerType: "nginx"},
			{ServerName: "b.com", HasSSL: false, ServerType: "nginx"},
		}

		result := mergeSameNameSites(sites)
		if len(result) != 2 {
			t.Fatalf("不同域名不应合并，期望 2 实际 %d", len(result))
		}
	})

	t.Run("单条目不变", func(t *testing.T) {
		sites := []*matcher.ScannedSiteInfo{
			{ServerName: "a.com", HasSSL: true, CertPath: "/a.pem", KeyPath: "/a.key", ServerType: "nginx"},
		}
		result := mergeSameNameSites(sites)
		if len(result) != 1 {
			t.Fatalf("单条目应保持，期望 1 实际 %d", len(result))
		}
	})

	t.Run("空列表", func(t *testing.T) {
		result := mergeSameNameSites(nil)
		if len(result) != 0 {
			t.Fatalf("空列表应返回空，实际 %d", len(result))
		}
	})
}

// TestBuildCertName 测试证书名称生成
func TestBuildCertName(t *testing.T) {
	tests := []struct {
		domain  string
		orderID int
		want    string
	}{
		{"example.com", 12345, "example.com-12345"},
		{"*.example.com", 99999, "WILDCARD.example.com-99999"},
		{"sub.example.com", 1, "sub.example.com-1"},
		{"*.sub.example.com", 100, "WILDCARD.sub.example.com-100"},
	}

	for _, tt := range tests {
		got := buildCertName(tt.domain, tt.orderID)
		if got != tt.want {
			t.Errorf("buildCertName(%q, %d) = %q, want %q", tt.domain, tt.orderID, got, tt.want)
		}
	}
}

// TestPrewriteKeyThenCert_KeyBeforeCert 验证 needSSLInstall 预写"先写私钥后写证书"：
// 证书写入失败时私钥应已落盘，证明写序为 key→cert（旧序 cert→key 下私钥不会被写入）。
func TestPrewriteKeyThenCert_KeyBeforeCert(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "key.pem")
	certPath := filepath.Join(tmpDir, "cert.pem")
	// 制造证书写入失败：cert 路径为目录
	if err := os.Mkdir(certPath, 0700); err != nil {
		t.Fatalf("制造证书写入障碍失败: %v", err)
	}

	err := prewriteKeyThenCert(certPath, keyPath, "FULLCHAIN", "PRIVATEKEY")
	if err == nil {
		t.Fatal("证书路径为目录时预写应失败")
	}
	// 关键断言：证书写入失败时私钥已先落盘
	got, readErr := os.ReadFile(keyPath)
	if readErr != nil {
		t.Fatalf("私钥应先于证书写入（写序应为 key→cert）: %v", readErr)
	}
	if string(got) != "PRIVATEKEY" {
		t.Errorf("私钥内容 = %q, want PRIVATEKEY", string(got))
	}
}

// TestPrewriteKeyThenCert_Success 正常路径：私钥与证书均写入，私钥权限 0600、证书 0644。
func TestPrewriteKeyThenCert_Success(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "key.pem")
	certPath := filepath.Join(tmpDir, "cert.pem")

	if err := prewriteKeyThenCert(certPath, keyPath, "FULLCHAIN", "PRIVATEKEY"); err != nil {
		t.Fatalf("正常预写应成功: %v", err)
	}
	if data, _ := os.ReadFile(keyPath); string(data) != "PRIVATEKEY" {
		t.Errorf("私钥内容 = %q, want PRIVATEKEY", string(data))
	}
	if data, _ := os.ReadFile(certPath); string(data) != "FULLCHAIN" {
		t.Errorf("证书内容 = %q, want FULLCHAIN", string(data))
	}
	if fi, err := os.Stat(keyPath); err == nil && fi.Mode().Perm() != 0600 {
		t.Errorf("私钥权限 = %o, want 0600", fi.Mode().Perm())
	}
}

func TestCreateBindingDockerPartialMountKeepsContainerPaths(t *testing.T) {
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	site := &matcher.ScannedSiteInfo{
		ServerName: "partial.example.com", ServerType: config.ServerTypeDockerNginx,
		ContainerName: "nginx", HasSSL: true,
		CertPath: "/etc/nginx/ssl/cert.pem", KeyPath: "/etc/nginx/ssl/key.pem",
		HostCertPath: "/host/cert.pem", VolumeMode: false,
	}
	binding := createBinding(site, cm)
	if binding.Paths.Certificate != site.CertPath || binding.Paths.PrivateKey != site.KeyPath || !config.IsDockerCopyBinding(&binding) {
		t.Fatalf("部分挂载的 copy 绑定必须保留两个容器路径: %+v", binding)
	}
}

func TestInstallSSLForBatchRejectsCopyBeforeHostWrites(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	for _, file := range []string{certPath, keyPath} {
		if err := os.WriteFile(file, []byte("host-sentinel"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	site := &matcher.ScannedSiteInfo{ServerName: "copy.example.com"}
	plan := &certDeployPlan{Bindings: []config.SiteBinding{{ServerName: site.ServerName, ServerType: config.ServerTypeDockerNginx, Enabled: true, Docker: &config.DockerInfo{DeployMode: "copy", ContainerName: "web"}, Paths: config.BindingPaths{Certificate: certPath, PrivateKey: keyPath}}}}
	installSSLForBatch(site, plan, &setupParams{})
	if plan.Bindings[0].Enabled {
		t.Fatal("不支持的 HTTP-only copy 绑定应禁用")
	}
	for _, file := range []string{certPath, keyPath} {
		data, err := os.ReadFile(file)
		if err != nil || string(data) != "host-sentinel" {
			t.Fatal("禁止向宿主机写入容器证书")
		}
	}
}
