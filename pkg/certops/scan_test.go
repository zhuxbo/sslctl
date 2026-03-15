// Package certops 扫描逻辑测试
package certops

import (
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/logger"
)

// TestScanOptions_Defaults 测试扫描选项默认值
func TestScanOptions_Defaults(t *testing.T) {
	opts := ScanOptions{}

	if opts.SSLOnly {
		t.Error("默认 SSLOnly 应为 false")
	}
	if opts.ServerType != "" {
		t.Errorf("默认 ServerType 应为空，实际: %s", opts.ServerType)
	}
}

// TestScanOptions_SSLOnlyEnabled 测试仅 SSL 选项
func TestScanOptions_SSLOnlyEnabled(t *testing.T) {
	opts := ScanOptions{SSLOnly: true}

	if !opts.SSLOnly {
		t.Error("SSLOnly 应为 true")
	}
}

// TestScanResult_Basic 测试扫描结果基本结构
func TestScanResult_Basic(t *testing.T) {
	result := &ScanResult{
		ScanTime:    time.Now(),
		Environment: "local",
		Sites: []ScannedSite{
			{
				Name:        "Example Site",
				Source:      "local",
				ServerName:  "example.com",
				ServerAlias: []string{"www.example.com"},
				ListenPorts: []string{"443 ssl"},
			},
		},
	}

	if len(result.Sites) != 1 {
		t.Errorf("Sites 长度 = %d, 期望 1", len(result.Sites))
	}

	if result.Environment != "local" {
		t.Errorf("Environment = %s, 期望 local", result.Environment)
	}
}

// TestScannedSite_LocalSite 测试本地站点扫描结构
func TestScannedSite_LocalSite(t *testing.T) {
	site := ScannedSite{
		Name:            "Test Site",
		Source:          "local",
		ConfigFile:      "/etc/nginx/sites-enabled/test.conf",
		ServerName:      "test.example.com",
		ServerAlias:     []string{"www.test.example.com", "api.test.example.com"},
		ListenPorts:     []string{"443 ssl", "8443 ssl"},
		CertificatePath: "/etc/ssl/certs/test.crt",
		PrivateKeyPath:  "/etc/ssl/private/test.key",
	}

	if len(site.ServerAlias) != 2 {
		t.Errorf("ServerAlias 长度 = %d, 期望 2", len(site.ServerAlias))
	}

	if len(site.ListenPorts) != 2 {
		t.Errorf("ListenPorts 长度 = %d, 期望 2", len(site.ListenPorts))
	}
}

// TestScannedSite_DockerSite 测试 Docker 站点扫描结构
func TestScannedSite_DockerSite(t *testing.T) {
	site := ScannedSite{
		Name:          "Docker Nginx Site",
		Source:        "docker",
		ContainerID:   "abc123def456",
		ContainerName: "nginx-container",
		ServerName:    "docker.example.com",
		HostCertPath:  "/opt/certs/docker.example.com/cert.pem",
		HostKeyPath:   "/opt/certs/docker.example.com/key.pem",
		VolumeMode:    true,
	}

	if site.Source != "docker" {
		t.Errorf("Source = %s, 期望 docker", site.Source)
	}

	if site.ContainerID == "" {
		t.Error("ContainerID 不应为空")
	}

	if !site.VolumeMode {
		t.Error("VolumeMode 应为 true")
	}
}


// TestScanService_Creation 测试扫描服务创建
func TestScanService_Creation(t *testing.T) {
	tmpDir := t.TempDir()

	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	if svc == nil {
		t.Fatal("NewService 返回 nil")
	}
}

// TestScanResult_Empty 测试空扫描结果
func TestScanResult_Empty(t *testing.T) {
	result := &ScanResult{
		ScanTime:    time.Now(),
		Environment: "local",
		Sites:       []ScannedSite{},
	}

	if len(result.Sites) != 0 {
		t.Errorf("空结果的 Sites 长度应为 0，实际 %d", len(result.Sites))
	}
}

// TestScanResult_MultipleSites 测试多站点扫描结果
func TestScanResult_MultipleSites(t *testing.T) {
	result := &ScanResult{
		ScanTime:    time.Now(),
		Environment: "local",
		Sites: []ScannedSite{
			{ServerName: "site1.com"},
			{ServerName: "site2.com"},
			{ServerName: "site3.com"},
		},
	}

	if len(result.Sites) != 3 {
		t.Errorf("Sites 长度 = %d, 期望 3", len(result.Sites))
	}

	// 验证每个站点
	expectedNames := []string{"site1.com", "site2.com", "site3.com"}
	for i, expected := range expectedNames {
		if result.Sites[i].ServerName != expected {
			t.Errorf("Sites[%d].ServerName = %s, 期望 %s", i, result.Sites[i].ServerName, expected)
		}
	}
}

// TestConfigScanResultConversion 测试配置扫描结果转换
func TestConfigScanResultConversion(t *testing.T) {
	// 创建 certops.ScanResult
	certopsResult := &ScanResult{
		ScanTime:    time.Now(),
		Environment: "local",
		Sites: []ScannedSite{
			{
				Name:            "Test",
				Source:          "local",
				ConfigFile:      "/etc/nginx/test.conf",
				ServerName:      "test.com",
				ServerAlias:     []string{"www.test.com"},
				ListenPorts:     []string{"443 ssl"},
				CertificatePath: "/etc/ssl/test.crt",
				PrivateKeyPath:  "/etc/ssl/test.key",
			},
		},
	}

	// 转换为 config.ScanResult
	configResult := &config.ScanResult{
		ScanTime:    certopsResult.ScanTime,
		Environment: certopsResult.Environment,
		Sites:       make([]config.ScannedSite, len(certopsResult.Sites)),
	}

	for i, site := range certopsResult.Sites {
		configResult.Sites[i] = config.ScannedSite{
			Name:            site.Name,
			Source:          site.Source,
			ConfigFile:      site.ConfigFile,
			ServerName:      site.ServerName,
			ServerAlias:     site.ServerAlias,
			ListenPorts:     site.ListenPorts,
			CertificatePath: site.CertificatePath,
			PrivateKeyPath:  site.PrivateKeyPath,
		}
	}

	// 验证转换
	if len(configResult.Sites) != len(certopsResult.Sites) {
		t.Errorf("转换后站点数量不一致")
	}

	if configResult.Sites[0].ServerName != certopsResult.Sites[0].ServerName {
		t.Errorf("ServerName 转换不正确")
	}
}

// TestScanOptions_SSLOnlyFilter 测试 SSL 过滤
func TestScanOptions_SSLOnlyFilter(t *testing.T) {
	allSites := []ScannedSite{
		{ServerName: "ssl1.com", CertificatePath: "/etc/ssl/ssl1.crt"},
		{ServerName: "http1.com", CertificatePath: ""},
		{ServerName: "ssl2.com", CertificatePath: "/etc/ssl/ssl2.crt"},
		{ServerName: "http2.com", CertificatePath: ""},
	}

	opts := ScanOptions{SSLOnly: true}

	var filtered []ScannedSite
	for _, site := range allSites {
		if opts.SSLOnly && site.CertificatePath == "" {
			continue
		}
		filtered = append(filtered, site)
	}

	if len(filtered) != 2 {
		t.Errorf("过滤后站点数量 = %d, 期望 2", len(filtered))
	}

	for _, site := range filtered {
		if site.CertificatePath == "" {
			t.Errorf("过滤后不应包含无 SSL 的站点: %s", site.ServerName)
		}
	}
}

// TestScanResult_MixedEnvironment 测试混合环境
func TestScanResult_MixedEnvironment(t *testing.T) {
	result := &ScanResult{
		ScanTime:    time.Now(),
		Environment: "mixed",
		Sites: []ScannedSite{
			{ServerName: "local.example.com", Source: "local"},
			{ServerName: "docker.example.com", Source: "docker"},
		},
	}

	if result.Environment != "mixed" {
		t.Errorf("Environment = %s, 期望 mixed", result.Environment)
	}

	localCount := 0
	dockerCount := 0
	for _, site := range result.Sites {
		switch site.Source {
		case "local":
			localCount++
		case "docker":
			dockerCount++
		}
	}

	if localCount != 1 || dockerCount != 1 {
		t.Errorf("local=%d, docker=%d, 期望各 1 个", localCount, dockerCount)
	}
}

// TestScanSites_Basic 测试基本扫描功能
func TestScanSites_Basic(t *testing.T) {
	tmpDir := t.TempDir()

	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	// 执行扫描
	result, err := svc.ScanSites(t.Context(), ScanOptions{})
	if err != nil {
		t.Errorf("扫描不应报错: %v", err)
	}

	if result == nil {
		t.Fatal("扫描结果不应为 nil")
	}

	// 验证基本字段
	if result.ScanTime.IsZero() {
		t.Error("扫描时间不应为零值")
	}
	if result.Environment != "local" {
		t.Errorf("Environment = %s, 期望 local", result.Environment)
	}
}

// TestScanSites_SSLOnly 测试仅 SSL 站点扫描
func TestScanSites_SSLOnly(t *testing.T) {
	tmpDir := t.TempDir()

	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	// 使用 SSLOnly 选项扫描
	result, err := svc.ScanSites(t.Context(), ScanOptions{SSLOnly: true})
	if err != nil {
		t.Errorf("SSL 扫描不应报错: %v", err)
	}

	if result == nil {
		t.Fatal("扫描结果不应为 nil")
	}

	// 验证所有站点都有 SSL 配置
	for _, site := range result.Sites {
		if site.CertificatePath == "" {
			t.Errorf("SSLOnly 过滤后站点 %s 不应无 SSL 配置", site.ServerName)
		}
	}
}

// TestScanSites_WithServerType 测试指定服务器类型的扫描
func TestScanSites_WithServerType(t *testing.T) {
	tmpDir := t.TempDir()

	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	// 测试指定 nginx 类型
	result, err := svc.ScanSites(t.Context(), ScanOptions{ServerType: "nginx"})
	if err != nil {
		t.Errorf("Nginx 扫描不应报错: %v", err)
	}

	if result == nil {
		t.Fatal("扫描结果不应为 nil")
	}
}

// TestDeployOptions_Struct 测试部署选项结构
func TestDeployOptions_Struct(t *testing.T) {
	opts := DeployOptions{
		CertName: "test-cert",
		All:      false,
		DryRun:   true,
	}

	if opts.CertName != "test-cert" {
		t.Errorf("CertName = %s, 期望 test-cert", opts.CertName)
	}
	if opts.All {
		t.Error("All 应为 false")
	}
	if !opts.DryRun {
		t.Error("DryRun 应为 true")
	}
}

// TestDeployOptions_AllMode 测试全部部署选项
func TestDeployOptions_AllMode(t *testing.T) {
	opts := DeployOptions{
		All: true,
	}

	if !opts.All {
		t.Error("All 应为 true")
	}
	if opts.CertName != "" {
		t.Error("使用 All 时 CertName 应为空")
	}
}

// TestScannedSite_EmptyFields 测试空字段
func TestScannedSite_EmptyFields(t *testing.T) {
	site := ScannedSite{}

	if site.Source != "" {
		t.Error("空站点 Source 应为空")
	}
	if site.VolumeMode {
		t.Error("空站点 VolumeMode 应为 false")
	}
	if site.ServerAlias != nil {
		t.Error("空站点 ServerAlias 应为 nil")
	}
	if site.ListenPorts != nil {
		t.Error("空站点 ListenPorts 应为 nil")
	}
}

// TestScanResult_TimeFormat 测试扫描时间格式
func TestScanResult_TimeFormat(t *testing.T) {
	scanTime := time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC)
	result := &ScanResult{
		ScanTime:    scanTime,
		Environment: "local",
		Sites:       []ScannedSite{},
	}

	if result.ScanTime.Year() != 2024 {
		t.Errorf("年份 = %d, 期望 2024", result.ScanTime.Year())
	}
	if result.ScanTime.Month() != time.June {
		t.Errorf("月份 = %v, 期望 June", result.ScanTime.Month())
	}
	if result.ScanTime.Day() != 15 {
		t.Errorf("日期 = %d, 期望 15", result.ScanTime.Day())
	}
}


// TestScanOptions_AllServerTypes 测试所有服务器类型选项
func TestScanOptions_AllServerTypes(t *testing.T) {
	serverTypes := []string{"nginx", "apache", "auto", ""}

	for _, serverType := range serverTypes {
		opts := ScanOptions{ServerType: serverType}
		if opts.ServerType != serverType {
			t.Errorf("ServerType = %s, 期望 %s", opts.ServerType, serverType)
		}
	}
}

// TestScanResult_Environment_Values 测试环境值
func TestScanResult_Environment_Values(t *testing.T) {
	environments := []string{"local", "docker", "mixed"}

	for _, env := range environments {
		result := &ScanResult{
			Environment: env,
		}
		if result.Environment != env {
			t.Errorf("Environment = %s, 期望 %s", result.Environment, env)
		}
	}
}
