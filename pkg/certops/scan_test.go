// Package certops 扫描逻辑测试
package certops

import (
	"testing"
	"time"

	"github.com/zhuxbo/cert-deploy/pkg/config"
	"github.com/zhuxbo/cert-deploy/pkg/logger"
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
				ID:          "example.com",
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
		ID:              "test.example.com",
		Name:            "Test Site",
		Source:          "local",
		ConfigFile:      "/etc/nginx/sites-enabled/test.conf",
		ServerName:      "test.example.com",
		ServerAlias:     []string{"www.test.example.com", "api.test.example.com"},
		ListenPorts:     []string{"443 ssl", "8443 ssl"},
		CertificatePath: "/etc/ssl/certs/test.crt",
		PrivateKeyPath:  "/etc/ssl/private/test.key",
	}

	if site.ID == "" {
		t.Error("ID 不应为空")
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
		ID:            "docker-nginx",
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

// TestToScannedSite_AllFields 测试类型转换
func TestToScannedSite_AllFields(t *testing.T) {
	configSite := &config.ScannedSite{
		ID:              "full.example.com",
		Name:            "Full Site",
		Source:          "local",
		ContainerID:     "",
		ContainerName:   "",
		ConfigFile:      "/etc/nginx/conf.d/full.conf",
		ServerName:      "full.example.com",
		ServerAlias:     []string{"www.full.example.com"},
		ListenPorts:     []string{"443 ssl"},
		CertificatePath: "/etc/ssl/full.crt",
		PrivateKeyPath:  "/etc/ssl/full.key",
		HostCertPath:    "",
		HostKeyPath:     "",
		VolumeMode:      false,
	}

	result := toScannedSite(configSite)

	if result.ID != configSite.ID {
		t.Errorf("ID = %s, 期望 %s", result.ID, configSite.ID)
	}
	if result.Name != configSite.Name {
		t.Errorf("Name = %s, 期望 %s", result.Name, configSite.Name)
	}
	if result.Source != configSite.Source {
		t.Errorf("Source = %s, 期望 %s", result.Source, configSite.Source)
	}
	if result.ConfigFile != configSite.ConfigFile {
		t.Errorf("ConfigFile = %s, 期望 %s", result.ConfigFile, configSite.ConfigFile)
	}
	if result.ServerName != configSite.ServerName {
		t.Errorf("ServerName = %s, 期望 %s", result.ServerName, configSite.ServerName)
	}
	if len(result.ServerAlias) != len(configSite.ServerAlias) {
		t.Errorf("ServerAlias 长度 = %d, 期望 %d", len(result.ServerAlias), len(configSite.ServerAlias))
	}
	if len(result.ListenPorts) != len(configSite.ListenPorts) {
		t.Errorf("ListenPorts 长度 = %d, 期望 %d", len(result.ListenPorts), len(configSite.ListenPorts))
	}
	if result.CertificatePath != configSite.CertificatePath {
		t.Errorf("CertificatePath = %s, 期望 %s", result.CertificatePath, configSite.CertificatePath)
	}
	if result.PrivateKeyPath != configSite.PrivateKeyPath {
		t.Errorf("PrivateKeyPath = %s, 期望 %s", result.PrivateKeyPath, configSite.PrivateKeyPath)
	}
}

// TestToScannedSite_DockerFields 测试 Docker 站点字段转换
func TestToScannedSite_DockerFields(t *testing.T) {
	configSite := &config.ScannedSite{
		ID:            "docker.example.com",
		Name:          "Docker Site",
		Source:        "docker",
		ContainerID:   "container-123",
		ContainerName: "nginx-container",
		HostCertPath:  "/host/path/cert.pem",
		HostKeyPath:   "/host/path/key.pem",
		VolumeMode:    true,
	}

	result := toScannedSite(configSite)

	if result.ContainerID != configSite.ContainerID {
		t.Errorf("ContainerID = %s, 期望 %s", result.ContainerID, configSite.ContainerID)
	}
	if result.ContainerName != configSite.ContainerName {
		t.Errorf("ContainerName = %s, 期望 %s", result.ContainerName, configSite.ContainerName)
	}
	if result.HostCertPath != configSite.HostCertPath {
		t.Errorf("HostCertPath = %s, 期望 %s", result.HostCertPath, configSite.HostCertPath)
	}
	if result.HostKeyPath != configSite.HostKeyPath {
		t.Errorf("HostKeyPath = %s, 期望 %s", result.HostKeyPath, configSite.HostKeyPath)
	}
	if result.VolumeMode != configSite.VolumeMode {
		t.Errorf("VolumeMode = %v, 期望 %v", result.VolumeMode, configSite.VolumeMode)
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
			{ID: "site1.com", ServerName: "site1.com"},
			{ID: "site2.com", ServerName: "site2.com"},
			{ID: "site3.com", ServerName: "site3.com"},
		},
	}

	if len(result.Sites) != 3 {
		t.Errorf("Sites 长度 = %d, 期望 3", len(result.Sites))
	}

	// 验证每个站点
	expectedIDs := []string{"site1.com", "site2.com", "site3.com"}
	for i, expected := range expectedIDs {
		if result.Sites[i].ID != expected {
			t.Errorf("Sites[%d].ID = %s, 期望 %s", i, result.Sites[i].ID, expected)
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
				ID:              "test.com",
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
			ID:              site.ID,
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

	if configResult.Sites[0].ID != certopsResult.Sites[0].ID {
		t.Errorf("ID 转换不正确")
	}
}

// TestScanOptions_SSLOnlyFilter 测试 SSL 过滤
func TestScanOptions_SSLOnlyFilter(t *testing.T) {
	allSites := []ScannedSite{
		{ID: "ssl1.com", CertificatePath: "/etc/ssl/ssl1.crt"},
		{ID: "http1.com", CertificatePath: ""},
		{ID: "ssl2.com", CertificatePath: "/etc/ssl/ssl2.crt"},
		{ID: "http2.com", CertificatePath: ""},
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
			t.Errorf("过滤后不应包含无 SSL 的站点: %s", site.ID)
		}
	}
}

// TestScanResult_MixedEnvironment 测试混合环境
func TestScanResult_MixedEnvironment(t *testing.T) {
	result := &ScanResult{
		ScanTime:    time.Now(),
		Environment: "mixed",
		Sites: []ScannedSite{
			{ID: "local.example.com", Source: "local"},
			{ID: "docker.example.com", Source: "docker"},
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
	result, err := svc.ScanSites(nil, ScanOptions{})
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
	result, err := svc.ScanSites(nil, ScanOptions{SSLOnly: true})
	if err != nil {
		t.Errorf("SSL 扫描不应报错: %v", err)
	}

	if result == nil {
		t.Fatal("扫描结果不应为 nil")
	}

	// 验证所有站点都有 SSL 配置
	for _, site := range result.Sites {
		if site.CertificatePath == "" {
			t.Errorf("SSLOnly 过滤后站点 %s 不应无 SSL 配置", site.ID)
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
	result, err := svc.ScanSites(nil, ScanOptions{ServerType: "nginx"})
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

	if site.ID != "" {
		t.Error("空站点 ID 应为空")
	}
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

// TestToScannedSite_EmptyInput 测试空输入转换
func TestToScannedSite_EmptyInput(t *testing.T) {
	configSite := &config.ScannedSite{}
	result := toScannedSite(configSite)

	if result.ID != "" {
		t.Error("空输入转换后 ID 应为空")
	}
	if result.Source != "" {
		t.Error("空输入转换后 Source 应为空")
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
