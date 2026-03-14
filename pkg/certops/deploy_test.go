// Package certops 部署逻辑测试
package certops

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zhuxbo/sslctl/pkg/backup"
	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
	certs "github.com/zhuxbo/sslctl/testdata/certs"
)

// TestPickKeyPath_AllCases 详细测试 pickKeyPath 函数
func TestPickKeyPath_AllCases(t *testing.T) {
	tests := []struct {
		name string
		cert config.CertConfig
		want string
	}{
		{
			name: "空绑定列表",
			cert: config.CertConfig{Bindings: nil},
			want: "",
		},
		{
			name: "空切片绑定列表",
			cert: config.CertConfig{Bindings: []config.SiteBinding{}},
			want: "",
		},
		{
			name: "单个启用绑定",
			cert: config.CertConfig{
				Bindings: []config.SiteBinding{
					{Enabled: true, Paths: config.BindingPaths{PrivateKey: "/path/to/key.pem"}},
				},
			},
			want: "/path/to/key.pem",
		},
		{
			name: "多个绑定，选择第一个启用的",
			cert: config.CertConfig{
				Bindings: []config.SiteBinding{
					{Enabled: false, Paths: config.BindingPaths{PrivateKey: "/path/to/disabled.pem"}},
					{Enabled: true, Paths: config.BindingPaths{PrivateKey: "/path/to/enabled1.pem"}},
					{Enabled: true, Paths: config.BindingPaths{PrivateKey: "/path/to/enabled2.pem"}},
				},
			},
			want: "/path/to/enabled1.pem",
		},
		{
			name: "所有禁用时回退到第一个",
			cert: config.CertConfig{
				Bindings: []config.SiteBinding{
					{Enabled: false, Paths: config.BindingPaths{PrivateKey: "/path/to/first.pem"}},
					{Enabled: false, Paths: config.BindingPaths{PrivateKey: "/path/to/second.pem"}},
				},
			},
			want: "/path/to/first.pem",
		},
		{
			name: "启用但私钥为空，回退到第一个绑定",
			cert: config.CertConfig{
				Bindings: []config.SiteBinding{
					{Enabled: true, Paths: config.BindingPaths{PrivateKey: ""}},
					{Enabled: false, Paths: config.BindingPaths{PrivateKey: "/path/to/key.pem"}},
				},
			},
			want: "", // 回退到第一个绑定的 PrivateKey，即空字符串
		},
		{
			name: "第一个禁用第二个启用有路径",
			cert: config.CertConfig{
				Bindings: []config.SiteBinding{
					{Enabled: false, Paths: config.BindingPaths{PrivateKey: "/path/to/disabled.pem"}},
					{Enabled: true, Paths: config.BindingPaths{PrivateKey: "/path/to/enabled.pem"}},
				},
			},
			want: "/path/to/enabled.pem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pickKeyPath(&tt.cert)
			if got != tt.want {
				t.Errorf("pickKeyPath() = %s, 期望 %s", got, tt.want)
			}
		})
	}
}

// TestRollbackFromBackup 测试回滚功能
func TestRollbackFromBackup(t *testing.T) {
	tmpDir := t.TempDir()

	// 创建配置管理器
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	// 创建模拟的备份目录和文件
	backupDir := filepath.Join(tmpDir, "backup", "test-site", "20240101-120000")
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		t.Fatalf("创建备份目录失败: %v", err)
	}

	// 创建备份文件
	backupCert := "-----BEGIN CERTIFICATE-----\nbackup-cert\n-----END CERTIFICATE-----"
	backupKey := "-----BEGIN RSA PRIVATE KEY-----\nbackup-key\n-----END RSA PRIVATE KEY-----"
	if err := os.WriteFile(filepath.Join(backupDir, "cert.pem"), []byte(backupCert), 0644); err != nil {
		t.Fatalf("写入备份证书失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(backupDir, "key.pem"), []byte(backupKey), 0600); err != nil {
		t.Fatalf("写入备份私钥失败: %v", err)
	}

	// 创建目标目录
	targetDir := filepath.Join(tmpDir, "certs", "test-site")
	if err := os.MkdirAll(targetDir, 0700); err != nil {
		t.Fatalf("创建目标目录失败: %v", err)
	}

	// 创建当前文件（将被覆盖）
	if err := os.WriteFile(filepath.Join(targetDir, "cert.pem"), []byte("current-cert"), 0644); err != nil {
		t.Fatalf("写入当前证书失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(targetDir, "key.pem"), []byte("current-key"), 0600); err != nil {
		t.Fatalf("写入当前私钥失败: %v", err)
	}

	binding := &config.SiteBinding{
		SiteName:   "test-site",
		ServerType: config.ServerTypeNginx,
		Paths: config.BindingPaths{
			Certificate: filepath.Join(targetDir, "cert.pem"),
			PrivateKey:  filepath.Join(targetDir, "key.pem"),
		},
		Reload: config.ReloadConfig{
			TestCommand:   "",
			ReloadCommand: "",
		},
	}

	// 执行回滚
	err = svc.rollbackFromBackup(binding, backupDir)
	if err != nil {
		t.Fatalf("rollbackFromBackup() error = %v", err)
	}

	// 验证文件已回滚
	certData, err := os.ReadFile(filepath.Join(targetDir, "cert.pem"))
	if err != nil {
		t.Fatalf("读取回滚后证书失败: %v", err)
	}
	if string(certData) != backupCert {
		t.Errorf("证书未正确回滚, got = %s", string(certData))
	}

	keyData, err := os.ReadFile(filepath.Join(targetDir, "key.pem"))
	if err != nil {
		t.Fatalf("读取回滚后私钥失败: %v", err)
	}
	if string(keyData) != backupKey {
		t.Errorf("私钥未正确回滚, got = %s", string(keyData))
	}
}

// TestDeployToBinding_UnsupportedServerType 测试不支持的服务器类型
func TestDeployToBinding_UnsupportedServerType(t *testing.T) {
	tmpDir := t.TempDir()

	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	// 生成有效证书
	testCert, err := certs.GenerateValidCert("test.example.com", []string{"test.example.com"})
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	binding := &config.SiteBinding{
		SiteName:   "test-site",
		ServerType: "unsupported-type",
		Paths: config.BindingPaths{
			Certificate: filepath.Join(tmpDir, "cert.pem"),
			PrivateKey:  filepath.Join(tmpDir, "key.pem"),
		},
	}

	certData := &fetcher.CertData{
		Cert:             testCert.CertPEM,
		IntermediateCert: "",
	}

	// 测试不支持的服务器类型
	err = svc.deployToBinding(t.Context(), binding, certData, testCert.KeyPEM)
	if err == nil {
		t.Error("不支持的服务器类型应返回错误")
	}
	// 通过 webserver 抽象层，错误信息变为 "创建部署器失败: unknown server type"
	if err != nil && !strings.Contains(err.Error(), "unknown server type") && !strings.Contains(err.Error(), "创建部署器失败") {
		t.Errorf("错误信息不正确: %v", err)
	}
}

// TestDeployToBinding_InvalidCert 测试无效证书
func TestDeployToBinding_InvalidCert(t *testing.T) {
	tmpDir := t.TempDir()

	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	binding := &config.SiteBinding{
		SiteName:   "test-site",
		ServerType: config.ServerTypeNginx,
		Paths: config.BindingPaths{
			Certificate: filepath.Join(tmpDir, "cert.pem"),
			PrivateKey:  filepath.Join(tmpDir, "key.pem"),
		},
	}

	tests := []struct {
		name    string
		cert    string
		wantErr bool
	}{
		{"无效 PEM", certs.InvalidPEM, true},
		{"空 PEM", certs.EmptyPEM, true},
		{"非证书 PEM", certs.NotCertPEM, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certData := &fetcher.CertData{
				Cert:             tt.cert,
				IntermediateCert: "",
			}
			err := svc.deployToBinding(t.Context(), binding, certData, "fake-key")
			if (err != nil) != tt.wantErr {
				t.Errorf("deployToBinding() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestDeployToBinding_MismatchedKeyPair 测试不匹配的证书私钥对
func TestDeployToBinding_MismatchedKeyPair(t *testing.T) {
	tmpDir := t.TempDir()

	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	// 生成不匹配的证书私钥对
	mismatchedPair, err := certs.GenerateMismatchedKeyPair("test.example.com")
	if err != nil {
		t.Fatalf("生成不匹配密钥对失败: %v", err)
	}

	binding := &config.SiteBinding{
		SiteName:   "test-site",
		ServerType: config.ServerTypeNginx,
		Paths: config.BindingPaths{
			Certificate: filepath.Join(tmpDir, "cert.pem"),
			PrivateKey:  filepath.Join(tmpDir, "key.pem"),
		},
	}

	certData := &fetcher.CertData{
		Cert:             mismatchedPair.CertPEM,
		IntermediateCert: "",
	}

	err = svc.deployToBinding(t.Context(), binding, certData, mismatchedPair.WrongKey)
	if err == nil {
		t.Error("不匹配的密钥对应返回错误")
	}
	if err != nil && !strings.Contains(err.Error(), "私钥不匹配") {
		t.Errorf("错误信息不正确: %v", err)
	}
}

// TestDeployResult_SuccessAndFail 测试 DeployResult 结构的成功和失败情况
func TestDeployResult_SuccessAndFail(t *testing.T) {
	// 成功结果
	successResult := &DeployResult{
		CertName: "test-cert",
		Success:  true,
		Error:    nil,
	}

	if !successResult.Success {
		t.Error("成功结果的 Success 应为 true")
	}
	if successResult.Error != nil {
		t.Error("成功结果的 Error 应为 nil")
	}

	// 失败结果
	failResult := &DeployResult{
		CertName: "test-cert",
		Success:  false,
		Error:    os.ErrNotExist,
	}

	if failResult.Success {
		t.Error("失败结果的 Success 应为 false")
	}
	if failResult.Error == nil {
		t.Error("失败结果的 Error 不应为 nil")
	}
}

// TestBackupManagerIntegration 测试备份管理器集成
func TestBackupManagerIntegration(t *testing.T) {
	tmpDir := t.TempDir()

	// 创建备份管理器
	backupDir := filepath.Join(tmpDir, "backup")
	mgr := backup.NewManager(backupDir, 5)

	// 准备测试文件
	certsDir := filepath.Join(tmpDir, "certs")
	if err := os.MkdirAll(certsDir, 0700); err != nil {
		t.Fatalf("创建证书目录失败: %v", err)
	}

	certPath := filepath.Join(certsDir, "cert.pem")
	keyPath := filepath.Join(certsDir, "key.pem")

	if err := os.WriteFile(certPath, []byte("test-cert"), 0644); err != nil {
		t.Fatalf("写入测试证书失败: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("test-key"), 0600); err != nil {
		t.Fatalf("写入测试私钥失败: %v", err)
	}

	// 执行备份
	result, err := mgr.Backup("test-site", certPath, keyPath, nil, "")
	if err != nil {
		t.Fatalf("备份失败: %v", err)
	}

	if result.BackupPath == "" {
		t.Error("备份路径不应为空")
	}

	// 验证备份文件存在
	backupCertPath, backupKeyPath, _ := mgr.GetBackupPathsWithChain(result.BackupPath)
	if _, err := os.Stat(backupCertPath); os.IsNotExist(err) {
		t.Error("备份证书文件不存在")
	}
	if _, err := os.Stat(backupKeyPath); os.IsNotExist(err) {
		t.Error("备份私钥文件不存在")
	}
}

// TestCertChainDeployment 测试带证书链的部署场景
func TestCertChainDeployment(t *testing.T) {
	// 生成证书链
	chain, err := certs.GenerateCertChain("leaf.example.com", []string{"leaf.example.com", "www.leaf.example.com"})
	if err != nil {
		t.Fatalf("生成证书链失败: %v", err)
	}

	// 验证证书链各部分不为空
	if chain.LeafCertPEM == "" {
		t.Error("叶子证书为空")
	}
	if chain.IntermediateCertPEM == "" {
		t.Error("中间证书为空")
	}
	if chain.RootCertPEM == "" {
		t.Error("根证书为空")
	}
	if chain.LeafKeyPEM == "" {
		t.Error("叶子私钥为空")
	}

	// 验证完整链
	fullChain := chain.FullChainPEM()
	if fullChain == "" {
		t.Error("完整证书链为空")
	}

	// 验证中间链
	intermediateChain := chain.IntermediateChainPEM()
	if intermediateChain == "" {
		t.Error("中间证书链为空")
	}
}

// TestECCertDeployment 测试 ECC 证书
func TestECCertDeployment(t *testing.T) {
	ecCert, err := certs.GenerateECCert("ec.example.com", []string{"ec.example.com"})
	if err != nil {
		t.Fatalf("生成 EC 证书失败: %v", err)
	}

	if ecCert.CertPEM == "" {
		t.Error("EC 证书 PEM 为空")
	}
	if ecCert.KeyPEM == "" {
		t.Error("EC 私钥 PEM 为空")
	}
}

// TestWildcardCertDeployment 测试通配符证书
func TestWildcardCertDeployment(t *testing.T) {
	wildcardCert, err := certs.GenerateWildcardCert("example.com")
	if err != nil {
		t.Fatalf("生成通配符证书失败: %v", err)
	}

	if wildcardCert.CertPEM == "" {
		t.Error("通配符证书 PEM 为空")
	}
	if wildcardCert.Cert == nil {
		t.Error("通配符证书对象为空")
	}

	// 验证 DNS 名称包含通配符
	hasWildcard := false
	for _, dns := range wildcardCert.Cert.DNSNames {
		if dns == "*.example.com" {
			hasWildcard = true
			break
		}
	}
	if !hasWildcard {
		t.Error("通配符证书应包含 *.example.com")
	}
}

// TestDeployToBinding_Nginx_Success 测试 Nginx 部署成功
func TestDeployToBinding_Nginx_Success(t *testing.T) {
	tmpDir := t.TempDir()

	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	// 生成有效证书
	testCert, err := certs.GenerateValidCert("test.example.com", []string{"test.example.com"})
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	certPath := filepath.Join(tmpDir, "ssl", "cert.pem")
	keyPath := filepath.Join(tmpDir, "ssl", "key.pem")

	binding := &config.SiteBinding{
		SiteName:   "test-site",
		ServerType: config.ServerTypeNginx,
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
		Cert:             testCert.CertPEM,
		IntermediateCert: "",
	}

	err = svc.deployToBinding(t.Context(), binding, certData, testCert.KeyPEM)
	if err != nil {
		t.Errorf("Nginx 部署失败: %v", err)
	}

	// 验证文件已创建
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("证书文件未创建")
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("私钥文件未创建")
	}
}

// TestDeployToBinding_Apache_Success 测试 Apache 部署成功
func TestDeployToBinding_Apache_Success(t *testing.T) {
	tmpDir := t.TempDir()

	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	// 生成有效证书
	testCert, err := certs.GenerateValidCert("test.example.com", []string{"test.example.com"})
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	certPath := filepath.Join(tmpDir, "ssl", "cert.pem")
	keyPath := filepath.Join(tmpDir, "ssl", "key.pem")
	chainPath := filepath.Join(tmpDir, "ssl", "chain.pem")

	binding := &config.SiteBinding{
		SiteName:   "test-site",
		ServerType: config.ServerTypeApache,
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
		Cert:             testCert.CertPEM,
		IntermediateCert: "",
	}

	err = svc.deployToBinding(t.Context(), binding, certData, testCert.KeyPEM)
	if err != nil {
		t.Errorf("Apache 部署失败: %v", err)
	}

	// 验证文件已创建
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("证书文件未创建")
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("私钥文件未创建")
	}
}

// TestDeployToBinding_WithBackup 测试带备份的部署
func TestDeployToBinding_WithBackup(t *testing.T) {
	tmpDir := t.TempDir()

	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	// 生成有效证书
	testCert, err := certs.GenerateValidCert("test.example.com", []string{"test.example.com"})
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	// 创建现有证书目录和文件
	sslDir := filepath.Join(tmpDir, "ssl")
	if err := os.MkdirAll(sslDir, 0755); err != nil {
		t.Fatalf("创建 SSL 目录失败: %v", err)
	}

	certPath := filepath.Join(sslDir, "cert.pem")
	keyPath := filepath.Join(sslDir, "key.pem")

	// 写入旧证书
	if err := os.WriteFile(certPath, []byte("old-cert"), 0644); err != nil {
		t.Fatalf("写入旧证书失败: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("old-key"), 0600); err != nil {
		t.Fatalf("写入旧私钥失败: %v", err)
	}

	binding := &config.SiteBinding{
		SiteName:   "test-site",
		ServerType: config.ServerTypeNginx,
		Paths: config.BindingPaths{
			Certificate: certPath,
			PrivateKey:  keyPath,
		},
	}

	certData := &fetcher.CertData{
		Cert:             testCert.CertPEM,
		IntermediateCert: "",
	}

	err = svc.deployToBinding(t.Context(), binding, certData, testCert.KeyPEM)
	if err != nil {
		t.Errorf("带备份的部署失败: %v", err)
	}

	// 验证备份目录存在
	backupDir := filepath.Join(tmpDir, "backup")
	if _, err := os.Stat(backupDir); os.IsNotExist(err) {
		t.Error("备份目录未创建")
	}

	// 验证新证书已部署
	newCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("读取新证书失败: %v", err)
	}
	if string(newCert) == "old-cert" {
		t.Error("证书未更新")
	}
}

// TestDeployToBinding_DockerNginx 测试 Docker Nginx 部署
func TestDeployToBinding_DockerNginx(t *testing.T) {
	tmpDir := t.TempDir()

	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	// 生成有效证书
	testCert, err := certs.GenerateValidCert("test.example.com", []string{"test.example.com"})
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	certPath := filepath.Join(tmpDir, "ssl", "cert.pem")
	keyPath := filepath.Join(tmpDir, "ssl", "key.pem")

	binding := &config.SiteBinding{
		SiteName:   "docker-site",
		ServerType: config.ServerTypeDockerNginx,
		Paths: config.BindingPaths{
			Certificate: certPath,
			PrivateKey:  keyPath,
		},
	}

	certData := &fetcher.CertData{
		Cert:             testCert.CertPEM,
		IntermediateCert: "",
	}

	err = svc.deployToBinding(t.Context(), binding, certData, testCert.KeyPEM)
	if err != nil {
		t.Errorf("Docker Nginx 部署失败: %v", err)
	}
}

// TestDeployToBinding_DockerApache 测试 Docker Apache 部署
func TestDeployToBinding_DockerApache(t *testing.T) {
	tmpDir := t.TempDir()

	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	// 生成有效证书
	testCert, err := certs.GenerateValidCert("test.example.com", []string{"test.example.com"})
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	certPath := filepath.Join(tmpDir, "ssl", "cert.pem")
	keyPath := filepath.Join(tmpDir, "ssl", "key.pem")

	binding := &config.SiteBinding{
		SiteName:   "docker-site",
		ServerType: config.ServerTypeDockerApache,
		Paths: config.BindingPaths{
			Certificate: certPath,
			PrivateKey:  keyPath,
		},
	}

	certData := &fetcher.CertData{
		Cert:             testCert.CertPEM,
		IntermediateCert: "",
	}

	err = svc.deployToBinding(t.Context(), binding, certData, testCert.KeyPEM)
	if err != nil {
		t.Errorf("Docker Apache 部署失败: %v", err)
	}
}

// TestDeployToBinding_WithIntermediateCert 测试带中间证书的部署
func TestDeployToBinding_WithIntermediateCert(t *testing.T) {
	tmpDir := t.TempDir()

	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	// 生成证书链
	chain, err := certs.GenerateCertChain("test.example.com", []string{"test.example.com"})
	if err != nil {
		t.Fatalf("生成证书链失败: %v", err)
	}

	certPath := filepath.Join(tmpDir, "ssl", "cert.pem")
	keyPath := filepath.Join(tmpDir, "ssl", "key.pem")

	binding := &config.SiteBinding{
		SiteName:   "test-site",
		ServerType: config.ServerTypeNginx,
		Paths: config.BindingPaths{
			Certificate: certPath,
			PrivateKey:  keyPath,
		},
	}

	certData := &fetcher.CertData{
		Cert:             chain.LeafCertPEM,
		IntermediateCert: chain.IntermediateCertPEM,
	}

	err = svc.deployToBinding(t.Context(), binding, certData, chain.LeafKeyPEM)
	if err != nil {
		t.Errorf("带中间证书的部署失败: %v", err)
	}

	// 验证证书文件包含中间证书
	certContent, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("读取证书失败: %v", err)
	}
	if !strings.Contains(string(certContent), "-----BEGIN CERTIFICATE-----") {
		t.Error("证书文件内容不正确")
	}
}

// TestRollbackFromBackup_WithChainFile 测试带证书链文件的回滚
func TestRollbackFromBackup_WithChainFile(t *testing.T) {
	tmpDir := t.TempDir()

	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	// 创建备份目录和文件
	backupDir := filepath.Join(tmpDir, "backup", "test-site", "20240101-120000")
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		t.Fatalf("创建备份目录失败: %v", err)
	}

	backupCert := "backup-cert-content"
	backupKey := "backup-key-content"
	backupChain := "backup-chain-content"

	if err := os.WriteFile(filepath.Join(backupDir, "cert.pem"), []byte(backupCert), 0644); err != nil {
		t.Fatalf("写入备份证书失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(backupDir, "key.pem"), []byte(backupKey), 0600); err != nil {
		t.Fatalf("写入备份私钥失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(backupDir, "chain.pem"), []byte(backupChain), 0644); err != nil {
		t.Fatalf("写入备份证书链失败: %v", err)
	}

	// 创建目标目录和文件
	targetDir := filepath.Join(tmpDir, "ssl")
	if err := os.MkdirAll(targetDir, 0700); err != nil {
		t.Fatalf("创建目标目录失败: %v", err)
	}

	certPath := filepath.Join(targetDir, "cert.pem")
	keyPath := filepath.Join(targetDir, "key.pem")
	chainPath := filepath.Join(targetDir, "chain.pem")

	if err := os.WriteFile(certPath, []byte("current-cert"), 0644); err != nil {
		t.Fatalf("写入当前证书失败: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("current-key"), 0600); err != nil {
		t.Fatalf("写入当前私钥失败: %v", err)
	}
	if err := os.WriteFile(chainPath, []byte("current-chain"), 0644); err != nil {
		t.Fatalf("写入当前证书链失败: %v", err)
	}

	binding := &config.SiteBinding{
		SiteName:   "test-site",
		ServerType: config.ServerTypeApache,
		Paths: config.BindingPaths{
			Certificate: certPath,
			PrivateKey:  keyPath,
			ChainFile:   chainPath,
		},
	}

	err = svc.rollbackFromBackup(binding, backupDir)
	if err != nil {
		t.Fatalf("回滚失败: %v", err)
	}

	// 验证文件已回滚
	certData, _ := os.ReadFile(certPath)
	if string(certData) != backupCert {
		t.Error("证书未正确回滚")
	}

	keyData, _ := os.ReadFile(keyPath)
	if string(keyData) != backupKey {
		t.Error("私钥未正确回滚")
	}
}

// TestNewService_Fields 测试创建服务后内部字段
func TestNewService_Fields(t *testing.T) {
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
	if svc.cfgManager != cm {
		t.Error("cfgManager 未正确设置")
	}
	if svc.fetcher == nil {
		t.Error("fetcher 未初始化")
	}
	if svc.backupMgr == nil {
		t.Error("backupMgr 未初始化")
	}
	if svc.log != log {
		t.Error("log 未正确设置")
	}
}


// TestSendDeployCallback_EmptyAPI 测试 API URL 为空时回调直接返回
func TestSendDeployCallback_EmptyAPI(t *testing.T) {
	tmpDir := t.TempDir()
	cm, _ := config.NewConfigManagerWithDir(tmpDir)
	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	// API 为空的证书
	cert := &config.CertConfig{
		CertName: "test-cert",
		OrderID:  123,
		Domains:  []string{"example.com"},
	}
	result := &DeployResult{CertName: "test-cert", Success: true}

	// API URL 为空，不应 panic
	svc.sendDeployCallback(t.Context(), cert, result)

	// API Token 为空
	cert2 := &config.CertConfig{
		CertName: "test-cert",
		OrderID:  123,
		Domains:  []string{"example.com"},
		API:      config.APIConfig{URL: "https://api.com", Token: ""},
	}
	svc.sendDeployCallback(t.Context(), cert2, result)
}

// TestSendDeployCallback_SuccessResult 测试成功结果的回调
func TestSendDeployCallback_SuccessResult(t *testing.T) {
	tmpDir := t.TempDir()
	cm, _ := config.NewConfigManagerWithDir(tmpDir)
	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	callbackServer := newCallbackTestServer(t)
	defer callbackServer.Close()

	cert := &config.CertConfig{
		CertName: "test-cert",
		OrderID:  123,
		Domains:  []string{"example.com", "www.example.com"},
		API:      config.APIConfig{URL: callbackServer.URL, Token: "test-token"},
		Bindings: []config.SiteBinding{
			{SiteName: "site1", ServerType: config.ServerTypeNginx, Enabled: true},
		},
	}
	result := &DeployResult{CertName: "test-cert", Success: true}

	// 使用本地回调服务，不应 panic（非关键路径）
	svc.sendDeployCallback(t.Context(), cert, result)
}

// TestSendDeployCallback_FailureResult 测试失败结果的回调
func TestSendDeployCallback_FailureResult(t *testing.T) {
	tmpDir := t.TempDir()
	cm, _ := config.NewConfigManagerWithDir(tmpDir)
	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	callbackServer := newCallbackTestServer(t)
	defer callbackServer.Close()

	cert := &config.CertConfig{
		CertName: "test-cert",
		OrderID:  456,
		Domains:  []string{"fail.com"},
		API:      config.APIConfig{URL: callbackServer.URL, Token: "test-token"},
	}
	result := &DeployResult{
		CertName: "test-cert",
		Success:  false,
		Error:    fmt.Errorf("deploy error"),
	}

	// 失败结果也不应 panic
	svc.sendDeployCallback(t.Context(), cert, result)
}

// TestSendDeployCallback_WithCallbackURL 测试使用 CallbackURL 的回调
func TestSendDeployCallback_WithCallbackURL(t *testing.T) {
	tmpDir := t.TempDir()
	cm, _ := config.NewConfigManagerWithDir(tmpDir)
	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	callbackServer := newCallbackTestServer(t)
	defer callbackServer.Close()

	// 使用自定义 CallbackURL
	cert := &config.CertConfig{
		CertName: "test-cert",
		OrderID:  789,
		Domains:  []string{"callback.com"},
		API: config.APIConfig{
			URL:         callbackServer.URL,
			Token:       "test-token",
			CallbackURL: callbackServer.URL + "/hook",
		},
	}
	result := &DeployResult{CertName: "test-cert", Success: true}

	svc.sendDeployCallback(t.Context(), cert, result)
}
