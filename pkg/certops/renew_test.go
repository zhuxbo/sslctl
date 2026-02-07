// Package certops 续签逻辑测试
package certops

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
	certs "github.com/zhuxbo/sslctl/testdata/certs"
)

// TestGetPendingKeyPath 测试待确认私钥路径生成
func TestGetPendingKeyPath(t *testing.T) {
	workDir := "/opt/sslctl"
	certName := "order-123"

	path := getPendingKeyPath(workDir, certName)
	expected := "/opt/sslctl/pending-keys/order-123/pending-key.pem"

	if path != expected {
		t.Errorf("getPendingKeyPath() = %s, 期望 %s", path, expected)
	}
}

// TestSavePendingKey 测试保存待确认私钥
func TestSavePendingKey(t *testing.T) {
	workDir := t.TempDir()
	certName := "test-cert"
	keyPEM := "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"

	err := savePendingKey(workDir, certName, keyPEM)
	if err != nil {
		t.Fatalf("savePendingKey() error = %v", err)
	}

	// 验证文件已创建
	pendingPath := getPendingKeyPath(workDir, certName)
	if _, err := os.Stat(pendingPath); os.IsNotExist(err) {
		t.Error("待确认私钥文件未创建")
	}

	// 验证文件内容
	data, _ := os.ReadFile(pendingPath)
	if string(data) != keyPEM {
		t.Error("待确认私钥内容不正确")
	}

	// 验证文件权限
	info, _ := os.Stat(pendingPath)
	if info.Mode().Perm() != 0600 {
		t.Errorf("文件权限 = %o, 期望 0600", info.Mode().Perm())
	}
}

// TestReadPendingKey 测试读取待确认私钥
func TestReadPendingKey(t *testing.T) {
	workDir := t.TempDir()
	certName := "test-cert"
	keyPEM := "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"

	// 先保存
	_ = savePendingKey(workDir, certName, keyPEM)

	// 读取
	readKey, err := readPendingKey(workDir, certName)
	if err != nil {
		t.Fatalf("readPendingKey() error = %v", err)
	}

	if readKey != keyPEM {
		t.Error("读取的私钥内容不正确")
	}
}

// TestReadPendingKey_NotExist 测试读取不存在的待确认私钥
func TestReadPendingKey_NotExist(t *testing.T) {
	workDir := t.TempDir()
	certName := "nonexistent"

	_, err := readPendingKey(workDir, certName)
	if err == nil {
		t.Error("读取不存在的私钥应返回错误")
	}
}

// TestCommitPendingKey 测试提交待确认私钥
func TestCommitPendingKey(t *testing.T) {
	workDir := t.TempDir()
	certName := "test-cert"
	keyPEM := "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"

	// 先保存待确认私钥
	_ = savePendingKey(workDir, certName, keyPEM)

	// 目标路径
	targetPath := filepath.Join(workDir, "certs", certName, "key.pem")

	// 提交
	err := commitPendingKey(workDir, certName, targetPath)
	if err != nil {
		t.Fatalf("commitPendingKey() error = %v", err)
	}

	// 验证目标文件已创建
	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		t.Error("目标私钥文件未创建")
	}

	// 验证待确认私钥已删除
	pendingPath := getPendingKeyPath(workDir, certName)
	if _, err := os.Stat(pendingPath); !os.IsNotExist(err) {
		t.Error("待确认私钥文件应已删除")
	}
}

// TestCommitPendingKey_NotExist 测试提交不存在的待确认私钥
func TestCommitPendingKey_NotExist(t *testing.T) {
	workDir := t.TempDir()
	certName := "nonexistent"
	targetPath := filepath.Join(workDir, "key.pem")

	// 应该不报错（静默跳过）
	err := commitPendingKey(workDir, certName, targetPath)
	if err != nil {
		t.Errorf("commitPendingKey() 不存在时应静默跳过，但返回错误: %v", err)
	}
}

// TestCleanupPendingKey 测试清理待确认私钥
func TestCleanupPendingKey(t *testing.T) {
	workDir := t.TempDir()
	certName := "test-cert"
	keyPEM := "test-key"

	// 先保存
	_ = savePendingKey(workDir, certName, keyPEM)

	// 验证文件存在
	pendingPath := getPendingKeyPath(workDir, certName)
	if _, err := os.Stat(pendingPath); os.IsNotExist(err) {
		t.Fatal("待确认私钥文件未创建")
	}

	// 清理
	cleanupPendingKey(workDir, certName)

	// 验证文件已删除
	if _, err := os.Stat(pendingPath); !os.IsNotExist(err) {
		t.Error("待确认私钥文件应已删除")
	}
}

// TestGetRenewMode_Defaults 测试续签模式默认值
func TestGetRenewMode_Defaults(t *testing.T) {
	// 空 schedule
	schedule := &config.ScheduleConfig{}
	mode := getRenewMode(schedule)
	if mode != config.RenewModePull {
		t.Errorf("空模式应默认为 pull，实际: %s", mode)
	}

	// local 模式
	schedule.RenewMode = config.RenewModeLocal
	mode = getRenewMode(schedule)
	if mode != config.RenewModeLocal {
		t.Errorf("显式 local 模式应为 local，实际: %s", mode)
	}
}

// TestMaxIssueRetryCount 测试最大重试次数常量
func TestMaxIssueRetryCount(t *testing.T) {
	if MaxIssueRetryCount <= 0 {
		t.Error("MaxIssueRetryCount 应大于 0")
	}
	if MaxIssueRetryCount > 100 {
		t.Error("MaxIssueRetryCount 不应过大")
	}
}

// TestCommitPendingKey_CrossFileSystem 测试跨文件系统提交
func TestCommitPendingKey_CrossFileSystem(t *testing.T) {
	workDir := t.TempDir()
	certName := "test-cert"
	keyPEM := "-----BEGIN RSA PRIVATE KEY-----\ntest-key\n-----END RSA PRIVATE KEY-----"

	// 先保存待确认私钥
	err := savePendingKey(workDir, certName, keyPEM)
	if err != nil {
		t.Fatalf("savePendingKey() error = %v", err)
	}

	// 目标路径
	targetPath := filepath.Join(workDir, "certs", certName, "key.pem")

	// 提交
	err = commitPendingKey(workDir, certName, targetPath)
	if err != nil {
		t.Fatalf("commitPendingKey() error = %v", err)
	}

	// 验证目标文件已创建且内容正确
	data, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("读取目标文件失败: %v", err)
	}
	if string(data) != keyPEM {
		t.Error("目标文件内容不正确")
	}

	// 验证目标文件权限
	info, err := os.Stat(targetPath)
	if err != nil {
		t.Fatalf("获取文件信息失败: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("文件权限 = %o, 期望 0600", info.Mode().Perm())
	}
}

// TestPendingKeyDir 测试待确认私钥目录常量
func TestPendingKeyDir(t *testing.T) {
	if pendingKeyDir == "" {
		t.Error("pendingKeyDir 不应为空")
	}
	if pendingKeyDir != "pending-keys" {
		t.Errorf("pendingKeyDir = %s, 期望 pending-keys", pendingKeyDir)
	}
}

// TestCsrPendingTimeout 测试 CSR 超时常量
func TestCsrPendingTimeout(t *testing.T) {
	if csrPendingTimeout <= 0 {
		t.Error("csrPendingTimeout 应大于 0")
	}
	if csrPendingTimeout != 24*time.Hour {
		t.Errorf("csrPendingTimeout = %v, 期望 24h", csrPendingTimeout)
	}
}

// TestGetPendingKeyPath_Format 测试待确认私钥路径格式
func TestGetPendingKeyPath_Format(t *testing.T) {
	tests := []struct {
		workDir  string
		certName string
		want     string
	}{
		{"/opt/sslctl", "order-123", "/opt/sslctl/pending-keys/order-123/pending-key.pem"},
		{"/var/lib/cert", "test.com", "/var/lib/cert/pending-keys/test.com/pending-key.pem"},
		{"/tmp", "cert-abc", "/tmp/pending-keys/cert-abc/pending-key.pem"},
	}

	for _, tt := range tests {
		t.Run(tt.certName, func(t *testing.T) {
			got := getPendingKeyPath(tt.workDir, tt.certName)
			if got != tt.want {
				t.Errorf("getPendingKeyPath() = %s, 期望 %s", got, tt.want)
			}
		})
	}
}

// TestSavePendingKey_CreateDirectory 测试保存待确认私钥时创建目录
func TestSavePendingKey_CreateDirectory(t *testing.T) {
	workDir := t.TempDir()
	certName := "deep/nested/cert"
	keyPEM := "test-key"

	err := savePendingKey(workDir, certName, keyPEM)
	if err != nil {
		t.Fatalf("savePendingKey() error = %v", err)
	}

	// 验证文件已创建
	pendingPath := getPendingKeyPath(workDir, certName)
	if _, err := os.Stat(pendingPath); os.IsNotExist(err) {
		t.Error("待确认私钥文件未创建")
	}
}

// TestCleanupPendingKey_Multiple 测试多次清理
func TestCleanupPendingKey_Multiple(t *testing.T) {
	workDir := t.TempDir()
	certName := "test-cert"

	// 先保存
	_ = savePendingKey(workDir, certName, "test-key")

	// 第一次清理
	cleanupPendingKey(workDir, certName)

	// 验证已删除
	pendingPath := getPendingKeyPath(workDir, certName)
	if _, err := os.Stat(pendingPath); !os.IsNotExist(err) {
		t.Error("第一次清理后文件应不存在")
	}

	// 第二次清理（不应报错）
	cleanupPendingKey(workDir, certName)
}

// TestRenewOptions 测试续签选项
func TestRenewOptions_Force(t *testing.T) {
	opts := RenewOptions{Force: false}
	if opts.Force {
		t.Error("默认 Force 应为 false")
	}

	opts.Force = true
	if !opts.Force {
		t.Error("设置后 Force 应为 true")
	}
}

// TestRenewResult_Status 测试续签结果状态
func TestRenewResult_Status(t *testing.T) {
	tests := []struct {
		name   string
		status string
	}{
		{"成功", "success"},
		{"待处理", "pending"},
		{"失败", "failure"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RenewResult{
				CertName: "test-cert",
				Status:   tt.status,
			}
			if result.Status != tt.status {
				t.Errorf("Status = %s, 期望 %s", result.Status, tt.status)
			}
		})
	}
}

// TestRenewResult_WithError 测试带错误的续签结果
func TestRenewResult_WithError(t *testing.T) {
	testErr := os.ErrNotExist
	result := RenewResult{
		CertName: "test-cert",
		Status:   "failure",
		Error:    testErr,
	}

	if result.Error == nil {
		t.Error("Error 不应为 nil")
	}
	if result.Error != testErr {
		t.Error("Error 应为指定的错误")
	}
}

// TestRenewResult_DeployCount 测试部署计数
func TestRenewResult_DeployCount(t *testing.T) {
	result := RenewResult{
		CertName:    "test-cert",
		Status:      "success",
		DeployCount: 3,
	}

	if result.DeployCount != 3 {
		t.Errorf("DeployCount = %d, 期望 3", result.DeployCount)
	}
}

// TestGetRenewMode_AllModes 测试所有续签模式
func TestGetRenewMode_AllModes(t *testing.T) {
	tests := []struct {
		name     string
		mode     string
		expected string
	}{
		{"空模式", "", config.RenewModePull},
		{"显式 pull", config.RenewModePull, config.RenewModePull},
		{"显式 local", config.RenewModeLocal, config.RenewModeLocal},
		{"其他值", "other", "other"}, // 函数不做验证，直接返回
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			schedule := &config.ScheduleConfig{RenewMode: tt.mode}
			got := getRenewMode(schedule)
			if got != tt.expected {
				t.Errorf("getRenewMode() = %s, 期望 %s", got, tt.expected)
			}
		})
	}
}

// TestCheckAndRenewAll_NoAPIConfig 测试无 API 配置时的续签
func TestCheckAndRenewAll_NoAPIConfig(t *testing.T) {
	tmpDir := t.TempDir()

	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	ctx := t.Context()
	_, err = svc.CheckAndRenewAll(ctx)

	if err == nil {
		t.Error("无 API 配置应返回错误")
	}
}

// TestCheckAndRenewAll_EmptyAPIURL 测试 API URL 为空时的续签
func TestCheckAndRenewAll_EmptyAPIURL(t *testing.T) {
	tmpDir := t.TempDir()

	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	// 设置不完整的 API 配置
	_ = cm.SetAPI(config.APIConfig{URL: "", Token: "test-token"})

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	ctx := t.Context()
	_, err = svc.CheckAndRenewAll(ctx)

	if err == nil {
		t.Error("API URL 为空应返回错误")
	}
}

// TestCheckAndRenewAll_EmptyAPIToken 测试 API Token 为空时的续签
func TestCheckAndRenewAll_EmptyAPIToken(t *testing.T) {
	tmpDir := t.TempDir()

	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	// 设置不完整的 API 配置
	_ = cm.SetAPI(config.APIConfig{URL: "http://example.com", Token: ""})

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	ctx := t.Context()
	_, err = svc.CheckAndRenewAll(ctx)

	if err == nil {
		t.Error("API Token 为空应返回错误")
	}
}

// TestCheckAndRenewAll_NoCertificates 测试无证书时的续签
func TestCheckAndRenewAll_NoCertificates(t *testing.T) {
	tmpDir := t.TempDir()

	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	// 设置完整的 API 配置
	_ = cm.SetAPI(config.APIConfig{URL: "http://example.com", Token: "test-token"})

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	ctx := t.Context()
	results, err := svc.CheckAndRenewAll(ctx)

	if err != nil {
		t.Errorf("无证书时不应返回错误: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("无证书时应返回空结果，实际: %d", len(results))
	}
}

// TestCheckAndRenewAll_DisabledCert 测试禁用证书时的续签
func TestCheckAndRenewAll_DisabledCert(t *testing.T) {
	tmpDir := t.TempDir()

	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	// 设置 API 配置
	_ = cm.SetAPI(config.APIConfig{URL: "http://example.com", Token: "test-token"})

	// 添加禁用的证书
	cert := &config.CertConfig{
		CertName: "disabled-cert",
		OrderID:  12345,
		Enabled:  false, // 禁用
		Domains:  []string{"example.com"},
	}
	_ = cm.AddCert(cert)

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	ctx := t.Context()
	results, err := svc.CheckAndRenewAll(ctx)

	if err != nil {
		t.Errorf("禁用证书不应导致错误: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("禁用证书不应有续签结果，实际: %d", len(results))
	}
}

// TestCheckAndRenewAll_CertNotNeedRenewal 测试证书不需要续签时
func TestCheckAndRenewAll_CertNotNeedRenewal(t *testing.T) {
	tmpDir := t.TempDir()

	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	// 设置 API 配置
	_ = cm.SetAPI(config.APIConfig{URL: "http://example.com", Token: "test-token"})

	// 添加有效期充足的证书
	cert := &config.CertConfig{
		CertName: "valid-cert",
		OrderID:  12345,
		Enabled:  true,
		Domains:  []string{"example.com"},
		Metadata: config.CertMetadata{
			CertExpiresAt: time.Now().Add(90 * 24 * time.Hour), // 90 天后过期
		},
	}
	_ = cm.AddCert(cert)

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	ctx := t.Context()
	results, err := svc.CheckAndRenewAll(ctx)

	if err != nil {
		t.Errorf("有效期充足的证书不应导致错误: %v", err)
	}

	// 证书不需要续签，不应有结果
	if len(results) != 0 {
		t.Errorf("有效期充足的证书不应有续签结果，实际: %d", len(results))
	}
}

// TestDeployCertToBindings_NoBindings 测试无绑定时的部署
func TestDeployCertToBindings_NoBindings(t *testing.T) {
	tmpDir := t.TempDir()

	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	// 生成测试证书
	testCert, err := certs.GenerateValidCert("test.com", []string{"test.com"})
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	cert := &config.CertConfig{
		CertName: "test-cert",
		Bindings: []config.SiteBinding{}, // 无绑定
	}

	certData := &fetcher.CertData{
		Cert: testCert.CertPEM,
	}

	ctx := t.Context()
	count, err := svc.deployCertToBindings(ctx, cert, certData, testCert.KeyPEM)

	if err != nil {
		t.Errorf("无绑定时不应返回错误: %v", err)
	}

	if count != 0 {
		t.Errorf("无绑定时部署计数应为 0，实际: %d", count)
	}
}

// TestDeployCertToBindings_AllDisabled 测试所有绑定禁用时的部署
func TestDeployCertToBindings_AllDisabled(t *testing.T) {
	tmpDir := t.TempDir()

	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	// 生成测试证书
	testCert, err := certs.GenerateValidCert("test.com", []string{"test.com"})
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	cert := &config.CertConfig{
		CertName: "test-cert",
		Bindings: []config.SiteBinding{
			{SiteName: "site1", Enabled: false},
			{SiteName: "site2", Enabled: false},
		},
	}

	certData := &fetcher.CertData{
		Cert: testCert.CertPEM,
	}

	ctx := t.Context()
	count, err := svc.deployCertToBindings(ctx, cert, certData, testCert.KeyPEM)

	if err != nil {
		t.Errorf("所有绑定禁用时不应返回错误: %v", err)
	}

	if count != 0 {
		t.Errorf("所有绑定禁用时部署计数应为 0，实际: %d", count)
	}
}

// TestDeployCertToBindings_InvalidCert 测试无效证书时的部署
func TestDeployCertToBindings_InvalidCert(t *testing.T) {
	tmpDir := t.TempDir()

	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	cert := &config.CertConfig{
		CertName: "test-cert",
		Bindings: []config.SiteBinding{
			{SiteName: "site1", Enabled: true},
		},
	}

	certData := &fetcher.CertData{
		Cert: "invalid-cert-data",
	}

	ctx := t.Context()
	_, err = svc.deployCertToBindings(ctx, cert, certData, "invalid-key")

	if err == nil {
		t.Error("无效证书应返回错误")
	}
}

// TestDeployCertToBindings_MismatchedKey 测试私钥不匹配时的部署
func TestDeployCertToBindings_MismatchedKey(t *testing.T) {
	tmpDir := t.TempDir()

	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	// 生成测试证书和不匹配的私钥
	testCert, err := certs.GenerateValidCert("test.com", []string{"test.com"})
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	// 生成另一个证书以获取不匹配的私钥
	anotherCert, err := certs.GenerateValidCert("other.com", []string{"other.com"})
	if err != nil {
		t.Fatalf("生成另一个测试证书失败: %v", err)
	}

	cert := &config.CertConfig{
		CertName: "test-cert",
		Bindings: []config.SiteBinding{
			{SiteName: "site1", Enabled: true},
		},
	}

	certData := &fetcher.CertData{
		Cert: testCert.CertPEM,
	}

	ctx := t.Context()
	_, err = svc.deployCertToBindings(ctx, cert, certData, anotherCert.KeyPEM)

	if err == nil {
		t.Error("私钥不匹配应返回错误")
	}
}

// TestDeployCertToBindings_SuccessfulDeploy 测试成功部署
func TestDeployCertToBindings_SuccessfulDeploy(t *testing.T) {
	tmpDir := t.TempDir()

	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	// 生成测试证书
	testCert, err := certs.GenerateValidCert("test.com", []string{"test.com"})
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	// 创建输出路径
	certPath := filepath.Join(tmpDir, "ssl", "cert.pem")
	keyPath := filepath.Join(tmpDir, "ssl", "key.pem")

	cert := &config.CertConfig{
		CertName: "test-cert",
		Bindings: []config.SiteBinding{
			{
				SiteName:   "site1",
				ServerType: config.ServerTypeNginx,
				Enabled:    true,
				Paths: config.BindingPaths{
					Certificate: certPath,
					PrivateKey:  keyPath,
				},
			},
		},
	}

	certData := &fetcher.CertData{
		Cert: testCert.CertPEM,
	}

	ctx := t.Context()
	count, err := svc.deployCertToBindings(ctx, cert, certData, testCert.KeyPEM)

	if err != nil {
		t.Errorf("成功部署不应返回错误: %v", err)
	}

	if count != 1 {
		t.Errorf("部署计数应为 1，实际: %d", count)
	}

	// 验证元数据已更新
	if cert.Metadata.LastDeployAt.IsZero() {
		t.Error("LastDeployAt 应已更新")
	}

	if cert.Metadata.CertExpiresAt.IsZero() {
		t.Error("CertExpiresAt 应已更新")
	}

	if cert.Metadata.CertSerial == "" {
		t.Error("CertSerial 应已更新")
	}
}

// TestDeployCertToBindings_PartialSuccess 测试部分成功的部署
func TestDeployCertToBindings_PartialSuccess(t *testing.T) {
	tmpDir := t.TempDir()

	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	// 生成测试证书
	testCert, err := certs.GenerateValidCert("test.com", []string{"test.com"})
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	// 创建输出路径
	validCertPath := filepath.Join(tmpDir, "ssl", "cert.pem")
	validKeyPath := filepath.Join(tmpDir, "ssl", "key.pem")

	// 无效路径（只读目录）
	invalidCertPath := "/nonexistent/path/cert.pem"
	invalidKeyPath := "/nonexistent/path/key.pem"

	cert := &config.CertConfig{
		CertName: "test-cert",
		Bindings: []config.SiteBinding{
			{
				SiteName:   "valid-site",
				ServerType: config.ServerTypeNginx,
				Enabled:    true,
				Paths: config.BindingPaths{
					Certificate: validCertPath,
					PrivateKey:  validKeyPath,
				},
			},
			{
				SiteName:   "invalid-site",
				ServerType: config.ServerTypeNginx,
				Enabled:    true,
				Paths: config.BindingPaths{
					Certificate: invalidCertPath,
					PrivateKey:  invalidKeyPath,
				},
			},
		},
	}

	certData := &fetcher.CertData{
		Cert: testCert.CertPEM,
	}

	ctx := t.Context()
	count, err := svc.deployCertToBindings(ctx, cert, certData, testCert.KeyPEM)

	// 应该有一个成功
	if count != 1 {
		t.Errorf("部署计数应为 1，实际: %d", count)
	}

	// 应该返回错误（来自失败的部署）
	if err == nil {
		t.Error("部分失败应返回错误")
	}
}

// TestCommitPendingKey_TargetDirNotExist 测试 commitPendingKey 目标目录不存在时的行为
func TestCommitPendingKey_TargetDirNotExist(t *testing.T) {
	workDir := t.TempDir()
	certName := "commit-test"
	keyPEM := "-----BEGIN RSA PRIVATE KEY-----\ntest-key\n-----END RSA PRIVATE KEY-----"

	// 先保存一个待确认私钥
	if err := savePendingKey(workDir, certName, keyPEM); err != nil {
		t.Fatalf("savePendingKey() error = %v", err)
	}

	// 目标路径指向一个存在的目录
	targetDir := t.TempDir()
	targetPath := filepath.Join(targetDir, "key.pem")

	// 提交应该成功
	err := commitPendingKey(workDir, certName, targetPath)
	if err != nil {
		t.Fatalf("commitPendingKey() 应成功: %v", err)
	}

	// 验证目标文件已创建
	data, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("读取目标文件失败: %v", err)
	}
	if string(data) != keyPEM {
		t.Error("目标文件内容不正确")
	}
}

// TestCommitPendingKey_NoPendingKey 测试 commitPendingKey 不存在待确认私钥时的行为
func TestCommitPendingKey_NoPendingKey(t *testing.T) {
	workDir := t.TempDir()
	// 不存在待确认私钥时应返回 nil（跳过）
	err := commitPendingKey(workDir, "nonexistent", "/tmp/key.pem")
	if err != nil {
		t.Errorf("commitPendingKey() 不存在时应返回 nil: %v", err)
	}
}

// TestSendRenewCallback_EmptyAPI 测试续签回调在 API 配置为空时的行为
func TestSendRenewCallback_EmptyAPI(t *testing.T) {
	tmpDir := t.TempDir()
	cm, _ := config.NewConfigManagerWithDir(tmpDir)
	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	cert := &config.CertConfig{
		CertName: "test-cert",
		OrderID:  123,
		Domains:  []string{"example.com"},
	}
	result := &RenewResult{CertName: "test-cert", Status: "success"}

	// API URL 为空时应直接返回，不 panic
	cfg := &config.Config{API: config.APIConfig{URL: "", Token: ""}}
	svc.sendRenewCallback(t.Context(), cert, result, cfg)

	// Token 为空
	cfg2 := &config.Config{API: config.APIConfig{URL: "https://api.com", Token: ""}}
	svc.sendRenewCallback(t.Context(), cert, result, cfg2)
}

// TestSendRenewCallback_SuccessResult 测试成功结果的续签回调
func TestSendRenewCallback_SuccessResult(t *testing.T) {
	tmpDir := t.TempDir()
	cm, _ := config.NewConfigManagerWithDir(tmpDir)
	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	cert := &config.CertConfig{
		CertName: "test-cert",
		OrderID:  123,
		Domains:  []string{"example.com"},
		Metadata: config.CertMetadata{
			CertExpiresAt: time.Now().Add(90 * 24 * time.Hour),
			CertSerial:    "ABC123",
		},
	}
	result := &RenewResult{CertName: "test-cert", Status: "success"}

	callbackServer := newCallbackTestServer(t)
	defer callbackServer.Close()

	cfg := &config.Config{API: config.APIConfig{URL: callbackServer.URL, Token: "test-token"}}
	// 不应 panic（非关键路径）
	svc.sendRenewCallback(t.Context(), cert, result, cfg)
}

// TestSendRenewCallback_FailureResult 测试失败结果的续签回调
func TestSendRenewCallback_FailureResult(t *testing.T) {
	tmpDir := t.TempDir()
	cm, _ := config.NewConfigManagerWithDir(tmpDir)
	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	cert := &config.CertConfig{
		CertName: "test-cert",
		OrderID:  456,
		Domains:  []string{"fail.com"},
	}
	result := &RenewResult{
		CertName: "test-cert",
		Status:   "failure",
		Error:    os.ErrNotExist,
	}

	callbackServer := newCallbackTestServer(t)
	defer callbackServer.Close()

	cfg := &config.Config{API: config.APIConfig{URL: callbackServer.URL, Token: "test-token"}}
	svc.sendRenewCallback(t.Context(), cert, result, cfg)
}

// TestSendRenewCallback_WithCallbackURL 测试使用自定义 CallbackURL 的续签回调
func TestSendRenewCallback_WithCallbackURL(t *testing.T) {
	tmpDir := t.TempDir()
	cm, _ := config.NewConfigManagerWithDir(tmpDir)
	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	cert := &config.CertConfig{
		CertName: "test-cert",
		OrderID:  789,
		Domains:  []string{"callback.com"},
	}
	result := &RenewResult{CertName: "test-cert", Status: "success"}

	callbackServer := newCallbackTestServer(t)
	defer callbackServer.Close()

	cfg := &config.Config{API: config.APIConfig{
		URL:         callbackServer.URL,
		Token:       "test-token",
		CallbackURL: callbackServer.URL + "/hook",
	}}
	svc.sendRenewCallback(t.Context(), cert, result, cfg)
}

// TestCommitPendingKey_ReadOnlyTargetDir 测试 commitPendingKey 目标目录不可写时的行为
func TestCommitPendingKey_ReadOnlyTargetDir(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root 用户跳过权限测试")
	}

	workDir := t.TempDir()
	certName := "readonly-test"
	keyPEM := "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"

	if err := savePendingKey(workDir, certName, keyPEM); err != nil {
		t.Fatalf("savePendingKey() error = %v", err)
	}

	// 创建只读目标目录
	readOnlyDir := filepath.Join(t.TempDir(), "readonly")
	_ = os.MkdirAll(readOnlyDir, 0500)
	targetPath := filepath.Join(readOnlyDir, "subdir", "key.pem")

	// 提交应该失败
	err := commitPendingKey(workDir, certName, targetPath)
	if err == nil {
		t.Error("commitPendingKey() 目标不可写时应返回错误")
	}
}
