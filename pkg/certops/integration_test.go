// Package certops 集成测试（使用真实 API）
package certops

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/csr"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
)

var loadEnvOnce sync.Once

func ensureTestEnv(t *testing.T) {
	t.Helper()
	loadEnvOnce.Do(func() {
		if err := loadDotEnv(".env"); err != nil {
			t.Logf("加载 .env 失败: %v", err)
		}
	})
}

func loadDotEnv(filename string) error {
	startDir, err := os.Getwd()
	if err != nil {
		return err
	}

	dir := startDir
	for {
		envPath := filepath.Join(dir, filename)
		if _, statErr := os.Stat(envPath); statErr == nil {
			return applyDotEnv(envPath)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return nil
}

func applyDotEnv(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" {
			continue
		}
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}
		if os.Getenv(key) == "" {
			_ = os.Setenv(key, value)
		}
	}
	return scanner.Err()
}

// getTestAPIConfig 获取测试 API 配置（必须通过环境变量设置）
func getTestAPIConfig(t *testing.T) (string, string) {
	ensureTestEnv(t)
	url := os.Getenv("TEST_API_URL")
	token := os.Getenv("TEST_API_TOKEN")
	if url == "" || token == "" {
		t.Skip("跳过集成测试: 未设置 TEST_API_URL 或 TEST_API_TOKEN 环境变量")
	}
	return url, token
}

func getTestAPIDomain(t *testing.T) string {
	ensureTestEnv(t)
	domain := strings.TrimSpace(os.Getenv("TEST_API_DOMAIN"))
	if domain == "" {
		t.Skip("跳过集成测试: 未设置 TEST_API_DOMAIN 环境变量")
	}
	return domain
}

func getTestAPIMethod() string {
	method := strings.TrimSpace(os.Getenv("TEST_API_METHOD"))
	if method == "" {
		return "http"
	}
	return method
}

func requireWriteAccess(t *testing.T) {
	t.Helper()
	ensureTestEnv(t)
	if strings.TrimSpace(os.Getenv("TEST_API_ALLOW_WRITE")) != "1" {
		t.Skip("跳过写入型集成测试: 未设置 TEST_API_ALLOW_WRITE=1")
	}
}

func requireCallbackAccess(t *testing.T) {
	t.Helper()
	ensureTestEnv(t)
	if strings.TrimSpace(os.Getenv("TEST_API_ALLOW_CALLBACK")) != "1" {
		t.Skip("跳过回调集成测试: 未设置 TEST_API_ALLOW_CALLBACK=1")
	}
}

func splitDomains(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	domains := make([]string, 0, len(parts))
	for _, part := range parts {
		domain := strings.TrimSpace(part)
		if domain != "" {
			domains = append(domains, domain)
		}
	}
	return domains
}

func containsDomain(domains []string, target string) bool {
	target = normalizeDomain(target)
	for _, domain := range domains {
		if matchDomain(target, normalizeDomain(domain)) {
			return true
		}
	}
	return false
}

func normalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSpace(domain))
}

// matchDomain 支持简单通配符匹配（仅支持前缀 *.)
func matchDomain(expect, candidate string) bool {
	if expect == "" || candidate == "" {
		return false
	}
	if expect == candidate {
		return true
	}

	if strings.HasPrefix(expect, "*.") {
		suffix := strings.TrimPrefix(expect, "*.")
		if strings.HasPrefix(candidate, "*.") {
			candSuffix := strings.TrimPrefix(candidate, "*.")
			return candSuffix == suffix || strings.HasSuffix(candSuffix, "."+suffix)
		}
		return candidate == suffix || strings.HasSuffix(candidate, "."+suffix)
	}

	if strings.HasPrefix(candidate, "*.") {
		candSuffix := strings.TrimPrefix(candidate, "*.")
		return expect == candSuffix || strings.HasSuffix(expect, "."+candSuffix)
	}

	return false
}

// TestIntegration_FetcherInfo 测试 Fetcher.Info 获取证书信息
func TestIntegration_FetcherInfo(t *testing.T) {
	apiURL, token := getTestAPIConfig(t)

	f := fetcher.New(30 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	certData, err := f.Info(ctx, apiURL, token)
	if err != nil {
		t.Logf("Info() 失败（API 可能不支持此接口）: %v", err)
		return
	}

	t.Logf("获取到证书信息:")
	t.Logf("  OrderID: %d", certData.OrderID)
	t.Logf("  Status: %s", certData.Status)
	t.Logf("  Domains: %s", certData.Domains)
	t.Logf("  IssuedAt: %s", certData.IssuedAt)
	t.Logf("  ExpiresAt: %s", certData.ExpiresAt)
	t.Logf("  HasCert: %v", certData.Cert != "")
	t.Logf("  HasKey: %v", certData.PrivateKey != "")
	t.Logf("  HasCA: %v", certData.IntermediateCert != "")
}

// TestIntegration_DomainMatch 验证 API 返回的域名包含预期域名
func TestIntegration_DomainMatch(t *testing.T) {
	apiURL, token := getTestAPIConfig(t)
	expectDomain := getTestAPIDomain(t)

	f := fetcher.New(30 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	certData, err := f.Info(ctx, apiURL, token)
	if err != nil {
		t.Fatalf("Info() 失败: %v", err)
	}

	candidates := splitDomains(certData.Domains)

	if !containsDomain(candidates, expectDomain) {
		t.Fatalf("域名不匹配: want %q, got %v", expectDomain, candidates)
	}

	t.Logf("✓ 域名匹配: %s", expectDomain)
}

// TestIntegration_QueryByDomain 测试按域名查询
func TestIntegration_QueryByDomain(t *testing.T) {
	apiURL, token := getTestAPIConfig(t)
	expectDomain := getTestAPIDomain(t)

	f := fetcher.New(30 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	certData, err := f.Query(ctx, apiURL, token, expectDomain)
	if err != nil {
		t.Fatalf("Query() 失败: %v", err)
	}

	if certData == nil {
		t.Fatal("Query() 返回空数据")
	}

	candidates := splitDomains(certData.Domains)

	if !containsDomain(candidates, expectDomain) {
		t.Fatalf("查询结果域名不匹配: want %q, got %v", expectDomain, candidates)
	}
}

// TestIntegration_UpdateWithCSR 测试更新/续费接口（需显式允许写入）
func TestIntegration_UpdateWithCSR(t *testing.T) {
	requireWriteAccess(t)
	apiURL, token := getTestAPIConfig(t)
	expectDomain := getTestAPIDomain(t)

	f := fetcher.New(30 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	infoData, err := f.Info(ctx, apiURL, token)
	if err != nil {
		t.Fatalf("Info() 失败: %v", err)
	}
	if infoData.OrderID == 0 {
		t.Skip("未获取到有效 OrderID，跳过更新测试")
	}

	keyPEM, csrPEM, _, err := csr.GenerateKeyAndCSR(csr.KeyOptions{}, csr.CSROptions{
		CommonName: expectDomain,
	})
	if err != nil {
		t.Fatalf("生成 CSR 失败: %v", err)
	}
	if keyPEM == "" || csrPEM == "" {
		t.Fatalf("CSR 或私钥为空")
	}

	domains := strings.TrimSpace(os.Getenv("TEST_API_DOMAINS"))
	if domains == "" {
		domains = infoData.Domains
	}
	if domains == "" {
		domains = expectDomain
	}

	method := getTestAPIMethod()
	updated, err := f.Update(ctx, apiURL, token, infoData.OrderID, csrPEM, domains, method)
	if err != nil {
		t.Fatalf("Update() 失败: %v", err)
	}
	if updated == nil {
		t.Fatal("Update() 返回空数据")
	}
	if updated.OrderID == 0 {
		t.Log("注意: Update() 未返回有效 OrderID")
	}
}

// TestIntegration_CallbackNew 测试回调接口（需显式允许写入与回调）
func TestIntegration_CallbackNew(t *testing.T) {
	requireWriteAccess(t)
	requireCallbackAccess(t)
	apiURL, token := getTestAPIConfig(t)

	f := fetcher.New(30 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	infoData, err := f.Info(ctx, apiURL, token)
	if err != nil {
		t.Fatalf("Info() 失败: %v", err)
	}
	if infoData.OrderID == 0 {
		t.Skip("未获取到有效 OrderID，跳过回调测试")
	}

	req := &fetcher.CallbackRequest{
		OrderID:    infoData.OrderID,
		Status:     "success",
		DeployedAt: time.Now().Format(time.RFC3339),
	}

	if err := f.CallbackNew(ctx, apiURL, token, req); err != nil {
		t.Fatalf("CallbackNew() 失败: %v", err)
	}
}

// TestIntegration_QueryOrder 测试按订单 ID 查询
func TestIntegration_QueryOrder(t *testing.T) {
	apiURL, token := getTestAPIConfig(t)

	f := fetcher.New(30 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// 先获取一个有效的订单 ID
	infoData, err := f.Info(ctx, apiURL, token)
	if err != nil {
		t.Logf("无法获取订单信息: %v", err)
		return
	}

	if infoData.OrderID == 0 {
		t.Log("未获取到有效的 OrderID")
		return
	}

	t.Logf("使用 OrderID %d 进行查询", infoData.OrderID)

	certData, err := f.QueryOrder(ctx, apiURL, token, infoData.OrderID)
	if err != nil {
		t.Logf("QueryOrder() 失败: %v", err)
		return
	}

	t.Logf("QueryOrder 返回:")
	t.Logf("  OrderID: %d", certData.OrderID)
	t.Logf("  Status: %s", certData.Status)
	t.Logf("  Domains: %s", certData.Domains)

	// 验证返回的订单 ID 匹配
	if certData.OrderID != infoData.OrderID {
		t.Errorf("OrderID 不匹配: got %d, want %d", certData.OrderID, infoData.OrderID)
	}
}

// TestIntegration_DeployToLocal 测试部署证书到本地目录
func TestIntegration_DeployToLocal(t *testing.T) {
	apiURL, token := getTestAPIConfig(t)

	f := fetcher.New(30 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// 获取证书数据
	certData, err := f.Info(ctx, apiURL, token)
	if err != nil {
		t.Logf("无法获取证书信息: %v", err)
		return
	}

	if certData.Status != "active" || certData.Cert == "" {
		t.Logf("证书未就绪 (status=%s, hasCert=%v)", certData.Status, certData.Cert != "")
		return
	}

	if certData.PrivateKey == "" {
		t.Log("API 未返回私钥，跳过部署测试")
		return
	}

	t.Logf("准备部署证书:")
	t.Logf("  Domains: %s", certData.Domains)
	t.Logf("  ExpiresAt: %s", certData.ExpiresAt)

	// 创建临时目录进行部署
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")
	chainPath := filepath.Join(tmpDir, "chain.pem")

	// 创建配置管理器
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	// 创建服务
	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	// 创建绑定配置
	binding := &config.SiteBinding{
		ServerName: "integration-test",
		ServerType: config.ServerTypeNginx,
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

	// 执行部署
	err = svc.deployToBinding(ctx, binding, certData, certData.PrivateKey)
	if err != nil {
		t.Fatalf("部署失败: %v", err)
	}

	// 验证证书文件
	certContent, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("读取证书文件失败: %v", err)
	}
	if !strings.Contains(string(certContent), "-----BEGIN CERTIFICATE-----") {
		t.Error("证书文件内容不正确")
	}
	t.Logf("证书文件大小: %d bytes", len(certContent))

	// 验证私钥文件
	keyContent, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("读取私钥文件失败: %v", err)
	}
	if !strings.Contains(string(keyContent), "-----BEGIN") {
		t.Error("私钥文件内容不正确")
	}
	t.Logf("私钥文件大小: %d bytes", len(keyContent))

	// 验证文件权限
	keyInfo, _ := os.Stat(keyPath)
	if keyInfo.Mode().Perm() != 0600 {
		t.Errorf("私钥权限 = %o, 期望 0600", keyInfo.Mode().Perm())
	}

	t.Log("✓ 证书部署成功")
}

// TestIntegration_FullDeployWorkflow 测试完整部署工作流
func TestIntegration_FullDeployWorkflow(t *testing.T) {
	apiURL, token := getTestAPIConfig(t)

	// 创建临时目录
	tmpDir := t.TempDir()

	// 创建配置管理器
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	// 初始化 API 配置
	// API 配置直接写入证书级别（见下方 cert 定义）

	// 获取证书信息确定 OrderID
	f := fetcher.New(30 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	certData, err := f.Info(ctx, apiURL, token)
	if err != nil {
		t.Logf("无法获取证书信息: %v", err)
		return
	}

	if certData.OrderID == 0 {
		t.Log("未获取到有效 OrderID")
		return
	}

	// 创建证书配置（cert_name 格式: {domain}-{orderID}）
	domains := strings.Split(certData.Domains, ",")
	domain := strings.TrimSpace(domains[0])
	certName := strings.Replace(domain, "*.", "WILDCARD.", 1) + "-" + strconv.Itoa(certData.OrderID)
	siteCertsDir := filepath.Join(tmpDir, "certs", certName)

	cert := &config.CertConfig{
		CertName: certName,
		OrderID:  certData.OrderID,
		Enabled:  true,
		Domains:  strings.Split(certData.Domains, ","),
		API:      config.APIConfig{URL: apiURL, Token: token},
		Bindings: []config.SiteBinding{
			{
				ServerName: "test-site",
				ServerType: config.ServerTypeNginx,
				Enabled:    true,
				Paths: config.BindingPaths{
					Certificate: filepath.Join(siteCertsDir, "cert.pem"),
					PrivateKey:  filepath.Join(siteCertsDir, "key.pem"),
				},
			},
		},
	}

	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书配置失败: %v", err)
	}

	// 创建服务并部署
	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	result, err := svc.DeployOne(ctx, certName)
	if err != nil {
		t.Logf("部署失败: %v", err)
		return
	}

	t.Logf("部署结果:")
	t.Logf("  CertName: %s", result.CertName)
	t.Logf("  Success: %v", result.Success)
	if result.Error != nil {
		t.Logf("  Error: %v", result.Error)
	}

	if result.Success {
		// 验证文件已创建
		if _, err := os.Stat(filepath.Join(siteCertsDir, "cert.pem")); os.IsNotExist(err) {
			t.Error("证书文件未创建")
		}
		if _, err := os.Stat(filepath.Join(siteCertsDir, "key.pem")); os.IsNotExist(err) {
			t.Error("私钥文件未创建")
		}
		t.Log("✓ 完整部署工作流成功")
	}
}

// TestIntegration_ScanAndDeploy 测试扫描后部署
func TestIntegration_ScanAndDeploy(t *testing.T) {
	tmpDir := t.TempDir()

	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	// 执行扫描
	ctx := context.Background()
	scanResult, err := svc.ScanSites(ctx, ScanOptions{})
	if err != nil {
		t.Logf("扫描失败: %v", err)
	}

	t.Logf("扫描结果:")
	t.Logf("  扫描时间: %s", scanResult.ScanTime.Format(time.RFC3339))
	t.Logf("  环境: %s", scanResult.Environment)
	t.Logf("  站点数: %d", len(scanResult.Sites))

	for i, site := range scanResult.Sites {
		t.Logf("  [%d] %s", i+1, site.ServerName)
		t.Logf("      配置文件: %s", site.ConfigFile)
		t.Logf("      SSL证书: %s", site.CertificatePath)
	}
}

// TestIntegration_APIResponseParsing 测试 API 响应解析
func TestIntegration_APIResponseParsing(t *testing.T) {
	apiURL, token := getTestAPIConfig(t)

	f := fetcher.New(30 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	certData, err := f.Info(ctx, apiURL, token)
	if err != nil {
		t.Logf("API 调用失败: %v", err)
		return
	}

	// 验证必要字段
	if certData.OrderID <= 0 {
		t.Log("注意: OrderID 为空或无效")
	}

	if certData.Status == "" {
		t.Error("Status 不应为空")
	}

	// 验证证书格式
	if certData.Cert != "" {
		if !strings.Contains(certData.Cert, "-----BEGIN CERTIFICATE-----") {
			t.Error("证书格式不正确")
		}
		if !strings.Contains(certData.Cert, "-----END CERTIFICATE-----") {
			t.Error("证书格式不完整")
		}
		t.Logf("证书长度: %d 字符", len(certData.Cert))
	}

	// 验证私钥格式
	if certData.PrivateKey != "" {
		if !strings.Contains(certData.PrivateKey, "-----BEGIN") {
			t.Error("私钥格式不正确")
		}
		t.Logf("私钥长度: %d 字符", len(certData.PrivateKey))
	}

	// 验证 CA 证书格式
	if certData.IntermediateCert != "" {
		if !strings.Contains(certData.IntermediateCert, "-----BEGIN CERTIFICATE-----") {
			t.Error("CA证书格式不正确")
		}
		t.Logf("CA证书长度: %d 字符", len(certData.IntermediateCert))
	}
}

// TestIntegration_DeployWithBackup 测试带备份的部署
func TestIntegration_DeployWithBackup(t *testing.T) {
	apiURL, token := getTestAPIConfig(t)

	f := fetcher.New(30 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	certData, err := f.Info(ctx, apiURL, token)
	if err != nil || certData.Cert == "" || certData.PrivateKey == "" {
		t.Log("无法获取有效证书，跳过备份测试")
		return
	}

	tmpDir := t.TempDir()
	cm, _ := config.NewConfigManagerWithDir(tmpDir)
	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	// 创建 SSL 目录和旧证书
	sslDir := filepath.Join(tmpDir, "ssl")
	_ = os.MkdirAll(sslDir, 0755)

	certPath := filepath.Join(sslDir, "cert.pem")
	keyPath := filepath.Join(sslDir, "key.pem")

	// 写入旧证书
	_ = os.WriteFile(certPath, []byte("OLD-CERT"), 0644)
	_ = os.WriteFile(keyPath, []byte("OLD-KEY"), 0600)

	binding := &config.SiteBinding{
		ServerName: "backup-test",
		ServerType: config.ServerTypeNginx,
		Enabled:    true,
		Paths: config.BindingPaths{
			Certificate: certPath,
			PrivateKey:  keyPath,
		},
	}

	// 部署新证书
	err = svc.deployToBinding(ctx, binding, certData, certData.PrivateKey)
	if err != nil {
		t.Fatalf("部署失败: %v", err)
	}

	// 验证备份目录存在
	backupDir := filepath.Join(tmpDir, "backup")
	if _, err := os.Stat(backupDir); os.IsNotExist(err) {
		t.Log("注意: 备份目录未创建（旧证书可能太短）")
	} else {
		t.Log("✓ 备份已创建")
	}

	// 验证新证书已部署
	newCert, _ := os.ReadFile(certPath)
	if string(newCert) == "OLD-CERT" {
		t.Error("证书未更新")
	} else {
		t.Log("✓ 证书已更新")
	}
}

// TestIntegration_PreparePullRenew 测试自动签发续签
func TestIntegration_PreparePullRenew(t *testing.T) {
	apiURL, token := getTestAPIConfig(t)

	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	// API 配置在证书级别设置

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	// 先获取订单信息
	f := fetcher.New(30 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	infoData, err := f.Info(ctx, apiURL, token)
	if err != nil {
		t.Logf("无法获取订单信息: %v", err)
		return
	}

	if infoData.OrderID == 0 {
		t.Log("未获取到有效 OrderID")
		return
	}

	// 创建测试证书配置
	certPath := filepath.Join(tmpDir, "certs", "test", "key.pem")
	cert := &config.CertConfig{
		CertName: "test-pull",
		OrderID:  infoData.OrderID,
		Enabled:  true,
		Domains:  strings.Split(infoData.Domains, ","),
		Bindings: []config.SiteBinding{
			{
				ServerName: "test-site",
				ServerType: config.ServerTypeNginx,
				Enabled:    true,
				Paths: config.BindingPaths{
					PrivateKey: certPath,
				},
			},
		},
	}

	api := config.APIConfig{URL: apiURL, Token: token}

	// 测试 preparePullRenew
	certData, privateKey, err := svc.preparePullRenew(ctx, cert, api)

	if err != nil {
		t.Logf("preparePullRenew 失败: %v", err)
		return
	}

	if certData == nil {
		t.Log("certData 为 nil（证书可能不是 active 状态）")
		return
	}

	t.Logf("preparePullRenew 成功:")
	t.Logf("  OrderID: %d", certData.OrderID)
	t.Logf("  Status: %s", certData.Status)
	t.Logf("  HasPrivateKey: %v", privateKey != "")
}

// TestIntegration_CheckAndRenewAll 测试完整续签流程
func TestIntegration_CheckAndRenewAll(t *testing.T) {
	apiURL, token := getTestAPIConfig(t)

	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	// API 配置在证书级别设置

	// 先获取订单信息
	f := fetcher.New(30 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	infoData, err := f.Info(ctx, apiURL, token)
	if err != nil {
		t.Logf("无法获取订单信息: %v", err)
		return
	}

	if infoData.OrderID == 0 {
		t.Log("未获取到有效 OrderID")
		return
	}

	// 创建需要续签的证书（过期时间设置在 14 天内触发续签）
	certDir := filepath.Join(tmpDir, "ssl", "test")
	cert := &config.CertConfig{
		CertName: "renew-test",
		OrderID:  infoData.OrderID,
		Enabled:  true,
		Domains:  strings.Split(infoData.Domains, ","),
		API:      config.APIConfig{URL: apiURL, Token: token},
		Metadata: config.CertMetadata{
			CertExpiresAt: time.Now().Add(7 * 24 * time.Hour), // 7 天后过期（触发续签）
		},
		Bindings: []config.SiteBinding{
			{
				ServerName: "renew-site",
				ServerType: config.ServerTypeNginx,
				Enabled:    true,
				Paths: config.BindingPaths{
					Certificate: filepath.Join(certDir, "cert.pem"),
					PrivateKey:  filepath.Join(certDir, "key.pem"),
				},
			},
		},
	}
	_ = cm.AddCert(cert)

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	results, err := svc.CheckAndRenewAll(ctx)
	if err != nil {
		t.Logf("CheckAndRenewAll 失败: %v", err)
		return
	}

	t.Logf("CheckAndRenewAll 结果: %d 个证书", len(results))
	for _, r := range results {
		t.Logf("  %s: status=%s, mode=%s, deployCount=%d",
			r.CertName, r.Status, r.Mode, r.DeployCount)
		if r.Error != nil {
			t.Logf("    error: %v", r.Error)
		}
	}
}

// TestIntegration_RenewWithLocalKey 测试本地私钥续签
func TestIntegration_RenewWithLocalKey(t *testing.T) {
	apiURL, token := getTestAPIConfig(t)

	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	// API 配置在证书级别设置

	// 设置本机提交
	cfg, _ := cm.Load()
	cfg.Schedule = config.ScheduleConfig{
		RenewMode:       config.RenewModeLocal,
		RenewBeforeDays: 13,
	}
	_ = cm.Save(cfg)

	// 先获取订单信息
	f := fetcher.New(30 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	infoData, err := f.Info(ctx, apiURL, token)
	if err != nil {
		t.Logf("无法获取订单信息: %v", err)
		return
	}

	if infoData.OrderID == 0 {
		t.Log("未获取到有效 OrderID")
		return
	}

	// 如果 API 返回了私钥，先保存到本地
	certDir := filepath.Join(tmpDir, "ssl", "local-test")
	keyPath := filepath.Join(certDir, "key.pem")

	if infoData.PrivateKey != "" {
		_ = os.MkdirAll(certDir, 0700)
		_ = os.WriteFile(keyPath, []byte(infoData.PrivateKey), 0600)
		t.Log("已保存私钥到本地")
	} else {
		t.Log("API 未返回私钥，跳过本地私钥续签测试")
		return
	}

	cert := &config.CertConfig{
		CertName: "local-key-test",
		OrderID:  infoData.OrderID,
		Enabled:  true,
		Domains:  strings.Split(infoData.Domains, ","),
		API:      config.APIConfig{URL: apiURL, Token: token},
		Metadata: config.CertMetadata{
			CertExpiresAt: time.Now().Add(7 * 24 * time.Hour), // 触发续签
		},
		Bindings: []config.SiteBinding{
			{
				ServerName: "local-site",
				ServerType: config.ServerTypeNginx,
				Enabled:    true,
				Paths: config.BindingPaths{
					Certificate: filepath.Join(certDir, "cert.pem"),
					PrivateKey:  keyPath,
				},
			},
		},
	}
	_ = cm.AddCert(cert)

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	results, err := svc.CheckAndRenewAll(ctx)
	if err != nil {
		t.Logf("CheckAndRenewAll 失败: %v", err)
	}

	t.Logf("本地私钥续签结果: %d 个证书", len(results))
	for _, r := range results {
		t.Logf("  %s: status=%s, mode=%s", r.CertName, r.Status, r.Mode)
	}
}
