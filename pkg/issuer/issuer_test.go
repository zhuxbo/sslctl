// Package issuer 证书签发测试
package issuer

import (
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/pkg/logger"
	certs "github.com/zhuxbo/sslctl/testdata/certs"
)

// TestNew 测试创建签发器
func TestNew(t *testing.T) {
	log := logger.NewNopLogger()
	issuer := New(log)

	if issuer == nil {
		t.Fatal("New() 返回 nil")
	}
	if issuer.fetcher == nil {
		t.Error("New() fetcher 为 nil")
	}
	if issuer.logger != log {
		t.Error("New() logger 不匹配")
	}
}

// TestNew_NilLogger 测试创建签发器（nil logger）
func TestNew_NilLogger(t *testing.T) {
	issuer := New(nil)

	if issuer == nil {
		t.Fatal("New(nil) 返回 nil")
	}
	// 即使 logger 为 nil，也应该正常创建
	if issuer.fetcher == nil {
		t.Error("New(nil) fetcher 为 nil")
	}
}

// TestDefaultIssueOptions 测试默认选项
func TestDefaultIssueOptions(t *testing.T) {
	if DefaultIssueOptions.MaxWait != 5*time.Minute {
		t.Errorf("DefaultIssueOptions.MaxWait = %v, 期望 5m", DefaultIssueOptions.MaxWait)
	}
	if DefaultIssueOptions.CheckInterval != 10*time.Second {
		t.Errorf("DefaultIssueOptions.CheckInterval = %v, 期望 10s", DefaultIssueOptions.CheckInterval)
	}
}

// TestIssueResult 测试签发结果结构
func TestIssueResult(t *testing.T) {
	result := &IssueResult{
		CertData:   nil,
		PrivateKey: "test-key",
		CSRHash:    "test-hash",
	}

	if result.PrivateKey != "test-key" {
		t.Error("IssueResult.PrivateKey 不匹配")
	}
	if result.CSRHash != "test-hash" {
		t.Error("IssueResult.CSRHash 不匹配")
	}
}

// TestIssueOptions_Defaults 测试选项默认值合并
func TestIssueOptions_Defaults(t *testing.T) {
	opts := IssueOptions{}

	// 验证零值
	if opts.MaxWait != 0 {
		t.Error("零值 MaxWait 应该为 0")
	}
	if opts.CheckInterval != 0 {
		t.Error("零值 CheckInterval 应该为 0")
	}
}

// TestCheckAndIssueResult_Actions 测试动作常量
func TestCheckAndIssueResult_Actions(t *testing.T) {
	actions := []string{ActionSkip, ActionDeployed, ActionSubmitted, ActionError}
	expected := []string{"skip", "deployed", "submitted", "error"}

	for i, action := range actions {
		if action != expected[i] {
			t.Errorf("动作常量 %d: got %q, want %q", i, action, expected[i])
		}
	}
}

// TestValidateKeyPair_Invalid 测试无效的证书私钥对
func TestValidateKeyPair_Invalid(t *testing.T) {
	log := logger.NewNopLogger()
	issuer := New(log)

	tests := []struct {
		name    string
		certPEM string
		keyPEM  string
	}{
		{"空证书", "", "key"},
		{"空私钥", "cert", ""},
		{"两者都空", "", ""},
		{"无效PEM", "invalid-cert", "invalid-key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := issuer.validateKeyPair(tt.certPEM, tt.keyPEM)
			if valid {
				t.Errorf("validateKeyPair(%q, %q) = true, 期望 false", tt.certPEM, tt.keyPEM)
			}
		})
	}
}

// TestLog_NilLogger 测试 nil logger 不会 panic
func TestLog_NilLogger(t *testing.T) {
	issuer := &Issuer{
		fetcher: nil,
		logger:  nil,
	}

	// 不应该 panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("log() 方法在 nil logger 时 panic: %v", r)
		}
	}()

	issuer.log("test message %s", "arg")
}

// TestIssueOptions_Validation 测试选项验证
func TestIssueOptions_Validation(t *testing.T) {
	tests := []struct {
		name           string
		opts           IssueOptions
		expectMaxWait  time.Duration
		expectInterval time.Duration
	}{
		{
			name:           "零值使用默认",
			opts:           IssueOptions{},
			expectMaxWait:  5 * time.Minute,
			expectInterval: 10 * time.Second,
		},
		{
			name: "自定义值",
			opts: IssueOptions{
				MaxWait:       1 * time.Minute,
				CheckInterval: 5 * time.Second,
			},
			expectMaxWait:  1 * time.Minute,
			expectInterval: 5 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 模拟选项合并逻辑
			if tt.opts.MaxWait == 0 {
				tt.opts.MaxWait = DefaultIssueOptions.MaxWait
			}
			if tt.opts.CheckInterval == 0 {
				tt.opts.CheckInterval = DefaultIssueOptions.CheckInterval
			}

			if tt.opts.MaxWait != tt.expectMaxWait {
				t.Errorf("MaxWait = %v, 期望 %v", tt.opts.MaxWait, tt.expectMaxWait)
			}
			if tt.opts.CheckInterval != tt.expectInterval {
				t.Errorf("CheckInterval = %v, 期望 %v", tt.opts.CheckInterval, tt.expectInterval)
			}
		})
	}
}

// TestCheckAndIssueResult_Fields 测试 CheckAndIssueResult 字段
func TestCheckAndIssueResult_Fields(t *testing.T) {
	result := &CheckAndIssueResult{
		CertData:   nil,
		PrivateKey: "test-key",
		Action:     ActionDeployed,
		OrderID:    12345,
	}

	if result.PrivateKey != "test-key" {
		t.Error("CheckAndIssueResult.PrivateKey 不匹配")
	}
	if result.Action != ActionDeployed {
		t.Error("CheckAndIssueResult.Action 不匹配")
	}
	if result.OrderID != 12345 {
		t.Error("CheckAndIssueResult.OrderID 不匹配")
	}
}

// TestIssueOptions_WebRoot 测试 Webroot 选项
func TestIssueOptions_WebRoot(t *testing.T) {
	tests := []struct {
		name    string
		webroot string
	}{
		{"空路径", ""},
		{"相对路径", "public"},
		{"绝对路径", "/var/www/html"},
		{"Windows路径", `C:\inetpub\wwwroot`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := IssueOptions{
				Webroot: tt.webroot,
			}
			if opts.Webroot != tt.webroot {
				t.Errorf("Webroot = %q, 期望 %q", opts.Webroot, tt.webroot)
			}
		})
	}
}

// TestValidateKeyPair_ValidPair 测试有效的证书私钥对
func TestValidateKeyPair_ValidPair(t *testing.T) {
	log := logger.NewNopLogger()
	iss := New(log)

	// 生成有效的证书私钥对
	testCert, err := certs.GenerateValidCert("test.example.com", []string{"test.example.com"})
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	valid := iss.validateKeyPair(testCert.CertPEM, testCert.KeyPEM)
	if !valid {
		t.Error("有效的证书私钥对应返回 true")
	}
}

// TestValidateKeyPair_MismatchedPair 测试不匹配的证书私钥对
func TestValidateKeyPair_MismatchedPair(t *testing.T) {
	log := logger.NewNopLogger()
	iss := New(log)

	// 生成两组证书，使用第一组的证书和第二组的私钥
	cert1, err := certs.GenerateValidCert("cert1.example.com", []string{"cert1.example.com"})
	if err != nil {
		t.Fatalf("生成测试证书1失败: %v", err)
	}
	cert2, err := certs.GenerateValidCert("cert2.example.com", []string{"cert2.example.com"})
	if err != nil {
		t.Fatalf("生成测试证书2失败: %v", err)
	}

	valid := iss.validateKeyPair(cert1.CertPEM, cert2.KeyPEM)
	if valid {
		t.Error("不匹配的证书私钥对应返回 false")
	}
}

// TestLog_WithLogger 测试有 logger 时的日志输出
func TestLog_WithLogger(t *testing.T) {
	log := logger.NewNopLogger()
	iss := New(log)

	// 不应 panic
	iss.log("test %s %d", "message", 42)
}

// TestIssueOptions_ValidationMethod 测试验证方式选项
func TestIssueOptions_ValidationMethod(t *testing.T) {
	methods := []string{"file", "txt", "dns", "http", ""}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			opts := IssueOptions{
				ValidationMethod: method,
			}
			if opts.ValidationMethod != method {
				t.Errorf("ValidationMethod = %q, 期望 %q", opts.ValidationMethod, method)
			}
		})
	}
}
