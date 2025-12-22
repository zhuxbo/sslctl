package certstore

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/cnssl/cert-deploy/testdata/certs"
)

func TestParseCertificate(t *testing.T) {
	// 生成有效证书
	testCert, err := certs.GenerateValidCert("example.com", []string{"example.com"})
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	cert, err := parseCertificate(testCert.CertPEM)
	if err != nil {
		t.Errorf("解析证书失败: %v", err)
	}

	if cert.Subject.CommonName != "example.com" {
		t.Errorf("CN 不匹配: 期望 example.com, 实际 %s", cert.Subject.CommonName)
	}
}

func TestParseCertificate_InvalidPEM(t *testing.T) {
	_, err := parseCertificate(certs.InvalidPEM)
	if err == nil {
		t.Error("期望无效 PEM 解析失败，但实际通过")
	}
}

func TestParseCertificate_EmptyPEM(t *testing.T) {
	_, err := parseCertificate("")
	if err == nil {
		t.Error("期望空 PEM 解析失败，但实际通过")
	}
}

func TestParseCertificate_WrongType(t *testing.T) {
	// 传入私钥而非证书
	testCert, _ := certs.GenerateValidCert("example.com", nil)
	_, err := parseCertificate(testCert.KeyPEM)
	if err == nil {
		t.Error("期望非证书类型 PEM 解析失败，但实际通过")
	}
}

func TestParsePrivateKey_RSA(t *testing.T) {
	testCert, err := certs.GenerateValidCert("example.com", nil)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	key, err := parsePrivateKey(testCert.KeyPEM)
	if err != nil {
		t.Errorf("解析 RSA 私钥失败: %v", err)
	}

	if key == nil {
		t.Error("解析的私钥为 nil")
	}
}

func TestParsePrivateKey_EC(t *testing.T) {
	testCert, err := certs.GenerateECCert("example.com", nil)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	key, err := parsePrivateKey(testCert.KeyPEM)
	if err != nil {
		t.Errorf("解析 EC 私钥失败: %v", err)
	}

	if key == nil {
		t.Error("解析的私钥为 nil")
	}
}

func TestParsePrivateKey_InvalidPEM(t *testing.T) {
	_, err := parsePrivateKey(certs.InvalidPEM)
	if err == nil {
		t.Error("期望无效 PEM 解析失败，但实际通过")
	}
}

func TestParsePrivateKey_WrongType(t *testing.T) {
	// 传入证书而非私钥
	testCert, _ := certs.GenerateValidCert("example.com", nil)
	_, err := parsePrivateKey(testCert.CertPEM)
	if err == nil {
		t.Error("期望非私钥类型 PEM 解析失败，但实际通过")
	}
}

func TestGeneratePassword(t *testing.T) {
	// 测试密码生成
	passwords := make(map[string]bool)

	for i := 0; i < 100; i++ {
		pwd, err := GeneratePassword(32)
		if err != nil {
			t.Fatalf("生成密码失败: %v", err)
		}

		if len(pwd) != 32 {
			t.Errorf("密码长度期望 32，实际 %d", len(pwd))
		}

		// 检查唯一性
		if passwords[pwd] {
			t.Error("生成了重复的密码")
		}
		passwords[pwd] = true
	}
}

func TestGeneratePassword_DifferentLengths(t *testing.T) {
	lengths := []int{8, 16, 32, 64}
	for _, length := range lengths {
		pwd, err := GeneratePassword(length)
		if err != nil {
			t.Errorf("生成 %d 长度密码失败: %v", length, err)
		}
		if len(pwd) != length {
			t.Errorf("密码长度期望 %d，实际 %d", length, len(pwd))
		}
	}
}

func TestConvertToPFX(t *testing.T) {
	// 生成测试证书和私钥
	testCert, err := certs.GenerateValidCert("example.com", []string{"example.com"})
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	// 生成中间证书（模拟）
	intermediateCert, err := certs.GenerateValidCert("Intermediate CA", nil)
	if err != nil {
		t.Fatalf("生成中间证书失败: %v", err)
	}

	// 创建临时目录
	tmpDir, err := os.MkdirTemp("", "pfx-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// 创建转换器
	converter := NewConverter(tmpDir)
	password := "testpassword123"

	// 转换为 PFX
	pfxPath, err := converter.ConvertToPFX(testCert.CertPEM, testCert.KeyPEM, intermediateCert.CertPEM, password)
	if err != nil {
		t.Fatalf("转换为 PFX 失败: %v", err)
	}

	// 验证 PFX 文件存在
	if _, err := os.Stat(pfxPath); os.IsNotExist(err) {
		t.Error("PFX 文件未创建")
	}

	// 验证 PFX 文件不为空
	info, _ := os.Stat(pfxPath)
	if info.Size() == 0 {
		t.Error("PFX 文件为空")
	}

	// 清理
	err = converter.CleanupPFX(pfxPath)
	if err != nil {
		t.Errorf("清理 PFX 文件失败: %v", err)
	}

	// 验证文件已删除
	if _, err := os.Stat(pfxPath); !os.IsNotExist(err) {
		t.Error("PFX 文件未删除")
	}
}

func TestConvertToPFX_NoIntermediate(t *testing.T) {
	// 测试没有中间证书的情况
	testCert, err := certs.GenerateValidCert("example.com", nil)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	tmpDir, err := os.MkdirTemp("", "pfx-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	converter := NewConverter(tmpDir)
	password := "testpassword123"

	// 转换为 PFX（无中间证书）
	pfxPath, err := converter.ConvertToPFX(testCert.CertPEM, testCert.KeyPEM, "", password)
	if err != nil {
		t.Fatalf("转换为 PFX 失败: %v", err)
	}

	// 验证 PFX 文件存在
	if _, err := os.Stat(pfxPath); os.IsNotExist(err) {
		t.Error("PFX 文件未创建")
	}

	converter.CleanupPFX(pfxPath)
}

func TestConvertToPFX_InvalidCert(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pfx-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	converter := NewConverter(tmpDir)

	// 无效证书
	_, err = converter.ConvertToPFX(certs.InvalidPEM, "", "", "password")
	if err == nil {
		t.Error("期望无效证书转换失败，但实际通过")
	}
}

func TestConvertToPFX_InvalidKey(t *testing.T) {
	testCert, _ := certs.GenerateValidCert("example.com", nil)

	tmpDir, err := os.MkdirTemp("", "pfx-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	converter := NewConverter(tmpDir)

	// 无效私钥
	_, err = converter.ConvertToPFX(testCert.CertPEM, certs.InvalidPEM, "", "password")
	if err == nil {
		t.Error("期望无效私钥转换失败，但实际通过")
	}
}

func TestValidatePrivateKey(t *testing.T) {
	// 生成匹配的证书和私钥
	testCert, err := certs.GenerateValidCert("example.com", nil)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	// 解析证书
	block, _ := pem.Decode([]byte(testCert.CertPEM))
	cert, _ := x509.ParseCertificate(block.Bytes)

	// 解析私钥
	key, _ := parsePrivateKey(testCert.KeyPEM)

	// 验证匹配
	err = ValidatePrivateKey(cert, key)
	if err != nil {
		t.Errorf("验证匹配的证书和私钥失败: %v", err)
	}
}

func TestValidatePrivateKey_Mismatch(t *testing.T) {
	// 生成两对不同的证书/私钥
	cert1, _ := certs.GenerateValidCert("example1.com", nil)
	cert2, _ := certs.GenerateValidCert("example2.com", nil)

	// 解析 cert1 的证书
	block, _ := pem.Decode([]byte(cert1.CertPEM))
	cert, _ := x509.ParseCertificate(block.Bytes)

	// 解析 cert2 的私钥
	key, _ := parsePrivateKey(cert2.KeyPEM)

	// 验证不匹配
	err := ValidatePrivateKey(cert, key)
	if err == nil {
		t.Error("期望不匹配的证书和私钥验证失败，但实际通过")
	}
}

func TestCleanupPFX_NonExistent(t *testing.T) {
	converter := NewConverter(os.TempDir())

	// 清理不存在的文件不应报错
	err := converter.CleanupPFX("/nonexistent/path/to/file.pfx")
	if err != nil {
		t.Errorf("清理不存在的文件不应报错: %v", err)
	}
}

func TestCleanupPFX_Empty(t *testing.T) {
	converter := NewConverter(os.TempDir())

	// 清理空路径不应报错
	err := converter.CleanupPFX("")
	if err != nil {
		t.Errorf("清理空路径不应报错: %v", err)
	}
}
