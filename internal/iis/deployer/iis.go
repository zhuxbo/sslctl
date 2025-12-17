// Package deployer IIS 证书部署器
package deployer

import (
	"fmt"
	"path/filepath"

	"github.com/cnssl/cert-deploy/internal/iis/certstore"
	"github.com/cnssl/cert-deploy/internal/iis/powershell"
)

// IISDeployer IIS 部署器
type IISDeployer struct {
	siteName  string
	hostname  string
	port      int
	tempDir   string
	psRunner  *powershell.Runner
	converter *certstore.Converter
}

// NewIISDeployer 创建 IIS 部署器
func NewIISDeployer(siteName, hostname string, port int, tempDir string) *IISDeployer {
	return &IISDeployer{
		siteName:  siteName,
		hostname:  hostname,
		port:      port,
		tempDir:   tempDir,
		psRunner:  powershell.NewRunner(),
		converter: certstore.NewConverter(tempDir),
	}
}

// Deploy 部署证书到 IIS
// cert: 服务器证书 PEM
// intermediate: 中间证书 PEM
// key: 私钥 PEM
func (d *IISDeployer) Deploy(cert, intermediate, key string) error {
	// 1. 生成临时 PFX 密码
	password, err := certstore.GeneratePassword(32)
	if err != nil {
		return fmt.Errorf("failed to generate password: %w", err)
	}

	// 2. 转换证书为 PFX 格式
	pfxPath, err := d.converter.ConvertToPFX(cert, key, intermediate, password)
	if err != nil {
		return fmt.Errorf("failed to convert to PFX: %w", err)
	}

	// 确保清理临时文件
	if pfxPath != "" {
		defer d.converter.CleanupPFX(pfxPath)
	}

	// 3. 导入证书到 Windows 证书存储
	thumbprint, err := d.psRunner.ImportCertificate(pfxPath, password)
	if err != nil {
		return fmt.Errorf("failed to import certificate: %w", err)
	}

	// 4. 绑定证书到 IIS 站点
	if err := d.psRunner.BindCertificate(d.siteName, thumbprint, d.hostname, d.port); err != nil {
		// 如果绑定失败,尝试清理已导入的证书
		d.psRunner.RemoveCertificate(thumbprint)
		return fmt.Errorf("failed to bind certificate: %w", err)
	}

	return nil
}

// GetCurrentThumbprint 获取当前站点绑定的证书指纹
func (d *IISDeployer) GetCurrentThumbprint() (string, error) {
	_, err := d.psRunner.ListSites()
	if err != nil {
		return "", err
	}
	return "", nil
}

// RemoveOldCertificate 移除旧证书
func (d *IISDeployer) RemoveOldCertificate(thumbprint string) error {
	if thumbprint == "" {
		return nil
	}
	return d.psRunner.RemoveCertificate(thumbprint)
}

// ValidateIISModule 验证 IIS 模块是否可用
func (d *IISDeployer) ValidateIISModule() error {
	command := `
Import-Module WebAdministration -ErrorAction Stop
Write-Output "IIS module loaded successfully"
`
	_, err := d.psRunner.Run(command)
	if err != nil {
		return fmt.Errorf("IIS WebAdministration module not available: %w", err)
	}
	return nil
}

// GetSiteName 获取站点名称
func (d *IISDeployer) GetSiteName() string {
	return d.siteName
}

// GetHostname 获取主机名
func (d *IISDeployer) GetHostname() string {
	return d.hostname
}

// GetPort 获取端口
func (d *IISDeployer) GetPort() int {
	return d.port
}

// GetTempDir 获取临时目录
func (d *IISDeployer) GetTempDir() string {
	return filepath.Clean(d.tempDir)
}
