// Package installer 为 IIS 站点安装 HTTPS 配置
package installer

import (
	"fmt"
	"strings"

	"github.com/cnssl/cert-deploy/internal/iis/powershell"
)

// IISInstaller IIS HTTPS 安装器
type IISInstaller struct {
	siteName    string             // IIS 站点名称
	hostname    string             // 主机名
	port        int                // HTTPS 端口
	thumbprint  string             // 证书指纹
	psRunner    *powershell.Runner // PowerShell 执行器
}

// NewIISInstaller 创建 IIS 安装器
func NewIISInstaller(siteName, hostname string, port int, thumbprint string) *IISInstaller {
	if port == 0 {
		port = 443
	}
	return &IISInstaller{
		siteName:   siteName,
		hostname:   hostname,
		port:       port,
		thumbprint: thumbprint,
		psRunner:   powershell.NewRunner(),
	}
}

// InstallResult 安装结果
type InstallResult struct {
	BindingCreated bool   // 是否创建了绑定
	Message        string // 结果消息
}

// Install 安装 HTTPS 配置
// 为站点添加 HTTPS 绑定并关联证书
func (i *IISInstaller) Install() (*InstallResult, error) {
	// 1. 检查 HTTPS 绑定是否已存在
	exists, err := i.hasHTTPSBinding()
	if err != nil {
		return nil, fmt.Errorf("检查 HTTPS 绑定失败: %w", err)
	}

	if exists {
		return &InstallResult{
			BindingCreated: false,
			Message:        "HTTPS 绑定已存在",
		}, nil
	}

	// 2. 添加 HTTPS 绑定并关联证书
	if err := i.addHTTPSBinding(); err != nil {
		return nil, fmt.Errorf("添加 HTTPS 绑定失败: %w", err)
	}

	return &InstallResult{
		BindingCreated: true,
		Message:        fmt.Sprintf("已为站点 %s 添加 HTTPS 绑定", i.siteName),
	}, nil
}

// hasHTTPSBinding 检查是否已有 HTTPS 绑定
func (i *IISInstaller) hasHTTPSBinding() (bool, error) {
	command := fmt.Sprintf(`
Import-Module WebAdministration

$siteName = "%s"
$hostname = "%s"
$port = %d

try {
    $bindings = Get-WebBinding -Name $siteName -Protocol "https" -ErrorAction SilentlyContinue

    if ($bindings) {
        $matchingBinding = $bindings | Where-Object {
            $info = $_.bindingInformation.Split(':')
            ($info[1] -eq $port) -and ($info[2] -eq $hostname)
        }

        if ($matchingBinding) {
            Write-Output "EXISTS"
            exit 0
        }
    }

    Write-Output "NOT_EXISTS"
    exit 0
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
`, escapePSString(i.siteName), escapePSString(i.hostname), i.port)

	output, err := i.psRunner.Run(command)
	if err != nil {
		return false, err
	}

	return strings.TrimSpace(output) == "EXISTS", nil
}

// addHTTPSBinding 添加 HTTPS 绑定
func (i *IISInstaller) addHTTPSBinding() error {
	command := fmt.Sprintf(`
Import-Module WebAdministration

$siteName = "%s"
$hostname = "%s"
$port = %d
$thumbprint = "%s"

try {
    # 检查站点是否存在
    $site = Get-Website -Name $siteName -ErrorAction Stop
    if (-not $site) {
        Write-Error "站点不存在: $siteName"
        exit 1
    }

    # 检查证书是否存在
    $cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $thumbprint }
    if (-not $cert) {
        Write-Error "证书不存在: $thumbprint"
        exit 1
    }

    # 创建 HTTPS 绑定
    $bindingInfo = "*:${port}:${hostname}"
    New-WebBinding -Name $siteName -Protocol "https" -BindingInformation $bindingInfo -ErrorAction Stop

    # 关联证书
    $binding = Get-WebBinding -Name $siteName -Protocol "https" | Where-Object { $_.bindingInformation -eq $bindingInfo }
    if ($binding) {
        $binding.AddSslCertificate($thumbprint, "My")
        Write-Output "HTTPS 绑定创建成功"
        exit 0
    } else {
        Write-Error "无法获取新创建的绑定"
        exit 1
    }
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
`, escapePSString(i.siteName), escapePSString(i.hostname), i.port, escapePSString(i.thumbprint))

	_, err := i.psRunner.Run(command)
	return err
}

// Rollback 回滚 - 移除 HTTPS 绑定
func (i *IISInstaller) Rollback() error {
	command := fmt.Sprintf(`
Import-Module WebAdministration

$siteName = "%s"
$hostname = "%s"
$port = %d

try {
    $bindingInfo = "*:${port}:${hostname}"
    $binding = Get-WebBinding -Name $siteName -Protocol "https" | Where-Object { $_.bindingInformation -eq $bindingInfo }

    if ($binding) {
        $binding | Remove-WebBinding
        Write-Output "HTTPS 绑定已移除"
    } else {
        Write-Output "未找到匹配的 HTTPS 绑定"
    }

    exit 0
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
`, escapePSString(i.siteName), escapePSString(i.hostname), i.port)

	_, err := i.psRunner.Run(command)
	return err
}

// escapePSString 转义 PowerShell 字符串
func escapePSString(s string) string {
	s = strings.ReplaceAll(s, "`", "``")
	s = strings.ReplaceAll(s, "$", "`$")
	s = strings.ReplaceAll(s, "\"", "`\"")
	s = strings.ReplaceAll(s, "\n", "`n")
	s = strings.ReplaceAll(s, "\r", "`r")
	return s
}

// FindHTTPSite 查找 HTTP 站点
func FindHTTPSite(siteName string) (bool, error) {
	runner := powershell.NewRunner()

	command := fmt.Sprintf(`
Import-Module WebAdministration

$siteName = "%s"

try {
    $site = Get-Website -Name $siteName -ErrorAction SilentlyContinue

    if ($site) {
        $httpBindings = $site.Bindings.Collection | Where-Object { $_.protocol -eq "http" }

        if ($httpBindings) {
            Write-Output "FOUND"
            exit 0
        }
    }

    Write-Output "NOT_FOUND"
    exit 0
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
`, escapePSString(siteName))

	output, err := runner.Run(command)
	if err != nil {
		return false, err
	}

	return strings.TrimSpace(output) == "FOUND", nil
}
