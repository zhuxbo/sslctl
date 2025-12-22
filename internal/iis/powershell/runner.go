// Package powershell PowerShell 执行器
package powershell

import (
	"fmt"
	"os/exec"
	"strings"
)

// Runner PowerShell 执行器
type Runner struct {
	executable string // powershell.exe 路径
}

// NewRunner 创建 PowerShell 执行器
func NewRunner() *Runner {
	return &Runner{
		executable: "powershell.exe",
	}
}

// escapePSString 转义 PowerShell 字符串中的特殊字符
// 在双引号字符串中，需要转义: ` $ " 和换行符
func escapePSString(s string) string {
	// 转义顺序很重要：先转义反引号，再转义其他字符
	s = strings.ReplaceAll(s, "`", "``")
	s = strings.ReplaceAll(s, "$", "`$")
	s = strings.ReplaceAll(s, "\"", "`\"")
	s = strings.ReplaceAll(s, "\n", "`n")
	s = strings.ReplaceAll(s, "\r", "`r")
	return s
}

// Run 执行 PowerShell 命令
func (r *Runner) Run(command string) (string, error) {
	cmd := exec.Command(
		r.executable,
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", command,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("powershell execution failed: %w\nOutput: %s", err, string(output))
	}

	return string(output), nil
}

// RunScript 执行 PowerShell 脚本文件
func (r *Runner) RunScript(scriptPath string, args ...string) (string, error) {
	cmdArgs := []string{
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-File", scriptPath,
	}
	cmdArgs = append(cmdArgs, args...)

	cmd := exec.Command(r.executable, cmdArgs...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("script execution failed: %w\nOutput: %s", err, string(output))
	}

	return string(output), nil
}

// ImportCertificate 导入 PFX 证书到 Windows 证书存储
func (r *Runner) ImportCertificate(pfxPath, password string) (string, error) {
	command := fmt.Sprintf(`
$pfxPath = "%s"
$password = ConvertTo-SecureString -String "%s" -Force -AsPlainText

try {
    $cert = Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation Cert:\LocalMachine\My -Password $password -Exportable

    Write-Output $cert.Thumbprint
    exit 0
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
`, escapePSString(pfxPath), escapePSString(password))

	output, err := r.Run(command)
	if err != nil {
		return "", fmt.Errorf("failed to import certificate: %w", err)
	}

	thumbprint := strings.TrimSpace(output)
	return thumbprint, nil
}

// BindCertificate 绑定证书到 IIS 站点
func (r *Runner) BindCertificate(siteName, thumbprint, hostname string, port int) error {
	command := fmt.Sprintf(`
Import-Module WebAdministration

$siteName = "%s"
$thumbprint = "%s"
$hostname = "%s"
$port = %d

try {
    # 检查站点是否存在
    $site = Get-Website -Name $siteName -ErrorAction Stop
    if (-not $site) {
        Write-Error "Site not found: $siteName"
        exit 1
    }

    # 移除旧的 HTTPS 绑定
    $oldBindings = Get-WebBinding -Name $siteName -Protocol "https"
    if ($hostname) {
        $oldBindings = $oldBindings | Where-Object { $_.bindingInformation -like "*$hostname" }
    }
    $oldBindings | Remove-WebBinding

    # 创建新绑定
    $bindingInfo = "*:${port}:${hostname}"
    New-WebBinding -Name $siteName -Protocol "https" -BindingInformation $bindingInfo -ErrorAction Stop

    # 绑定证书
    $binding = Get-WebBinding -Name $siteName -Protocol "https" | Where-Object { $_.bindingInformation -eq $bindingInfo }
    $binding.AddSslCertificate($thumbprint, "My")

    Write-Output "Certificate bound successfully"
    exit 0
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
`, escapePSString(siteName), escapePSString(thumbprint), escapePSString(hostname), port)

	_, err := r.Run(command)
	if err != nil {
		return fmt.Errorf("failed to bind certificate: %w", err)
	}

	return nil
}

// ListSites 列出所有 IIS SSL 站点
func (r *Runner) ListSites() (string, error) {
	command := `
Import-Module WebAdministration

try {
    $sites = @()

    Get-Website | ForEach-Object {
        $site = $_
        $httpsBindings = $site.Bindings.Collection | Where-Object { $_.protocol -eq "https" }

        foreach ($binding in $httpsBindings) {
            $certHash = $binding.certificateHash
            $cert = $null

            if ($certHash) {
                $cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $certHash }
            }

            $sites += [PSCustomObject]@{
                SiteName = $site.Name
                HostName = $binding.bindingInformation.Split(':')[2]
                Port = $binding.bindingInformation.Split(':')[1]
                CertThumbprint = $certHash
                CertExpires = if ($cert) { $cert.NotAfter.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
                CertSubject = if ($cert) { $cert.Subject } else { "N/A" }
                PhysicalPath = $site.PhysicalPath
            }
        }
    }

    $sites | ConvertTo-Json -Depth 10
    exit 0
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
`

	output, err := r.Run(command)
	if err != nil {
		return "", fmt.Errorf("failed to list sites: %w", err)
	}

	return output, nil
}

// RemoveCertificate 从证书存储中移除证书
func (r *Runner) RemoveCertificate(thumbprint string) error {
	command := fmt.Sprintf(`
$thumbprint = "%s"

try {
    $cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $thumbprint }
    if ($cert) {
        Remove-Item -Path $cert.PSPath -Force
        Write-Output "Certificate removed"
    } else {
        Write-Warning "Certificate not found"
    }
    exit 0
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
`, escapePSString(thumbprint))

	_, err := r.Run(command)
	if err != nil {
		return fmt.Errorf("failed to remove certificate: %w", err)
	}

	return nil
}

// ListHTTPSites 列出仅有 HTTP 绑定的 IIS 站点（无 HTTPS 绑定）
func (r *Runner) ListHTTPSites() (string, error) {
	command := `
Import-Module WebAdministration

try {
    $sites = @()

    Get-Website | ForEach-Object {
        $site = $_
        $httpBindings = $site.Bindings.Collection | Where-Object { $_.protocol -eq "http" }
        $httpsBindings = $site.Bindings.Collection | Where-Object { $_.protocol -eq "https" }

        # 只返回有 HTTP 绑定但没有 HTTPS 绑定的站点
        if ($httpBindings -and (-not $httpsBindings)) {
            foreach ($binding in $httpBindings) {
                $sites += [PSCustomObject]@{
                    SiteName = $site.Name
                    HostName = $binding.bindingInformation.Split(':')[2]
                    Port = $binding.bindingInformation.Split(':')[1]
                    PhysicalPath = $site.PhysicalPath
                }
            }
        }
    }

    $sites | ConvertTo-Json -Depth 10
    exit 0
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
`

	output, err := r.Run(command)
	if err != nil {
		return "", fmt.Errorf("failed to list HTTP sites: %w", err)
	}

	return output, nil
}
