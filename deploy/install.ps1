# sslctl Windows 安装脚本
# 自动检测架构，下载部署工具
# 使用方法:
#   直接执行: .\install.ps1 [-Dev] [-Stable] [-Version <ver>] [-Force] [-Help]
#   管道模式: irm https://release.example.com/sslctl/install.ps1 | iex
#
# 服务端要求:
#   管道模式依赖服务端返回 Content-Type: text/plain; charset=utf-8，
#   否则 PowerShell 5.1 会用系统默认编码 (GBK) 解码导致中文乱码。
#   nginx 配置示例:
#     location ~ \.ps1$ {
#         types { text/plain ps1; }
#         charset utf-8;
#     }

param(
    [switch]$Dev,
    [switch]$Stable,
    [string]$Version,
    [switch]$Force,
    [switch]$Help
)

#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

# 设置控制台编码为 UTF-8，解决中文乱码
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    [Console]::InputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch {}

function Write-Info { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Err { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }

# 帮助信息
if ($Help) {
    Write-Host "用法: install.ps1 [选项]"
    Write-Host ""
    Write-Host "选项:"
    Write-Host "  -Dev          安装测试版（dev 通道）"
    Write-Host "  -Stable       安装稳定版（main 通道，默认）"
    Write-Host "  -Version VER  安装指定版本"
    Write-Host "  -Force        强制重新安装（即使版本相同）"
    Write-Host "  -Help         显示此帮助信息"
    Write-Host ""
    Write-Host "示例:"
    Write-Host "  .\install.ps1                              # 安装最新稳定版"
    Write-Host "  .\install.ps1 -Dev                         # 安装最新测试版"
    Write-Host "  .\install.ps1 -Version 1.0.0               # 安装指定版本"
    Write-Host "  .\install.ps1 -Dev -Version 1.0.1-dev      # 安装指定测试版"
    Write-Host "  .\install.ps1 -Force                       # 强制重新安装"
    Write-Host ""
    Write-Host "管道模式 (irm ... | iex) 不支持参数，默认安装最新稳定版。"
    exit 0
}

# Release 服务器（由发布脚本自动替换，与 Linux 保持一致）
$ReleaseUrl = "__RELEASE_URL__"
# 去掉末尾斜杠，避免拼接出错
$ReleaseUrl = $ReleaseUrl.TrimEnd("/")

# 检测占位符未被替换（直接运行源码中的脚本）
if (-not $ReleaseUrl.StartsWith("https://")) {
    Write-Err "安装脚本未正确配置，请从官方渠道下载安装脚本"
    exit 1
}

# --- 辅助函数 ---

# 规范化版本号（确保带 v 前缀）
function Normalize-Version {
    param([string]$Ver)
    if (-not $Ver.StartsWith("v")) {
        return "v$Ver"
    }
    return $Ver
}

# 获取已安装版本
function Get-InstalledVersion {
    $ExePath = "C:\sslctl\sslctl.exe"
    if (-not (Test-Path $ExePath)) {
        return ""
    }
    try {
        $output = & $ExePath --version 2>&1
        if ($output -match '(v?\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?)') {
            return Normalize-Version $Matches[1]
        }
    } catch {}
    return ""
}

# 获取目标版本（支持通道/版本选择）
# 返回 hashtable: @{ Version; Channel; ReleaseInfo }
function Get-TargetVersion {
    param(
        [string]$BaseUrl,
        [string]$RequestedVersion,
        [switch]$UseDev,
        [switch]$UseStable
    )

    $releaseInfo = $null

    # 获取 releases.json（指定版本时也需要，用于校验和）
    try {
        $releaseInfo = Invoke-RestMethod -Uri "$BaseUrl/releases.json" -TimeoutSec 30 -ErrorAction Stop
    } catch {
        # 指定了版本时可以不需要 releases.json（但无法校验）
        if (-not $RequestedVersion) {
            return $null
        }
    }

    $channel = ""
    $targetVersion = ""

    if ($RequestedVersion) {
        # 指定了版本，直接使用
        $targetVersion = Normalize-Version $RequestedVersion

        # 自动推断通道（除非已指定）
        if ($UseDev) {
            $channel = "dev"
        } elseif ($UseStable) {
            $channel = "main"
        } elseif ($targetVersion -match "-") {
            $channel = "dev"
        } else {
            $channel = "main"
        }
    } else {
        # 从 releases.json 获取最新版本
        if (-not $releaseInfo) {
            return $null
        }

        if ($UseDev) {
            $targetVersion = $releaseInfo.latest_dev
            $channel = "dev"
        } elseif ($UseStable) {
            $targetVersion = $releaseInfo.latest_main
            $channel = "main"
        } else {
            # 默认：优先 main
            $targetVersion = $releaseInfo.latest_main
            $channel = "main"
            if (-not $targetVersion) {
                $targetVersion = $releaseInfo.latest_dev
                $channel = "dev"
            }
        }
    }

    if (-not $targetVersion) {
        return $null
    }

    return @{
        Version     = $targetVersion
        Channel     = $channel
        ReleaseInfo = $releaseInfo
    }
}

# 验证 SHA256 校验和
# expected 格式: "sha256:hexstring"
function Verify-SHA256Checksum {
    param(
        [string]$FilePath,
        [string]$Expected
    )

    if (-not $Expected) {
        Write-Warn "无校验和信息，跳过校验（兼容旧版本）"
        return $true
    }

    # 解析 sha256:hex 格式
    if (-not $Expected.StartsWith("sha256:")) {
        Write-Warn "未知校验和格式: $Expected，跳过校验"
        return $true
    }

    $expectedHash = $Expected.Substring(7).ToLower()

    $actualHash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.ToLower()

    if ($actualHash -ne $expectedHash) {
        Write-Err "SHA256 校验失败"
        Write-Err "  期望: $expectedHash"
        Write-Err "  实际: $actualHash"
        return $false
    }

    Write-Info "SHA256 校验通过"
    return $true
}

# --- 主流程 ---

# 检测架构
Write-Info "检测系统..."
$Arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "x86" }

if ($Arch -ne "amd64") {
    Write-Err "不支持的架构: $Arch (仅支持 64 位系统)"
    exit 1
}

Write-Info "系统: windows, 架构: $Arch"

# 检测 Web 服务
$services = @()
if (Get-Command nginx -ErrorAction SilentlyContinue) {
    $services += "nginx"
}
$apacheServices = Get-Service -Name "Apache*" -ErrorAction SilentlyContinue
if ($apacheServices) {
    $services += "apache"
}

if ($services.Count -gt 0) {
    Write-Info "检测到 Web 服务: $($services -join ', ')"
} else {
    Write-Warn "未检测到 nginx 或 apache，仍可继续安装"
}

# IIS 提示
try {
    $iisFeature = Get-WindowsOptionalFeature -Online -FeatureName IIS-WebServer -ErrorAction SilentlyContinue
    if ($iisFeature -and $iisFeature.State -eq 'Enabled') {
        Write-Warn "检测到 IIS，请使用 sslctlw 工具"
    }
} catch {}

# 获取目标版本
Write-Info "获取目标版本..."
$targetInfo = Get-TargetVersion -BaseUrl $ReleaseUrl -RequestedVersion $Version -UseDev:$Dev -UseStable:$Stable

if (-not $targetInfo) {
    Write-Err "无法获取版本信息"
    exit 1
}

$TargetVersion = $targetInfo.Version
$Channel = $targetInfo.Channel
$releaseInfo = $targetInfo.ReleaseInfo

# 显示通道信息
if ($Channel -eq "dev") {
    Write-Info "目标版本: $TargetVersion (测试版)"
} else {
    Write-Info "目标版本: $TargetVersion (稳定版)"
}

# 检测已安装版本
$CurrentVersion = Get-InstalledVersion

if ($CurrentVersion) {
    if ($CurrentVersion -eq $TargetVersion) {
        if ($Force) {
            Write-Info "当前版本: $CurrentVersion，强制重新安装"
        } else {
            Write-Info "当前版本 $CurrentVersion 已是目标版本，使用 -Force 强制重新安装"
            exit 0
        }
    } else {
        Write-Info "升级: $CurrentVersion -> $TargetVersion"
    }
}

# 创建安装目录
$InstallDir = "C:\sslctl"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# 创建工作目录
$WorkDir = "C:\sslctl"
foreach ($dir in @("sites", "logs", "backup", "certs")) {
    $path = Join-Path $WorkDir $dir
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
}

# 下载
$Filename = "sslctl-windows-$Arch.exe.gz"
$TempFile = "$env:TEMP\$Filename"
$DownloadUrl = "$ReleaseUrl/$Channel/$TargetVersion/$Filename"

Write-Info "下载 $Filename..."

$downloaded = $false
try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempFile -TimeoutSec 120 -ErrorAction Stop
    $downloaded = $true
} catch {}

if (-not $downloaded) {
    Write-Err "下载失败: $DownloadUrl"
    exit 1
}

# SHA256 校验
$expectedChecksum = ""
if ($releaseInfo) {
    try {
        $versions = $releaseInfo.versions
        if ($versions -and $versions.$TargetVersion) {
            $checksums = $versions.$TargetVersion.checksums
            if ($checksums -and $checksums.$Filename) {
                $expectedChecksum = $checksums.$Filename
            }
        }
    } catch {}
}

$checksumOk = Verify-SHA256Checksum -FilePath $TempFile -Expected $expectedChecksum
if (-not $checksumOk) {
    Remove-Item $TempFile -Force -ErrorAction SilentlyContinue
    Write-Err "文件校验失败，安装中止"
    exit 1
}

# 解压 gzip
Write-Info "安装中..."
Add-Type -AssemblyName System.IO.Compression

$ExePath = "$InstallDir\sslctl.exe"
$inStream = [System.IO.File]::OpenRead($TempFile)
$gzipStream = New-Object System.IO.Compression.GzipStream($inStream, [System.IO.Compression.CompressionMode]::Decompress)
$outStream = [System.IO.File]::Create($ExePath)

try {
    $gzipStream.CopyTo($outStream)
} finally {
    $outStream.Close()
    $gzipStream.Close()
    $inStream.Close()
}

# 清理临时文件
Remove-Item $TempFile -Force -ErrorAction SilentlyContinue

# 写入 release_url 到配置文件（解析失败不覆盖原文件）
$ConfigFile = Join-Path $WorkDir "config.json"
if (Test-Path $ConfigFile) {
    try {
        $cfg = Get-Content $ConfigFile -Raw | ConvertFrom-Json
    } catch {
        Write-Err "配置解析失败，未修改 release_url"
        exit 1
    }
} else {
    $cfg = @{ version = "1.0" }
}
$cfg.release_url = $ReleaseUrl
$ConfigTmpFile = "$ConfigFile.tmp"
$cfg | ConvertTo-Json -Depth 10 | Set-Content -Path $ConfigTmpFile -Encoding UTF8
Move-Item -Path $ConfigTmpFile -Destination $ConfigFile -Force

# 添加到 PATH
$Path = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($Path -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$Path;$InstallDir", "Machine")
    Write-Info "已添加 $InstallDir 到系统 PATH"
}

# 同时更新当前会话 PATH（无需重启终端即可使用）
if ($env:Path -notlike "*$InstallDir*") {
    $env:Path = "$env:Path;$InstallDir"
}

Write-Host ""
Write-Info "安装完成！"
Write-Host ""
Write-Host "使用方法:"
Write-Host "  sslctl scan                              # 扫描站点"
Write-Host "  sslctl deploy --site example.com         # 部署证书"
Write-Host "  sslctl status                            # 查看服务状态"
Write-Host "  sslctl upgrade                           # 升级工具"
Write-Host "  sslctl --debug scan                      # 调试模式"
Write-Host "  sslctl help                              # 查看帮助"
Write-Host ""
Write-Host "配置目录: C:\sslctl\sites\"
Write-Host "日志目录: C:\sslctl\logs\"
Write-Host ""
Write-Host "IIS 用户请使用 sslctlw 工具"
