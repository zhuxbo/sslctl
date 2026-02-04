# sslctl Windows 安装脚本
# 自动检测架构，下载部署工具
# 使用方法: irm https://raw.githubusercontent.com/zhuxbo/sslctl/main/deploy/install.ps1 | iex

#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

function Write-Info { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Err { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }

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
        Write-Warn "检测到 IIS，请使用 sslctl-iis 项目 (https://github.com/cnssl/sslctl-iis)"
    }
} catch {}

# 获取最新版本号
function Get-LatestVersion {
    $version = $null
    try {
        $releases = Invoke-RestMethod -Uri "https://api.github.com/repos/zhuxbo/sslctl/releases" -TimeoutSec 30 -ErrorAction Stop
        if ($releases.Count -gt 0) {
            $version = $releases[0].tag_name
        }
    } catch {}
    return $version
}

Write-Info "获取最新版本..."
$Version = Get-LatestVersion

if (-not $Version) {
    Write-Err "无法获取版本信息"
    exit 1
}

Write-Info "最新版本: $Version"

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
$GithubUrl = "https://github.com/zhuxbo/sslctl/releases/download/$Version/$Filename"

Write-Info "下载 $Filename..."

$downloaded = $false
try {
    Invoke-WebRequest -Uri $GithubUrl -OutFile $TempFile -TimeoutSec 120 -ErrorAction Stop
    $downloaded = $true
} catch {}

if (-not $downloaded) {
    Write-Err "下载失败"
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

# 添加到 PATH
$Path = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($Path -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$Path;$InstallDir", "Machine")
    Write-Info "已添加 $InstallDir 到系统 PATH"
}

Write-Host ""
Write-Info "安装完成！"
Write-Host ""
Write-Host "使用方法 (需重新打开终端):"
Write-Host "  sslctl nginx scan                    # 扫描 Nginx SSL 站点"
Write-Host "  sslctl apache scan                   # 扫描 Apache SSL 站点"
Write-Host "  sslctl nginx deploy --site example.com  # 部署证书"
Write-Host "  sslctl --debug nginx scan            # 调试模式"
Write-Host "  sslctl help                          # 查看帮助"
Write-Host ""
Write-Host "配置目录: C:\sslctl\sites\"
Write-Host "日志目录: C:\sslctl\logs\"
Write-Host ""
Write-Host "IIS 用户请使用: https://github.com/cnssl/sslctl-iis"
