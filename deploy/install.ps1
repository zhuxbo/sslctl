# cert-deploy Windows 安装脚本
# 自动检测架构和 Web 服务，下载对应的部署工具
# 使用方法: irm https://gitee.com/zhuxbo/cert-deploy/raw/main/deploy/install.ps1 | iex

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
function Detect-WebServers {
    $servers = @()

    # 检测 IIS
    try {
        $iisFeature = Get-WindowsOptionalFeature -Online -FeatureName IIS-WebServer -ErrorAction SilentlyContinue
        if ($iisFeature -and $iisFeature.State -eq 'Enabled') {
            $servers += "iis"
        }
    } catch {
        # Windows Server 使用不同的方法
        try {
            $iisService = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
            if ($iisService) {
                $servers += "iis"
            }
        } catch {}
    }

    # 检测 Nginx
    if (Get-Command nginx -ErrorAction SilentlyContinue) {
        $servers += "nginx"
    }

    # 检测 Apache
    $apacheServices = Get-Service -Name "Apache*" -ErrorAction SilentlyContinue
    if ($apacheServices) {
        $servers += "apache"
    }

    return $servers
}

$Tools = Detect-WebServers

if ($Tools.Count -eq 0) {
    Write-Warn "未检测到 IIS、Nginx 或 Apache，将安装 nginx 版本"
    $Tools = @("nginx")
}

Write-Info "将安装: $($Tools -join ', ')"

# 获取最新版本号
function Get-LatestVersion {
    $version = $null

    # 优先 Gitee
    try {
        $release = Invoke-RestMethod -Uri "https://gitee.com/api/v5/repos/zhuxbo/cert-deploy/releases/latest" -TimeoutSec 10 -ErrorAction Stop
        $version = $release.tag_name
    } catch {
        # 回退 GitHub
        try {
            $releases = Invoke-RestMethod -Uri "https://api.github.com/repos/zhuxbo/cert-deploy/releases" -TimeoutSec 10 -ErrorAction Stop
            if ($releases.Count -gt 0) {
                $version = $releases[0].tag_name
            }
        } catch {}
    }

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
$InstallDir = "C:\Program Files\cert-deploy"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# 下载函数
function Download-File {
    param($Filename, $OutputPath)

    $giteeUrl = "https://gitee.com/zhuxbo/cert-deploy/releases/download/$Version/$Filename"
    $githubUrl = "https://github.com/zhuxbo/cert-deploy/releases/download/$Version/$Filename"

    try {
        Invoke-WebRequest -Uri $giteeUrl -OutFile $OutputPath -TimeoutSec 60 -ErrorAction Stop
        return $true
    } catch {
        Write-Warn "Gitee 下载失败，尝试 GitHub..."
        try {
            Invoke-WebRequest -Uri $githubUrl -OutFile $OutputPath -TimeoutSec 60 -ErrorAction Stop
            return $true
        } catch {
            return $false
        }
    }
}

# 解压 gzip 函数
function Expand-Gzip {
    param($GzipPath, $OutputPath)

    Add-Type -AssemblyName System.IO.Compression

    $inStream = [System.IO.File]::OpenRead($GzipPath)
    $gzipStream = New-Object System.IO.Compression.GzipStream($inStream, [System.IO.Compression.CompressionMode]::Decompress)
    $outStream = [System.IO.File]::Create($OutputPath)

    try {
        $gzipStream.CopyTo($outStream)
    } finally {
        $outStream.Close()
        $gzipStream.Close()
        $inStream.Close()
    }
}

# 下载并安装
foreach ($Tool in $Tools) {
    $Filename = "cert-deploy-$Tool-windows-$Arch.exe.gz"
    $TempFile = "$env:TEMP\$Filename"
    $ExePath = "$InstallDir\cert-deploy-$Tool.exe"

    Write-Info "下载 cert-deploy-$Tool..."

    if (-not (Download-File -Filename $Filename -OutputPath $TempFile)) {
        Write-Err "下载 $Filename 失败"
        exit 1
    }

    # 解压
    Expand-Gzip -GzipPath $TempFile -OutputPath $ExePath

    # 清理临时文件
    Remove-Item $TempFile -Force -ErrorAction SilentlyContinue

    Write-Info "已安装 cert-deploy-$Tool 到 $InstallDir"
}

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
foreach ($Tool in $Tools) {
    Write-Host "  cert-deploy-$Tool -help    # 查看帮助"
    Write-Host "  cert-deploy-$Tool -scan    # 扫描站点"
}
