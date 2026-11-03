# sslctl Windows 安装脚本
# 自动检测架构，下载部署工具
# 使用方法:
#   直接执行: .\install.ps1 -ReleaseHost release.example.com [-Dev] [-Stable] [-Version <ver>] [-Force] [-Help]
#   管道模式: irm https://release.example.com/sslctl/install.ps1 | iex
#   不传 -ReleaseHost 时使用内置默认地址
#
# 注意: PowerShell 5.1 默认不启用 TLS 1.2，下载脚本前需先执行:
#   [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
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
    [string]$ReleaseHost,
    [switch]$Dev,
    [switch]$Stable,
    [string]$Version,
    [switch]$Force,
    [switch]$Help
)

#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
# 全局禁用 Invoke-WebRequest / Invoke-RestMethod 的进度条
# 在脚本级别设置，避免函数作用域导致 PowerShell 5.1 进度条仍然渲染覆盖控制台输出
$ProgressPreference = 'SilentlyContinue'

# 兼容 Linux 风格 --flag 参数（PowerShell 可能将 --dev 等误解析为 $Version 值）
if ($Version -eq "--dev") { $Dev = [switch]::new($true); $Version = "" }
if ($Version -eq "--stable") { $Stable = [switch]::new($true); $Version = "" }
if ($Version -eq "--force") { $Force = [switch]::new($true); $Version = "" }
if ($Version -eq "--help") { $Help = [switch]::new($true); $Version = "" }

# 强制启用 TLS 1.2（PowerShell 5.1 默认仅 SSL3/TLS 1.0，无法连接现代 HTTPS 服务）
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {}

# 保存原始控制台编码（StreamWriter 降级时使用，避免 UTF-8 与 GBK 不匹配导致乱码）
$script:OrigConsoleEncoding = [Console]::OutputEncoding

# 仅当控制台当前已经是 UTF-8 (CP 65001) 时才跟着设为 UTF-8
# 在 Windows Server 2012 R2 等老系统上，控制台代码页通常是 CP 936 (GBK)，
# 强制改成 UTF-8 会导致 PowerShell 按 UTF-8 写字节、而控制台按 GBK 解码 → 中文乱码
# 保持系统默认时 PowerShell 会自动把字符串转成控制台编码再输出，各版本都能正确显示
if ([Console]::OutputEncoding.CodePage -eq 65001) {
    try {
        [Console]::InputEncoding = [System.Text.Encoding]::UTF8
        $OutputEncoding = [System.Text.Encoding]::UTF8
    } catch {}
}

# 兼容控制台缓冲区损坏的 Windows 终端（0x1F 错误）
# 创建底层输出流作为备用，覆盖 Write-Host：每次调用先尝试原生，失败自动降级
# StreamWriter 使用原始编码，因为降级时 raw stdout 不经过 PowerShell 编码转换
$script:RawOut = try {
    $w = [System.IO.StreamWriter]::new([Console]::OpenStandardOutput(), $script:OrigConsoleEncoding)
    $w.AutoFlush = $true; $w
} catch { $null }
$script:OrigWriteHost = $ExecutionContext.InvokeCommand.GetCommand('Microsoft.PowerShell.Utility\Write-Host', 'Cmdlet')
function Write-Host {
    param([Parameter(Position=0)]$Object = '', $ForegroundColor, $BackgroundColor, [switch]$NoNewline, $Separator)
    try {
        $p = @{ Object = $Object }
        if ($ForegroundColor) { $p.ForegroundColor = $ForegroundColor }
        if ($NoNewline) { $p.NoNewline = $true }
        & $script:OrigWriteHost @p
    } catch {
        if ($script:RawOut) {
            $t = if ($Object -ne $null) { $Object.ToString() } else { '' }
            if ($NoNewline) { $script:RawOut.Write($t) } else { $script:RawOut.WriteLine($t) }
        }
    }
}

function Write-Info { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Err { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }

function Test-PathContainsDirectory {
    param(
        [string]$PathValue,
        [string]$Directory
    )

    if ([string]::IsNullOrWhiteSpace($PathValue) -or [string]::IsNullOrWhiteSpace($Directory)) {
        return $false
    }

    $target = $Directory.Trim().Trim('"').TrimEnd([char[]]"\/")
    foreach ($entry in ($PathValue -split ";")) {
        $candidate = $entry.Trim().Trim('"').TrimEnd([char[]]"\/")
        if ([string]::Equals($candidate, $target, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Ensure-InstallDirOnPath {
    param([string]$Directory)

    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if (-not (Test-PathContainsDirectory -PathValue $machinePath -Directory $Directory)) {
        $newMachinePath = if ([string]::IsNullOrWhiteSpace($machinePath)) { $Directory } else { "$machinePath;$Directory" }
        [Environment]::SetEnvironmentVariable("Path", $newMachinePath, "Machine")
        Write-Info "已添加 $Directory 到系统 PATH"
    }

    # 同时更新当前会话 PATH（无需重启终端即可使用）
    if (-not (Test-PathContainsDirectory -PathValue $env:Path -Directory $Directory)) {
        $env:Path = if ([string]::IsNullOrWhiteSpace($env:Path)) { $Directory } else { "$env:Path;$Directory" }
    }
}

# 帮助信息
if ($Help) {
    Write-Host "用法: .\install.ps1 [-ReleaseHost <host>] [选项]"
    Write-Host ""
    Write-Host "参数:"
    Write-Host "  -ReleaseHost   升级服务器（域名或域名+路径，默认 release.cnssl.com）"
    Write-Host ""
    Write-Host "选项:"
    Write-Host "  -Dev          安装测试版（dev 通道）"
    Write-Host "  -Stable       安装稳定版（main 通道，默认）"
    Write-Host "  -Version VER  安装指定版本"
    Write-Host "  -Force        强制重新安装（即使版本相同）"
    Write-Host "  -Help         显示此帮助信息"
    Write-Host ""
    Write-Host "示例:"
    Write-Host "  .\install.ps1 -ReleaseHost release.example.com              # 安装最新稳定版"
    Write-Host "  .\install.ps1 -ReleaseHost release.example.com -Dev         # 安装最新测试版（或 --dev）"
    Write-Host "  .\install.ps1 -ReleaseHost release.example.com -Version 1.0.0  # 安装指定版本"
    Write-Host "  .\install.ps1 -ReleaseHost cdn.example.com/mirror           # 多层目录"
    Write-Host ""
    Write-Host "未指定 -ReleaseHost 时使用内置默认地址。"
    exit 0
}

# 发布目录探测
# 先尝试根目录 https://{host}/sslctl，失败回落到 https://{host}/release/sslctl
function Resolve-ReleaseUrl {
    param([string]$Host_)
    $Host_ = $Host_.TrimEnd("/")
    if ($Host_ -match "^https?://") { return $Host_ }
    $candidates = @("https://$Host_/sslctl", "https://$Host_/release/sslctl")
    foreach ($base in $candidates) {
        try {
            $json = Invoke-RestMethod -Uri "$base/releases.json" -TimeoutSec 10 -ErrorAction Stop
            if ($json.main -or $json.dev) {
                return $base
            }
        } catch {}
    }
    return $null
}

$FallbackHost = "release.cnssl.com"
$TargetHost = if ($ReleaseHost) { $ReleaseHost } else { $FallbackHost }

Write-Info "探测发布目录..."
$ReleaseUrl = Resolve-ReleaseUrl $TargetHost
if (-not $ReleaseUrl) {
    $h = $TargetHost.TrimEnd("/")
    Write-Err "发布目录不可达: https://$h/sslctl/releases.json 与 https://$h/release/sslctl/releases.json 均无响应"
    exit 1
}
Write-Info "使用发布地址: $ReleaseUrl"

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
            $channel = "dev"
            $targetVersion = $releaseInfo.$channel.latest
        } elseif ($UseStable) {
            $channel = "main"
            $targetVersion = $releaseInfo.$channel.latest
        } else {
            # 默认：优先 main
            $channel = "main"
            $targetVersion = $releaseInfo.$channel.latest
            if (-not $targetVersion) {
                $channel = "dev"
                $targetVersion = $releaseInfo.$channel.latest
            }
        }
    }

    if (-not $targetVersion) {
        return $null
    }

    return @{
        Version     = Normalize-Version $targetVersion
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

# 检测 Web 服务（PATH 查找 + 进程检测）
$services = @()
if ((Get-Command nginx -ErrorAction SilentlyContinue) -or
    (Get-Process -Name nginx -ErrorAction SilentlyContinue)) {
    $services += "nginx"
}
if ((Get-Service -Name "Apache*" -ErrorAction SilentlyContinue) -or
    (Get-Process -Name httpd -ErrorAction SilentlyContinue)) {
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

$ExePath = "$InstallDir\sslctl.exe"

# 获取目标版本
Write-Info "获取目标版本..."
$targetInfo = Get-TargetVersion -BaseUrl $ReleaseUrl -RequestedVersion $Version -UseDev:$Dev -UseStable:$Stable

if (-not $targetInfo) {
    Write-Err "无法获取版本信息: $ReleaseUrl/releases.json"
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
            Ensure-InstallDirOnPath -Directory $InstallDir
            Write-Info "当前版本 $CurrentVersion 已是目标版本，使用 -Force 强制重新安装"
            exit 0
        }
    } else {
        Write-Info "安装: $CurrentVersion -> $TargetVersion"
    }
}

# 下载
$Filename = "sslctl-windows-$Arch.exe.gz"
$TempFile = "$env:TEMP\$Filename"
$DownloadUrl = "$ReleaseUrl/$Channel/$TargetVersion/$Filename"

Write-Info "下载 $Filename..."

$downloaded = $false
# PowerShell 5.1 的 Invoke-WebRequest 默认解析 DOM，极慢
# -UseBasicParsing 跳过 DOM 解析；进度条已在脚本级别全局禁用
try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempFile -TimeoutSec 120 -UseBasicParsing -ErrorAction Stop
    $downloaded = $true
} catch {}

if (-not $downloaded) {
    Write-Err "下载失败: $DownloadUrl"
    exit 1
}
$fileSizeMB = [math]::Round((Get-Item $TempFile).Length / 1MB, 2)
Write-Info "下载完成 ($fileSizeMB MB)"

# SHA256 校验
$expectedChecksum = ""
if ($releaseInfo) {
    try {
        $channelData = $releaseInfo.$Channel
        if ($channelData -and $channelData.versions) {
            $versionNoV = $TargetVersion -replace '^v', ''
            foreach ($v in $channelData.versions) {
                if ($v.version -eq $versionNoV) {
                    if ($v.checksums -and $v.checksums.$Filename) {
                        $expectedChecksum = $v.checksums.$Filename
                    }
                    break
                }
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

# 升级时先停止服务（释放 exe 文件句柄）
$svcWasRunning = $false
$svc = Get-Service -Name "sslctl" -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-Info "停止服务..."
    Stop-Service -Name "sslctl" -Force -ErrorAction SilentlyContinue
    # 等待服务完全停止
    for ($i = 0; $i -lt 30; $i++) {
        $svc = Get-Service -Name "sslctl" -ErrorAction SilentlyContinue
        if (-not $svc -or $svc.Status -eq "Stopped") { break }
        Start-Sleep -Seconds 1
    }
    $svcWasRunning = $true
}

# 解压 gzip
Write-Info "安装中..."
Add-Type -AssemblyName System.IO.Compression

# Windows 上运行中的 exe 无法覆盖，先重命名旧文件
$oldPath = "$ExePath.old"
Remove-Item $oldPath -Force -ErrorAction SilentlyContinue
if (Test-Path $ExePath) {
    try {
        Rename-Item $ExePath $oldPath -Force -ErrorAction Stop
    } catch {
        # 重命名失败，尝试直接写入
    }
}

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

# 清理
Remove-Item $TempFile -Force -ErrorAction SilentlyContinue
Remove-Item $oldPath -Force -ErrorAction SilentlyContinue

# 写入配置文件
$ConfigFile = Join-Path $WorkDir "config.json"
# 写入配置文件（ReleaseUrl 始终有值：参数传入或内置回落）
if (Test-Path $ConfigFile) {
    try {
        $cfg = Get-Content $ConfigFile -Raw | ConvertFrom-Json
    } catch {
        Write-Err "配置解析失败，未修改 release_url"
        exit 1
    }
} else {
    $cfg = @{}
}
$cfg.release_url = $ReleaseUrl
$saveChannel = if ($Channel) { $Channel } else { "main" }
$cfg | Add-Member -NotePropertyName "upgrade_channel" -NotePropertyValue $saveChannel -Force
$ConfigTmpFile = "$ConfigFile.tmp"
# PowerShell 5.1 的 -Encoding UTF8 会写 BOM，Go JSON 解析器不支持 BOM
# 使用 .NET 直接写入 UTF-8 无 BOM
$json = $cfg | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText($ConfigTmpFile, $json, (New-Object System.Text.UTF8Encoding $false))
Move-Item -Path $ConfigTmpFile -Destination $ConfigFile -Force

# 添加到 PATH
Ensure-InstallDirOnPath -Directory $InstallDir

# 升级时重启服务
if ($svcWasRunning) {
    Write-Info "启动服务..."
    Start-Service -Name "sslctl" -ErrorAction SilentlyContinue
    $svc = Get-Service -Name "sslctl" -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-Info "服务已启动"
    } else {
        Write-Warn "服务启动失败，请手动运行: sslctl service repair"
    }
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
Write-Host ""
Write-Warn "请重新打开 PowerShell 窗口，使 PATH 生效"
