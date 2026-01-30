// cert-deploy - SSL 证书自动部署工具
// 支持 Nginx、Apache
package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/zhuxbo/cert-deploy/cmd/apache"
	"github.com/zhuxbo/cert-deploy/cmd/nginx"
	apacheScanner "github.com/zhuxbo/cert-deploy/internal/apache/scanner"
	nginxScanner "github.com/zhuxbo/cert-deploy/internal/nginx/scanner"
	"github.com/zhuxbo/cert-deploy/pkg/config"
	"github.com/zhuxbo/cert-deploy/pkg/fetcher"
	"github.com/zhuxbo/cert-deploy/pkg/logger"
	"github.com/zhuxbo/cert-deploy/pkg/service"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	// Windows 服务模式检测
	if runtime.GOOS == "windows" && service.IsWindowsService() {
		runWindowsService()
		return
	}

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// 解析全局参数
	args := os.Args[1:]
	debug := false

	// 检查 --debug 参数
	for i, arg := range args {
		if arg == "--debug" {
			debug = true
			args = append(args[:i], args[i+1:]...)
			break
		}
	}

	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	// 设置 debug 模式
	if debug {
		os.Setenv("LOG_LEVEL", "debug")
		os.Setenv("CERT_DEPLOY_DEBUG", "1")
	}

	cmd := args[0]
	subArgs := args[1:]

	switch cmd {
	case "scan":
		runAutoCommand("scan", subArgs, debug)
	case "deploy":
		runAutoCommand("deploy", subArgs, debug)
	case "issue":
		runAutoCommand("issue", subArgs, debug)
	case "install-https":
		runAutoCommand("install-https", subArgs, debug)
	case "init":
		runAutoCommand("init", subArgs, debug)
	case "daemon":
		runAutoCommand("daemon", subArgs, debug)
	case "status":
		runStatus()
	case "upgrade":
		runUpgrade(subArgs)
	case "service":
		runService(subArgs)
	case "setup":
		runSetup(subArgs, debug)
	case "uninstall":
		runUninstall(subArgs)
	case "version", "-v", "--version":
		fmt.Printf("cert-deploy %s (built at %s)\n", version, buildTime)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "未知命令: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`cert-deploy %s - SSL 证书自动部署工具

使用方法:
  cert-deploy [--debug] <command> [options]

命令:
  scan            扫描站点（自动检测 Web 服务器）
  deploy          部署证书
  issue           签发证书
  install-https   安装 HTTPS 配置
  init            生成站点配置
  status          显示服务状态
  upgrade         升级工具
  service         管理系统服务
  setup           一键部署
  uninstall       卸载工具
  version         显示版本信息
  help            显示帮助信息

全局参数:
  --debug   启用调试模式（详细日志）

常用命令:
  cert-deploy scan                          扫描所有站点
  cert-deploy scan --ssl-only               仅扫描 SSL 站点
  cert-deploy deploy --site <name>          部署指定站点
  cert-deploy issue --site <name>           签发证书
  cert-deploy install-https                 安装 HTTPS 配置
  cert-deploy init --url <url> --token <token>   生成站点配置
  cert-deploy status                        查看服务状态
  cert-deploy upgrade                       升级到最新版本
  cert-deploy upgrade --check               检查更新
  cert-deploy service repair                修复 systemd 服务

一键部署:
  cert-deploy setup --url <base_url> --token <token> --domain <domain>

卸载:
  cert-deploy uninstall           # 卸载程序
  cert-deploy uninstall --purge   # 卸载并清理配置

示例:
  cert-deploy scan
  cert-deploy --debug deploy --site example.com
  cert-deploy setup --url https://api.example.com --token abc123 --domain example.com

更多信息请访问: https://github.com/zhuxbo/cert-deploy
`, version)
}

// runWindowsService 以 Windows 服务方式运行
func runWindowsService() {
	err := service.RunAsService("cert-deploy", func() {
		// 检测 Web 服务器类型并运行 daemon
		serverType := detectWebServer()
		if serverType == "" {
			serverType = "nginx" // 默认使用 nginx
		}

		if serverType == "nginx" {
			nginx.Run([]string{"daemon"}, version, buildTime, false)
		} else {
			apache.Run([]string{"daemon"}, version, buildTime, false)
		}
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Windows 服务运行失败: %v\n", err)
		os.Exit(1)
	}
}

// runAutoCommand 自动检测 Web 服务器并执行命令
func runAutoCommand(cmd string, args []string, debug bool) {
	serverType := detectWebServer()
	if serverType == "" {
		serverType = promptSelectServer()
		if serverType == "" {
			fmt.Fprintln(os.Stderr, "已取消")
			os.Exit(1)
		}
	}

	// 构造子命令参数
	subArgs := append([]string{cmd}, args...)

	if serverType == "nginx" {
		nginx.Run(subArgs, version, buildTime, debug)
	} else {
		apache.Run(subArgs, version, buildTime, debug)
	}
}

// promptSelectServer 提示用户选择服务器类型
func promptSelectServer() string {
	fmt.Println("未检测到运行中的 Web 服务器")
	fmt.Println("请选择服务器类型:")
	fmt.Println("  1. Nginx")
	fmt.Println("  2. Apache")
	fmt.Print("选择 [1/2]: ")

	reader := bufio.NewReader(os.Stdin)
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	switch choice {
	case "1":
		return "nginx"
	case "2":
		return "apache"
	default:
		return ""
	}
}

// runStatus 显示服务状态
func runStatus() {
	// 1. 版本信息
	fmt.Printf("版本: %s (编译时间: %s)\n", version, buildTime)
	fmt.Printf("系统: %s/%s\n", runtime.GOOS, runtime.GOARCH)

	// 2. Web 服务器检测
	serverType := detectWebServer()
	if serverType != "" {
		fmt.Printf("Web 服务器: %s\n", serverType)
	} else {
		fmt.Println("Web 服务器: 未检测到")
	}

	// 3. 服务状态（使用跨平台服务模块）
	fmt.Printf("\n服务管理: %s\n", service.GetInitSystemName())

	svcMgr, err := service.New(nil)
	if err != nil {
		fmt.Printf("  状态: %s\n", err)
	} else {
		status, err := svcMgr.Status()
		if err != nil {
			fmt.Printf("  状态: 获取失败 (%v)\n", err)
		} else {
			if status.Running {
				fmt.Println("  运行状态: 运行中")
			} else {
				fmt.Println("  运行状态: 未运行")
			}
			if status.Enabled {
				fmt.Println("  开机自启: 已启用")
			} else {
				fmt.Println("  开机自启: 未启用")
			}
		}
	}

	// 4. 站点统计
	cfgManager, err := config.NewManager()
	if err == nil {
		sites, _ := cfgManager.ListSites()
		fmt.Printf("\n站点配置: %d 个\n", len(sites))
	}
}

// runService 管理服务
func runService(args []string) {
	if len(args) == 0 || args[0] != "repair" {
		fmt.Println("用法: cert-deploy service repair")
		fmt.Println("")
		fmt.Printf("修复/重新安装服务 (当前系统: %s)\n", service.GetInitSystemName())
		os.Exit(1)
	}

	// 检查权限（Windows 不需要 root，但需要管理员权限）
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "请使用 root 权限运行此命令")
		os.Exit(1)
	}

	repairService()
}

// repairService 修复/重新安装服务
func repairService() {
	initSys := service.GetInitSystemName()
	fmt.Printf("修复服务 (%s)...\n", initSys)

	svcMgr, err := service.New(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "不支持的系统: %v\n", err)
		os.Exit(1)
	}

	// 停止现有服务
	svcMgr.Stop()

	// 安装服务
	if err := svcMgr.Install(); err != nil {
		fmt.Fprintf(os.Stderr, "安装服务失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("已安装服务")

	// 启用服务
	if err := svcMgr.Enable(); err != nil {
		fmt.Fprintf(os.Stderr, "启用服务失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("已启用开机自启")

	// 启动服务
	if err := svcMgr.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "启动服务失败: %v\n", err)
		if runtime.GOOS == "linux" {
			fmt.Fprintln(os.Stderr, "\n查看详细日志: journalctl -u cert-deploy -n 50")
		}
		os.Exit(1)
	}

	// 检查服务状态
	time.Sleep(time.Second)
	status, _ := svcMgr.Status()
	if status != nil && status.Running {
		fmt.Println("服务已启动")
	} else {
		fmt.Fprintln(os.Stderr, "服务启动后退出")
		if runtime.GOOS == "linux" {
			fmt.Fprintln(os.Stderr, "查看日志: journalctl -u cert-deploy -n 50")
		}
		os.Exit(1)
	}
}

// releaseInfo 发布信息
type releaseInfo struct {
	LatestStable string `json:"latest_stable"`
	LatestDev    string `json:"latest_dev"`
}

// runUpgrade 升级命令
func runUpgrade(args []string) {
	fs := flag.NewFlagSet("upgrade", flag.ExitOnError)
	channel := fs.String("channel", "", "更新通道 (stable/dev)")
	targetVersion := fs.String("version", "", "指定版本")
	force := fs.Bool("force", false, "强制重新安装")
	checkOnly := fs.Bool("check", false, "仅检查更新")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: cert-deploy upgrade [选项]\n\n选项:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	// 检查权限（Linux 需要 root，Windows 需要管理员）
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "请使用 root 权限运行此命令")
		os.Exit(1)
	}

	releaseURL := "https://cert-deploy-cn.cnssl.com"

	// 1. 获取远程版本信息
	fmt.Println("检查更新...")
	resp, err := http.Get(releaseURL + "/releases.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "获取版本信息失败: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var info releaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		fmt.Fprintf(os.Stderr, "解析版本信息失败: %v\n", err)
		os.Exit(1)
	}

	// 2. 确定目标版本和通道
	var target string
	var ch string

	if *targetVersion != "" {
		target = normalizeVersion(*targetVersion)
		if *channel != "" {
			ch = *channel
		} else if strings.Contains(target, "-") {
			ch = "dev"
		} else {
			ch = "stable"
		}
	} else {
		if *channel == "dev" {
			target = info.LatestDev
			ch = "dev"
		} else {
			target = info.LatestStable
			ch = "stable"
			if target == "" {
				target = info.LatestDev
				ch = "dev"
			}
		}
	}

	if target == "" {
		fmt.Fprintln(os.Stderr, "未找到可用版本")
		os.Exit(1)
	}

	// 3. 比较版本
	current := normalizeVersion(version)
	fmt.Printf("当前版本: %s\n", current)
	fmt.Printf("最新版本: %s (%s)\n", target, ch)

	if current == target && !*force {
		fmt.Println("已是最新版本")
		return
	}

	// 4. 如果 --check，显示信息后返回
	if *checkOnly {
		if current != target {
			fmt.Println("\n有新版本可用，运行 'cert-deploy upgrade' 进行升级")
		}
		return
	}

	// 5. 下载并安装
	fmt.Printf("\n开始升级到 %s...\n", target)

	osName := runtime.GOOS
	arch := runtime.GOARCH
	var filename string
	if osName == "windows" {
		filename = fmt.Sprintf("cert-deploy-%s-%s.exe.gz", osName, arch)
	} else {
		filename = fmt.Sprintf("cert-deploy-%s-%s.gz", osName, arch)
	}
	downloadURL := fmt.Sprintf("%s/%s/%s/%s", releaseURL, ch, target, filename)

	fmt.Printf("下载 %s...\n", filename)
	resp, err = http.Get(downloadURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "下载失败: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "下载失败: HTTP %d\n", resp.StatusCode)
		os.Exit(1)
	}

	// 解压 gzip
	gzReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "解压失败: %v\n", err)
		os.Exit(1)
	}
	defer gzReader.Close()

	// 写入临时文件
	tmpFile, err := os.CreateTemp("", "cert-deploy-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "创建临时文件失败: %v\n", err)
		os.Exit(1)
	}
	tmpPath := tmpFile.Name()

	if _, err := io.Copy(tmpFile, gzReader); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		fmt.Fprintf(os.Stderr, "写入文件失败: %v\n", err)
		os.Exit(1)
	}
	tmpFile.Close()

	// 设置执行权限
	if err := os.Chmod(tmpPath, 0755); err != nil {
		os.Remove(tmpPath)
		fmt.Fprintf(os.Stderr, "设置权限失败: %v\n", err)
		os.Exit(1)
	}

	// 6. 替换二进制
	var binPath string
	if runtime.GOOS == "windows" {
		// Windows: 使用当前可执行文件路径或 %LOCALAPPDATA%\cert-deploy
		if exePath, err := os.Executable(); err == nil {
			binPath = exePath
		} else {
			binPath = filepath.Join(os.Getenv("LOCALAPPDATA"), "cert-deploy", "cert-deploy.exe")
		}
	} else {
		binPath = "/usr/local/bin/cert-deploy"
	}

	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(binPath), 0755); err != nil {
		os.Remove(tmpPath)
		fmt.Fprintf(os.Stderr, "创建目录失败: %v\n", err)
		os.Exit(1)
	}

	if err := os.Rename(tmpPath, binPath); err != nil {
		// 跨文件系统移动，使用复制
		src, _ := os.Open(tmpPath)
		dst, err := os.Create(binPath)
		if err != nil {
			src.Close()
			os.Remove(tmpPath)
			fmt.Fprintf(os.Stderr, "安装失败: %v\n", err)
			os.Exit(1)
		}
		io.Copy(dst, src)
		src.Close()
		dst.Close()
		os.Chmod(binPath, 0755)
		os.Remove(tmpPath)
	}

	fmt.Println("安装完成")

	// 7. 如果服务运行中，重启服务
	svcMgr, err := service.New(nil)
	if err == nil {
		status, _ := svcMgr.Status()
		if status != nil && status.Running {
			fmt.Println("重启服务...")
			if err := svcMgr.Restart(); err != nil {
				fmt.Fprintf(os.Stderr, "重启服务失败: %v\n", err)
			} else {
				fmt.Println("服务已重启")
			}
		}
	}

	fmt.Printf("\n升级完成: %s → %s\n", current, target)
}

// normalizeVersion 规范化版本号（确保带 v 前缀）
func normalizeVersion(ver string) string {
	if !strings.HasPrefix(ver, "v") {
		return "v" + ver
	}
	return ver
}

// runSetup 一键部署命令
func runSetup(args []string, debug bool) {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	apiURL := fs.String("url", "", "证书 API 基础地址")
	token := fs.String("token", "", "API 认证 Token")
	domain := fs.String("domain", "", "要部署的域名")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: cert-deploy setup --url <base_url> --token <token> --domain <domain>\n\n选项:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *apiURL == "" || *token == "" || *domain == "" {
		fs.Usage()
		os.Exit(1)
	}

	// 1. 检测 Web 服务类型
	serverType := detectWebServer()
	if serverType == "" {
		fmt.Fprintln(os.Stderr, "未检测到 Nginx 或 Apache 服务")
		os.Exit(1)
	}
	fmt.Printf("检测到 Web 服务: %s\n", serverType)

	// 2. 初始化配置管理器
	cfgManager, err := config.NewManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "初始化失败: %v\n", err)
		os.Exit(1)
	}

	// 初始化日志
	logDir := cfgManager.GetLogsDir()
	if debug {
		logDir = filepath.Join(logDir, "debug")
	}
	log, err := logger.New(logDir, "setup")
	if err != nil {
		fmt.Fprintf(os.Stderr, "创建日志失败: %v\n", err)
		os.Exit(1)
	}
	defer log.Close()

	if debug {
		log.SetLevel(logger.LevelDebug)
	}

	// 3. 扫描站点找到匹配域名
	fmt.Printf("扫描站点寻找域名: %s\n", *domain)

	var site *config.ScannedSite
	var hasSSL bool

	if serverType == "nginx" {
		s := nginxScanner.New()
		allSites, err := s.ScanAll()
		if err != nil {
			fmt.Fprintf(os.Stderr, "扫描失败: %v\n", err)
			os.Exit(1)
		}

		// 收集所有匹配的站点，优先选择有 SSL 的
		var matchedSite *nginxScanner.Site
		for _, ss := range allSites {
			if matchesDomain(ss.ServerName, *domain) || containsDomain(ss.ServerAlias, *domain) {
				if matchedSite == nil || (!matchedSite.HasSSL && ss.HasSSL) {
					matchedSite = ss
				}
			}
		}
		if matchedSite != nil {
			site = &config.ScannedSite{
				ID:              matchedSite.ServerName,
				ServerName:      matchedSite.ServerName,
				ServerAlias:     matchedSite.ServerAlias,
				ConfigFile:      matchedSite.ConfigFile,
				ListenPorts:     matchedSite.ListenPorts,
				Webroot:         matchedSite.Webroot,
				CertificatePath: matchedSite.CertificatePath,
				PrivateKeyPath:  matchedSite.PrivateKeyPath,
				Source:          "local",
			}
			hasSSL = matchedSite.HasSSL
		}
	} else {
		s := apacheScanner.New()
		allSites, err := s.ScanAll()
		if err != nil {
			fmt.Fprintf(os.Stderr, "扫描失败: %v\n", err)
			os.Exit(1)
		}

		// 收集所有匹配的站点，优先选择有 SSL 的
		var matchedSite *apacheScanner.Site
		for _, ss := range allSites {
			if matchesDomain(ss.ServerName, *domain) || containsDomain(ss.ServerAlias, *domain) {
				if matchedSite == nil || (!matchedSite.HasSSL && ss.HasSSL) {
					matchedSite = ss
				}
			}
		}
		if matchedSite != nil {
			site = &config.ScannedSite{
				ID:              matchedSite.ServerName,
				ServerName:      matchedSite.ServerName,
				ServerAlias:     matchedSite.ServerAlias,
				ConfigFile:      matchedSite.ConfigFile,
				ListenPorts:     matchedSite.ListenPorts,
				Webroot:         matchedSite.Webroot,
				CertificatePath: matchedSite.CertificatePath,
				PrivateKeyPath:  matchedSite.PrivateKeyPath,
				Source:          "local",
			}
			hasSSL = matchedSite.HasSSL
		}
	}

	if site == nil {
		fmt.Fprintf(os.Stderr, "未找到域名 %s 对应的站点配置\n", *domain)
		os.Exit(1)
	}

	fmt.Printf("找到站点: %s (SSL: %v)\n", site.ServerName, hasSSL)

	// 4. 若无 SSL 配置，提示安装
	if !hasSSL {
		fmt.Printf("站点 %s 尚未配置 HTTPS\n", site.ServerName)
		fmt.Println("请先使用以下命令安装 HTTPS 配置:")
		fmt.Printf("  cert-deploy install-https --site %s\n", site.ServerName)
		os.Exit(1)
	}

	// 5. 调用 API 查询订单获取证书
	fmt.Println("查询证书信息...")
	f := fetcher.New(30 * time.Second)
	ctx := context.Background()
	certData, err := f.Query(ctx, *apiURL, *token, *domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "查询证书失败: %v\n", err)
		os.Exit(1)
	}

	if certData.Status != "active" || certData.Cert == "" {
		fmt.Fprintf(os.Stderr, "证书未就绪: status=%s\n", certData.Status)
		os.Exit(1)
	}

	fmt.Printf("证书已就绪，订单 ID: %d\n", certData.OrderID)

	// 6. 生成站点配置
	siteCfg := &config.SiteConfig{
		Version:    "1.0",
		SiteName:   site.ServerName,
		Enabled:    true,
		ServerType: serverType,
		API: config.APIConfig{
			URL:         *apiURL,
			Token:       *token,
			CallbackURL: buildCallbackURL(*apiURL),
		},
		Domains: append([]string{site.ServerName}, site.ServerAlias...),
		Paths: config.PathsConfig{
			Certificate: site.CertificatePath,
			PrivateKey:  site.PrivateKeyPath,
			ConfigFile:  site.ConfigFile,
			Webroot:     site.Webroot,
		},
		Validation: config.ValidationConfig{
			VerifyDomain: true, // 默认启用证书域名校验
		},
		Reload: getReloadConfig(serverType),
		Backup: config.BackupConfig{
			Enabled:      true,
			KeepVersions: 3,
		},
		Schedule: config.ScheduleConfig{
			CheckIntervalHours: 12,
			RenewBeforeDays:    30,
		},
	}

	if err := cfgManager.SaveSite(siteCfg); err != nil {
		fmt.Fprintf(os.Stderr, "保存站点配置失败: %v\n", err)
		os.Exit(1)
	}

	configPath := filepath.Join(cfgManager.GetSitesDir(), site.ServerName+".json")
	fmt.Printf("站点配置已生成: %s\n", configPath)

	// 7. 部署证书
	fmt.Println("开始部署证书...")
	if serverType == "nginx" {
		nginx.Run([]string{"deploy", "--site", site.ServerName}, version, buildTime, debug)
	} else {
		apache.Run([]string{"deploy", "--site", site.ServerName}, version, buildTime, debug)
	}

	// 8. 配置 systemd 服务
	fmt.Println("\n部署完成！")
	fmt.Println("\n下一步（可选）:")
	fmt.Println("  systemctl enable cert-deploy   # 开机自启")
	fmt.Println("  systemctl start cert-deploy    # 启动守护进程")
}

// runUninstall 卸载命令
func runUninstall(args []string) {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	purge := fs.Bool("purge", false, "同时删除配置文件和数据")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: cert-deploy uninstall [--purge]\n\n选项:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	// 检查权限
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "请使用 root 权限运行此命令")
		os.Exit(1)
	}

	fmt.Println("开始卸载 cert-deploy...")

	// 1. 卸载服务
	svcMgr, err := service.New(nil)
	if err == nil {
		fmt.Println("卸载服务...")
		svcMgr.Uninstall()
	}

	// 2. 删除二进制文件
	cfg := service.DefaultConfig()
	binPath := cfg.ExecPath
	if _, err := os.Stat(binPath); err == nil {
		fmt.Printf("删除 %s...\n", binPath)
		os.Remove(binPath)
	}

	// 3. 清理配置目录（仅在 --purge 时）
	if *purge {
		workDir := cfg.WorkDir
		fmt.Printf("删除配置目录 %s...\n", workDir)
		os.RemoveAll(workDir)
	}

	fmt.Println("卸载完成！")
	if !*purge {
		cfg := service.DefaultConfig()
		fmt.Printf("配置文件保留在 %s，使用 --purge 可删除\n", cfg.WorkDir)
	}
}

// detectWebServer 检测 Web 服务类型
func detectWebServer() string {
	// 优先检测 nginx
	if _, err := exec.LookPath("nginx"); err == nil {
		if _, err := nginxScanner.DetectNginx(); err == nil {
			return "nginx"
		}
	}

	// 检测 apache
	if _, err := exec.LookPath("apache2ctl"); err == nil {
		if _, _, err := apacheScanner.DetectApache(); err == nil {
			return "apache"
		}
	}
	if _, err := exec.LookPath("apachectl"); err == nil {
		if _, _, err := apacheScanner.DetectApache(); err == nil {
			return "apache"
		}
	}
	if _, err := exec.LookPath("httpd"); err == nil {
		if _, _, err := apacheScanner.DetectApache(); err == nil {
			return "apache"
		}
	}

	return ""
}

// containsDomain 检查域名列表是否包含指定域名
// matchesDomain 检查 serverName 是否匹配目标域名（支持通配符）
func matchesDomain(serverName, domain string) bool {
	if serverName == domain {
		return true
	}
	// 支持通配符匹配: *.example.com 匹配 www.example.com
	if strings.HasPrefix(serverName, "*.") && strings.HasSuffix(domain, serverName[1:]) {
		return true
	}
	return false
}

func containsDomain(domains []string, domain string) bool {
	for _, d := range domains {
		if matchesDomain(d, domain) {
			return true
		}
	}
	return false
}

// getReloadConfig 获取重载配置
func getReloadConfig(serverType string) config.ReloadConfig {
	if serverType == "nginx" {
		return config.ReloadConfig{
			TestCommand:   "nginx -t",
			ReloadCommand: "nginx -s reload",
		}
	}
	return config.ReloadConfig{
		TestCommand:   "apache2ctl -t",
		ReloadCommand: "systemctl reload apache2",
	}
}

// buildCallbackURL 构建回调 URL
// 如果 baseURL 已包含 /api/deploy 路径，则添加 /callback
// 否则添加完整的 /api/deploy/callback
func buildCallbackURL(baseURL string) string {
	// 先去掉尾部斜杠，统一处理
	base := strings.TrimSuffix(baseURL, "/")
	if strings.HasSuffix(base, "/api/deploy") {
		return base + "/callback"
	}
	return base + "/api/deploy/callback"
}

// SetDebugLogger 设置调试日志记录器
func SetDebugLogger(log *logger.Logger) {
	log.SetLevel(logger.LevelDebug)
}
