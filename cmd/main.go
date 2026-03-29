// sslctl - SSL 证书自动部署工具
// 支持 Nginx、Apache
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/zhuxbo/sslctl/cmd/daemon"
	"github.com/zhuxbo/sslctl/cmd/deploy"
	"github.com/zhuxbo/sslctl/cmd/setup"
	// 空白导入以触发 webserver 工厂注册
	_ "github.com/zhuxbo/sslctl/internal"
	"github.com/zhuxbo/sslctl/pkg/backup"
	"github.com/zhuxbo/sslctl/pkg/certops"
	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/logger"
	"github.com/zhuxbo/sslctl/pkg/service"
	"github.com/zhuxbo/sslctl/pkg/upgrade"
	"github.com/zhuxbo/sslctl/pkg/util"
	"github.com/zhuxbo/sslctl/pkg/validator"
	"github.com/zhuxbo/sslctl/pkg/webserver"
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
		_ = os.Setenv("LOG_LEVEL", "debug")
		_ = os.Setenv("SSLCTL_DEBUG", "1")
	}

	cmd := args[0]
	subArgs := args[1:]

	switch cmd {
	case "scan":
		runScan(subArgs, debug)
	case "deploy":
		deploy.Run(subArgs, version, buildTime, debug)
	case "daemon":
		daemon.Run(subArgs, version, buildTime, debug)
	case "status":
		runStatus()
	case "upgrade":
		runUpgrade(subArgs)
	case "service":
		runService(subArgs)
	case "rollback":
		runRollback(subArgs)
	case "setup":
		setup.Run(subArgs, debug)
	case "uninstall":
		runUninstall(subArgs)
	case "version", "-v", "--version":
		fmt.Printf("sslctl %s (built at %s)\n", version, buildTime)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "未知命令: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`sslctl %s - SSL 证书自动部署工具

使用方法:
  sslctl [--debug] <command> [options]

命令:
  scan            扫描站点（自动检测 Web 服务器）
  deploy          部署证书
  rollback        回滚证书到备份版本
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
  sslctl scan                                扫描所有站点
  sslctl scan --ssl-only                     仅扫描 SSL 站点
  sslctl deploy --cert <name>                部署指定证书
  sslctl deploy --cert <name> --site <site>  绑定站点并部署
  sslctl deploy --all                        部署所有证书
  sslctl rollback --site <name>              回滚证书到上一次备份
  sslctl rollback --site <name> --list       查看备份列表
  sslctl status                              查看服务状态
  sslctl upgrade                             升级到最新版本
  sslctl upgrade --check                     检查更新
  sslctl service repair                      修复 systemd 服务

一键部署:
  sslctl setup --url <url> --token <token> --order <order_id>
  sslctl setup --url <url> --token <token> --order <order_id> --local-key
  sslctl setup --url <url> --token <token> --order <order_id> --yes --no-service

卸载:
  sslctl uninstall           # 卸载程序（交互确认是否清理配置）

示例:
  sslctl scan
  sslctl --debug deploy --cert example.com
  sslctl setup --url https://api.example.com --token abc123 --order 12345
`, version)
}

// runWindowsService 以 Windows 服务方式运行
func runWindowsService() {
	err := service.RunAsService("sslctl", func() {
		daemon.Run(nil, version, buildTime, false)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Windows 服务运行失败: %v\n", err)
		os.Exit(1)
	}
}

// runScan 扫描站点
func runScan(args []string, debug bool) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	sslOnly := fs.Bool("ssl-only", false, "仅扫描 SSL 站点")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: sslctl scan [选项]\n\n选项:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	cfgManager, err := config.NewConfigManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "初始化配置失败: %v\n", err)
		os.Exit(1)
	}

	log, err := logger.New(cfgManager.GetLogsDir(), "scan")
	if err != nil {
		fmt.Fprintf(os.Stderr, "创建日志失败: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = log.Close() }()

	if debug {
		log.SetLevel(logger.LevelDebug)
	}

	svc := certops.NewService(cfgManager, log)

	ctx := context.Background()
	result, err := svc.ScanSites(ctx, certops.ScanOptions{
		SSLOnly: *sslOnly,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "扫描失败: %v\n", err)
		os.Exit(1)
	}

	// 输出结果
	fmt.Printf("扫描完成，发现 %d 个站点 (环境: %s)\n\n", len(result.Sites), result.Environment)

	for i, site := range result.Sites {
		fmt.Printf("[%d] %s\n", i+1, site.ServerName)
		fmt.Printf("    来源: %s\n", site.Source)
		if site.ContainerName != "" {
			fmt.Printf("    容器: %s\n", site.ContainerName)
		}
		fmt.Printf("    配置: %s\n", site.ConfigFile)
		if len(site.ListenPorts) > 0 {
			fmt.Printf("    端口: %s\n", strings.Join(site.ListenPorts, ", "))
		}
		if site.CertificatePath != "" {
			fmt.Printf("    证书: %s\n", site.CertificatePath)
			fmt.Printf("    私钥: %s\n", site.PrivateKeyPath)
		}
		fmt.Println()
	}
}

// runStatus 显示服务状态
func runStatus() {
	// 1. 版本信息
	fmt.Printf("版本: %s (编译时间: %s)\n", version, buildTime)
	fmt.Printf("系统: %s/%s\n", runtime.GOOS, runtime.GOARCH)

	// 2. Web 服务器检测
	serverType := webserver.DetectWebServerType()
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

	// 4. 证书详情
	cfgManager, err := config.NewConfigManager()
	if err != nil {
		return
	}

	cfg, err := cfgManager.Load()
	if err != nil {
		return
	}

	// 显示续签模式
	renewMode := cfg.Schedule.RenewMode
	if renewMode == "" {
		renewMode = config.RenewModePull
	}
	fmt.Printf("\n续签模式: %s\n", renewMode)

	// 显示上次检查时间
	if !cfg.Metadata.LastCheckAt.IsZero() {
		fmt.Printf("上次检查: %s\n", cfg.Metadata.LastCheckAt.Format("2006-01-02 15:04:05"))
	}

	certs := cfg.Certificates
	enabledCount := 0
	for _, cert := range certs {
		if cert.Enabled {
			enabledCount++
		}
	}
	fmt.Printf("\n证书配置: %d 个 (%d 个已启用)\n", len(certs), enabledCount)

	// 显示每个证书的过期时间和剩余天数
	now := time.Now()
	for _, cert := range certs {
		if !cert.Enabled {
			continue
		}

		status := "\033[32m有效\033[0m" // 绿色
		daysStr := ""

		if cert.Metadata.CertExpiresAt.IsZero() {
			status = "未部署"
		} else {
			remaining := cert.Metadata.CertExpiresAt.Sub(now)

			if remaining < 0 {
				// 已过期
				days := int((-remaining).Hours() / 24)
				if days == 0 {
					status = "\033[31m已过期\033[0m" // 红色
					daysStr = " (今天过期)"
				} else {
					status = "\033[31m已过期\033[0m" // 红色
					daysStr = fmt.Sprintf(" (已过期 %d 天)", days)
				}
			} else {
				days := int(remaining.Hours() / 24)
				if days == 0 {
					status = "\033[31m即将过期\033[0m" // 红色
					daysStr = " (今天过期)"
				} else if days < 7 {
					status = "\033[31m即将过期\033[0m" // 红色
					daysStr = fmt.Sprintf(" (剩余 %d 天)", days)
				} else if days < 13 {
					status = "\033[33m即将过期\033[0m" // 黄色
					daysStr = fmt.Sprintf(" (剩余 %d 天)", days)
				} else {
					daysStr = fmt.Sprintf(" (剩余 %d 天)", days)
				}
			}
		}

		fmt.Printf("  %-30s %s%s\n", cert.CertName, status, daysStr)
		if !cert.Metadata.CertExpiresAt.IsZero() {
			fmt.Printf("    过期时间: %s\n", cert.Metadata.CertExpiresAt.Format("2006-01-02 15:04:05"))
		}
		if !cert.Metadata.LastDeployAt.IsZero() {
			fmt.Printf("    上次部署: %s\n", cert.Metadata.LastDeployAt.Format("2006-01-02 15:04:05"))
		}
	}
}

// runService 管理服务
func runService(args []string) {
	if len(args) == 0 || args[0] != "repair" {
		fmt.Println("用法: sslctl service repair")
		fmt.Println("")
		fmt.Printf("修复/重新安装服务 (当前系统: %s)\n", service.GetInitSystemName())
		os.Exit(1)
	}

	if err := util.CheckRootPrivilege(); err != nil {
		fmt.Fprintln(os.Stderr, err)
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
	_ = svcMgr.Stop()

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
			fmt.Fprintln(os.Stderr, "\n查看详细日志: journalctl -u sslctl -n 50")
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
			fmt.Fprintln(os.Stderr, "查看日志: journalctl -u sslctl -n 50")
		}
		os.Exit(1)
	}
}

// runUpgrade 升级命令
func runUpgrade(args []string) {
	fs := flag.NewFlagSet("upgrade", flag.ExitOnError)
	channel := fs.String("channel", "", "更新通道 (main/dev)")
	targetVersion := fs.String("version", "", "指定版本")
	force := fs.Bool("force", false, "强制重新安装")
	checkOnly := fs.Bool("check", false, "仅检查更新")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: sslctl upgrade [选项]\n\n选项:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if err := util.CheckRootPrivilege(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	cfgManager, err := config.NewConfigManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "初始化配置失败: %v\n", err)
		os.Exit(1)
	}

	cfg, err := cfgManager.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载配置失败: %v\n", err)
		os.Exit(1)
	}

	releaseURL, err := resolveReleaseURL(cfgManager, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	// 通道优先级: 命令行参数 > 配置文件 > 自动判断
	effectiveChannel := *channel
	if effectiveChannel == "" {
		effectiveChannel = cfg.UpgradeChannel
	}

	opts := upgrade.Options{
		Channel:        effectiveChannel,
		TargetVersion:  *targetVersion,
		Force:          *force,
		CheckOnly:      *checkOnly,
		CurrentVersion: version,
		ReleaseURL:     releaseURL,
	}

	// 使用 fmt.Printf 作为日志回调
	logFunc := func(format string, args ...interface{}) {
		fmt.Printf(format+"\n", args...)
	}

	result, err := upgrade.Execute(opts, logFunc)
	if err != nil {
		// 升级失败，交互终端下提示输入新域名重试
		if isTerminalFunc() {
			newURL := promptNewReleaseURL(err)
			if newURL != "" {
				opts.ReleaseURL = newURL
				result, err = upgrade.Execute(opts, logFunc)
				if err != nil {
					fmt.Fprintf(os.Stderr, "%v\n", err)
					os.Exit(1)
				}
				// 重试成功，保存新地址
				cfg.ReleaseURL = newURL
				_ = cfgManager.Save(cfg)
			} else {
				os.Exit(1)
			}
		} else {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
	}

	// 显式传了 --channel 时始终保存；升级成功时也保存实际通道
	saveChannel := ""
	if *channel != "" {
		saveChannel = *channel
	} else if result != nil && result.NeedUpgrade && !*checkOnly {
		saveChannel = result.Channel
	}
	if saveChannel != "" {
		if saveErr := cfgManager.SetUpgradeChannel(saveChannel); saveErr != nil {
			fmt.Fprintf(os.Stderr, "保存升级通道失败: %v\n", saveErr)
		}
	}
}

// resolveReleaseURL 从配置文件读取升级地址。
// 未配置时在交互终端提示输入并保存，非交互环境返回错误。
func resolveReleaseURL(cfgManager *config.ConfigManager, cfg *config.Config) (string, error) {
	releaseURL := strings.TrimRight(strings.TrimSpace(cfg.ReleaseURL), "/")
	if releaseURL != "" {
		if err := validator.ValidateAPIURL(releaseURL); err != nil {
			return "", fmt.Errorf("配置文件中的升级地址不安全: %w", err)
		}
		return releaseURL, nil
	}

	// 非交互环境直接报错
	if !isTerminalFunc() {
		return "", fmt.Errorf("未配置升级地址（release_url），请在交互终端运行 sslctl upgrade 输入，或使用安装脚本传入参数")
	}

	// 交互提示输入
	fmt.Fprintln(os.Stderr, "未配置升级地址（release_url）。")
	fmt.Fprintln(os.Stderr, "格式示例: https://release.example.com/sslctl")
	fmt.Fprint(os.Stderr, "请输入升级地址: ")

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("读取输入失败: %w", err)
	}

	releaseURL = strings.TrimRight(strings.TrimSpace(input), "/")
	if releaseURL == "" {
		return "", fmt.Errorf("升级地址不能为空")
	}

	if err := validator.ValidateAPIURL(releaseURL); err != nil {
		return "", fmt.Errorf("升级地址不安全: %w", err)
	}

	// 校验可用性
	if _, err := upgrade.FetchReleaseInfo(releaseURL); err != nil {
		return "", fmt.Errorf("升级地址校验失败: %w", err)
	}

	// 保存到配置
	cfg.ReleaseURL = releaseURL
	if err := cfgManager.Save(cfg); err != nil {
		return "", fmt.Errorf("保存升级地址失败: %w", err)
	}

	return releaseURL, nil
}

// promptNewReleaseURL 升级失败后提示输入新的升级域名
// 返回新的完整 URL，用户取消则返回空字符串
func promptNewReleaseURL(origErr error) string {
	fmt.Fprintf(os.Stderr, "\n升级失败: %v\n", origErr)
	fmt.Fprint(os.Stderr, "输入新的升级域名（直接回车取消）: ")

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}

	host := strings.TrimSpace(input)
	if host == "" {
		return ""
	}
	host = strings.TrimRight(host, "/")

	// 支持输入完整 URL 或纯域名
	if strings.HasPrefix(host, "https://") {
		return strings.TrimRight(host, "/")
	}
	return "https://" + host + "/sslctl"
}

// isTerminalFunc 检查 stdin 是否为交互终端（可在测试中替换）
var isTerminalFunc = func() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// runRollback 回滚命令
func runRollback(args []string) {
	fs := flag.NewFlagSet("rollback", flag.ExitOnError)
	siteName := fs.String("site", "", "站点名称")
	listOnly := fs.Bool("list", false, "列出备份版本")
	versionTS := fs.String("version", "", "指定备份版本（时间戳）")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: sslctl rollback --site <name> [选项]\n\n选项:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *siteName == "" {
		fs.Usage()
		os.Exit(1)
	}

	if err := util.CheckRootPrivilege(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	cfgManager, err := config.NewConfigManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "初始化配置失败: %v\n", err)
		os.Exit(1)
	}

	backupMgr := backup.NewManager(cfgManager.GetBackupDir(), 5)

	// 列出备份
	if *listOnly {
		backups, err := backupMgr.ListBackups(*siteName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "获取备份列表失败: %v\n", err)
			os.Exit(1)
		}
		if len(backups) == 0 {
			fmt.Printf("站点 %s 没有备份记录\n", *siteName)
			return
		}
		fmt.Printf("站点 %s 的备份列表（共 %d 个）:\n\n", *siteName, len(backups))
		for i, ts := range backups {
			backupPath := cfgManager.GetBackupDir() + "/" + *siteName + "/" + ts
			meta, metaErr := backupMgr.LoadMetadata(backupPath)
			if metaErr != nil {
				fmt.Printf("  [%d] %s\n", i+1, ts)
			} else {
				fmt.Printf("  [%d] %s  备份时间: %s\n", i+1, ts, meta.BackupAt.Format("2006-01-02 15:04:05"))
				if meta.CertInfo.Subject != "" {
					fmt.Printf("      证书: %s  过期: %s\n", meta.CertInfo.Subject, meta.CertInfo.NotAfter.Format("2006-01-02"))
				}
			}
		}
		return
	}

	// 执行回滚
	fmt.Printf("正在回滚站点 %s...\n", *siteName)

	var metadata *backup.Metadata
	if *versionTS != "" {
		metadata, err = backupMgr.Restore(*siteName, *versionTS)
	} else {
		metadata, err = backupMgr.Restore(*siteName)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "回滚失败: %v\n", err)
		os.Exit(1)
	}

	// 更新配置中的证书元数据（非关键路径，失败仅提示）
	parsedCert, parseErr := parseRollbackCert(metadata.CertPath)
	if parseErr != nil {
		fmt.Fprintf(os.Stderr, "警告: %v\n", parseErr)
	}
	cfg, cfgErr := cfgManager.Load()
	if cfgErr != nil {
		fmt.Fprintf(os.Stderr, "警告: 加载配置失败，无法更新元数据: %v\n", cfgErr)
	} else {
		updated := applyRollbackMetadata(cfg, *siteName, parsedCert, metadata, time.Now())
		if len(updated) == 0 {
			fmt.Fprintf(os.Stderr, "警告: 未找到站点 %s 对应的证书配置，未更新元数据\n", *siteName)
		}
		for _, cert := range updated {
			if err := cfgManager.UpdateCert(cert); err != nil {
				fmt.Fprintf(os.Stderr, "警告: 更新证书元数据失败(%s): %v\n", cert.CertName, err)
			}
		}
	}

	fmt.Println("文件恢复完成")
	fmt.Printf("  证书: %s\n", metadata.CertPath)
	fmt.Printf("  私钥: %s\n", metadata.KeyPath)
	if metadata.ChainPath != "" {
		fmt.Printf("  证书链: %s\n", metadata.ChainPath)
	}

	// 提示用户重载 Web 服务器
	serverType := webserver.DetectWebServerType()
	if serverType == "nginx" {
		nginxCmds := webserver.DetectNginxCommands()
		fmt.Println("\n请重载 Nginx 使证书生效:")
		fmt.Printf("  %s && %s\n", nginxCmds.TestCmd, nginxCmds.ReloadCmd)
	} else if serverType == "apache" {
		apacheCmds := webserver.DetectApacheCommands()
		fmt.Println("\n请重载 Apache 使证书生效:")
		fmt.Printf("  %s && %s\n", apacheCmds.TestCmd, apacheCmds.ReloadCmd)
	} else {
		fmt.Println("\n请手动重载 Web 服务器使证书生效")
	}
}

// runUninstall 卸载命令
func runUninstall(args []string) {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: sslctl uninstall\n")
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if err := util.CheckRootPrivilege(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println("开始卸载 sslctl...")

	// 1. 停止并卸载服务
	svcMgr, err := service.New(nil)
	if err == nil {
		fmt.Println("停止服务...")
		_ = svcMgr.Stop()
		fmt.Println("卸载服务...")
		_ = svcMgr.Uninstall()
	}

	// 2. 删除二进制文件
	cfg := service.DefaultConfig()
	binPath := cfg.ExecPath
	if _, err := os.Stat(binPath); err == nil {
		fmt.Printf("删除 %s...\n", binPath)
		_ = os.Remove(binPath)
	}

	// 3. 询问是否清理配置目录
	workDir := cfg.WorkDir
	if _, err := os.Stat(workDir); err == nil {
		fmt.Printf("是否删除配置目录 %s？[y/N] ", workDir)
		var answer string
		_, _ = fmt.Scanln(&answer)
		if answer == "y" || answer == "Y" {
			fmt.Printf("删除配置目录 %s...\n", workDir)
			_ = os.RemoveAll(workDir)
		} else {
			fmt.Printf("配置文件保留在 %s\n", workDir)
		}
	}

	fmt.Println("卸载完成！")
}
