// sslctl - SSL 证书自动部署工具
// 支持 Nginx、Apache
package main

import (
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
	"github.com/zhuxbo/sslctl/pkg/certops"
	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/logger"
	"github.com/zhuxbo/sslctl/pkg/service"
	"github.com/zhuxbo/sslctl/pkg/upgrade"
	"github.com/zhuxbo/sslctl/pkg/util"
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
	case "setup":
		setup.Run(subArgs, version, buildTime, debug)
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
  sslctl scan                          扫描所有站点
  sslctl scan --ssl-only               仅扫描 SSL 站点
  sslctl deploy --cert <name>          部署指定证书
  sslctl deploy --all                  部署所有证书
  sslctl status                        查看服务状态
  sslctl upgrade                       升级到最新版本
  sslctl upgrade --check               检查更新
  sslctl service repair                修复 systemd 服务

一键部署:
  sslctl setup --url <url> --token <token> --order <order_id>
  sslctl setup --url <url> --token <token> --order <order_id> --local-key
  sslctl setup --url <url> --token <token> --order <order_id> --yes --no-service

卸载:
  sslctl uninstall           # 卸载程序
  sslctl uninstall --purge   # 卸载并清理配置

示例:
  sslctl scan
  sslctl --debug deploy --cert example.com
  sslctl setup --url https://api.example.com --token abc123 --order 12345

更多信息请访问: https://github.com/zhuxbo/sslctl
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
	result, err := svc.Scan(ctx, certops.ScanOptions{
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

	// 4. 证书统计
	cfgManager, err := config.NewConfigManager()
	if err == nil {
		certs, _ := cfgManager.ListCerts()
		enabledCount := 0
		for _, cert := range certs {
			if cert.Enabled {
				enabledCount++
			}
		}
		fmt.Printf("\n证书配置: %d 个 (%d 个已启用)\n", len(certs), enabledCount)
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
	channel := fs.String("channel", "", "更新通道 (stable/dev)")
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

	opts := upgrade.Options{
		Channel:        *channel,
		TargetVersion:  *targetVersion,
		Force:          *force,
		CheckOnly:      *checkOnly,
		CurrentVersion: version,
	}

	// 使用 fmt.Printf 作为日志回调
	logFunc := func(format string, args ...interface{}) {
		fmt.Printf(format+"\n", args...)
	}

	if _, err := upgrade.Execute(opts, logFunc); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

// runUninstall 卸载命令
func runUninstall(args []string) {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	purge := fs.Bool("purge", false, "同时删除配置文件和数据")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: sslctl uninstall [--purge]\n\n选项:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if err := util.CheckRootPrivilege(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println("开始卸载 sslctl...")

	// 1. 卸载服务
	svcMgr, err := service.New(nil)
	if err == nil {
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

	// 3. 清理配置目录（仅在 --purge 时）
	if *purge {
		workDir := cfg.WorkDir
		fmt.Printf("删除配置目录 %s...\n", workDir)
		_ = os.RemoveAll(workDir)
	}

	fmt.Println("卸载完成！")
	if !*purge {
		cfg := service.DefaultConfig()
		fmt.Printf("配置文件保留在 %s，使用 --purge 可删除\n", cfg.WorkDir)
	}
}
