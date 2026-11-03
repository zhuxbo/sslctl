// sslctl - SSL 证书自动部署工具
// 支持 Nginx、Apache
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	cleanupcmd "github.com/zhuxbo/sslctl/cmd/cleanup"
	"github.com/zhuxbo/sslctl/cmd/daemon"
	"github.com/zhuxbo/sslctl/cmd/deploy"
	"github.com/zhuxbo/sslctl/cmd/setup"
	// 空白导入以触发 webserver 工厂注册
	_ "github.com/zhuxbo/sslctl/internal"
	apacheScanner "github.com/zhuxbo/sslctl/internal/apache/scanner"
	nginxScanner "github.com/zhuxbo/sslctl/internal/nginx/scanner"
	"github.com/zhuxbo/sslctl/pkg/backup"
	"github.com/zhuxbo/sslctl/pkg/certops"
	"github.com/zhuxbo/sslctl/pkg/config"
	sslerrors "github.com/zhuxbo/sslctl/pkg/errors"
	"github.com/zhuxbo/sslctl/pkg/logger"
	"github.com/zhuxbo/sslctl/pkg/service"
	"github.com/zhuxbo/sslctl/pkg/upgrade"
	"github.com/zhuxbo/sslctl/pkg/util"
	"github.com/zhuxbo/sslctl/pkg/validator"
	"github.com/zhuxbo/sslctl/pkg/webserver"
)

var (
	version    = "dev"
	buildTime  = "unknown"
	runCleanup = cleanupcmd.Run
)

const (
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorRed    = "\033[31m"
	colorReset  = "\033[0m"
)

// colorize 在支持 ANSI 的终端上给文本加颜色，否则返回原文
// Windows Server 2012 R2 等不支持 VT 的老系统走纯文本分支，
// 避免控制台把 ESC 序列当作乱码显示
func colorize(text, color string) string {
	if !supportsANSIColor() {
		return text
	}
	return color + text + colorReset
}

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
		daemon.Run(context.Background(), subArgs, version, buildTime, debug)
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
	case "cleanup":
		runCleanup(subArgs)
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
  cleanup         解除指定站点或证书的 sslctl 管理
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
  sslctl cleanup --site <site>               解除指定站点管理
  sslctl cleanup --cert <name>               解除指定证书管理
  sslctl cleanup --list                      列出全部受管证书和站点绑定

诊断命令:
%s

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
`, version, diagnosticCommandsHelp())
}

func diagnosticCommandsHelp() string {
	return `  sslctl status                              查看 sslctl、证书及 Web 服务器状态
  systemctl status sslctl                    查看 Linux 服务状态
  journalctl -u sslctl -f                    跟踪 Linux 服务日志
  sc query sslctl                            查看 Windows 服务状态`
}

// runWindowsService 以 Windows 服务方式运行
func runWindowsService() {
	err := service.RunAsService("sslctl", func(ctx context.Context) {
		daemon.Run(ctx, nil, version, buildTime, false)
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
	nginxPrefix := fs.String("nginx-prefix", "", "显式指定 nginx 普通相对路径的 prefix（不影响证书路径，仅本次生效）")
	apachePrefix := fs.String("apache-prefix", "", "显式指定 Apache ServerRoot 解析基准（仅本次生效，不写入配置）")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: sslctl scan [选项]\n\n选项:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *nginxPrefix != "" {
		nginxScanner.SetPrefixOverride(*nginxPrefix)
	}
	if *apachePrefix != "" {
		apacheScanner.SetPrefixOverride(*apachePrefix)
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
		var prefixErr *sslerrors.PrefixUnknownError
		if errors.As(err, &prefixErr) {
			fmt.Fprint(os.Stderr, prefixErr.RenderHint())
			os.Exit(1)
		}
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
		if site.ContainerID != "" && !site.VolumeMode {
			fmt.Println("    [!] 证书路径未挂载为卷，重建容器后需要重新部署")
		}
		fmt.Println()
	}
}

// runStatus 显示服务状态
func runStatus() {
	// 1. 版本信息
	fmt.Printf("版本: %s (编译时间: %s)\n", version, buildTime)
	fmt.Printf("系统: %s/%s\n", runtime.GOOS, runtime.GOARCH)

	// 提前读取配置，让纯 Docker 环境也能展示 setup 保存的站点绑定。
	var cfg *config.Config
	cfgManager, cfgManagerErr := config.NewConfigManager()
	if cfgManagerErr == nil {
		cfg, _ = cfgManager.Load()
	}

	// 2. Web 服务器检测
	fmt.Printf("Web 服务器: %s\n", webServerStatusSummary(webserver.DetectWebServerType(), cfg))

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
	if cfg == nil {
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

		status := colorize("有效", colorGreen)
		daysStr := ""

		if cert.Metadata.CertExpiresAt.IsZero() {
			status = "未部署"
		} else {
			remaining := cert.Metadata.CertExpiresAt.Sub(now)

			if remaining < 0 {
				days := int((-remaining).Hours() / 24)
				status = colorize("已过期", colorRed)
				if days == 0 {
					daysStr = " (今天过期)"
				} else {
					daysStr = fmt.Sprintf(" (已过期 %d 天)", days)
				}
			} else {
				days := int(remaining.Hours() / 24)
				if days == 0 {
					status = colorize("即将过期", colorRed)
					daysStr = " (今天过期)"
				} else if days < 7 {
					status = colorize("即将过期", colorRed)
					daysStr = fmt.Sprintf(" (剩余 %d 天)", days)
				} else if days < 13 {
					status = colorize("即将过期", colorYellow)
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
		printCertHaltState(os.Stdout, &cert)
	}
}

// printCertHaltState 展示停机/阻断/陈旧绑定状态。
// 这些状态此前只出现在日志里，`status` 看上去一切正常，人工排查无从下手。
func printCertHaltState(w io.Writer, cert *config.CertConfig) {
	if !cert.Metadata.NoBindingBlockedAt.IsZero() {
		_, _ = fmt.Fprintf(w, "    %s 无启用绑定，自动续签与部署已阻断（自 %s），请重新 setup 或恢复绑定\n",
			colorize("[阻断]", colorRed), cert.Metadata.NoBindingBlockedAt.Format("2006-01-02 15:04:05"))
	}
	if cert.Metadata.LastIssueState == config.IssueStateCapped {
		// 停更与计数触顶成因不同：前者是长期只查询无进展（订单卡死/被删等），
		// 后者是尝试次数用尽，展示上必须可区分，否则运维不知道该查哪一头
		if cert.Metadata.CappedPhase == config.CappedPhaseStalled {
			_, _ = fmt.Fprintf(w, "    %s 连续 %d 天无任何进展（订单长期未推进），已停止拉取，需人工核对订单状态\n",
				colorize("[停更]", colorRed), config.MaxNoProgressDays)
		} else {
			phase := cert.Metadata.CappedPhase
			if phase == "" {
				phase = "未知阶段"
			}
			_, _ = fmt.Fprintf(w, "    %s 已达尝试次数上限（阶段: %s），已停止自动重试，需人工处理\n",
				colorize("[停机]", colorRed), phase)
		}
	}
	if !cert.Metadata.NoProgressSince.IsZero() {
		_, _ = fmt.Fprintf(w, "    %s 自 %s 起无进展（%d 天后停止拉取）\n",
			colorize("[无进展]", colorYellow), formatStatusTime(cert.Metadata.NoProgressSince),
			config.MaxNoProgressDays)
	}
	if cert.Metadata.LastDeployBlockReason != "" {
		// 环境阻断与部署失败要能区分：前者是既有 Web 配置损坏、与本证书无关，
		// 修好配置即自动恢复，不需要人工解除任何状态
		_, _ = fmt.Fprintf(w, "    %s %s（自 %s，已上报 %d/%d 次）\n",
			colorize("[环境阻断]", colorRed), cert.Metadata.LastDeployBlockReason,
			formatStatusTime(cert.Metadata.LastDeployBlockAt),
			cert.Metadata.BlockReportCount, config.MaxBlockReportCount)
	}
	if cert.Metadata.UnchangedCertRounds > 0 {
		_, _ = fmt.Fprintf(w, "    %s 服务端连续 %d/%d 轮返回同一张证书，证书未实际更新\n",
			colorize("[未更替]", colorYellow), cert.Metadata.UnchangedCertRounds,
			config.CertUnchangedRounds)
	}
	if len(cert.Metadata.StaleBindings) > 0 {
		_, _ = fmt.Fprintf(w, "    %s 长期未部署成功的站点: %s（自 %s），这些站点仍在使用旧证书\n",
			colorize("[陈旧]", colorRed), strings.Join(cert.Metadata.StaleBindings, ", "),
			formatStatusTime(cert.Metadata.StaleSince))
	}
	if len(cert.Metadata.FailedBindings) > 0 {
		_, _ = fmt.Fprintf(w, "    %s 待重试的失败站点: %s（已重试 %d/%d 轮）\n",
			colorize("[重试中]", colorYellow), strings.Join(cert.Metadata.FailedBindings, ", "),
			cert.Metadata.RetryAttemptCount, certops.MaxRetryAttemptCount)
	}
}

// formatStatusTime 缺失时间时给出明确占位，避免打印空串
func formatStatusTime(t time.Time) string {
	if t.IsZero() {
		return "时间未知"
	}
	return t.Format("2006-01-02 15:04:05")
}

func webServerStatusSummary(localServerType string, cfg *config.Config) string {
	var servers []string
	seen := make(map[string]struct{})
	if localServerType != "" {
		servers = append(servers, localServerType)
		seen[localServerType+"\x00"] = struct{}{}
	}

	if cfg != nil {
		for _, cert := range cfg.Certificates {
			if !cert.Enabled {
				continue
			}
			for _, binding := range cert.Bindings {
				if !binding.Enabled || binding.ServerType == "" {
					continue
				}

				containerName := ""
				if binding.Docker != nil {
					containerName = binding.Docker.ContainerName
				}
				key := binding.ServerType + "\x00" + containerName
				if _, exists := seen[key]; exists {
					continue
				}

				label := binding.ServerType + "（已配置）"
				if containerName != "" {
					label = fmt.Sprintf("%s（已配置，容器: %s）", binding.ServerType, containerName)
				}
				servers = append(servers, label)
				seen[key] = struct{}{}
			}
		}
	}

	if len(servers) == 0 {
		return "未检测到"
	}
	return strings.Join(servers, ", ")
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

	// 停止现有服务（忽略错误，可能不存在）
	_ = svcMgr.Stop()

	// 安装服务（已存在时自动删除重建）
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
		// 仅发布源相关错误（地址/网络/版本）才提示换域名重试
		var releaseErr *upgrade.ErrReleaseSource
		if isTerminalFunc() && errors.As(err, &releaseErr) {
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

// 回滚入口的系统边界独立保留，测试可使用临时配置并观察退出状态。
var (
	rollbackCheckRoot        = util.CheckRootPrivilege
	rollbackNewConfigManager = config.NewConfigManager
	rollbackExit             = os.Exit
)

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
		rollbackExit(1)
	}

	if err := rollbackCheckRoot(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		rollbackExit(1)
	}

	cfgManager, err := rollbackNewConfigManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "初始化配置失败: %v\n", err)
		rollbackExit(1)
	}

	backupMgr := backup.NewManager(cfgManager.GetBackupDir(), 5)

	// 列出备份
	if *listOnly {
		backups, err := backupMgr.ListBackups(*siteName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "获取备份列表失败: %v\n", err)
			rollbackExit(1)
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

	// 与守护进程共享续签互斥锁，避免回滚与自动续签并发操作同一证书目录（--list 只读不加锁）
	release, acquired, lockErr := config.AcquireRenewalLock(cfgManager.GetWorkDir())
	if lockErr != nil {
		fmt.Fprintf(os.Stderr, "警告: %v，继续执行\n", lockErr)
	} else if !acquired {
		fmt.Fprintln(os.Stderr, "守护进程正在续签（或另一部署进程正在运行），请稍后再试")
		rollbackExit(1)
	} else {
		defer release()
	}

	// 执行回滚
	fmt.Printf("正在回滚站点 %s...\n", *siteName)

	backupPath, err := backupMgr.ResolveBackupPath(*siteName, *versionTS)
	if err != nil {
		fmt.Fprintf(os.Stderr, "回滚失败: %v\n", err)
		rollbackExit(1)
	}
	metadata, err := backupMgr.LoadMetadata(backupPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取备份失败: %v\n", err)
		rollbackExit(1)
	}
	parsedCert, parseErr := parseRollbackCert(filepath.Join(backupPath, "cert.pem"))
	if metadata.ContainerName != "" {
		err = certops.RestoreDockerBackup(context.Background(), backupMgr, backupPath, metadata)
	} else {
		metadata, err = backupMgr.Restore(*siteName, *versionTS)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "回滚失败: %v\n", err)
		rollbackExit(1)
	}

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

	if metadata.ContainerName != "" {
		fmt.Printf("  容器 %s 已通过配置检查并重载\n", metadata.ContainerName)
		return
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
