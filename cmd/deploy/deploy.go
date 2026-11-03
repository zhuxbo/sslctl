// Package deploy 证书部署命令
package deploy

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zhuxbo/sslctl/pkg/backup"
	"github.com/zhuxbo/sslctl/pkg/certops"
	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
	"github.com/zhuxbo/sslctl/pkg/matcher"
	"github.com/zhuxbo/sslctl/pkg/util"
	"github.com/zhuxbo/sslctl/pkg/validator"
	"github.com/zhuxbo/sslctl/pkg/webserver"
)

// Run 运行 deploy 命令
func Run(args []string, version, buildTime string, debug bool) {
	// 检查是否为 local 子命令
	if len(args) > 0 && args[0] == "local" {
		runLocal(args[1:], debug)
		return
	}

	fs := flag.NewFlagSet("deploy", flag.ExitOnError)
	certName := fs.String("cert", "", "证书名称")
	siteName := fs.String("site", "", "绑定并部署到指定站点（需配合 --cert）")
	yes := fs.Bool("yes", false, "跳过确认提示（配合 --site 使用）")
	all := fs.Bool("all", false, "部署所有证书")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: sslctl deploy --cert <name>\n")
		fmt.Fprintf(os.Stderr, "      sslctl deploy --cert <name> --site <server_name>\n")
		fmt.Fprintf(os.Stderr, "      sslctl deploy --all\n")
		fmt.Fprintf(os.Stderr, "      sslctl deploy local --cert <file> --key <file> --site <name>\n\n选项:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *certName == "" && !*all {
		fs.Usage()
		os.Exit(1)
	}

	if *siteName != "" && *certName == "" {
		fmt.Fprintln(os.Stderr, "--site 需要配合 --cert 使用")
		os.Exit(1)
	}
	if *siteName != "" && *all {
		fmt.Fprintln(os.Stderr, "--site 不能与 --all 一起使用")
		os.Exit(1)
	}

	cfgManager, err := config.NewConfigManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "初始化失败: %v\n", err)
		os.Exit(1)
	}

	logDir := cfgManager.GetLogsDir()
	if debug {
		logDir = filepath.Join(logDir, "debug")
	}

	log, err := logger.New(logDir, "deploy")
	if err != nil {
		fmt.Fprintf(os.Stderr, "创建日志失败: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = log.Close() }()

	if debug {
		log.SetLevel(logger.LevelDebug)
	}

	// 与守护进程共享续签互斥锁，避免手动部署与自动续签并发操作同一证书目录与配置
	release, acquired, lockErr := config.AcquireRenewalLock(cfgManager.GetWorkDir())
	if lockErr != nil {
		log.Warn("%v，继续执行", lockErr)
	} else if !acquired {
		fmt.Fprintln(os.Stderr, "守护进程正在续签（或另一部署进程正在运行），请稍后再试")
		os.Exit(1)
	} else {
		defer release()
	}

	ctx := context.Background()
	f := fetcher.New()
	backupMgr := backup.NewManager(cfgManager.GetBackupDir(), 5)

	if *all {
		// 部署所有证书
		certs, err := cfgManager.ListEnabledCerts()
		if err != nil {
			fmt.Fprintf(os.Stderr, "获取证书列表失败: %v\n", err)
			os.Exit(1)
		}
		if err := deployAllCerts(certs, func(cert *config.CertConfig) error {
			err := fetchAndDeployCert(ctx, cfgManager, cert, f, backupMgr, log)
			if err != nil {
				log.Error("部署证书 %s 失败: %v", cert.CertName, err)
			}
			return err
		}); err != nil {
			fmt.Fprintf(os.Stderr, "部署未全部完成: %v\n", err)
			os.Exit(1)
		}
	} else {
		// 部署指定证书
		cert, err := cfgManager.GetCert(*certName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "证书不存在: %s\n", *certName)
			os.Exit(1)
		}

		// 如果指定了 --site，先绑定站点到证书
		if *siteName != "" {
			if err := bindSiteToCert(ctx, cfgManager, cert, *siteName, f, *yes); err != nil {
				fmt.Fprintf(os.Stderr, "绑定站点失败: %v\n", err)
				os.Exit(1)
			}
		}

		if err := fetchAndDeployCert(ctx, cfgManager, cert, f, backupMgr, log); err != nil {
			fmt.Fprintf(os.Stderr, "部署失败: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Println("部署完成")
}

func deployAllCerts(certs []config.CertConfig, deploy func(*config.CertConfig) error) error {
	failedCerts := make([]string, 0)
	for i := range certs {
		cert := &certs[i]
		if err := deploy(cert); err != nil {
			fmt.Fprintf(os.Stderr, "  失败: %v\n", err)
			failedCerts = append(failedCerts, fmt.Sprintf("%s: %v", cert.CertName, err))
		}
	}
	if len(failedCerts) > 0 {
		return fmt.Errorf("%d 个证书部署失败: %s", len(failedCerts), strings.Join(failedCerts, "; "))
	}
	return nil
}

// fetchAndDeployCert 从 API 获取并部署单个证书到所有绑定
func fetchAndDeployCert(ctx context.Context, cfgManager *config.ConfigManager, cert *config.CertConfig, f *fetcher.Fetcher, backupMgr *backup.Manager, log *logger.Logger) error {
	fmt.Printf("部署证书: %s\n", cert.CertName)

	api := cert.GetAPI(log)
	if api.URL == "" || api.Token == "" {
		return fmt.Errorf("证书 %s 的 API 配置不完整，请先运行 setup 命令", cert.CertName)
	}

	// 查询证书
	certData, renewBeforeDays, err := f.QueryOrder(ctx, api.URL, api.Token, cert.OrderID)
	if err != nil {
		return fmt.Errorf("查询证书失败: %w", err)
	}
	applyDeployRenewBeforeDays(cfgManager, log, renewBeforeDays)

	// 订单续费后 API 返回新订单号，同步更新 order_id
	if certData.OrderID > 0 && certData.OrderID != cert.OrderID {
		fmt.Printf("  订单已续费，订单号更新: %d -> %d\n", cert.OrderID, certData.OrderID)
		log.Info("证书 %s 订单已续费，订单号更新: %d -> %d", cert.CertName, cert.OrderID, certData.OrderID)
		cert.OrderID = certData.OrderID
	}

	// 修正 cert_name：确保与 order_id 一致（复用 certops 单一实现，含 pending 私钥迁移）
	oldCertName := cert.CertName
	certops.FixCertName(cfgManager, cert, log)
	if cert.CertName != oldCertName {
		fmt.Printf("  证书名称修正: %s -> %s\n", oldCertName, cert.CertName)
	}

	if certData.Status != config.OrderStatusActive || certData.Cert == "" {
		return fmt.Errorf("证书未就绪: status=%s", certData.Status)
	}

	// 验证证书
	v := validator.New("")
	parsedCert, err := v.ValidateCert(certData.Cert)
	if err != nil {
		return fmt.Errorf("证书验证失败: %w", err)
	}

	// 获取私钥：优先使用 API 返回，否则从本地读取（pending 感知，配对校验；
	// 续签部署全失败后 pending 私钥尚未转正，手动 deploy 须能用它补救）
	privateKey, err := certops.GetPrivateKeyForCert(ctx, cfgManager.GetWorkDir(), cert, certData.Cert, certData.PrivateKey, log)
	if err != nil {
		return err
	}
	if certData.PrivateKey == "" && len(cert.Bindings) > 0 && cert.Bindings[0].Paths.PrivateKey != "" {
		fmt.Printf("  使用本地私钥: %s\n", cert.Bindings[0].Paths.PrivateKey)
	}

	// 验证私钥与证书匹配
	if err := v.ValidateCertKeyPair(certData.Cert, privateKey); err != nil {
		return fmt.Errorf("私钥与证书不匹配: %w", err)
	}

	// 验证中间证书
	if certData.IntermediateCert == "" {
		return fmt.Errorf("中间证书为空，无法部署")
	}

	// 部署到所有绑定
	enabledCount := 0
	for _, b := range cert.Bindings {
		if b.Enabled {
			enabledCount++
		}
	}
	if enabledCount == 0 {
		fmt.Printf("  跳过: 没有启用的站点绑定\n")
		return cfgManager.UpdateCert(cert)
	}

	successCount, failedNames, deployErr := deployToBindings(ctx, cert, certData, privateKey, backupMgr, log)

	// 仅在至少有一个绑定部署成功时才更新元数据
	if successCount > 0 {
		cert.Metadata.LastDeployAt = time.Now()
		cert.Metadata.CertExpiresAt = parsedCert.NotAfter
		cert.Metadata.CertSerial = fmt.Sprintf("%X", parsedCert.SerialNumber)
		// 部署成功后补转正 pending 私钥（若本次使用的正是 pending 私钥）
		certops.CommitPendingKeyIfMatches(cfgManager.GetWorkDir(), cert, privateKey, log)
		// 人工修复后必须解除停机状态：此前 CAPPED 的证书手动部署成功后仍会永久静默，
		// 因为 last_issue_state 与计数从未被清理。
		cert.Metadata.LastIssueState = ""
		cert.Metadata.CappedPhase = ""
		cert.Metadata.IssueRetryCount = 0
		cert.Metadata.DeployAttemptCount = 0
		cert.Metadata.DeployStartedAt = time.Time{}
		cert.Metadata.RetryAttemptCount = 0
		// 无进展计时同样解除：手动部署成功本身就是最强的进展信号
		cert.Metadata.NoProgressSince = time.Time{}
		// 全部绑定部署成功才确认环境恢复，部分成功不能解除其他站点的阻断。
		if deployErr == nil {
			cert.Metadata.LastDeployBlockReason = ""
			cert.Metadata.LastDeployBlockAt = time.Time{}
			cert.Metadata.BlockReportCount = 0
		}
	}
	// 失败绑定原样记录（不是清空）：清空会让 daemon 不再接手仍失败的站点，
	// 制造"手动部署部分成功 → 剩下的永远没人管"的新洞
	cert.Metadata.FailedBindings = failedNames
	if len(failedNames) > 0 {
		if cert.Metadata.FailedBindingsAt.IsZero() {
			cert.Metadata.FailedBindingsAt = time.Now()
		}
	} else {
		cert.Metadata.FailedBindingsAt = time.Time{}
	}

	if err := cfgManager.UpdateCert(cert); err != nil {
		return err
	}

	// 上报部署结果（deploy-spec §5.1 步骤 6）：此前手动 deploy 全链不发回调，
	// 服务端会一直停留在最后一次 failure 上，直到下个续签窗口。
	sendDeployResultCallback(ctx, cfgManager, cert, api, f, deployErr, log)
	return deployErr
}

// sendDeployResultCallback 上报一次手动部署结果（非关键路径，失败仅记日志）。
// CLI 的 ctx 无 deadline，显式限定预算，避免部署已成功却让命令再挂几分钟。
func sendDeployResultCallback(ctx context.Context, cfgManager *config.ConfigManager, cert *config.CertConfig,
	api config.APIConfig, f *fetcher.Fetcher, deployErr error, log *logger.Logger) {
	req := &fetcher.CallbackRequest{
		OrderID:    cert.OrderID,
		Status:     "success",
		DeployedAt: time.Now().Format(time.RFC3339),
	}
	if deployErr != nil {
		req.Status = "failure"
		req.Message = certops.CallbackMessage(deployErr)
	}

	cbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), certops.CallbackFallbackBudget)
	defer cancel()

	renewBeforeDays, err := f.CallbackNew(cbCtx, api.URL, api.Token, req)
	if err != nil {
		if log != nil {
			log.Warn("上报部署结果失败（不影响部署结果）: %v", err)
		}
		return
	}
	applyDeployRenewBeforeDays(cfgManager, log, renewBeforeDays)
}

// deployToBindings 部署全部启用绑定；只要有一个绑定失败就返回错误，
// 便于脚本调用方通过退出码识别部分失败，同时不影响其他绑定继续部署。
// 返回成功数、仍失败的站点名（供 FailedBindings 记录）与聚合错误。
func deployToBindings(ctx context.Context, cert *config.CertConfig, certData *fetcher.CertData, privateKey string, backupMgr *backup.Manager, log *logger.Logger) (int, []string, error) {
	successCount := 0
	failedSites := make([]string, 0)
	failedNames := make([]string, 0)
	bindings := cert.Bindings
	for i := range bindings {
		binding := &bindings[i]
		if !binding.Enabled {
			continue
		}

		fmt.Printf("  部署到: %s\n", binding.ServerName)
		if err := deployToBinding(ctx, binding, certData, privateKey, backupMgr, log); err != nil {
			fmt.Printf("    失败: %v\n", err)
			failedSites = append(failedSites, fmt.Sprintf("%s: %v", binding.ServerName, err))
			failedNames = append(failedNames, binding.ServerName)
			continue
		}
		certops.ClearStaleBinding(cert, binding.ServerName)
		fmt.Printf("    成功\n")
		successCount++
	}

	if len(failedSites) > 0 {
		return successCount, failedNames, fmt.Errorf("%d 个站点部署失败: %s", len(failedSites), strings.Join(failedSites, "; "))
	}
	return successCount, failedNames, nil
}

func applyDeployRenewBeforeDays(cm *config.ConfigManager, log *logger.Logger, value int) {
	if value > config.MaxRenewBeforeDays {
		if log != nil {
			log.Warn("服务端返回的 renew_before_days=%d 超过上限 %d，保留本地配置", value, config.MaxRenewBeforeDays)
		}
		return
	}
	if _, err := cm.UpdateRenewBeforeDays(value); err != nil && log != nil {
		log.Warn("更新 renew_before_days 失败: %v", err)
	}
}

// deployToBinding 部署到绑定（带备份和回滚）
func deployToBinding(ctx context.Context, binding *config.SiteBinding, certData *fetcher.CertData, privateKey string, backupMgr *backup.Manager, log *logger.Logger) error {
	if config.IsDockerCopyBinding(binding) {
		return certops.DeployDockerCopy(ctx, binding, certData, privateKey, backupMgr, log)
	}
	// volume 绑定校验宿主机路径与容器重载命令；copy 已在上方分流。
	if config.IsDockerType(binding.ServerType) {
		if err := config.ValidateDockerBinding(binding); err != nil {
			return err
		}
	} else if binding.Reload.ReloadCommand == "" && log != nil {
		log.Warn("站点 %s 无重载命令，部署后不会自动重载服务", binding.ServerName)
	}

	certDir := filepath.Dir(binding.Paths.Certificate)
	if err := util.EnsureDir(certDir, 0700); err != nil {
		return fmt.Errorf("创建证书目录失败: %w", err)
	}

	deployer, err := webserver.NewDeployer(
		webserver.ServerType(binding.ServerType),
		binding.Paths.Certificate,
		binding.Paths.PrivateKey,
		binding.Paths.ChainFile,
		binding.Reload.TestCommand,
		binding.Reload.ReloadCommand,
	)
	if err != nil {
		return fmt.Errorf("创建部署器失败: %w", err)
	}

	if prepared, ok := deployer.(interface{ Prepare() error }); ok {
		if err := prepared.Prepare(); err != nil {
			return fmt.Errorf("准备证书文件失败: %w", err)
		}
	}

	// 备份现有证书（如果存在）
	var backupPath string
	if util.FileExists(binding.Paths.Certificate) && util.FileExists(binding.Paths.PrivateKey) {
		result, err := backupMgr.Backup(binding.ServerName, binding.Paths.Certificate, binding.Paths.PrivateKey, nil, binding.Paths.ChainFile)
		if err != nil {
			return fmt.Errorf("备份现有证书失败，中止部署: %w", err)
		}
		if result != nil {
			backupPath = result.BackupPath
			log.Info("已备份证书到: %s", backupPath)
		}
	}

	deployErr := deployer.Deploy(ctx, certData.Cert, certData.IntermediateCert, privateKey)

	// 部署失败时回滚
	if deployErr != nil && backupPath != "" {
		log.Warn("部署失败，尝试回滚: %v", deployErr)
		certPath, keyPath, chainPath := backupMgr.GetBackupPathsWithChain(backupPath)
		// 回滚脱离取消传播：部署失败常常正是 ctx 被取消所致，
		// 沿用同一个 ctx 会让兜底回滚当场失败、服务停在坏状态
		rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), certops.RollbackBudget)
		rollbackErr := deployer.Rollback(rbCtx, certPath, keyPath, chainPath)
		cancel()
		if rollbackErr != nil {
			log.Error("回滚失败: %v", rollbackErr)
			return fmt.Errorf("部署失败且回滚失败: deploy=%v, rollback=%v", deployErr, rollbackErr)
		}
		log.Info("已回滚到备份: %s", backupPath)
		return fmt.Errorf("部署失败（已回滚）: %w", deployErr)
	}

	return deployErr
}

// bindSiteToCert 绑定站点到证书
// 流程：查找站点 → 域名匹配校验 → SSL 安装（如需） → 保存绑定
func bindSiteToCert(ctx context.Context, cfgManager *config.ConfigManager, cert *config.CertConfig, siteName string, f *fetcher.Fetcher, skipConfirm bool) error {
	// 1. 从扫描结果查找站点（优先，包含域名等完整信息）
	site, binding, err := findSiteForBinding(cfgManager, siteName)
	if err != nil {
		return err
	}

	// 2. 域名匹配校验（仅扫描结果中有域名信息时）
	if site != nil && len(cert.Domains) > 0 {
		m := matcher.New(cert.Domains)
		domains := append([]string{site.ServerName}, site.ServerAlias...)
		result := m.Match(domains)

		switch result.Type {
		case config.MatchTypeFull:
			// 完全匹配，无需提示
		case config.MatchTypePartial:
			fmt.Printf("  域名部分匹配:\n")
			fmt.Printf("    匹配: %s\n", strings.Join(result.MatchedDomains, ", "))
			fmt.Printf("    未覆盖: %s\n", strings.Join(result.MissedDomains, ", "))
		case config.MatchTypeNone:
			fmt.Printf("  警告: 域名不匹配\n")
			fmt.Printf("    证书域名: %s\n", strings.Join(cert.Domains, ", "))
			siteDomains := site.ServerName
			if len(site.ServerAlias) > 0 {
				siteDomains += ", " + strings.Join(site.ServerAlias, ", ")
			}
			fmt.Printf("    站点域名: %s\n", siteDomains)
			if !skipConfirm && !confirmAction("  是否继续绑定?") {
				return fmt.Errorf("已取消")
			}
		}
	}

	// 3. 站点未启用 SSL 时安装 HTTPS 配置
	if site != nil && site.CertificatePath == "" {
		fmt.Printf("  站点 %s 未启用 SSL，正在安装 HTTPS 配置...\n", siteName)
		if err := installSSLForSite(ctx, site, binding, cfgManager, cert, f); err != nil {
			return fmt.Errorf("安装 SSL 配置失败: %w", err)
		}
		// 更新内存中的站点状态，防止后续逻辑重复判断为未启用 SSL
		site.CertificatePath = binding.Paths.Certificate
	}

	// 4. 更新或添加绑定（用 binding.ServerName 匹配，避免重复追加）
	updated := false
	for i := range cert.Bindings {
		if cert.Bindings[i].ServerName == binding.ServerName {
			cert.Bindings[i] = *binding
			updated = true
			break
		}
	}
	if !updated {
		cert.Bindings = append(cert.Bindings, *binding)
	}

	// AddCert 会自动移除其他证书中对同一站点的绑定
	if err := cfgManager.AddCert(cert); err != nil {
		return fmt.Errorf("保存配置失败: %w", err)
	}

	fmt.Printf("已绑定站点: %s -> %s\n", siteName, cert.CertName)
	return nil
}

// findSiteForBinding 查找站点信息用于绑定
// 优先从扫描结果获取（包含域名等完整信息），回退到已有配置
func findSiteForBinding(cfgManager *config.ConfigManager, siteName string) (*config.ScannedSite, *config.SiteBinding, error) {
	// 优先从扫描结果
	scanResult, _ := config.LoadScanResult()
	if scanResult != nil {
		if site := scanResult.FindSiteByServerName(siteName); site != nil {
			binding := buildBindingFromScanResult(site, cfgManager)
			return site, binding, nil
		}
	}

	// 回退到已有配置（站点已部署过，跳过域名匹配和 SSL 检查）
	binding, err := cfgManager.GetSiteBinding(siteName)
	if err != nil {
		return nil, nil, fmt.Errorf("站点 %s 未找到，请先运行 'sslctl scan'", siteName)
	}
	return nil, binding, nil
}

// installSSLForSite 为未启用 SSL 的站点安装 HTTPS 配置
// 需要先写入证书文件，否则 nginx -t / apachectl -t 会失败
func installSSLForSite(ctx context.Context, site *config.ScannedSite, binding *config.SiteBinding, cfgManager *config.ConfigManager, cert *config.CertConfig, f *fetcher.Fetcher) error {
	if config.IsDockerCopyBinding(binding) {
		return fmt.Errorf("容器 copy 仅支持已有 HTTPS 配置的站点")
	}
	// 获取证书数据
	api := cert.GetAPI(nil)
	if api.URL == "" || api.Token == "" {
		return fmt.Errorf("证书 API 配置不完整")
	}
	certData, renewBeforeDays, err := f.QueryOrder(ctx, api.URL, api.Token, cert.OrderID)
	if err != nil {
		return fmt.Errorf("获取证书失败: %w", err)
	}
	applyDeployRenewBeforeDays(cfgManager, nil, renewBeforeDays)
	if certData.Status != config.OrderStatusActive || certData.Cert == "" {
		return fmt.Errorf("证书未就绪: status=%s", certData.Status)
	}

	// 获取私钥（pending 感知，配对校验）
	privateKey, err := certops.GetPrivateKeyForCert(ctx, cfgManager.GetWorkDir(), cert, certData.Cert, certData.PrivateKey, nil)
	if err != nil {
		return err
	}

	// 写入证书和私钥文件（安装 SSL 配置前必须存在）
	certDir := filepath.Dir(binding.Paths.Certificate)
	if err := util.EnsureDir(certDir, 0700); err != nil {
		return fmt.Errorf("创建证书目录失败: %w", err)
	}

	fullchain := certData.Cert
	if certData.IntermediateCert != "" {
		fullchain += "\n" + certData.IntermediateCert
	}
	if err := util.AtomicWrite(binding.Paths.Certificate, []byte(fullchain), 0644); err != nil {
		return fmt.Errorf("写入证书失败: %w", err)
	}
	if err := util.AtomicWrite(binding.Paths.PrivateKey, []byte(privateKey), 0600); err != nil {
		return fmt.Errorf("写入私钥失败: %w", err)
	}

	// 安装 SSL 配置
	serverType := detectServerType(site)
	var testCmd string
	if serverType == config.ServerTypeApache {
		testCmd = webserver.DetectApacheCommands().TestCmd
	} else {
		testCmd = webserver.DetectNginxCommandsFor(site.ExecutablePath).TestCmd
	}

	installer, err := webserver.NewInstaller(
		webserver.ServerType(serverType),
		site.ConfigFile,
		binding.Paths.Certificate,
		binding.Paths.PrivateKey,
		"", // fullchain 模式
		site.ServerName,
		testCmd,
	)
	if err != nil {
		return err
	}

	result, err := installer.Install()
	if err != nil {
		return err
	}
	if result.Modified {
		fmt.Printf("    SSL 配置已安装（备份: %s）\n", result.BackupPath)
	}
	return nil
}

// confirmAction 确认提示
func confirmAction(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s [Y/n]: ", prompt)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	response = strings.ToLower(strings.TrimSpace(response))
	return response != "n" && response != "no"
}

// runLocal 运行本地证书部署子命令
func runLocal(args []string, debug bool) {
	fs := flag.NewFlagSet("deploy local", flag.ExitOnError)
	certFile := fs.String("cert", "", "证书文件路径")
	keyFile := fs.String("key", "", "私钥文件路径")
	caFile := fs.String("ca", "", "CA 证书链文件路径（Apache 需要）")
	siteName := fs.String("site", "", "目标站点名称")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: sslctl deploy local --cert <file> --key <file> --site <name>\n")
		fmt.Fprintf(os.Stderr, "      sslctl deploy local --cert <file> --key <file> --ca <file> --site <name>\n\n")
		fmt.Fprintf(os.Stderr, "从本地文件部署证书到指定站点。\n\n")
		fmt.Fprintf(os.Stderr, "选项:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\n示例:\n")
		fmt.Fprintf(os.Stderr, "  sslctl deploy local --cert cert.pem --key key.pem --site example.com\n")
		fmt.Fprintf(os.Stderr, "  sslctl deploy local --cert cert.pem --key key.pem --ca chain.pem --site apache-site.com\n")
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	// 验证必需参数
	if *certFile == "" || *keyFile == "" || *siteName == "" {
		fmt.Fprintln(os.Stderr, "错误: --cert, --key, --site 参数是必需的")
		fs.Usage()
		os.Exit(1)
	}

	// 初始化配置管理器
	cfgManager, err := config.NewConfigManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "初始化失败: %v\n", err)
		os.Exit(1)
	}

	// 初始化日志
	logDir := cfgManager.GetLogsDir()
	if debug {
		logDir = filepath.Join(logDir, "debug")
	}

	log, err := logger.New(logDir, "deploy-local")
	if err != nil {
		fmt.Fprintf(os.Stderr, "创建日志失败: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = log.Close() }()

	if debug {
		log.SetLevel(logger.LevelDebug)
	}

	// 与守护进程共享续签互斥锁，避免手动部署与自动续签并发操作同一证书目录与配置
	release, acquired, lockErr := config.AcquireRenewalLock(cfgManager.GetWorkDir())
	if lockErr != nil {
		log.Warn("%v，继续执行", lockErr)
	} else if !acquired {
		fmt.Fprintln(os.Stderr, "守护进程正在续签（或另一部署进程正在运行），请稍后再试")
		os.Exit(1)
	} else {
		defer release()
	}

	// 验证并读取证书文件（支持软链接并限制大小）
	const maxCertFileSize = 1 << 20 // 1MB
	certData, err := util.ReadCertificateFile(*certFile, maxCertFileSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取证书文件失败: %v\n", err)
		os.Exit(1)
	}

	// 验证并读取私钥文件
	keyData, err := util.ReadCertificateFile(*keyFile, maxCertFileSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取私钥文件失败: %v\n", err)
		os.Exit(1)
	}

	// 读取 CA 证书文件（可选）
	var caData string
	if *caFile != "" {
		ca, err := util.ReadCertificateFile(*caFile, maxCertFileSize)
		if err != nil {
			fmt.Fprintf(os.Stderr, "读取 CA 证书文件失败: %v\n", err)
			os.Exit(1)
		}
		caData = string(ca)
	}

	certPEM := string(certData)
	keyPEM := string(keyData)

	// 验证证书
	v := validator.New("")
	if _, err := v.ValidateCert(certPEM); err != nil {
		fmt.Fprintf(os.Stderr, "证书验证失败: %v\n", err)
		os.Exit(1)
	}

	// 验证私钥
	if err := v.ValidateKey(keyPEM); err != nil {
		fmt.Fprintf(os.Stderr, "私钥验证失败: %v\n", err)
		os.Exit(1)
	}

	// 验证证书和私钥匹配
	if err := v.ValidateCertKeyPair(certPEM, keyPEM); err != nil {
		fmt.Fprintf(os.Stderr, "证书和私钥不匹配: %v\n", err)
		os.Exit(1)
	}

	// 验证 CA 证书（如果提供）
	if caData != "" {
		if err := v.ValidateCA(caData); err != nil {
			fmt.Fprintf(os.Stderr, "CA 证书验证失败: %v\n", err)
			os.Exit(1)
		}
	}

	// 从配置获取站点绑定（优先从 config.json，回退到 scan-result.json）
	binding, err := getSiteBindingForLocal(cfgManager, *siteName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "获取站点配置失败: %v\n", err)
		fmt.Fprintf(os.Stderr, "提示: 请先运行 'sslctl scan' 扫描站点\n")
		os.Exit(1)
	}

	// 检查站点是否启用
	if !binding.Enabled {
		fmt.Fprintf(os.Stderr, "错误: 站点 %s 已被禁用\n", binding.ServerName)
		os.Exit(1)
	}

	// 检查 Apache 是否需要 CA 证书（仅当配置了 ChainFile 时才要求）
	if isApacheType(binding.ServerType) && binding.Paths.ChainFile != "" && caData == "" {
		fmt.Fprintf(os.Stderr, "错误: Apache 站点已配置证书链路径，需要提供 --ca 参数\n")
		os.Exit(1)
	}

	fmt.Printf("部署本地证书到站点: %s (%s)\n", binding.ServerName, binding.ServerType)

	// 构造 CertData 并部署
	certDataStruct := &fetcher.CertData{
		Cert:             certPEM,
		IntermediateCert: caData,
	}

	backupMgr := backup.NewManager(cfgManager.GetBackupDir(), 5)
	// CLI 单次操作：无上游 deadline，由 executor 的单命令上限兜底
	if err := deployToBinding(context.Background(), binding, certDataStruct, keyPEM, backupMgr, log); err != nil {
		fmt.Fprintf(os.Stderr, "部署失败: %v\n", err)
		os.Exit(1)
	}

	// 部署成功后记录到配置文件
	localCertName := fmt.Sprintf("local-%s", *siteName)
	localCertConfig := &config.CertConfig{
		CertName:  localCertName,
		RenewMode: config.RenewModeLocal,
		Enabled:   true,
		Bindings:  []config.SiteBinding{*binding},
	}

	// 从证书中提取域名和过期时间
	if parsedCert, parseErr := v.ValidateCert(certPEM); parseErr == nil {
		localCertConfig.Metadata.CertExpiresAt = parsedCert.NotAfter
		localCertConfig.Metadata.CertSerial = fmt.Sprintf("%X", parsedCert.SerialNumber)
		// 补齐 Domains：优先 DNSNames，回退 CN（避免续签时因缺少域名无法生成 CSR）
		if len(parsedCert.DNSNames) > 0 {
			localCertConfig.Domains = parsedCert.DNSNames
		} else if parsedCert.Subject.CommonName != "" {
			localCertConfig.Domains = []string{parsedCert.Subject.CommonName}
		}
	}
	localCertConfig.Metadata.LastDeployAt = time.Now()

	if err := cfgManager.AddCert(localCertConfig); err != nil {
		fmt.Fprintf(os.Stderr, "警告: 保存配置失败: %v\n", err)
	} else {
		fmt.Printf("配置已保存: %s (证书名: %s)\n", cfgManager.GetConfigPath(), localCertName)
	}

	fmt.Println("部署成功")
}

// isApacheType 判断是否为 Apache 类型服务器
func isApacheType(serverType string) bool {
	return strings.HasPrefix(serverType, "apache") || strings.HasSuffix(serverType, "-apache")
}

// getSiteBindingForLocal 获取站点绑定（用于 deploy local）
// 优先从 config.json 的证书绑定中查找，回退到 scan-result.json
func getSiteBindingForLocal(cfgManager *config.ConfigManager, siteName string) (*config.SiteBinding, error) {
	// 1. 优先从 config.json 的证书绑定中查找
	binding, err := cfgManager.GetSiteBinding(siteName)
	if err == nil {
		return binding, nil
	}

	// 2. 回退到 scan-result.json
	scanResult, err := config.LoadScanResult()
	if err != nil {
		return nil, fmt.Errorf("站点未找到，且无法加载扫描结果: %w", err)
	}

	site := scanResult.FindSiteByServerName(siteName)
	if site == nil {
		return nil, fmt.Errorf("站点 %s 不存在于配置或扫描结果中", siteName)
	}

	// 3. 从扫描结果构造绑定
	return buildBindingFromScanResult(site, cfgManager), nil
}

// buildBindingFromScanResult 从扫描结果构造站点绑定
func buildBindingFromScanResult(site *config.ScannedSite, cfgManager *config.ConfigManager) *config.SiteBinding {
	// 确定服务器类型（多重判断提高准确性）
	serverType := detectServerType(site)

	// 确定证书路径
	certPath := site.CertificatePath
	keyPath := site.PrivateKeyPath
	if site.VolumeMode && site.HostCertPath != "" {
		certPath = site.HostCertPath
	}
	if site.VolumeMode && site.HostKeyPath != "" {
		keyPath = site.HostKeyPath
	}

	// 如果扫描结果没有证书路径，使用默认路径
	if certPath == "" {
		certPath = config.GetDefaultCertPath(site.ServerName)
	}
	if keyPath == "" {
		keyPath = config.GetDefaultKeyPath(site.ServerName)
	}

	binding := &config.SiteBinding{
		ServerName: site.ServerName,
		ServerType: serverType,
		Enabled:    true,
		Paths: config.BindingPaths{
			Certificate: certPath,
			PrivateKey:  keyPath,
			ConfigFile:  site.ConfigFile,
			Webroot:     site.Webroot,
		},
	}

	// Apache：保留扫描到的 ChainFile 路径（已有 SSLCertificateChainFile 的站点）
	// 新站点 ChainFilePath 为空，使用 fullchain 模式。
	// Docker 卷模式必须用宿主机链路径，否则会把证书链写到容器内路径（宿主机错误位置）。
	if site.VolumeMode && site.HostChainPath != "" {
		binding.Paths.ChainFile = site.HostChainPath
	} else if site.ChainFilePath != "" {
		binding.Paths.ChainFile = site.ChainFilePath
	}

	// Docker 站点添加信息
	isDocker := config.IsDockerType(serverType)
	if isDocker {
		// 仅当卷模式且已解析出宿主机路径时，才算可通过宿主机写入部署（volume）
		deployMode := "copy"
		if site.VolumeMode && site.HostCertPath != "" {
			deployMode = "volume"
		}
		binding.Docker = &config.DockerInfo{
			ContainerName: site.ContainerName,
			DeployMode:    deployMode,
		}
	}

	// 添加默认重载命令（根据系统环境动态检测）
	var cmds webserver.ServerCommands
	switch {
	case isDocker:
		cmds = webserver.DetectDockerCommands(webserver.ServerType(serverType), site.ContainerName)
	case serverType == config.ServerTypeNginx:
		cmds = webserver.DetectNginxCommandsFor(site.ExecutablePath)
	case serverType == config.ServerTypeApache:
		cmds = webserver.DetectApacheCommands()
	}
	if cmds.TestCmd != "" {
		binding.Reload = config.ReloadConfig{
			TestCommand:   cmds.TestCmd,
			ReloadCommand: cmds.ReloadCmd,
		}
	}

	return binding
}

// detectServerType 检测服务器类型（多重判断提高准确性）
func detectServerType(site *config.ScannedSite) string {
	isDocker := site.Source == "docker"

	// 1. 通过配置文件内容特征判断（如果可读）
	if site.ConfigFile != "" {
		const maxConfigSize int64 = 10 << 20 // 10MB
		if content, err := util.SafeReadFile(site.ConfigFile, maxConfigSize); err == nil {
			contentStr := string(content)
			// Apache 特征指令
			if strings.Contains(contentStr, "<VirtualHost") ||
				strings.Contains(contentStr, "SSLCertificateFile") ||
				strings.Contains(contentStr, "SSLCertificateKeyFile") {
				if isDocker {
					return config.ServerTypeDockerApache
				}
				return config.ServerTypeApache
			}
			// Nginx 特征指令
			if strings.Contains(contentStr, "server {") ||
				strings.Contains(contentStr, "ssl_certificate") ||
				strings.Contains(contentStr, "ssl_certificate_key") {
				if isDocker {
					return config.ServerTypeDockerNginx
				}
				return config.ServerTypeNginx
			}
		}
	}

	// 2. 回退到路径关键词判断
	configPath := strings.ToLower(site.ConfigFile)
	if strings.Contains(configPath, "apache") || strings.Contains(configPath, "httpd") {
		if isDocker {
			return config.ServerTypeDockerApache
		}
		return config.ServerTypeApache
	}

	// 3. 默认为 Nginx
	if isDocker {
		return config.ServerTypeDockerNginx
	}
	return config.ServerTypeNginx
}
