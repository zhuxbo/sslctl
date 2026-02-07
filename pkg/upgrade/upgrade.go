// Package upgrade 升级执行逻辑
package upgrade

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/zhuxbo/sslctl/pkg/service"
)

// 链式升级常量
const (
	maxUpgradeDepth    = 5                      // 链式升级最大步数
	upgradeDepthEnvKey = "SSLCTL_UPGRADE_DEPTH" // 环境变量：当前升级步数
)

// execFunc 进程替换函数，可在测试中替换
var execFunc = defaultExecFunc

// installFunc 安装函数，可在测试中替换
var installFunc = Install

// Options 升级选项
type Options struct {
	Channel        string // 更新通道 (stable/dev)
	TargetVersion  string // 指定版本
	Force          bool   // 强制重新安装
	CheckOnly      bool   // 仅检查更新
	CurrentVersion string // 当前版本
}

// Result 升级结果
type Result struct {
	FromVersion string // 升级前版本
	ToVersion   string // 升级后版本
	Channel     string // 使用的通道
	Restarted   bool   // 是否重启了服务
	NeedUpgrade bool   // 是否需要升级
}

// Execute 执行升级
// 返回升级结果和日志回调（用于输出进度信息）
func Execute(opts Options, logFunc func(format string, args ...interface{})) (*Result, error) {
	return executeWithClient(opts, logFunc, ReleaseURL+"/releases.json", secureHTTPClient())
}

// executeWithClient 内部实现，接受 URL 和 client 参数（便于测试）
func executeWithClient(opts Options, logFunc func(format string, args ...interface{}), releaseURL string, client *http.Client) (*Result, error) {
	if logFunc == nil {
		logFunc = func(format string, args ...interface{}) {}
	}

	// 1. 获取远程版本信息
	logFunc("检查更新...")
	info, err := fetchReleaseInfoFrom(releaseURL, client)
	if err != nil {
		return nil, err
	}

	// 2. 确定目标版本和通道
	target, channel, err := ResolveTarget(opts.TargetVersion, opts.Channel, info)
	if err != nil {
		return nil, err
	}

	// 3. 比较版本
	current := NormalizeVersion(opts.CurrentVersion)
	logFunc("当前版本: %s", current)
	logFunc("最新版本: %s (%s)", target, channel)

	result := &Result{
		FromVersion: current,
		ToVersion:   target,
		Channel:     channel,
		NeedUpgrade: current != target || opts.Force,
	}

	if !result.NeedUpgrade {
		logFunc("已是最新版本")
		return result, nil
	}

	// 4. 检查最低客户端版本（密钥轮换等场景）
	baseURL := strings.TrimSuffix(releaseURL, "/releases.json")
	if info.MinClientVersion != "" && CompareVersions(current, info.MinClientVersion) < 0 {
		// CheckOnly 模式下不执行链式升级或下载，仅返回提示
		if opts.CheckOnly {
			if len(info.UpgradePath) > 0 {
				return result, fmt.Errorf("当前版本 %s 过旧（要求最低 %s），需要链式升级，请运行 'sslctl upgrade' 或重新安装:\n  curl -fsSL https://sslctl-cn.cnssl.com/install.sh | sudo bash",
					current, NormalizeVersion(info.MinClientVersion))
			}
			return result, fmt.Errorf("当前版本 %s 过旧（要求最低 %s），请重新安装:\n  curl -fsSL https://sslctl-cn.cnssl.com/install.sh | sudo bash",
				current, NormalizeVersion(info.MinClientVersion))
		}

		// 尝试链式升级
		if len(info.UpgradePath) > 0 {
			return nil, tryChainUpgrade(current, opts, info, logFunc, releaseURL, client, baseURL)
		}
		return nil, fmt.Errorf("当前版本 %s 过旧（要求最低 %s），请重新安装:\n  curl -fsSL https://sslctl-cn.cnssl.com/install.sh | sudo bash",
			current, NormalizeVersion(info.MinClientVersion))
	}

	// 5. 如果只是检查，返回结果
	if opts.CheckOnly {
		logFunc("\n有新版本可用，运行 'sslctl upgrade' 进行升级")
		return result, nil
	}

	// 6. 下载并安装
	if err := downloadVerifyInstall(target, channel, info, logFunc, client, baseURL); err != nil {
		return nil, err
	}

	// 7. 如果服务运行中，重启服务
	result.Restarted = tryRestartService(logFunc)

	logFunc("\n升级完成: %s → %s", current, target)
	return result, nil
}

// validChannels 允许的发布通道白名单
var validChannels = map[string]bool{"stable": true, "dev": true}

// downloadVerifyInstall 下载、验证签名/校验和、安装
// baseURL 为下载基础 URL，格式如 https://sslctl.cnssl.com
func downloadVerifyInstall(target, channel string, info *ReleaseInfo, logFunc func(format string, args ...interface{}), client *http.Client, baseURL string) error {
	// 安全校验：通道白名单（防止路径遍历）
	if !validChannels[channel] {
		return fmt.Errorf("不支持的发布通道: %s", channel)
	}

	logFunc("\n开始升级到 %s...", target)

	filename := GetDownloadFilename()
	downloadURL := fmt.Sprintf("%s/%s/%s/%s", baseURL, channel, target, filename)

	logFunc("下载 %s...", filename)
	var gzData []byte
	var err error
	if client != nil {
		gzData, err = downloadBinaryWithClient(downloadURL, client)
	} else {
		gzData, err = DownloadBinary(downloadURL)
	}
	if err != nil {
		return err
	}

	// 验证签名（优先于校验和，防止供应链攻击）
	// 降级攻击防护已在 VerifySignature 内部处理（空签名 + 已配置公钥 → 拒绝）
	expectedSignature := info.GetSignature(target, filename)
	logFunc("验证数字签名...")
	if err := VerifySignature(gzData, expectedSignature); err != nil {
		var keyNotFound *ErrKeyNotFound
		if errors.As(err, &keyNotFound) {
			return fmt.Errorf("签名密钥已更新，请重新安装以获取最新版本:\n  curl -fsSL https://sslctl-cn.cnssl.com/install.sh | sudo bash")
		}
		return fmt.Errorf("数字签名验证失败: %w", err)
	}
	logFunc("签名验证通过")

	// 验证校验和
	expectedChecksum := info.GetChecksum(target, filename)
	if expectedChecksum != "" {
		logFunc("验证文件完整性...")
		if err := VerifyChecksum(gzData, expectedChecksum); err != nil {
			return fmt.Errorf("文件完整性验证失败: %w", err)
		}
		logFunc("校验通过")
	}

	// 安装
	if _, err := installFunc(gzData); err != nil {
		return err
	}
	logFunc("安装完成")
	return nil
}

// tryChainUpgrade 尝试链式升级
// 在 upgrade_path 中找到第一个 > 当前版本的过渡版本，下载安装后用 syscall.Exec 替换进程
func tryChainUpgrade(current string, opts Options, info *ReleaseInfo, logFunc func(format string, args ...interface{}), releaseURL string, client *http.Client, baseURL string) error {
	// 检查升级深度
	depth := getUpgradeDepth()
	if depth >= maxUpgradeDepth {
		return fmt.Errorf("链式升级步数超过限制（%d），请重新安装:\n  curl -fsSL https://sslctl-cn.cnssl.com/install.sh | sudo bash", maxUpgradeDepth)
	}

	// 在 upgrade_path 中找第一个 > 当前版本的过渡版本
	var transitVersion string
	for _, v := range info.UpgradePath {
		v = NormalizeVersion(v)
		if CompareVersions(v, current) > 0 {
			transitVersion = v
			break
		}
	}

	if transitVersion == "" {
		return fmt.Errorf("当前版本 %s 过旧，无可用的过渡版本，请重新安装:\n  curl -fsSL https://sslctl-cn.cnssl.com/install.sh | sudo bash", current)
	}

	// 确定过渡版本的通道：含 - 为 dev，否则为 stable
	transitChannel := "stable"
	if strings.Contains(transitVersion, "-") {
		transitChannel = "dev"
	}
	if _, ok := info.Versions[transitVersion]; !ok {
		// 如果 Versions 中没有该版本信息，无法验证
		return fmt.Errorf("过渡版本 %s 缺少版本信息，请重新安装:\n  curl -fsSL https://sslctl-cn.cnssl.com/install.sh | sudo bash", transitVersion)
	}

	logFunc("链式升级: 先升级到过渡版本 %s（步骤 %d/%d）...", transitVersion, depth+1, maxUpgradeDepth)

	// 下载、验证并安装过渡版本
	if err := downloadVerifyInstall(transitVersion, transitChannel, info, logFunc, client, baseURL); err != nil {
		return fmt.Errorf("过渡版本 %s 安装失败: %w\n请重新安装:\n  curl -fsSL https://sslctl-cn.cnssl.com/install.sh | sudo bash", transitVersion, err)
	}

	logFunc("过渡版本 %s 安装完成，重新执行升级...", transitVersion)

	// 设置升级深度环境变量并用 syscall.Exec 替换进程
	if err := os.Setenv(upgradeDepthEnvKey, strconv.Itoa(depth+1)); err != nil {
		return fmt.Errorf("设置环境变量失败: %w", err)
	}

	binPath := GetBinaryPath()
	args := []string{binPath, "upgrade"}
	if opts.Channel != "" {
		args = append(args, "--channel", opts.Channel)
	}
	if opts.TargetVersion != "" {
		args = append(args, "--version", opts.TargetVersion)
	}
	if opts.Force {
		args = append(args, "--force")
	}
	return execFunc(binPath, args, os.Environ())
}

// getUpgradeDepth 获取当前链式升级深度
// 对非法值（非数字、负数）返回 maxUpgradeDepth，防止被绕过
func getUpgradeDepth() int {
	val := os.Getenv(upgradeDepthEnvKey)
	if val == "" {
		return 0
	}
	n, err := strconv.Atoi(val)
	if err != nil || n < 0 {
		return maxUpgradeDepth
	}
	return n
}

// tryRestartService 尝试优雅重启服务（如果运行中）
// 使用 Stop + 等待 + Start 代替 Restart，确保守护进程完成优雅退出
func tryRestartService(logFunc func(format string, args ...interface{})) bool {
	svcMgr, err := service.New(nil)
	if err != nil {
		return false
	}

	status, _ := svcMgr.Status()
	if status == nil || !status.Running {
		return false
	}

	logFunc("停止服务...")
	if err := svcMgr.Stop(); err != nil {
		logFunc("停止服务失败: %v", err)
		return false
	}

	// 等待服务完全停止（最多 30 秒）
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		st, _ := svcMgr.Status()
		if st == nil || !st.Running {
			break
		}
		time.Sleep(time.Second)
	}

	logFunc("启动服务...")
	if err := svcMgr.Start(); err != nil {
		logFunc("启动服务失败: %v", err)
		return false
	}

	logFunc("服务已重启")
	return true
}
