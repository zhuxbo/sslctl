// Package upgrade 升级执行逻辑
package upgrade

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/zhuxbo/sslctl/pkg/service"
)

// installFunc 安装函数，可在测试中替换
var installFunc = Install

// Options 升级选项
type Options struct {
	Channel        string // 更新通道 (main/dev)
	TargetVersion  string // 指定版本
	Force          bool   // 强制重新安装
	CheckOnly      bool   // 仅检查更新
	CurrentVersion string // 当前版本
	ReleaseURL     string // 发布地址（必需，从配置文件读取）
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
	// 统一处理末尾斜杠，避免拼接出错
	opts.ReleaseURL = strings.TrimRight(strings.TrimSpace(opts.ReleaseURL), "/")
	if opts.ReleaseURL == "" {
		return nil, fmt.Errorf("未配置升级地址，请运行 sslctl upgrade 在交互终端中输入，或使用安装脚本升级")
	}
	// 安全校验：强制 HTTPS
	if !strings.HasPrefix(opts.ReleaseURL, "https://") {
		return nil, fmt.Errorf("升级地址必须使用 HTTPS 协议")
	}
	return executeWithClient(opts, logFunc, opts.ReleaseURL+"/releases.json", secureHTTPClient())
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

	cmp := CompareVersions(target, current)
	result := &Result{
		FromVersion: current,
		ToVersion:   target,
		Channel:     channel,
		NeedUpgrade: cmp > 0 || opts.Force,
	}

	if !result.NeedUpgrade {
		if cmp < 0 {
			logFunc("当前版本高于远程版本，无需降级（如需降级请使用 --force）")
		} else {
			logFunc("已是最新版本")
		}
		return result, nil
	}

	baseURL := strings.TrimSuffix(releaseURL, "/releases.json")
	// 从 baseURL 提取域名+路径部分（去掉 https:// 前缀和 /sslctl 后缀）
	hostPath := strings.TrimPrefix(baseURL, "https://")
	hostPath = strings.TrimSuffix(hostPath, "/sslctl")
	installHint := fmt.Sprintf("curl -fsSL %s/install.sh | sudo bash -s -- %s", baseURL, hostPath)

	// 4. 如果只是检查，返回结果
	if opts.CheckOnly {
		logFunc("\n有新版本可用，运行 'sslctl upgrade' 进行升级")
		return result, nil
	}

	// 6. 下载并安装
	if err := downloadVerifyInstall(target, channel, info, logFunc, client, baseURL, installHint); err != nil {
		return nil, err
	}

	// 7. 如果服务运行中，重启服务
	result.Restarted = tryRestartService(logFunc)

	logFunc("\n升级完成: %s → %s", current, target)
	return result, nil
}

// validChannels 允许的发布通道白名单
var validChannels = map[string]bool{"main": true, "dev": true}

// downloadVerifyInstall 下载、验证签名/校验和、安装
// baseURL 为下载基础 URL，格式如 https://release.cnssl.com/sslctl
// installHint 为重新安装提示命令
func downloadVerifyInstall(target, channel string, info *ReleaseInfo, logFunc func(format string, args ...interface{}), client *http.Client, baseURL, installHint string) error {
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
		var noPublicKeys *ErrNoPublicKeys
		if errors.As(err, &keyNotFound) || errors.As(err, &noPublicKeys) {
			return fmt.Errorf("签名密钥已更新，请重新安装以获取最新版本:\n  %s", installHint)
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
