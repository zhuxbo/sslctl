// Package upgrade 升级执行逻辑
package upgrade

import (
	"fmt"

	"github.com/zhuxbo/sslctl/pkg/service"
)

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
	if logFunc == nil {
		logFunc = func(format string, args ...interface{}) {}
	}

	// 1. 获取远程版本信息
	logFunc("检查更新...")
	info, err := FetchReleaseInfo()
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

	// 4. 如果只是检查，返回结果
	if opts.CheckOnly {
		logFunc("\n有新版本可用，运行 'sslctl upgrade' 进行升级")
		return result, nil
	}

	// 5. 下载并安装
	logFunc("\n开始升级到 %s...", target)

	filename := GetDownloadFilename()
	downloadURL := GetDownloadURL(channel, target)

	logFunc("下载 %s...", filename)
	gzData, err := DownloadBinary(downloadURL)
	if err != nil {
		return nil, err
	}

	// 验证校验和
	expectedChecksum := info.GetChecksum(target, filename)
	if expectedChecksum != "" {
		logFunc("验证文件完整性...")
		if err := VerifyChecksum(gzData, expectedChecksum); err != nil {
			return nil, fmt.Errorf("文件完整性验证失败: %w", err)
		}
		logFunc("校验通过")
	}

	// 安装
	if _, err := Install(gzData); err != nil {
		return nil, err
	}
	logFunc("安装完成")

	// 6. 如果服务运行中，重启服务
	result.Restarted = tryRestartService(logFunc)

	logFunc("\n升级完成: %s → %s", current, target)
	return result, nil
}

// tryRestartService 尝试重启服务（如果运行中）
func tryRestartService(logFunc func(format string, args ...interface{})) bool {
	svcMgr, err := service.New(nil)
	if err != nil {
		return false
	}

	status, _ := svcMgr.Status()
	if status == nil || !status.Running {
		return false
	}

	logFunc("重启服务...")
	if err := svcMgr.Restart(); err != nil {
		logFunc("重启服务失败: %v", err)
		return false
	}

	logFunc("服务已重启")
	return true
}
