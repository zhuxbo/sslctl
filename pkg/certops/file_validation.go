// Package certops 文件验证支持
package certops

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
	"github.com/zhuxbo/sslctl/pkg/util"
)

// placeValidationFiles 将验证文件写入所有可用的 webroot
// 返回已写入的文件绝对路径列表
func placeValidationFiles(cert *config.CertConfig, file *fetcher.FileChallenge, log *logger.Logger) []string {
	if file == nil || file.Path == "" || file.Content == "" {
		return nil
	}

	// 收集所有已启用绑定的 webroot（去重）
	webroots := collectWebroots(cert)
	if len(webroots) == 0 {
		log.Warn("证书 %s 没有可用的 webroot，无法放置验证文件", cert.CertName)
		return nil
	}

	var placed []string
	for _, webroot := range webroots {
		fullPath, err := placeFileInWebroot(webroot, file, log)
		if err != nil {
			log.Warn("证书 %s 写入验证文件到 %s 失败: %v", cert.CertName, webroot, err)
			continue
		}
		placed = append(placed, fullPath)
		log.Info("证书 %s 验证文件已写入: %s", cert.CertName, fullPath)
	}

	return placed
}

// collectWebroots 从证书绑定中收集去重的 webroot 列表
func collectWebroots(cert *config.CertConfig) []string {
	seen := make(map[string]bool)
	var webroots []string
	for _, binding := range cert.Bindings {
		if !binding.Enabled || binding.Paths.Webroot == "" || config.IsDockerCopyBinding(&binding) {
			continue
		}
		if seen[binding.Paths.Webroot] {
			continue
		}
		seen[binding.Paths.Webroot] = true
		webroots = append(webroots, binding.Paths.Webroot)
	}
	return webroots
}

// placeFileInWebroot 将验证文件写入指定 webroot
func placeFileInWebroot(webroot string, file *fetcher.FileChallenge, log *logger.Logger) (string, error) {
	// 规范 3.6：验证文件路径必须位于 .well-known/ 下
	cleanPath := strings.TrimPrefix(file.Path, "/")
	if !strings.HasPrefix(cleanPath, ".well-known/") {
		return "", fmt.Errorf("验证文件路径必须位于 .well-known/ 下: %s", file.Path)
	}
	// 安全路径拼接（防目录穿越）
	fullPath, err := util.JoinUnderDir(webroot, file.Path)
	if err != nil {
		return "", err
	}

	// 检查 webroot 目录是否存在
	if _, err := os.Stat(webroot); err != nil {
		return "", err
	}

	// 确保父目录存在（如 .well-known/pki-validation/）
	parentDir := filepath.Dir(fullPath)
	if err := util.EnsureDir(parentDir, 0755); err != nil {
		return "", err
	}

	// 安全写入验证文件（HTTP 服务需要读取权限，使用 0644）
	if err := util.AtomicWrite(fullPath, []byte(file.Content), 0644); err != nil {
		return "", err
	}

	return fullPath, nil
}

// applyValidationFiles 放置验证文件并记录到证书元数据。
// 挑战存在但一个文件都未放置成功（无可用 webroot 或写入全部失败）时返回错误：
// 验证文件无法就位则签发永远不会完成，静默等待会让证书每天停在 pending 无人知晓。
// persist 为 true 时立即持久化元数据（调用方稍后自行保存时传 false）。
func (s *Service) applyValidationFiles(cert *config.CertConfig, file *fetcher.FileChallenge, persist bool) error {
	if file == nil {
		return nil
	}
	placed := placeValidationFiles(cert, file, s.log)
	if len(placed) == 0 {
		return fmt.Errorf("证书 %s 验证文件无法放置（无可用 webroot 或写入失败），文件验证无法完成，请检查绑定的 webroot 配置", cert.CertName)
	}
	cert.Metadata.ValidationFiles = placed
	if persist {
		if err := s.cfgManager.UpdateCert(cert); err != nil {
			s.log.Warn("持久化验证文件路径失败: %v", err)
		}
	}
	return nil
}

// cleanupValidationFiles 清理已放置的验证文件，返回仍未清理的路径。
func cleanupValidationFiles(files []string, log *logger.Logger) []string {
	var failed []string
	for _, f := range files {
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			log.Warn("清理验证文件 %s 失败: %v", f, err)
			failed = append(failed, f)
			continue
		}
		// 尝试删除空父目录（如 .well-known/pki-validation/）
		parentDir := filepath.Dir(f)
		_ = os.Remove(parentDir)
		// 尝试删除上层空目录（如 .well-known/）
		grandParentDir := filepath.Dir(parentDir)
		_ = os.Remove(grandParentDir)
	}
	return failed
}
