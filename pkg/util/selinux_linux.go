//go:build linux

package util

import (
	"fmt"
	"os/exec"
	"strings"
)

// RestoreFileContext 恢复文件的 SELinux 安全上下文
// 仅在 SELinux 为 Enforcing 模式且 restorecon 可用时执行
// 命令不存在或 SELinux 未启用时静默跳过
func RestoreFileContext(path string) error {
	// 检查 getenforce 是否可用
	getenforce, err := exec.LookPath("getenforce")
	if err != nil {
		return nil // getenforce 不存在，SELinux 未安装
	}

	// 检查 SELinux 是否为 Enforcing 模式
	output, err := exec.Command(getenforce).Output()
	if err != nil {
		return nil // 执行失败，静默跳过
	}

	mode := strings.TrimSpace(string(output))
	if mode != "Enforcing" {
		return nil // 非 Enforcing 模式，无需恢复上下文
	}

	// 检查 restorecon 是否可用
	restorecon, err := exec.LookPath("restorecon")
	if err != nil {
		return nil // restorecon 不存在，静默跳过
	}

	// 恢复文件安全上下文
	if err := exec.Command(restorecon, "-v", path).Run(); err != nil {
		return fmt.Errorf("restorecon failed for %s: %w", path, err)
	}
	return nil
}
