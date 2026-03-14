//go:build !linux

package util

// RestoreFileContext 非 Linux 平台空实现
func RestoreFileContext(path string) error {
	return nil
}
