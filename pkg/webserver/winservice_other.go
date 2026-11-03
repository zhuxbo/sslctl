//go:build !windows

package webserver

import (
	"context"
	"errors"
)

// FindWebServerService 在非 Windows 平台始终返回空字符串。
func FindWebServerService(_, _ string) string { return "" }

func FindWebServerServiceForExecutable(_, _ string) string { return "" }

// RestartWindowsService 在非 Windows 平台不可用，调用即报错。
func RestartWindowsService(_ context.Context, _ string) error {
	return errors.New("RestartWindowsService is only available on windows")
}
