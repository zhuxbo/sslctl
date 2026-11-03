// Package deployer context 贯通的行为测试（P2-1）
package deployer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/pkg/util"
)

// TestReloadService_RespectsCanceledContext 上游取消必须能中断重载命令，
// 否则 daemon 收到 SIGTERM 后只能等强杀窗口耗尽。
func TestReloadService_RespectsCanceledContext(t *testing.T) {
	installCanceledCommandFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// 用白名单内的命令替身，确保走到 exec 而不是在路径查找阶段失败
	b := &Base{ReloadCommand: "nginx -s reload"}
	err := b.ReloadService(ctx)
	if err == nil {
		t.Fatal("已取消的 ctx 下 ReloadService 应返回错误")
	}
	// 必须是取消导致的失败，而不是"本机没装 nginx"之类的巧合
	if !errors.Is(err, context.Canceled) {
		t.Errorf("错误应源自 ctx 取消，实际: %v", err)
	}
}

// TestTestConfig_RespectsCanceledContext 配置测试同样受取消约束
func TestTestConfig_RespectsCanceledContext(t *testing.T) {
	installCanceledCommandFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	b := &Base{TestCommand: "nginx -t"}
	err := b.TestConfig(ctx)
	if err == nil {
		t.Fatal("已取消的 ctx 下 TestConfig 应返回错误")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("错误应源自 ctx 取消，实际: %v", err)
	}
}

// TestTestConfig_EmptyCommandIgnoresContext 空命令是无操作，
// 不应因 ctx 已取消而凭空造出失败
func TestTestConfig_EmptyCommandIgnoresContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	b := &Base{}
	if err := b.TestConfig(ctx); err != nil {
		t.Errorf("空 TestCommand 应直接返回 nil，实际 %v", err)
	}
}

// TestWaitForApacheReload_AbortsOnCanceledContext 等待新 worker 的轮询必须响应取消，
// 否则单个绑定就能占满 15 秒
func TestWaitForApacheReload_AbortsOnCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	err := waitForApacheReload(ctx, 1, map[int]struct{}{}, 15*time.Second)
	if err == nil {
		t.Fatal("已取消的 ctx 下应立即返回错误")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("耗时 %v，取消未能中断轮询", elapsed)
	}
}

// 已取消的命令不得启动；替身只提供可解析路径并留下执行痕迹。
func installCanceledCommandFixture(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	marker := filepath.Join(dir, "executed")
	if runtime.GOOS == "windows" {
		// 取消必须发生在启动之前；原生测试程序使路径解析不依赖宿主安装。
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(executable)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "nginx.exe"), data, 0700); err != nil {
			t.Fatal(err)
		}
	} else {
		script := "#!/bin/sh\necho executed > " + util.ShellQuote(marker) + "\n"
		if err := os.WriteFile(filepath.Join(dir, "nginx"), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Cleanup(func() {
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Errorf("取消后仍执行了命令替身: %v", err)
		}
	})
}
