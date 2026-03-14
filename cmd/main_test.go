package main

import (
	"os"
	"strings"
	"testing"

	"github.com/zhuxbo/sslctl/pkg/config"
)

func TestResolveReleaseURL_FromConfig_TrimsAndSaves(t *testing.T) {
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir error: %v", err)
	}

	cfg, err := cm.Load()
	if err != nil {
		t.Fatalf("Load config error: %v", err)
	}

	cfg.ReleaseURL = "https://localhost/"
	releaseURL, err := resolveReleaseURL(cm, cfg)
	if err != nil {
		t.Fatalf("resolveReleaseURL error: %v", err)
	}
	if releaseURL != "https://localhost" {
		t.Fatalf("releaseURL = %q, want %q", releaseURL, "https://localhost")
	}

	// 确认已保存为去尾斜杠的值
	cfg2, err := cm.Load()
	if err != nil {
		t.Fatalf("Load config error: %v", err)
	}
	if cfg2.ReleaseURL != "https://localhost" {
		t.Fatalf("saved releaseURL = %q, want %q", cfg2.ReleaseURL, "https://localhost")
	}
}

func TestResolveReleaseURL_NonTerminalError(t *testing.T) {
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir error: %v", err)
	}

	cfg, err := cm.Load()
	if err != nil {
		t.Fatalf("Load config error: %v", err)
	}

	// 强制进入需要交互输入的分支
	cfg.ReleaseURL = ""

	// 使用管道替换 stdin，确保非交互终端
	oldStdin := os.Stdin
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe error: %v", err)
	}
	os.Stdin = reader
	t.Cleanup(func() {
		os.Stdin = oldStdin
		_ = reader.Close()
		_ = writer.Close()
	})

	_, err = resolveReleaseURL(cm, cfg)
	if err == nil {
		t.Fatal("expected error for non-terminal stdin")
	}
	if !strings.Contains(err.Error(), "交互终端") {
		t.Fatalf("unexpected error: %v", err)
	}
}
