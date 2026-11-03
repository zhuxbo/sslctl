package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zhuxbo/sslctl/pkg/backup"
	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/testdata/certs"
	"github.com/zhuxbo/sslctl/testdata/testutil"
)

type rollbackExitCode int

func captureRollback(t *testing.T, cm *config.ConfigManager, args []string, rootErr, configErr error) (string, int) {
	t.Helper()
	oldRoot, oldManager, oldExit := rollbackCheckRoot, rollbackNewConfigManager, rollbackExit
	rollbackCheckRoot = func() error { return rootErr }
	rollbackNewConfigManager = func() (*config.ConfigManager, error) { return cm, configErr }
	rollbackExit = func(code int) { panic(rollbackExitCode(code)) }
	t.Cleanup(func() { rollbackCheckRoot, rollbackNewConfigManager, rollbackExit = oldRoot, oldManager, oldExit })
	output, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = output, output
	defer func() { os.Stdout, os.Stderr = oldOut, oldErr; _ = output.Close() }()
	code := 0
	func() {
		defer func() {
			if value := recover(); value != nil {
				if exit, ok := value.(rollbackExitCode); ok {
					code = int(exit)
				} else {
					panic(value)
				}
			}
		}()
		runRollback(args)
	}()
	data, err := os.ReadFile(output.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(data), code
}

func TestRollbackCommandRejectsBeforeRestoring(t *testing.T) {
	for _, failure := range []string{"site", "privilege", "config", "missing", "metadata", "locked", "list"} {
		t.Run(failure, func(t *testing.T) {
			cm, err := config.NewConfigManagerWithDir(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"--site", "site"}
			var rootErr, configErr error
			want := "回滚失败"
			switch failure {
			case "site":
				args = nil
				want = "用法"
			case "privilege":
				rootErr = errors.New("no privilege")
				want = "no privilege"
			case "config":
				configErr = errors.New("no configuration")
				want = "初始化配置失败"
			case "metadata":
				dir := filepath.Join(cm.GetBackupDir(), "site", "version")
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--version", "version")
				want = "读取备份失败"
			case "list":
				if err := os.WriteFile(filepath.Join(cm.GetBackupDir(), "site"), []byte("not-directory"), 0600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--list")
				want = "获取备份列表失败"
			case "locked":
				release, acquired, err := config.AcquireRenewalLock(cm.GetWorkDir())
				if err != nil || !acquired {
					t.Fatalf("lock: %v", err)
				}
				defer release()
				want = "正在续签"
			}
			output, code := captureRollback(t, cm, args, rootErr, configErr)
			if (failure == "site" || failure == "privilege" || failure == "config" || failure == "locked") && strings.Contains(output, "正在回滚") {
				t.Fatal("前置失败不能继续回滚")
			}
			if failure == "missing" && strings.Contains(output, "读取备份失败") {
				t.Fatal("解析备份路径失败不能继续读取元数据")
			}
			if code != 1 || !strings.Contains(output, want) {
				t.Fatalf("错误出口: code=%d output=%s", code, output)
			}
		})
	}
}

func TestRollbackCommandRoutesContainerAndHost(t *testing.T) {
	for _, container := range []bool{false, true} {
		t.Run(map[bool]string{false: "host", true: "container"}[container], func(t *testing.T) {
			f := testutil.NewDockerCLI(t)
			old, err := certs.GenerateValidCert("site", nil)
			if err != nil {
				t.Fatal(err)
			}
			f.WritePair(t, old.CertPEM, old.KeyPEM)
			cm, err := config.NewConfigManagerWithDir(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			mgr := backup.NewManager(cm.GetBackupDir(), 5)
			var result *backup.BackupResult
			if container {
				result, err = mgr.BackupContainer("site", "web", f.CertPath, f.KeyPath, f.CertPath, f.KeyPath)
			} else {
				result, err = mgr.Backup("site", f.CertPath, f.KeyPath, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			// 固定为历史版本，避免与恢复前当前秒创建的备份重名。
			historical := filepath.Join(cm.GetBackupDir(), "site", "20000101_000000")
			if err := os.Rename(result.BackupPath, historical); err != nil {
				t.Fatal(err)
			}
			result.BackupPath = historical
			f.WritePair(t, "current-cert", "current-key")
			output, code := captureRollback(t, cm, []string{"--site", "site", "--version", filepath.Base(result.BackupPath)}, nil, nil)
			if code != 0 {
				t.Fatalf("回滚失败: %s", output)
			}
			f.AssertPair(t, old.CertPEM, old.KeyPEM)
			if !strings.Contains(output, "文件恢复完成") {
				t.Fatalf("缺少恢复结果: %s", output)
			}
			if container {
				if !strings.Contains(output, "容器 web 已通过配置检查并重载") || strings.Contains(output, "请重载") {
					t.Fatalf("容器回滚必须自行重载: %s", output)
				}
				loaded, err := os.ReadFile(filepath.Join(f.Dir, "loaded-key"))
				if err != nil || string(loaded) != old.KeyPEM {
					t.Fatal("容器未重载备份私钥")
				}
			} else if _, err := os.Stat(f.Trace); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("宿主机备份不得调用 Docker")
			}
		})
	}
}

func TestRollbackCommandReturnsRestoreFailure(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	pair, err := certs.GenerateValidCert("site", nil)
	if err != nil {
		t.Fatal(err)
	}
	f.WritePair(t, pair.CertPEM, pair.KeyPEM)
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mgr := backup.NewManager(cm.GetBackupDir(), 5)
	result, err := mgr.BackupContainer("site", "web", f.CertPath, f.KeyPath, f.CertPath, f.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(result.BackupPath, "key.pem")); err != nil {
		t.Fatal(err)
	}
	output, code := captureRollback(t, cm, []string{"--site", "site"}, nil, nil)
	if code != 1 || !strings.Contains(output, "回滚失败") || strings.Contains(output, "文件恢复完成") {
		t.Fatalf("不能把不完整备份报为成功: %d %s", code, output)
	}
	f.AssertPair(t, pair.CertPEM, pair.KeyPEM)
}
