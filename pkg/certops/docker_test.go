package certops

import (
	"context"
	stderrors "errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/internal/nginx/docker"
	"github.com/zhuxbo/sslctl/pkg/backup"
	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
	"github.com/zhuxbo/sslctl/testdata/certs"
	"github.com/zhuxbo/sslctl/testdata/testutil"
)

func copyBinding(f *testutil.DockerCLI) *config.SiteBinding {
	return &config.SiteBinding{
		ServerName: "test.example.com", ServerType: config.ServerTypeDockerNginx, Enabled: true,
		Docker: &config.DockerInfo{ContainerName: "web", DeployMode: "copy"},
		Paths:  config.BindingPaths{Certificate: f.CertPath, PrivateKey: f.KeyPath},
		Reload: config.ReloadConfig{TestCommand: "docker exec web nginx -t", ReloadCommand: "docker exec web nginx -s reload"},
	}
}

func TestDeployDockerCopyUsesContainerAndPersistsBackup(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	oldCert, err := certs.GenerateValidCert("test.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	newCert, err := certs.GenerateValidCert("test.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	f.WritePair(t, oldCert.CertPEM, oldCert.KeyPEM)
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(cm, logger.NewNopLogger())
	if err := svc.DeployToBinding(t.Context(), copyBinding(f), &fetcher.CertData{Cert: newCert.CertPEM}, newCert.KeyPEM); err != nil {
		t.Fatal(err)
	}
	f.AssertPair(t, newCert.CertPEM, newCert.KeyPEM)
	loaded, err := os.ReadFile(filepath.Join(f.Dir, "loaded-cert"))
	if err != nil || string(loaded) != newCert.CertPEM {
		t.Fatal("未在目标容器中重载新证书")
	}
	backupPath, err := svc.backupMgr.GetLatestBackup("test.example.com")
	if err != nil {
		t.Fatal(err)
	}
	backupKey, err := os.ReadFile(filepath.Join(backupPath, "key.pem"))
	if err != nil || string(backupKey) != oldCert.KeyPEM {
		t.Fatal("未持久备份容器原私钥")
	}
	trace, err := os.ReadFile(f.Trace)
	if err != nil || !strings.Contains(string(trace), "exec fixture-id sh -c nginx -s reload") || strings.Contains(string(trace), "exec web ") {
		t.Fatal("单次部署未固定到解析后的容器 ID")
	}
}

func TestDeployDockerCopyFailuresRestoreOriginalFiles(t *testing.T) {
	for _, failure := range []string{"TEST_DOCKER_FAIL_CP", "TEST_DOCKER_FAIL_TEST", "TEST_DOCKER_FAIL_RELOAD"} {
		t.Run(failure, func(t *testing.T) {
			f := testutil.NewDockerCLI(t)
			oldCert, err := certs.GenerateValidCert("test.example.com", nil)
			if err != nil {
				t.Fatal(err)
			}
			newCert, err := certs.GenerateValidCert("test.example.com", nil)
			if err != nil {
				t.Fatal(err)
			}
			f.WritePair(t, oldCert.CertPEM, oldCert.KeyPEM)
			value := "1"
			if failure == "TEST_DOCKER_FAIL_CP" {
				value = "2"
			}
			t.Setenv(failure, value)
			cm, err := config.NewConfigManagerWithDir(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			svc := NewService(cm, logger.NewNopLogger())
			if err := svc.DeployToBinding(t.Context(), copyBinding(f), &fetcher.CertData{Cert: newCert.CertPEM}, newCert.KeyPEM); err == nil {
				t.Fatal("失败不能被报为部署成功")
			} else {
				var exitErr *exec.ExitError
				if !stderrors.As(err, &exitErr) {
					t.Fatalf("回滚成功后必须保留部署的命令失败原因: %v", err)
				}
			}
			f.AssertPair(t, oldCert.CertPEM, oldCert.KeyPEM)
			loaded, err := os.ReadFile(filepath.Join(f.Dir, "loaded-cert"))
			if err != nil || string(loaded) != oldCert.CertPEM {
				t.Fatal("回滚后应重新加载旧证书")
			}
		})
	}
}

func TestDeployDockerCopyReadOnlyFailsBeforeWriting(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	f.WritePair(t, "old-cert", "old-key")
	t.Setenv("TEST_DOCKER_INFO", f.ReadOnlyMountJSON())
	newCert, err := certs.GenerateValidCert("test.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(cm, logger.NewNopLogger())
	if err := svc.DeployToBinding(t.Context(), copyBinding(f), &fetcher.CertData{Cert: newCert.CertPEM}, newCert.KeyPEM); err == nil {
		t.Fatal("只读挂载不能写入")
	}
	if versions, err := svc.backupMgr.ListBackups("test.example.com"); err != nil || len(versions) != 0 {
		t.Fatalf("只读预检必须在创建备份前停止: %v %v", versions, err)
	}
	f.AssertPair(t, "old-cert", "old-key")
}

func TestDockerCopyPrivateKeyAndManualRollback(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	oldPair, err := certs.GenerateExpiredCert("test.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	newPair, err := certs.GenerateValidCert("test.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	f.WritePair(t, oldPair.CertPEM, oldPair.KeyPEM)
	if err := os.Chmod(f.KeyPath, 0640); err != nil {
		t.Fatal(err)
	}
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	binding := copyBinding(f)
	cert := &config.CertConfig{CertName: "copy-test", Bindings: []config.SiteBinding{*binding}}
	key, err := GetPrivateKeyForCert(t.Context(), cm.GetWorkDir(), cert, oldPair.CertPEM, "", nil)
	if err != nil || key != oldPair.KeyPEM {
		t.Fatalf("读取容器私钥失败: %v", err)
	}
	if err := savePendingKey(cm.GetWorkDir(), cert.CertName, newPair.KeyPEM); err != nil {
		t.Fatal(err)
	}
	key, err = GetPrivateKeyForCert(t.Context(), cm.GetWorkDir(), cert, newPair.CertPEM, "", nil)
	if err != nil || key != newPair.KeyPEM {
		t.Fatalf("pending 私钥匹配失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())
	if err := svc.DeployToBinding(t.Context(), binding, &fetcher.CertData{Cert: newPair.CertPEM}, key); err != nil {
		t.Fatal(err)
	}
	CommitPendingKeyIfMatches(cm.GetWorkDir(), cert, key, nil)
	if _, err := readPendingKey(cm.GetWorkDir(), cert.CertName); !stderrors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending 未清理: %v", err)
	}
	backupPath, err := svc.backupMgr.GetLatestBackup(binding.ServerName)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := svc.backupMgr.LoadMetadata(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := RestoreDockerBackup(t.Context(), svc.backupMgr, backupPath, meta); err != nil {
		t.Fatal(err)
	}
	f.AssertPair(t, oldPair.CertPEM, oldPair.KeyPEM)
	info, err := os.Stat(f.KeyPath)
	if err != nil || info.Mode().Perm() != 0640 {
		t.Fatalf("回滚未恢复私钥权限: %v, %v", info, err)
	}
	loaded, err := os.ReadFile(filepath.Join(f.Dir, "loaded-cert"))
	if err != nil || string(loaded) != oldPair.CertPEM {
		t.Fatal("手动回滚未加载旧证书")
	}
}

func TestDockerCopyDoesNotUseHostWebroot(t *testing.T) {
	binding := copyBinding(&testutil.DockerCLI{})
	binding.Paths.Webroot = t.TempDir()
	cert := &config.CertConfig{Bindings: []config.SiteBinding{*binding}}
	if roots := collectWebroots(cert); len(roots) != 0 {
		t.Fatal("不能把容器 webroot 用作宿主机路径")
	}
}

func TestDockerCopyMixedBindingPendingDoesNotRewriteFailedHost(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	oldPair, err := certs.GenerateValidCert("test.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	newPair, err := certs.GenerateValidCert("test.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	f.WritePair(t, newPair.CertPEM, newPair.KeyPEM)
	hostKey := filepath.Join(t.TempDir(), "host.key")
	if err := os.WriteFile(hostKey, []byte(oldPair.KeyPEM), 0600); err != nil {
		t.Fatal(err)
	}
	cert := &config.CertConfig{CertName: "mixed", Bindings: []config.SiteBinding{
		{Enabled: true, ServerType: config.ServerTypeNginx, Paths: config.BindingPaths{PrivateKey: hostKey}},
		*copyBinding(f),
	}}
	workDir := t.TempDir()
	if err := savePendingKey(workDir, cert.CertName, newPair.KeyPEM); err != nil {
		t.Fatal(err)
	}
	CommitPendingKeyIfMatches(workDir, cert, newPair.KeyPEM, nil)
	host, err := os.ReadFile(hostKey)
	if err != nil || string(host) != oldPair.KeyPEM {
		t.Fatal("pending 清理不能重写部署失败绑定的私钥")
	}
	key, err := GetPrivateKeyForCert(t.Context(), workDir, cert, newPair.CertPEM, "", nil)
	if err != nil || key != newPair.KeyPEM {
		t.Fatalf("应从已成功部署的容器绑定读取配对私钥: %v", err)
	}
}

func TestDockerCopyPreflightAndRecoveryErrors(t *testing.T) {
	for _, failure := range []string{"invalid-cert", "expired-cert", "wrong-key", "invalid-binding", "inspect", "missing-cert", "missing-key", "backup", "temporary", "rollback"} {
		t.Run(failure, func(t *testing.T) {
			f := testutil.NewDockerCLI(t)
			pair, err := certs.GenerateValidCert("test.example.com", nil)
			if err != nil {
				t.Fatal(err)
			}
			f.WritePair(t, "old-cert", "old-key")
			cm, err := config.NewConfigManagerWithDir(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			svc := NewService(cm, logger.NewNopLogger())
			binding := copyBinding(f)
			data, key := &fetcher.CertData{Cert: pair.CertPEM}, pair.KeyPEM
			switch failure {
			case "invalid-cert":
				data.Cert = "invalid-certificate"
			case "expired-cert":
				expired, err := certs.GenerateExpiredCert("test.example.com", nil)
				if err != nil {
					t.Fatal(err)
				}
				data.Cert, key = expired.CertPEM, expired.KeyPEM
			case "wrong-key":
				key = "invalid-private-key"
			case "invalid-binding":
				binding.Reload.TestCommand = "invalid command"
			case "inspect":
				t.Setenv("TEST_DOCKER_INSPECT_FAIL", "1")
			case "missing-cert":
				if err := os.Remove(f.CertPath); err != nil {
					t.Fatal(err)
				}
			case "missing-key":
				if err := os.Remove(f.KeyPath); err != nil {
					t.Fatal(err)
				}
			case "backup":
				if err := os.RemoveAll(cm.GetBackupDir()); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(cm.GetBackupDir(), []byte("not-directory"), 0600); err != nil {
					t.Fatal(err)
				}
			case "temporary":
				t.Setenv("TMPDIR", filepath.Join(f.Dir, "missing"))
			case "rollback":
				t.Setenv("TEST_DOCKER_FAIL_TEST", "1")
				t.Setenv("TEST_DOCKER_FAIL_RELOAD", "1")
			}
			err = svc.DeployToBinding(t.Context(), binding, data, key)
			if err == nil {
				t.Fatal("错误必须阻止成功结果")
			}
			wantMessage := map[string]string{
				"invalid-cert": "证书验证失败", "expired-cert": "证书验证失败",
				"wrong-key": "私钥不匹配", "invalid-binding": "容器绑定无效",
				"missing-cert": "读取容器现有证书失败", "missing-key": "读取容器现有私钥失败",
				"backup": "备份容器证书失败",
			}[failure]
			if wantMessage != "" && !strings.Contains(err.Error(), wantMessage) {
				t.Fatalf("必须在对应阶段停止，期望 %q，得到 %v", wantMessage, err)
			}
			if strings.HasPrefix(failure, "missing-") {
				var exitErr *exec.ExitError
				if !stderrors.As(err, &exitErr) {
					t.Fatalf("必须保留容器读取错误: %v", err)
				}
			}
			if failure == "temporary" {
				var pathErr *os.PathError
				if !stderrors.As(err, &pathErr) || !stderrors.Is(err, os.ErrNotExist) || !strings.Contains(pathErr.Path, filepath.Join(f.Dir, "missing")) {
					t.Fatalf("必须保留临时目录创建错误: %v", err)
				}
			}
			if failure != "rollback" {
				trace, readErr := os.ReadFile(f.Trace)
				if readErr != nil && !stderrors.Is(readErr, os.ErrNotExist) {
					t.Fatal(readErr)
				}
				if strings.Contains("\n"+string(trace), "\ncp ") || strings.Contains(string(trace), "nginx -s reload") {
					t.Fatal("预检失败不能复制文件或重载服务")
				}
			}
			if failure == "rollback" && (!strings.Contains(err.Error(), "回滚失败") || !strings.Contains(err.Error(), cm.GetBackupDir())) {
				t.Fatalf("回滚失败应提供持久备份位置: %v", err)
			}
			if !strings.HasPrefix(failure, "missing-") {
				f.AssertPair(t, "old-cert", "old-key")
			}
		})
	}
}

func TestDockerCopyPrivateKeyFailuresAndPendingRetention(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	f.WritePair(t, "old-cert", "old-key")
	binding := copyBinding(f)
	if _, err := ReadBindingPrivateKey(t.Context(), nil); err == nil {
		t.Fatal("缺少绑定应失败")
	}
	t.Setenv("TEST_DOCKER_INSPECT_FAIL", "1")
	if _, err := ReadBindingPrivateKey(t.Context(), binding); err == nil {
		t.Fatal("不能忽略容器探测失败")
	}
	t.Setenv("TEST_DOCKER_INSPECT_FAIL", "")
	cert := &config.CertConfig{CertName: "retained", Bindings: []config.SiteBinding{*binding}}
	workDir := t.TempDir()
	if err := savePendingKey(workDir, cert.CertName, "pending-key"); err != nil {
		t.Fatal(err)
	}
	CommitPendingKeyIfMatches(workDir, cert, "pending-key", logger.NewNopLogger())
	if key, err := readPendingKey(workDir, cert.CertName); err != nil || key != "pending-key" {
		t.Fatalf("未确认部署时应保留 pending: %v", err)
	}
	f.AssertPair(t, "old-cert", "old-key")
	cert.Bindings[0].Enabled = false
	if key, err := GetPrivateKey(t.Context(), cert, "", nil); err != nil || key != "old-key" {
		t.Fatalf("没有启用绑定时保留原有回退取钥行为: %v", err)
	}
}

func TestDockerCopyCancellationStillRestoresAndReloads(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	pair, err := certs.GenerateValidCert("test.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	f.WritePair(t, "old-cert", "old-key")
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(cm, logger.NewNopLogger())
	t.Setenv("TEST_DOCKER_WAIT_CP", "2")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	reachedCopy := make(chan bool, 1)
	go func() {
		deadline := time.NewTimer(5 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				if _, err := os.Stat(filepath.Join(f.Dir, "cp-blocked")); err == nil {
					reachedCopy <- true
					cancel()
					return
				}
			case <-deadline.C:
				reachedCopy <- false
				cancel()
				return
			case <-ctx.Done():
				reachedCopy <- false
				return
			}
		}
	}()
	err = svc.DeployToBinding(ctx, copyBinding(f), &fetcher.CertData{Cert: pair.CertPEM}, pair.KeyPEM)
	if !<-reachedCopy {
		t.Fatal("未进入复制阶段，不能证明取消后回滚")
	}
	if err == nil || !strings.Contains(err.Error(), "已回滚") {
		t.Fatalf("取消后仍须用独立预算回滚: %v", err)
	}
	f.AssertPair(t, "old-cert", "old-key")
	loaded, err := os.ReadFile(filepath.Join(f.Dir, "loaded-cert"))
	if err != nil || string(loaded) != "old-cert" {
		t.Fatal("取消后未重新加载旧证书")
	}
}

func TestMixedPrivateKeySkipsDisabledBindings(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	pair, err := certs.GenerateValidCert("test.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	f.WritePair(t, pair.CertPEM, pair.KeyPEM)
	hostKey := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(hostKey, []byte("wrong-key"), 0600); err != nil {
		t.Fatal(err)
	}
	binding := copyBinding(f)
	binding.Enabled = false
	cert := &config.CertConfig{CertName: "mixed-disabled", Bindings: []config.SiteBinding{
		{Enabled: true, ServerType: config.ServerTypeNginx, Paths: config.BindingPaths{PrivateKey: hostKey}},
		*binding,
		{Enabled: true, ServerType: config.ServerTypeDockerNginx, Docker: &config.DockerInfo{ContainerName: "web", DeployMode: "copy"}, Paths: config.BindingPaths{PrivateKey: filepath.Join(f.Dir, "missing-key")}},
	}}
	if key, err := GetPrivateKeyForCert(t.Context(), t.TempDir(), cert, pair.CertPEM, "", nil); err == nil || key != "" {
		t.Fatal("禁用绑定的配对私钥不能被选为候选")
	}
	cert.Bindings[1].Enabled = true
	if key, err := GetPrivateKeyForCert(t.Context(), t.TempDir(), cert, pair.CertPEM, "", nil); err != nil || key != pair.KeyPEM {
		t.Fatalf("启用的配对候选应可用于恢复: %v", err)
	}
}

func TestBindingPrivateKeySelectionAndReadErrors(t *testing.T) {
	file := filepath.Join(t.TempDir(), "missing-key")
	cert := &config.CertConfig{Bindings: []config.SiteBinding{
		{Enabled: true},
		{Enabled: false, Paths: config.BindingPaths{PrivateKey: "disabled"}},
		{Enabled: true, Paths: config.BindingPaths{PrivateKey: file}},
	}}
	if pickKeyBinding(&config.CertConfig{}) != nil {
		t.Fatal("空证书配置不应选择绑定")
	}
	var pathErr *os.PathError
	if _, err := GetPrivateKey(t.Context(), cert, "", nil); !stderrors.Is(err, os.ErrNotExist) || !stderrors.As(err, &pathErr) || pathErr.Path != file {
		t.Fatalf("应选择启用且含路径的绑定并保留读取错误: %v", err)
	}
	if _, err := GetPrivateKey(t.Context(), &config.CertConfig{}, "", nil); err == nil || !strings.Contains(err.Error(), "缺少私钥路径") {
		t.Fatalf("无绑定时应报告缺少路径: %v", err)
	}
	f := testutil.NewDockerCLI(t)
	f.WritePair(t, "cert", "key")
	binding := copyBinding(f)
	binding.Paths.PrivateKey = filepath.Join(f.Dir, "missing-key")
	var exitErr *exec.ExitError
	if _, err := ReadBindingPrivateKey(t.Context(), binding); !stderrors.As(err, &exitErr) {
		t.Fatalf("必须保留容器内读取失败: %v", err)
	}
}

func TestRestoreDockerBackupRejectsIncompleteSnapshot(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	f.WritePair(t, "current-cert", "current-key")
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(cm, logger.NewNopLogger())
	dir := t.TempDir()
	for _, existingCert := range []bool{false, true} {
		if existingCert {
			if err := os.WriteFile(filepath.Join(dir, "cert.pem"), []byte("snapshot"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		// 元数据尚未使用；缺失的证书或私钥快照必须先被拒绝。
		if err := RestoreDockerBackup(t.Context(), svc.backupMgr, dir, nil); !stderrors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), "failed to lstat file") {
			t.Fatalf("必须保留快照读取失败: %v", err)
		}
	}
	f.AssertPair(t, "current-cert", "current-key")
	if _, err := os.Stat(f.Trace); !stderrors.Is(err, os.ErrNotExist) {
		t.Fatal("快照不完整不能调用容器")
	}
}

func TestDisabledDockerBindingDoesNotEnableCopyKeyFlow(t *testing.T) {
	cert := &config.CertConfig{Bindings: []config.SiteBinding{{ServerType: config.ServerTypeDockerNginx, Docker: &config.DockerInfo{DeployMode: "copy"}}}}
	if hasDockerCopyBinding(cert) {
		t.Fatal("禁用的 copy 绑定不能触发容器取钥及 pending 清理流程")
	}
	cert.Bindings[0].Enabled = true
	if !hasDockerCopyBinding(cert) {
		t.Fatal("启用的 copy 绑定应触发容器私钥流程")
	}
}

func TestPrivateKeyBuffersAreCleared(t *testing.T) {
	for _, value := range []string{"", "private-key-payload"} {
		data := []byte(value)
		if got := consumePrivateKey(data); got != value {
			t.Fatal("清零不能改变已返回的私钥内容")
		}
		if strings.Trim(string(data), "\x00") != "" {
			t.Fatal("取钥后原始缓冲区必须清零")
		}
		for _, expected := range []string{value, "different"} {
			data := []byte(value)
			if got := matchPrivateKeyAndClear(data, expected); got != (value == expected) {
				t.Fatal("清零前的配对结果错误")
			}
			if strings.Trim(string(data), "\x00") != "" {
				t.Fatal("比较成功或失败后均须清零")
			}
		}
	}
}

func TestContainerSnapshotFailuresStopDeployment(t *testing.T) {
	for _, phase := range []string{"write", "chmod", "restore-write", "restore-chmod", "stat"} {
		t.Run(phase, func(t *testing.T) {
			f := testutil.NewDockerCLI(t)
			pair, err := certs.GenerateValidCert("test.example.com", nil)
			if err != nil {
				t.Fatal(err)
			}
			f.WritePair(t, pair.CertPEM, pair.KeyPEM)
			cm, err := config.NewConfigManagerWithDir(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			svc := NewService(cm, nil)
			originalWrite, originalChmod, originalStat := containerWriteFile, containerChmod, containerStat
			t.Cleanup(func() { containerWriteFile, containerChmod, containerStat = originalWrite, originalChmod, originalStat })
			fault := &os.PathError{Op: phase, Path: "snapshot", Err: os.ErrPermission}
			restore := strings.HasPrefix(phase, "restore-")
			selected := func(p string) bool { return strings.HasPrefix(filepath.Base(p), "restore-") == restore }
			if strings.HasSuffix(phase, "write") {
				containerWriteFile = func(p string, b []byte, mode os.FileMode) error {
					if selected(p) {
						return fault
					}
					return originalWrite(p, b, mode)
				}
			}
			if strings.HasSuffix(phase, "chmod") {
				containerChmod = func(p string, mode os.FileMode) error {
					if selected(p) {
						return fault
					}
					return originalChmod(p, mode)
				}
			}
			if phase == "stat" {
				containerStat = func(string) (os.FileInfo, error) { return nil, fault }
			}
			var got error
			if restore || phase == "stat" {
				backupPath := t.TempDir()
				if err := os.WriteFile(filepath.Join(backupPath, "cert.pem"), []byte(pair.CertPEM), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(backupPath, "key.pem"), []byte(pair.KeyPEM), 0600); err != nil {
					t.Fatal(err)
				}
				got = RestoreDockerBackup(t.Context(), svc.backupMgr, backupPath, &backup.Metadata{ServerName: "test.example.com", ContainerName: "web", CertPath: f.CertPath, KeyPath: f.KeyPath})
			} else {
				got = DeployDockerCopy(t.Context(), copyBinding(f), &fetcher.CertData{Cert: pair.CertPEM}, pair.KeyPEM, svc.backupMgr, nil)
			}
			if !stderrors.Is(got, fault) {
				t.Fatalf("必须保留快照阶段错误: %v", got)
			}
			trace, _ := os.ReadFile(f.Trace)
			if strings.Contains(string(trace), "cp ") || strings.Contains(string(trace), "nginx -") {
				t.Fatalf("快照失败后仍然写入或重载: %s", trace)
			}
			f.AssertPair(t, pair.CertPEM, pair.KeyPEM)
		})
	}
}

func TestCopyPendingCleanupAndLogs(t *testing.T) {
	for _, state := range []string{"confirmed", "unconfirmed", "cleanup-error", "disabled-first", "disabled-first-confirmed"} {
		t.Run(state, func(t *testing.T) {
			f := testutil.NewDockerCLI(t)
			f.WritePair(t, "certificate", "deployed-key")
			workDir := t.TempDir()
			cert := &config.CertConfig{CertName: "pending-test", Bindings: []config.SiteBinding{*copyBinding(f)}}
			if state == "unconfirmed" {
				f.WritePair(t, "certificate", "old-key")
			}
			if strings.HasPrefix(state, "disabled-first") {
				disabled := config.SiteBinding{Enabled: false, Paths: config.BindingPaths{PrivateKey: filepath.Join(t.TempDir(), "key")}}
				if err := os.WriteFile(disabled.Paths.PrivateKey, []byte("deployed-key"), 0600); err != nil {
					t.Fatal(err)
				}
				cert.Bindings = append([]config.SiteBinding{disabled}, cert.Bindings...)
				if state == "disabled-first" {
					f.WritePair(t, "certificate", "old-key")
				}
			}
			if err := savePendingKey(workDir, cert.CertName, "deployed-key"); err != nil {
				t.Fatal(err)
			}
			if state == "cleanup-error" {
				if err := os.WriteFile(filepath.Join(filepath.Dir(getPendingKeyPath(workDir, cert.CertName)), "keep"), []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			logDir := t.TempDir()
			log, err := logger.New(logDir, "test")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = log.Close() }()
			log.SetLevel(logger.LevelDebug)
			CommitPendingKeyIfMatches(workDir, cert, "deployed-key", log)
			contents, err := os.ReadFile(filepath.Join(logDir, "test-"+time.Now().Format("2006-01-02")+".log"))
			if err != nil {
				t.Fatal(err)
			}
			got := string(contents)
			if state == "cleanup-error" {
				if !strings.Contains(got, "清理 pending 私钥失败") {
					t.Fatalf("清理失败缺少告警: %s", got)
				}
			} else if state == "unconfirmed" || state == "disabled-first" {
				if !strings.Contains(got, "正式私钥尚未确认，保留 pending 私钥") {
					t.Fatalf("未确认缺少告警: %s", got)
				}
				if key, err := readPendingKey(workDir, cert.CertName); err != nil || key != "deployed-key" {
					t.Fatal("未确认不能清理 pending")
				}
			} else {
				if strings.Contains(got, "WARN") {
					t.Fatalf("成功时不应告警: %s", got)
				}
				if _, err := readPendingKey(workDir, cert.CertName); !stderrors.Is(err, os.ErrNotExist) {
					t.Fatalf("跳过禁用项后应确认并清理 pending: %v", err)
				}
			}
			if strings.Contains(got, "deployed-key") {
				t.Fatal("日志泄漏私钥")
			}
		})
	}
}

func TestCopyKeyLogsAndRejectsOtherMismatchedBindings(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	first, err := certs.GenerateValidCert("first.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := certs.GenerateValidCert("second.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	target, err := certs.GenerateValidCert("target.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	f.WritePair(t, first.CertPEM, first.KeyPEM)
	hostKey := filepath.Join(t.TempDir(), "host-key")
	if err := os.WriteFile(hostKey, []byte(second.KeyPEM), 0600); err != nil {
		t.Fatal(err)
	}
	cert := &config.CertConfig{CertName: "mixed", Bindings: []config.SiteBinding{*copyBinding(f), {Enabled: true, Paths: config.BindingPaths{PrivateKey: hostKey}}}}
	logDir := t.TempDir()
	log, err := logger.New(logDir, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	log.SetLevel(logger.LevelDebug)
	if key, err := GetPrivateKeyForCert(t.Context(), t.TempDir(), cert, target.CertPEM, "", log); err == nil || key != "" {
		t.Fatal("不得返回其他绑定中不匹配的私钥")
	}
	contents, err := os.ReadFile(filepath.Join(logDir, "test-"+time.Now().Format("2006-01-02")+".log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), "使用绑定私钥: "+f.KeyPath) || strings.Contains(string(contents), first.KeyPEM) {
		t.Fatal("日志必须标识来源路径且不泄漏私钥")
	}
	trace, _ := os.ReadFile(f.Trace)
	if got := strings.Count(string(trace), "head -c"); got != 1 {
		t.Fatalf("已经读取的正式绑定不应重复读取: %d", got)
	}
}

func TestDockerCopyCleanupWarning(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("权限错误需要非 root 用户")
	}
	for _, withLog := range []bool{false, true} {
		t.Run(fmt.Sprint(withLog), func(t *testing.T) {
			f := testutil.NewDockerCLI(t)
			pair, err := certs.GenerateValidCert("test.example.com", nil)
			if err != nil {
				t.Fatal(err)
			}
			f.WritePair(t, pair.CertPEM, pair.KeyPEM)
			backupDir := t.TempDir()
			old := filepath.Join(backupDir, "test.example.com", "20000101_000000")
			if err := os.MkdirAll(old, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(old, "keep"), []byte("old"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(old, 0500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(old, 0700) })
			var log *logger.Logger
			logDir := t.TempDir()
			if withLog {
				log, err = logger.New(logDir, "test")
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = log.Close() }()
			}
			if err := DeployDockerCopy(t.Context(), copyBinding(f), &fetcher.CertData{Cert: pair.CertPEM}, pair.KeyPEM, backup.NewManager(backupDir, 1), log); err != nil {
				t.Fatal(err)
			}
			if withLog {
				contents, err := os.ReadFile(filepath.Join(logDir, "test-"+time.Now().Format("2006-01-02")+".log"))
				if err != nil || !strings.Contains(string(contents), "清理旧容器备份失败") {
					t.Fatalf("清理失败必须告警: %s %v", contents, err)
				}
			}
			f.AssertPair(t, pair.CertPEM, pair.KeyPEM)
		})
	}
}

func TestDockerSnapshotBuffersAreCleared(t *testing.T) {
	files := [2]docker.ContainerFile{{Data: []byte("certificate")}, {Data: []byte("private-key")}}
	clearDockerSnapshots(&files)
	for _, f := range files {
		if strings.Trim(string(f.Data), "\x00") != "" {
			t.Fatal("恢复后快照缓冲区必须清零")
		}
	}
}

func TestPendingCleanupFailureWithoutLogger(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	f.WritePair(t, "certificate", "deployed-key")
	workDir := t.TempDir()
	cert := &config.CertConfig{CertName: "pending", Bindings: []config.SiteBinding{*copyBinding(f)}}
	if err := savePendingKey(workDir, cert.CertName, "deployed-key"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(getPendingKeyPath(workDir, cert.CertName)), "keep"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	CommitPendingKeyIfMatches(workDir, cert, "deployed-key", nil)
	if _, err := os.Stat(getPendingKeyPath(workDir, cert.CertName)); !stderrors.Is(err, os.ErrNotExist) {
		t.Fatal("删除目录失败不能影响已确认私钥的清理")
	}
}

func TestDockerCopySuccessDoesNotWarnAboutCleanup(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	pair, err := certs.GenerateValidCert("test.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	f.WritePair(t, pair.CertPEM, pair.KeyPEM)
	logDir := t.TempDir()
	log, err := logger.New(logDir, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	if err := DeployDockerCopy(t.Context(), copyBinding(f), &fetcher.CertData{Cert: pair.CertPEM}, pair.KeyPEM, backup.NewManager(t.TempDir(), 5), log); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filepath.Join(logDir, "test-"+time.Now().Format("2006-01-02")+".log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), "清理旧容器备份失败") {
		t.Fatalf("成功时不能误报清理故障: %s", contents)
	}
}
