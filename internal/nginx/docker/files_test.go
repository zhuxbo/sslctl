package docker

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/testdata/testutil"
)

func TestCopyStagesBothFilesBeforeReplacing(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	f.WritePair(t, "old-cert", "old-key")
	t.Setenv("TEST_DOCKER_FAIL_CP", "2")
	d := NewDeployer(NewClient("fixture-id"), DeployerOptions{CertPath: f.CertPath, KeyPath: f.KeyPath, DeployMode: "copy"})
	if err := d.deployToContainer(t.Context(), "new-cert", "new-key"); err == nil || !strings.Contains(err.Error(), "docker cp failed") {
		t.Fatal("第二个文件复制失败时应返回原始复制错误")
	}
	f.AssertPair(t, "old-cert", "old-key")
	matches, err := filepath.Glob(filepath.Join(f.Dir, ".sslctl-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("暂存文件未清理: %v, %v", matches, err)
	}
}

func TestCopyRejectsSymlinkTarget(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	f.WritePair(t, "old-cert", "old-key")
	link := filepath.Join(f.Dir, "linked-key.pem")
	if err := os.Symlink(f.KeyPath, link); err != nil {
		t.Fatal(err)
	}
	d := NewDeployer(NewClient("fixture-id"), DeployerOptions{CertPath: f.CertPath, KeyPath: link, DeployMode: "copy"})
	if err := d.deployToContainer(t.Context(), "new-cert", "new-key"); err == nil {
		t.Fatal("符号链接目标不应被覆盖")
	}
	f.AssertPair(t, "old-cert", "old-key")
}

func TestReadContainerFileBoundaries(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	f.WritePair(t, "certificate", "private-key")
	client, err := NewRunningClient(t.Context(), "web")
	if err != nil {
		t.Fatal(err)
	}
	file, err := client.ReadRegularFile(t.Context(), f.KeyPath, 11)
	if err != nil || string(file.Data) != "private-key" || file.Mode != 0600 {
		t.Fatalf("读取内容/权限错误: %v", err)
	}
	for _, size := range []int64{0, 10, 11 << 20} {
		if _, err := client.ReadRegularFile(t.Context(), f.KeyPath, size); err == nil {
			t.Fatalf("大小 %d 应拒绝", size)
		}
	}
	if _, err := client.ReadRegularFile(t.Context(), filepath.Join(f.Dir, "missing"), 100); err == nil {
		t.Fatal("缺失文件应拒绝")
	}
	if _, err := NewRunningClient(t.Context(), "bad;name"); err == nil {
		t.Fatal("无效容器名应拒绝")
	}
	t.Setenv("TEST_DOCKER_INFO", `[{"Id":"fixture-id","State":{"Running":false}}]`)
	if _, err := NewRunningClient(t.Context(), "web"); err == nil {
		t.Fatal("停止容器应拒绝")
	}
}

func TestCopyDeployAndRollbackPreservePairAndModes(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	f.WritePair(t, "old-cert", "old-key")
	d := NewDeployer(NewClient("fixture-id"), DeployerOptions{CertPath: f.CertPath, KeyPath: f.KeyPath, DeployMode: "copy"})
	if err := d.Deploy(t.Context(), "new-cert", "chain", "new-key"); err != nil {
		t.Fatal(err)
	}
	f.AssertPair(t, "new-cert\nchain", "new-key")
	for file, wantMode := range map[string]os.FileMode{f.CertPath: 0644, f.KeyPath: 0600} {
		info, err := os.Stat(file)
		if err != nil || info.Mode().Perm() != wantMode {
			t.Fatalf("证书部署权限错误: %v, %v", info, err)
		}
	}
	backupDir := t.TempDir()
	certFile, keyFile := filepath.Join(backupDir, "cert.pem"), filepath.Join(backupDir, "key.pem")
	if err := os.WriteFile(certFile, []byte("old-cert"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte("old-key"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyFile, 0640); err != nil {
		t.Fatal(err)
	}
	if err := d.Rollback(t.Context(), certFile, keyFile); err != nil {
		t.Fatal(err)
	}
	f.AssertPair(t, "old-cert", "old-key")
	info, err := os.Stat(f.KeyPath)
	if err != nil || info.Mode().Perm() != 0640 {
		t.Fatalf("回滚应恢复原权限: %v", err)
	}
	loaded, err := os.ReadFile(filepath.Join(f.Dir, "loaded-cert"))
	if err != nil || string(loaded) != "old-cert" {
		t.Fatal("回滚未重载旧证书")
	}
	if err := d.Rollback(t.Context(), filepath.Join(backupDir, "missing"), keyFile); err == nil {
		t.Fatal("缺失证书备份应拒绝")
	}
	if err := d.Rollback(t.Context(), certFile, filepath.Join(backupDir, "missing")); err == nil {
		t.Fatal("缺失私钥备份应拒绝")
	}
}

func TestCopyMountBoundaries(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	c := NewClient("fixture-id")
	cases := []struct {
		name      string
		mounts    []MountInfo
		paths     []string
		wantError bool
	}{
		{"writable-layer", nil, []string{f.CertPath, f.KeyPath}, false},
		{"named-volume", []MountInfo{{Type: "volume", Destination: f.Dir, RW: true}}, []string{f.CertPath, f.KeyPath}, false},
		{"directory-bind", []MountInfo{{Type: "bind", Destination: f.Dir, RW: true}}, []string{f.CertPath}, false},
		{"read-only", []MountInfo{{Type: "volume", Destination: f.Dir, RW: false}}, []string{f.KeyPath}, true},
		{"tmpfs", []MountInfo{{Type: "tmpfs", Destination: f.Dir, RW: true}}, []string{f.CertPath}, true},
		{"single-file", []MountInfo{{Type: "bind", Destination: f.CertPath, RW: true}}, []string{f.CertPath}, true},
		{"root-read-only", []MountInfo{{Type: "bind", Destination: "/", RW: false}}, []string{f.KeyPath}, true},
		{"nested-read-only", []MountInfo{{Type: "bind", Destination: "/", RW: true}, {Type: "bind", Destination: f.Dir, RW: false}}, []string{f.KeyPath}, true},
		{"duplicate-destination-keeps-first", []MountInfo{{Type: "bind", Destination: f.Dir, RW: false}, {Type: "bind", Destination: f.Dir, RW: true}}, []string{f.KeyPath}, true},
		{"nested-writable", []MountInfo{{Type: "bind", Destination: f.Dir, RW: true}, {Type: "bind", Destination: "/", RW: false}}, []string{f.KeyPath}, false},
		{"prefix-is-not-parent", []MountInfo{{Type: "bind", Destination: f.Dir + "-other", RW: false}}, []string{f.KeyPath}, false},
		{"second-path-invalid", nil, []string{f.CertPath, "relative/key"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal([]map[string]any{{"Id": "fixture-id", "State": map[string]bool{"Running": true}, "Mounts": tc.mounts}})
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("TEST_DOCKER_INFO", string(data))
			if err := c.CheckCopyPaths(t.Context(), tc.paths...); (err != nil) != tc.wantError {
				t.Fatalf("CheckCopyPaths()=%v, wantError=%v", err, tc.wantError)
			}
		})
	}
	t.Setenv("TEST_DOCKER_INSPECT_FAIL", "1")
	if err := c.CheckCopyPaths(t.Context(), f.KeyPath); err == nil {
		t.Fatal("inspect 失败不能被忽略")
	}
	if _, err := NewRunningClient(t.Context(), "web"); err == nil {
		t.Fatal("不能为 inspect 失败的容器创建运行客户端")
	}
	t.Setenv("TEST_DOCKER_INSPECT_FAIL", "")
	t.Setenv("TEST_DOCKER_INFO", `[{"Id":"bad;id","State":{"Running":true}}]`)
	if _, err := NewRunningClient(t.Context(), "web"); err == nil {
		t.Fatal("不能使用无效 ID")
	}
}

func TestContainerScriptFailureDoesNotExposeOutput(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	c := NewClient("fixture-id")
	output, err := c.runFileScript(t.Context(), `printf 'private-key-payload'; exit 42`)
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 42 || len(output) != 0 || strings.Contains(err.Error(), "private-key-payload") {
		t.Fatalf("错误必须保留退出原因且不能泄漏输出: bytes=%d error=%v", len(output), err)
	}
	f.WritePair(t, "cert", "key")
	// 非法路径应在执行前拒绝；即使这一保护被破坏，也要让用例自行终止并给出断言失败。
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	if _, err := c.ReadRegularFile(ctx, "relative", 100); err == nil || !strings.Contains(err.Error(), "invalid container path") {
		t.Fatal("不能读取相对路径")
	}
	if _, err := c.ReadRegularFile(t.Context(), f.KeyPath, 1); err == nil {
		t.Fatal("超限文件应拒绝")
	}
	if err := os.WriteFile(f.KeyPath, []byte("k"), 0600); err != nil {
		t.Fatal(err)
	}
	if file, err := c.ReadRegularFile(t.Context(), f.KeyPath, 1); err != nil || string(file.Data) != "k" {
		t.Fatalf("允许边界大小文件: %v", err)
	}
	if _, err := c.ReadRegularFile(t.Context(), f.KeyPath, 10<<20); err != nil {
		t.Fatalf("允许最大请求上限: %v", err)
	}
	if err := os.WriteFile(filepath.Join(f.Dir, "bin", "stat"), []byte("#!/bin/sh\nprintf 'invalid-mode\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReadRegularFile(t.Context(), f.KeyPath, 100); err == nil {
		t.Fatal("无效权限头应拒绝")
	}
}

func TestCopyRejectsInvalidStagingAndTempFailures(t *testing.T) {
	for _, failure := range []string{"same-path", "missing-key", "host-temp", "stage-command", "stage-outside", "stage-name", "stage-control", "read-only", "host-write", "commit", "cleanup"} {
		t.Run(failure, func(t *testing.T) {
			f := testutil.NewDockerCLI(t)
			f.WritePair(t, "old-cert", "old-key")
			c := NewClient("fixture-id")
			certPath, keyPath := f.CertPath, f.KeyPath
			var script string
			command := "mktemp"
			switch failure {
			case "same-path":
				keyPath = certPath
			case "missing-key":
				if err := os.Remove(keyPath); err != nil {
					t.Fatal(err)
				}
			case "host-temp":
				t.Setenv("TMPDIR", filepath.Join(f.Dir, "missing"))
			case "stage-command":
				script = "#!/bin/sh\nexit 43\n"
			case "stage-outside":
				script = "#!/bin/sh\nprintf '/different/.sslctl-abcd\\n'\n"
			case "stage-name":
				script = "#!/bin/sh\nprintf '%s/invalid-stage\\n' \"$TEST_DOCKER_DIR\"\n"
			case "stage-control":
				script = "#!/bin/sh\nprintf '%s/.sslctl-bad\\nname\\n' \"$TEST_DOCKER_DIR\"\n"
			case "read-only":
				t.Setenv("TEST_DOCKER_INFO", f.ReadOnlyMountJSON())
			case "host-write":
				hostTemp := t.TempDir()
				t.Setenv("TMPDIR", hostTemp)
				script = "#!/bin/sh\nstage=$(/usr/bin/mktemp \"$@\") || exit 1\nfor d in \"$TMPDIR\"/sslctl-copy-*; do /bin/mkdir \"$d/0\"; done\nprintf '%s\\n' \"$stage\"\n"
			case "commit":
				command = "mv"
				script = "#!/bin/sh\nexit 45\n"
			case "cleanup":
				command = "rmdir"
				script = "#!/bin/sh\n[ \"$1\" = -- ] && shift\ncase \"$1\" in */.sslctl-lock-*) exec /bin/rmdir \"$@\" ;; *) exit 44 ;; esac\n"
			}
			if script != "" {
				if err := os.WriteFile(filepath.Join(f.Dir, "bin", command), []byte(script), 0700); err != nil {
					t.Fatal(err)
				}
			}
			err := c.replaceCertificateFiles(t.Context(), certPath, keyPath, ContainerFile{Data: []byte("new-cert"), Mode: 0644}, ContainerFile{Data: []byte("new-key"), Mode: 0600})
			if err == nil {
				t.Fatal("失败必须返回错误")
			}
			if failure == "host-write" {
				var pathErr *os.PathError
				if !errors.As(err, &pathErr) || pathErr.Op != "open" || !strings.HasSuffix(pathErr.Path, "/0") {
					t.Fatalf("必须保留本地暂存写入错误: %v", err)
				}
			}
			if failure == "commit" {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != 45 {
					t.Fatalf("不能忽略最终替换错误: %v", err)
				}
			}
			if failure == "stage-command" {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != 43 {
					t.Fatalf("必须保留暂存命令错误: %v", err)
				}
			}
			if failure == "read-only" {
				if !strings.Contains(err.Error(), "只读") {
					t.Fatalf("应在路径检查时拒绝: %v", err)
				}
				trace, readErr := os.ReadFile(f.Trace)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if strings.Contains(string(trace), "exec ") || strings.Contains(string(trace), "cp ") {
					t.Fatal("只读路径不可开始暂存或复制")
				}
			}
			if strings.HasPrefix(failure, "stage-") && failure != "stage-command" && !strings.Contains(err.Error(), "无效暂存目录") {
				t.Fatalf("暂存路径必须在复制前校验: %v", err)
			}
			if failure != "missing-key" && failure != "cleanup" {
				f.AssertPair(t, "old-cert", "old-key")
			}
		})
	}
}

func TestReadContainerFileRejectsEmptyLimitAndPreservesErrors(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	f.WritePair(t, "", "")
	c := NewClient("fixture-id")
	for _, size := range []int64{-1, 0} {
		if _, err := c.ReadRegularFile(t.Context(), f.KeyPath, size); err == nil || !strings.Contains(err.Error(), "size limit") {
			t.Fatalf("空文件也不能接受无效上限 %d: %v", size, err)
		}
	}
	if _, err := os.Stat(f.Trace); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("无效上限不能执行容器命令")
	}
	if _, err := c.ReadRegularFile(t.Context(), filepath.Join(f.Dir, "missing"), 100); err == nil {
		t.Fatal("缺失文件应失败")
	} else {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("容器错误不可改写为权限解析错误: %v", err)
		}
	}
	// 十进制读取长度在跨进制边界仍要接受恰好达到上限的文件。
	body := strings.Repeat("x", 80)
	if err := os.WriteFile(f.KeyPath, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := c.ReadRegularFile(t.Context(), f.KeyPath, 80); err != nil || string(got.Data) != body {
		t.Fatalf("边界文件被截断: %v", err)
	}
}

func TestReadBackupFileSizeAndErrorBoundaries(t *testing.T) {
	file := filepath.Join(t.TempDir(), "backup.pem")
	for _, size := range []int64{10 << 20, (10 << 20) + 1} {
		f, err := os.Create(file)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(size); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		got, err := readBackupFile(file)
		if size == 10<<20 {
			if err != nil || int64(len(got.Data)) != size {
				t.Fatalf("上限内备份应完整读取: %v", err)
			}
		} else if err == nil {
			t.Fatal("超限备份应拒绝")
		}
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if _, err := readBackupFile(file); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("必须保留缺失备份错误: %v", err)
	}
}

func TestCopyRollbackStopsBeforeReloadOnFailure(t *testing.T) {
	for _, failure := range []string{"missing-key", "copy", "reload"} {
		t.Run(failure, func(t *testing.T) {
			f := testutil.NewDockerCLI(t)
			f.WritePair(t, "old-cert", "old-key")
			certFile, keyFile := filepath.Join(t.TempDir(), "cert"), filepath.Join(t.TempDir(), "key")
			if err := os.WriteFile(certFile, []byte("backup-cert"), 0644); err != nil {
				t.Fatal(err)
			}
			if failure != "missing-key" {
				if err := os.WriteFile(keyFile, []byte("backup-key"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if failure == "copy" {
				t.Setenv("TEST_DOCKER_FAIL_CP", "1")
			}
			if failure == "reload" {
				t.Setenv("TEST_DOCKER_FAIL_RELOAD", "1")
			}
			d := NewDeployer(NewClient("fixture-id"), DeployerOptions{CertPath: f.CertPath, KeyPath: f.KeyPath, DeployMode: "copy"})
			err := d.Rollback(t.Context(), certFile, keyFile)
			if err == nil {
				t.Fatal("回滚失败不可报告成功")
			}
			if failure == "missing-key" && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("必须保留备份读取错误: %v", err)
			}
			if failure == "reload" {
				if !strings.Contains(err.Error(), "重载失败") {
					t.Fatalf("必须报告重载错误: %v", err)
				}
			} else {
				f.AssertPair(t, "old-cert", "old-key")
				trace, readErr := os.ReadFile(f.Trace)
				if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
					t.Fatal(readErr)
				}
				if strings.Contains(string(trace), "nginx -") {
					t.Fatal("读取或复制失败不能继续验证和重载")
				}
			}
		})
	}
}

func TestContainerReadDoesNotFetchOversizedPayload(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	f.WritePair(t, "cert", strings.Repeat("x", 120))
	// 记录实际读取的字节数：超限文件只需多读一个字节来判定，不能先拉取整个负载。
	script := "#!/bin/sh\n/usr/bin/head \"$@\" > \"$TEST_DOCKER_DIR/read-bytes\"\nexec /bin/cat \"$TEST_DOCKER_DIR/read-bytes\"\n"
	if err := os.WriteFile(filepath.Join(f.Dir, "bin", "head"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := NewClient("fixture-id").ReadRegularFile(t.Context(), f.KeyPath, 80); err == nil {
		t.Fatal("超限文件不能被接受")
	}
	data, err := os.ReadFile(filepath.Join(f.Dir, "read-bytes"))
	if err != nil || len(data) > 81 {
		t.Fatalf("超限探测超出读取预算: bytes=%d err=%v", len(data), err)
	}
}

func TestReadBackupFileStatFailure(t *testing.T) {
	file := filepath.Join(t.TempDir(), "backup")
	if err := os.WriteFile(file, []byte("snapshot"), 0600); err != nil {
		t.Fatal(err)
	}
	original := backupFileStat
	t.Cleanup(func() { backupFileStat = original })
	fault := &os.PathError{Op: "stat", Path: file, Err: os.ErrNotExist}
	backupFileStat = func(string) (os.FileInfo, error) { return nil, fault }
	got, err := readBackupFile(file)
	if !errors.Is(err, fault) || got.Data != nil {
		t.Fatalf("读取后 stat 失败不能返回有效快照: %+v %v", got, err)
	}
}

func TestCopyCleanupOutlivesCanceledDeployment(t *testing.T) {
	type key struct{}
	parent, cancel := context.WithCancel(context.WithValue(t.Context(), key{}, "trace"))
	cancel()
	start := time.Now()
	ctx, stop := newCopyCleanupContext(parent)
	defer stop()
	if ctx.Err() != nil || ctx.Value(key{}) != "trace" {
		t.Fatal("清理应独立于部署取消并保留追踪上下文")
	}
	deadline, ok := ctx.Deadline()
	// 清理预算固定 35 秒，既覆盖 30 秒锁等待，也限制故障恢复的额外延迟。
	if !ok || deadline.Before(start.Add(35*time.Second)) || deadline.After(time.Now().Add(35*time.Second)) {
		t.Fatalf("清理期限不满足恢复预算: %v", deadline)
	}
	stop()
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("清理结束后必须能释放上下文")
	}
}

func TestCopyStagingPermissionsAndStableLock(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	f.WritePair(t, "old-cert", "old-key")
	shim := filepath.Join(f.Dir, "bin", "docker")
	original, err := os.ReadFile(shim)
	if err != nil {
		t.Fatal(err)
	}
	replacement := strings.Replace(string(original), "cp)\n", `cp)
  mode=$(stat -c %a "$2")
  [ "$mode" = 600 ] || { echo "unsafe staging permissions" >&2; exit 46; }
`, 1)
	if err := os.WriteFile(shim, []byte(replacement), 0700); err != nil {
		t.Fatal(err)
	}
	c := NewClient("fixture-id")
	if err := c.replaceCertificateFiles(t.Context(), f.CertPath, f.KeyPath, ContainerFile{Data: []byte("new-cert"), Mode: 0644}, ContainerFile{Data: []byte("new-key"), Mode: 0600}); err != nil {
		t.Fatal(err)
	}
	f.AssertPair(t, "new-cert", "new-key")
	hash := sha256.Sum256([]byte(f.CertPath + "\n" + f.KeyPath))
	lock := filepath.Join(filepath.Dir(f.CertPath), fmt.Sprintf(".sslctl-lock-%x", hash[:12]))
	trace, err := os.ReadFile(f.Trace)
	if err != nil {
		t.Fatal(err)
	}
	// 提交和两次清理必须使用同一个既定锁名，以便不同进程相互排斥。
	if got := strings.Count(string(trace), "sslctl "+lock+" "); got != 3 {
		t.Fatalf("提交和清理未共享固定锁协议: %d", got)
	}
}

func TestContainerModeFitsFileModeWithoutTruncatingOverflow(t *testing.T) {
	for _, tc := range []struct {
		header  string
		wantErr bool
	}{{"20000000640", false}, {"40000000640", true}} {
		t.Run(tc.header, func(t *testing.T) {
			f := testutil.NewDockerCLI(t)
			f.WritePair(t, "cert", "key")
			// 容器工具输出是不可信文本；保留 uint32 范围内的权限位，拒绝溢出而非截断。
			if err := os.WriteFile(filepath.Join(f.Dir, "bin", "stat"), []byte("#!/bin/sh\nprintf '%s\\n' '"+tc.header+"'\n"), 0700); err != nil {
				t.Fatal(err)
			}
			got, err := NewClient("fixture-id").ReadRegularFile(t.Context(), f.KeyPath, 100)
			if (err != nil) != tc.wantErr {
				t.Fatalf("权限头 %s 的边界错误: %v", tc.header, err)
			}
			if err == nil && (got.Mode != 0640 || string(got.Data) != "key") {
				t.Fatalf("权限或内容被损坏: %+v", got)
			}
		})
	}
}
