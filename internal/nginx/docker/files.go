package docker

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/zhuxbo/sslctl/internal/executor"
)

// NewRunningClient 每次操作按名称解析容器，再固定 ID，避免容器重建时跨实例写入或回滚。
func NewRunningClient(ctx context.Context, name string) (*Client, error) {
	if !executor.IsValidDockerContainerName(name) {
		return nil, fmt.Errorf("无效的 Docker 容器名称")
	}
	client := NewClient(name)
	info, err := client.GetContainerInfo(ctx)
	if err != nil {
		return nil, err
	}
	if !info.Running || !executor.IsValidDockerContainerName(info.ID) {
		return nil, fmt.Errorf("容器 %s 未运行或 ID 无效", name)
	}
	return NewClient(info.ID), nil
}

// CheckCopyPaths copy 只支持容器可写层和可写目录挂载；不能绕过只读子挂载。
func (c *Client) CheckCopyPaths(ctx context.Context, paths ...string) error {
	info, err := c.GetContainerInfo(ctx)
	if err != nil {
		return err
	}
	for _, filePath := range paths {
		if err := validateContainerPath(filePath); err != nil {
			return err
		}
		var selected *MountInfo
		for i := range info.Mounts {
			mount := &info.Mounts[i]
			dest := path.Clean(mount.Destination)
			if filePath == dest || dest == "/" || strings.HasPrefix(filePath, dest+"/") {
				if selected == nil || len(dest) > len(path.Clean(selected.Destination)) {
					selected = mount
				}
			}
		}
		if selected != nil && (!selected.RW || selected.Type == "tmpfs" || path.Clean(selected.Destination) == filePath) {
			return fmt.Errorf("容器证书路径 %s 位于只读、临时或单文件挂载中，copy 模式需要可写目录", filePath)
		}
	}
	return nil
}

// 路径通过位置参数传递；拒绝文件及其父目录中的符号链接。
const checkRegularFileScript = `
set -eu
check_file() {
  p=$1
  while [ "$p" != / ]; do
    [ ! -L "$p" ] || { echo "symbolic link not allowed" >&2; exit 1; }
    p=${p%/*}; [ -n "$p" ] || p=/
  done
  [ -f "$1" ] || { echo "existing regular certificate/key file required" >&2; exit 1; }
}
`

// ContainerFile 保留内容和原权限，以便失败后恢复；私钥内容不得写入日志。
type ContainerFile struct {
	Data []byte
	Mode os.FileMode
}

// ReadRegularFile 有界读取，避免把容器路径误当成宿主机路径或读取无限设备。
func (c *Client) ReadRegularFile(ctx context.Context, filePath string, maxSize int64) (ContainerFile, error) {
	if err := validateContainerPath(filePath); err != nil {
		return ContainerFile{}, err
	}
	if maxSize <= 0 || maxSize > 10<<20 {
		return ContainerFile{}, fmt.Errorf("invalid container file size limit")
	}
	output, err := c.runFileScript(ctx, checkRegularFileScript+`
check_file "$1"
stat -c %a "$1"
head -c "$2" "$1"
`, filePath, strconv.FormatInt(maxSize+1, 10))
	if err != nil {
		return ContainerFile{}, err
	}
	header, body, ok := strings.Cut(string(output), "\n")
	mode, modeErr := strconv.ParseUint(header, 8, 32)
	if !ok || modeErr != nil || int64(len(body)) > maxSize {
		return ContainerFile{}, fmt.Errorf("容器文件 %s 的权限无效或超过大小限制", filePath)
	}
	return ContainerFile{Data: []byte(body), Mode: os.FileMode(mode) & os.ModePerm}, nil
}

// runFileScript 仅供本文件的固定脚本使用，文件操作以容器内 root 执行，属主在替换时保留。
func (c *Client) runFileScript(ctx context.Context, script string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultDockerTimeout)
	defer cancel()
	commandArgs := []string{"exec", "--user", "0", c.containerID, "sh", "-c", script, "sslctl"}
	commandArgs = append(commandArgs, args...)
	cmd := exec.CommandContext(ctx, "docker", commandArgs...)
	output, err := cmd.Output()
	if err != nil {
		// 不拼接 stdout：读取失败时其中可能已有部分私钥。
		return nil, fmt.Errorf("容器文件操作失败: %w", err)
	}
	return output, nil
}

// 提交与清理共用容器内锁。Docker 客户端取消后远端 exec 可能仍在运行，
// 清理先等待旧提交结束，再撤销其暂存文件，防止旧提交晚于回滚覆盖证书。
const copyLockScript = `
set -eu
lock=$1; shift
n=0
until mkdir "$lock" 2>/dev/null; do
  n=$((n+1)); [ "$n" -lt 30 ] || exit 1
  sleep 1
done
trap 'rmdir "$lock"' EXIT
trap 'exit 1' HUP INT TERM
`

// replaceCertificateFiles 两份文件都暂存完毕后，才在各自目录内重命名替换。
// 两次重命名之间的失败由上层使用已持久备份回滚，不声称证书对跨文件原子。
func (c *Client) replaceCertificateFiles(ctx context.Context, certPath, keyPath string, cert, key ContainerFile) (retErr error) {
	ctx, cancel := context.WithTimeout(ctx, defaultDockerTimeout)
	defer cancel()
	if certPath == keyPath {
		return fmt.Errorf("证书与私钥必须使用不同文件")
	}
	if err := c.CheckCopyPaths(ctx, certPath, keyPath); err != nil {
		return err
	}
	tempDir, err := os.MkdirTemp("", "sslctl-copy-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tempDir) }()
	lockHash := sha256.Sum256([]byte(certPath + "\n" + keyPath))
	lockPath := path.Join(path.Dir(certPath), fmt.Sprintf(".sslctl-lock-%x", lockHash[:12]))
	var stages []string
	defer func() {
		cleanupCtx, cleanupCancel := newCopyCleanupContext(ctx)
		defer cleanupCancel()
		for _, stage := range stages {
			_, cleanupErr := c.runFileScript(cleanupCtx, copyLockScript+`rm -f -- "$1/new"; rmdir -- "$1"`, lockPath, stage)
			retErr = errors.Join(retErr, cleanupErr)
		}
	}()
	for i, filePath := range []string{keyPath, certPath} {
		stageOutput, stageErr := c.runFileScript(ctx, checkRegularFileScript+`
check_file "$1"
umask 077
mktemp -d "${1%/*}/.sslctl-XXXXXX"
`, filePath)
		if stageErr != nil {
			return stageErr
		}
		stage := strings.TrimSpace(string(stageOutput))
		if !isValidContainerPath(stage) || path.Dir(stage) != path.Dir(filePath) || !strings.HasPrefix(path.Base(stage), ".sslctl-") {
			return fmt.Errorf("容器返回了无效暂存目录")
		}
		stages = append(stages, stage)
		data := key.Data
		if i == 1 {
			data = cert.Data
		}
		localFile := filepath.Join(tempDir, strconv.Itoa(i))
		if err := os.WriteFile(localFile, data, 0600); err != nil {
			return err
		}
		if err := c.CopyToContainer(ctx, localFile, path.Join(stage, "new")); err != nil {
			return err
		}
	}
	_, err = c.runFileScript(ctx, copyLockScript+checkRegularFileScript+`
check_file "$1"; check_file "$2"; check_file "$3/new"; check_file "$4/new"
chown "$(stat -c %u:%g "$1")" "$3/new"
chown "$(stat -c %u:%g "$2")" "$4/new"
chmod "$5" "$3/new"
chmod "$6" "$4/new"
mv -f -- "$3/new" "$1"
mv -f -- "$4/new" "$2"
`, lockPath, keyPath, certPath, stages[0], stages[1], fmt.Sprintf("%o", key.Mode.Perm()), fmt.Sprintf("%o", cert.Mode.Perm()))
	return err
}

// 清理必须独立于已取消的部署，并给容器锁的 30 秒等待留出完成清理的时间。
func newCopyCleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), 35*time.Second)
}
