// Package docker 提供 Docker 容器操作支持
package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Client Docker 客户端
type Client struct {
	containerID string
	useCompose  bool
	composeFile string
	serviceName string
}

// MountInfo 挂载信息
type MountInfo struct {
	Type        string // bind | volume
	Source      string // 宿主机路径或卷名
	Destination string // 容器内路径
	RW          bool   // 是否可写
}

// ContainerInfo 容器信息
type ContainerInfo struct {
	ID      string
	Name    string
	Image   string
	Status  string
	Running bool
	Mounts  []MountInfo
}

// NewClient 创建 Docker 客户端
func NewClient(containerID string) *Client {
	return &Client{
		containerID: containerID,
		useCompose:  false,
	}
}

// NewComposeClient 创建 docker-compose 客户端
func NewComposeClient(composeFile, serviceName string) *Client {
	return &Client{
		composeFile: composeFile,
		serviceName: serviceName,
		useCompose:  true,
	}
}

// SetContainer 设置容器 ID（用于 compose 客户端需要直接操作容器时）
func (c *Client) SetContainer(containerID string) {
	c.containerID = containerID
}

// GetContainerID 获取容器 ID
func (c *Client) GetContainerID() string {
	return c.containerID
}

// IsComposeMode 是否是 compose 模式
func (c *Client) IsComposeMode() bool {
	return c.useCompose
}

// allowedExecCommands 容器内允许执行的命令白名单
// 仅允许 Web 服务器相关的测试和重载命令
var allowedExecCommands = map[string]struct{}{
	"nginx":     {},
	"apachectl": {},
	"apache2":   {},
	"httpd":     {},
	"cat":       {}, // 读取配置文件
	"test":      {}, // 测试文件存在
	"ls":        {}, // 列出目录
}

// Exec 在容器内执行命令
// 注意：命令会经过白名单验证，只允许特定的 Web 服务器相关命令
func (c *Client) Exec(ctx context.Context, cmd string) (string, error) {
	// 安全校验：验证命令是否在白名单中
	if err := validateExecCommand(cmd); err != nil {
		return "", err
	}

	var execCmd *exec.Cmd

	if c.useCompose && c.composeFile != "" {
		// 优先使用 docker-compose exec
		execCmd = exec.CommandContext(ctx, "docker-compose",
			"-f", c.composeFile,
			"exec", "-T", c.serviceName,
			"sh", "-c", cmd)
	} else if c.containerID != "" {
		// 回退到 docker exec
		execCmd = exec.CommandContext(ctx, "docker",
			"exec", c.containerID,
			"sh", "-c", cmd)
	} else {
		return "", fmt.Errorf("no container specified")
	}

	output, err := execCmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

// validateExecCommand 验证命令是否安全
// 检查命令的可执行文件是否在白名单中，并验证参数不包含危险字符
// 允许的 shell 特性：重定向（2>&1）、条件执行（&&）用于测试命令
func validateExecCommand(cmd string) error {
	if cmd == "" {
		return fmt.Errorf("empty command not allowed")
	}

	// 长度限制：防止缓冲区溢出
	if len(cmd) > 4096 {
		return fmt.Errorf("command too long (max 4096 characters)")
	}

	// 解析命令，获取可执行文件名
	// 注意：对于 "test -f file && echo ok" 这种形式，取第一个命令
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return fmt.Errorf("invalid command format")
	}

	// 获取命令名（去除路径）
	executable := filepath.Base(parts[0])

	// 检查是否在白名单中
	if _, ok := allowedExecCommands[executable]; !ok {
		return fmt.Errorf("command not allowed: %s (allowed: nginx, apachectl, apache2, httpd, cat, test, ls)", executable)
	}

	// 检查危险的命令注入模式
	// 注意：允许 "&&" 用于 "test -f file && echo ok" 这种安全模式
	//       允许 "2>&1" 用于重定向 stderr
	//       允许单引号用于 ShellQuote 包裹的安全参数（如 cat '/path/to/file'）
	//       但禁止命令替换和命令链接等危险模式
	dangerousPatterns := []string{
		";",  // 命令分隔符
		"||", // 或运算符
		"|",  // 管道
		"`",  // 反引号命令替换
		"$(", // 命令替换
		"${", // 变量替换
		"\n", // 换行符
		"\r", // 回车符
	}
	for _, pattern := range dangerousPatterns {
		if strings.Contains(cmd, pattern) {
			return fmt.Errorf("dangerous pattern in command: %s", pattern)
		}
	}

	// 对于包含 && 的命令，验证后续命令也在白名单中
	if strings.Contains(cmd, "&&") {
		cmdParts := strings.Split(cmd, "&&")
		for _, part := range cmdParts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			subParts := strings.Fields(part)
			if len(subParts) == 0 {
				continue
			}
			subExec := filepath.Base(subParts[0])
			// 允许 echo 用于 "test -f file && echo ok" 模式
			if _, ok := allowedExecCommands[subExec]; !ok && subExec != "echo" {
				return fmt.Errorf("command in chain not allowed: %s", subExec)
			}
		}
	}

	return nil
}

// CopyToContainer 复制文件到容器
// 对目标路径进行安全校验，防止命令注入
func (c *Client) CopyToContainer(ctx context.Context, srcPath, dstPath string) error {
	// 安全校验：验证容器内目标路径
	if !isValidContainerPath(dstPath) {
		return fmt.Errorf("invalid container path: contains dangerous characters")
	}

	var cpCmd *exec.Cmd

	if c.useCompose && c.composeFile != "" {
		// docker-compose cp（需要 v2.x+）
		cpCmd = exec.CommandContext(ctx, "docker-compose",
			"-f", c.composeFile,
			"cp", srcPath,
			fmt.Sprintf("%s:%s", c.serviceName, dstPath))
	} else if c.containerID != "" {
		// docker cp
		cpCmd = exec.CommandContext(ctx, "docker",
			"cp", srcPath,
			fmt.Sprintf("%s:%s", c.containerID, dstPath))
	} else {
		return fmt.Errorf("no container specified")
	}

	output, err := cpCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker cp failed: %v, output: %s", err, string(output))
	}
	return nil
}

// CopyFromContainer 从容器复制文件
// 对源路径进行安全校验，防止命令注入
func (c *Client) CopyFromContainer(ctx context.Context, srcPath, dstPath string) error {
	// 安全校验：验证容器内源路径
	if !isValidContainerPath(srcPath) {
		return fmt.Errorf("invalid container path: contains dangerous characters")
	}

	var cpCmd *exec.Cmd

	if c.useCompose && c.composeFile != "" {
		cpCmd = exec.CommandContext(ctx, "docker-compose",
			"-f", c.composeFile,
			"cp", fmt.Sprintf("%s:%s", c.serviceName, srcPath), dstPath)
	} else if c.containerID != "" {
		cpCmd = exec.CommandContext(ctx, "docker",
			"cp", fmt.Sprintf("%s:%s", c.containerID, srcPath), dstPath)
	} else {
		return fmt.Errorf("no container specified")
	}

	output, err := cpCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker cp failed: %v, output: %s", err, string(output))
	}
	return nil
}

// GetContainerInfo 获取容器信息
func (c *Client) GetContainerInfo(ctx context.Context) (*ContainerInfo, error) {
	containerID := c.containerID

	// 如果是 compose 模式，先获取容器 ID
	if c.useCompose && c.composeFile != "" && containerID == "" {
		id, err := c.getComposeContainerID(ctx)
		if err != nil {
			return nil, err
		}
		containerID = id
		c.containerID = id
	}

	if containerID == "" {
		return nil, fmt.Errorf("no container specified")
	}

	cmd := exec.CommandContext(ctx, "docker", "inspect", containerID)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker inspect failed: %w", err)
	}

	var inspectData []struct {
		ID    string `json:"Id"`
		Name  string `json:"Name"`
		State struct {
			Running bool `json:"Running"`
			Status  string `json:"Status"`
		} `json:"State"`
		Config struct {
			Image string `json:"Image"`
		} `json:"Config"`
		Mounts []struct {
			Type        string `json:"Type"`
			Source      string `json:"Source"`
			Destination string `json:"Destination"`
			RW          bool   `json:"RW"`
		} `json:"Mounts"`
	}

	if err := json.Unmarshal(output, &inspectData); err != nil {
		return nil, fmt.Errorf("parse docker inspect output failed: %w", err)
	}

	if len(inspectData) == 0 {
		return nil, fmt.Errorf("container not found: %s", containerID)
	}

	data := inspectData[0]
	info := &ContainerInfo{
		ID:      data.ID,
		Name:    strings.TrimPrefix(data.Name, "/"),
		Image:   data.Config.Image,
		Status:  data.State.Status,
		Running: data.State.Running,
		Mounts:  make([]MountInfo, 0, len(data.Mounts)),
	}

	for _, m := range data.Mounts {
		info.Mounts = append(info.Mounts, MountInfo{
			Type:        m.Type,
			Source:      m.Source,
			Destination: m.Destination,
			RW:          m.RW,
		})
	}

	return info, nil
}

// getComposeContainerID 获取 compose 服务对应的容器 ID
func (c *Client) getComposeContainerID(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "docker-compose",
		"-f", c.composeFile,
		"ps", "-q", c.serviceName)

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("docker-compose ps failed: %w", err)
	}

	containerID := strings.TrimSpace(string(output))
	if containerID == "" {
		return "", fmt.Errorf("service %s not running", c.serviceName)
	}

	// 可能返回多行（多个容器），取第一个
	lines := strings.Split(containerID, "\n")
	return strings.TrimSpace(lines[0]), nil
}

// FindMountForPath 查找容器内路径对应的挂载
func (c *Client) FindMountForPath(mounts []MountInfo, containerPath string) *MountInfo {
	var bestMatch *MountInfo
	bestLen := 0

	for i := range mounts {
		m := &mounts[i]
		if m.Type != "bind" || !m.RW {
			continue
		}

		// 检查容器路径是否在挂载目录下
		// 精确匹配：路径必须完全等于挂载点，或以挂载点+"/"为前缀
		// 特殊处理根挂载点 "/"：任何绝对路径都匹配
		dest := m.Destination
		if containerPath == dest || (dest == "/" && strings.HasPrefix(containerPath, "/")) || strings.HasPrefix(containerPath, dest+"/") {
			// 选择最长匹配
			if len(dest) > bestLen {
				bestMatch = m
				bestLen = len(dest)
			}
		}
	}

	return bestMatch
}

// ResolveHostPath 将容器内路径转换为宿主机路径
func (c *Client) ResolveHostPath(containerPath string, mount *MountInfo) string {
	if mount == nil {
		return ""
	}

	relPath := strings.TrimPrefix(containerPath, mount.Destination)
	relPath = strings.TrimPrefix(relPath, "/")
	return filepath.Join(mount.Source, relPath)
}

// CheckDockerAvailable 检查 docker 命令是否可用
func CheckDockerAvailable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "version")
	return cmd.Run() == nil
}

// CheckComposeAvailable 检查 docker-compose 命令是否可用
func CheckComposeAvailable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker-compose", "version")
	return cmd.Run() == nil
}

// CopyFilesForBackup 从容器复制证书文件用于备份
// 返回临时目录路径，调用者负责清理
func (c *Client) CopyFilesForBackup(ctx context.Context, certPath, keyPath string) (tmpCertPath, tmpKeyPath string, err error) {
	tmpDir, err := os.MkdirTemp("", "sslctl-backup-")
	if err != nil {
		return "", "", fmt.Errorf("create temp dir failed: %w", err)
	}
	// 设置安全权限
	if err := os.Chmod(tmpDir, 0700); err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", "", fmt.Errorf("set temp dir permission failed: %w", err)
	}

	tmpCertPath = filepath.Join(tmpDir, "cert.pem")
	tmpKeyPath = filepath.Join(tmpDir, "key.pem")

	if err := c.CopyFromContainer(ctx, certPath, tmpCertPath); err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", "", fmt.Errorf("copy cert from container failed: %w", err)
	}

	if err := c.CopyFromContainer(ctx, keyPath, tmpKeyPath); err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", "", fmt.Errorf("copy key from container failed: %w", err)
	}

	return tmpCertPath, tmpKeyPath, nil
}

// isValidContainerPath 验证容器内路径是否安全
// 拒绝包含命令注入字符的路径
// 注意：允许空格，因为使用 exec.Command 直接执行（非 shell），空格不会导致命令注入
func isValidContainerPath(path string) bool {
	if path == "" {
		return false
	}
	// 长度限制：防止缓冲区溢出和异常路径
	if len(path) > 4096 {
		return false
	}
	// 路径必须是绝对路径
	if !strings.HasPrefix(path, "/") {
		return false
	}
	// 检查路径穿越
	if strings.Contains(path, "..") {
		return false
	}
	// 检查危险字符（不包括空格，因为使用 exec.Command 而非 shell）
	// 这些字符在 shell 中有特殊含义，可能导致命令注入
	dangerousChars := []string{";", "&", "|", "$", "`", "(", ")", "{", "}", "<", ">", "!", "\n", "\r", "'", "\"", "\\", "*", "?", "[", "]"}
	for _, char := range dangerousChars {
		if strings.Contains(path, char) {
			return false
		}
	}
	return true
}

// ExecAux 执行辅助命令（mkdir/chmod），使用严格验证
// 不使用 sh -c，直接传递命令参数
func (c *Client) ExecAux(ctx context.Context, cmd string, args ...string) (string, error) {
	// 白名单命令
	allowedAuxCommands := map[string]struct{}{
		"mkdir": {},
		"chmod": {},
	}

	if _, ok := allowedAuxCommands[cmd]; !ok {
		return "", fmt.Errorf("command not allowed: %s", cmd)
	}

	// 验证所有参数
	for _, arg := range args {
		// 跳过 flag 参数（如 -p, 644）
		if strings.HasPrefix(arg, "-") || (len(arg) <= 4 && isNumeric(arg)) {
			continue
		}
		// 验证路径参数
		if !isValidContainerPath(arg) {
			return "", fmt.Errorf("invalid path argument: %s", arg)
		}
	}

	var execCmd *exec.Cmd
	cmdArgs := append([]string{cmd}, args...)

	if c.useCompose && c.composeFile != "" {
		fullArgs := append([]string{"-f", c.composeFile, "exec", "-T", c.serviceName}, cmdArgs...)
		execCmd = exec.CommandContext(ctx, "docker-compose", fullArgs...)
	} else if c.containerID != "" {
		fullArgs := append([]string{"exec", c.containerID}, cmdArgs...)
		execCmd = exec.CommandContext(ctx, "docker", fullArgs...)
	} else {
		return "", fmt.Errorf("no container specified")
	}

	output, err := execCmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

// isNumeric 检查字符串是否为纯数字
func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}
