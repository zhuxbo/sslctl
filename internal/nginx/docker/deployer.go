// Package docker 提供 Docker 容器操作支持
package docker

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zhuxbo/cert-deploy/pkg/util"
)

// DeployerOptions 部署器选项
type DeployerOptions struct {
	CertPath         string // 容器内证书路径
	KeyPath          string // 容器内私钥路径
	HostCertPath     string // 宿主机证书路径（挂载卷模式）
	HostKeyPath      string // 宿主机私钥路径
	TestCommand      string // 容器内测试命令
	ReloadCommand    string // 容器内重载命令
	DeployMode       string // volume | copy | auto
}

// Deployer Docker Nginx 部署器
type Deployer struct {
	client        *Client
	certPath      string // 容器内证书路径
	keyPath       string // 容器内私钥路径
	hostCertPath  string // 宿主机证书路径（挂载卷模式）
	hostKeyPath   string // 宿主机私钥路径
	testCommand   string // 容器内测试命令
	reloadCommand string // 容器内重载命令
	deployMode    string // volume | copy | auto
	volumeMode    bool   // 是否已检测为挂载卷模式
}

// allowedContainerCommands 容器内允许的命令白名单
var allowedContainerCommands = map[string]bool{
	"nginx -t":                  true,
	"nginx -s reload":           true,
	"nginx -s reopen":           true,
	"/usr/sbin/nginx -t":        true,
	"/usr/sbin/nginx -s reload": true,
	"kill -HUP 1":               true, // 常见的容器内重载方式
}

// NewDeployer 创建 Docker 部署器
func NewDeployer(client *Client, opts DeployerOptions) *Deployer {
	// 默认命令
	testCmd := opts.TestCommand
	if testCmd == "" {
		testCmd = "nginx -t"
	}
	reloadCmd := opts.ReloadCommand
	if reloadCmd == "" {
		reloadCmd = "nginx -s reload"
	}

	return &Deployer{
		client:        client,
		certPath:      opts.CertPath,
		keyPath:       opts.KeyPath,
		hostCertPath:  opts.HostCertPath,
		hostKeyPath:   opts.HostKeyPath,
		testCommand:   testCmd,
		reloadCommand: reloadCmd,
		deployMode:    opts.DeployMode,
	}
}

// Deploy 部署证书
func (d *Deployer) Deploy(ctx context.Context, cert, intermediate, key string) error {
	// 1. 检测或确认部署模式
	mode := d.deployMode
	if mode == "auto" || mode == "" {
		var err error
		mode, err = d.DetectDeployMode(ctx)
		if err != nil {
			return fmt.Errorf("检测部署模式失败: %w", err)
		}
	}

	// 2. 组合证书（服务器证书 + 中间证书）
	fullchain := cert
	if intermediate != "" {
		fullchain = cert + "\n" + intermediate
	}

	// 3. 根据模式部署
	if mode == "volume" {
		if err := d.deployToHost(fullchain, key); err != nil {
			return fmt.Errorf("挂载卷模式部署失败: %w", err)
		}
	} else {
		if err := d.deployToContainer(ctx, fullchain, key); err != nil {
			return fmt.Errorf("docker cp 模式部署失败: %w", err)
		}
	}

	// 4. 测试配置
	if d.testCommand != "" {
		if !allowedContainerCommands[d.testCommand] {
			return fmt.Errorf("command not in whitelist: %s", d.testCommand)
		}
		output, err := d.client.Exec(ctx, d.testCommand)
		if err != nil {
			return fmt.Errorf("配置测试失败: %v, output: %s", err, output)
		}
	}

	// 5. 重载 Nginx
	if d.reloadCommand != "" {
		if !allowedContainerCommands[d.reloadCommand] {
			return fmt.Errorf("command not in whitelist: %s", d.reloadCommand)
		}
		output, err := d.client.Exec(ctx, d.reloadCommand)
		if err != nil {
			return fmt.Errorf("重载失败: %v, output: %s", err, output)
		}
	}

	return nil
}

// DetectDeployMode 自动检测部署模式
func (d *Deployer) DetectDeployMode(ctx context.Context) (string, error) {
	// 如果已设置宿主机路径，直接使用 volume 模式
	if d.hostCertPath != "" && d.hostKeyPath != "" {
		d.volumeMode = true
		return "volume", nil
	}

	// 获取容器信息
	info, err := d.client.GetContainerInfo(ctx)
	if err != nil {
		return "copy", nil // 默认 copy 模式
	}

	// 检查证书路径是否有可写挂载
	certMount := d.client.FindMountForPath(info.Mounts, d.certPath)
	if certMount != nil {
		d.hostCertPath = d.client.ResolveHostPath(d.certPath, certMount)
		keyMount := d.client.FindMountForPath(info.Mounts, d.keyPath)
		if keyMount != nil {
			d.hostKeyPath = d.client.ResolveHostPath(d.keyPath, keyMount)
			d.volumeMode = true
			return "volume", nil
		}
		// key 路径无挂载，回退到 copy 模式
		d.hostCertPath = ""
	}

	return "copy", nil
}

// deployToHost 写入宿主机（挂载卷模式）
func (d *Deployer) deployToHost(fullchain, key string) error {
	// 确保目录存在
	certDir := filepath.Dir(d.hostCertPath)
	keyDir := filepath.Dir(d.hostKeyPath)

	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("create cert directory failed: %w", err)
	}
	if certDir != keyDir {
		if err := os.MkdirAll(keyDir, 0700); err != nil {
			return fmt.Errorf("create key directory failed: %w", err)
		}
	}

	// 原子写入证书文件
	if err := util.AtomicWrite(d.hostCertPath, []byte(fullchain), 0644); err != nil {
		return fmt.Errorf("write certificate failed: %w", err)
	}

	// 原子写入私钥文件（0600 权限）
	if err := util.AtomicWrite(d.hostKeyPath, []byte(key), 0600); err != nil {
		return fmt.Errorf("write private key failed: %w", err)
	}

	return nil
}

// deployToContainer 复制到容器（docker cp 模式）
func (d *Deployer) deployToContainer(ctx context.Context, fullchain, key string) error {
	// 创建临时目录
	tmpDir, err := os.MkdirTemp("", "cert-deploy-")
	if err != nil {
		return fmt.Errorf("create temp dir failed: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	// 设置安全权限
	if err := os.Chmod(tmpDir, 0700); err != nil {
		return fmt.Errorf("set temp dir permission failed: %w", err)
	}

	certFile := filepath.Join(tmpDir, "fullchain.pem")
	keyFile := filepath.Join(tmpDir, "privkey.pem")

	// 写入临时文件
	if err := os.WriteFile(certFile, []byte(fullchain), 0644); err != nil {
		return fmt.Errorf("write temp cert file failed: %w", err)
	}
	if err := os.WriteFile(keyFile, []byte(key), 0600); err != nil {
		return fmt.Errorf("write temp key file failed: %w", err)
	}

	// 确保容器内目录存在（使用安全的 ExecAux 方法）
	certDir := getDir(d.certPath)
	keyDir := getDir(d.keyPath)

	if certDir != "" {
		_, _ = d.client.ExecAux(ctx, "mkdir", "-p", certDir)
	}
	if keyDir != "" && keyDir != certDir {
		_, _ = d.client.ExecAux(ctx, "mkdir", "-p", keyDir)
	}

	// 复制到容器
	if err := d.client.CopyToContainer(ctx, certFile, d.certPath); err != nil {
		return fmt.Errorf("copy certificate to container failed: %w", err)
	}
	if err := d.client.CopyToContainer(ctx, keyFile, d.keyPath); err != nil {
		return fmt.Errorf("copy private key to container failed: %w", err)
	}

	// 设置容器内文件权限（使用安全的 ExecAux 方法）
	_, _ = d.client.ExecAux(ctx, "chmod", "644", d.certPath)
	_, _ = d.client.ExecAux(ctx, "chmod", "600", d.keyPath)

	return nil
}

// Rollback 回滚到备份的证书
func (d *Deployer) Rollback(ctx context.Context, backupCertPath, backupKeyPath string) error {
	mode := d.deployMode
	if mode == "auto" || mode == "" {
		if d.volumeMode || (d.hostCertPath != "" && d.hostKeyPath != "") {
			mode = "volume"
		} else {
			mode = "copy"
		}
	}

	if mode == "volume" {
		// 挂载卷模式：从宿主机复制备份
		if err := util.CopyFile(backupCertPath, d.hostCertPath); err != nil {
			return fmt.Errorf("restore certificate failed: %w", err)
		}
		if err := util.CopyFile(backupKeyPath, d.hostKeyPath); err != nil {
			return fmt.Errorf("restore private key failed: %w", err)
		}
	} else {
		// docker cp 模式
		if err := d.client.CopyToContainer(ctx, backupCertPath, d.certPath); err != nil {
			return fmt.Errorf("restore certificate to container failed: %w", err)
		}
		if err := d.client.CopyToContainer(ctx, backupKeyPath, d.keyPath); err != nil {
			return fmt.Errorf("restore private key to container failed: %w", err)
		}
	}

	// 测试配置
	if d.testCommand != "" {
		if !allowedContainerCommands[d.testCommand] {
			return fmt.Errorf("command not in whitelist: %s", d.testCommand)
		}
		output, err := d.client.Exec(ctx, d.testCommand)
		if err != nil {
			return fmt.Errorf("config test failed after rollback: %v, output: %s", err, output)
		}
	}

	// 重载服务
	if d.reloadCommand != "" {
		if !allowedContainerCommands[d.reloadCommand] {
			return fmt.Errorf("command not in whitelist: %s", d.reloadCommand)
		}
		output, err := d.client.Exec(ctx, d.reloadCommand)
		if err != nil {
			return fmt.Errorf("reload failed after rollback: %v, output: %s", err, output)
		}
	}

	return nil
}

// GetDeployMode 获取当前部署模式
func (d *Deployer) GetDeployMode() string {
	if d.volumeMode {
		return "volume"
	}
	if d.deployMode != "" {
		return d.deployMode
	}
	return "auto"
}

// IsVolumeMode 是否是挂载卷模式
func (d *Deployer) IsVolumeMode() bool {
	return d.volumeMode
}

// GetHostPaths 获取宿主机路径
func (d *Deployer) GetHostPaths() (certPath, keyPath string) {
	return d.hostCertPath, d.hostKeyPath
}

// SetHostPaths 设置宿主机路径
func (d *Deployer) SetHostPaths(certPath, keyPath string) {
	d.hostCertPath = certPath
	d.hostKeyPath = keyPath
	if certPath != "" && keyPath != "" {
		d.volumeMode = true
	}
}

// CreateFromSite 从扫描的站点信息创建部署器
func CreateFromSite(client *Client, site *SSLSite, testCmd, reloadCmd string) *Deployer {
	opts := DeployerOptions{
		CertPath:      site.CertificatePath,
		KeyPath:       site.PrivateKeyPath,
		TestCommand:   testCmd,
		ReloadCommand: reloadCmd,
	}

	if site.VolumeMode {
		opts.DeployMode = "volume"
		opts.HostCertPath = site.HostCertPath
		opts.HostKeyPath = site.HostKeyPath
	} else {
		opts.DeployMode = "copy"
	}

	return NewDeployer(client, opts)
}

// ValidateCommand 验证命令是否在白名单中
func ValidateCommand(cmd string) bool {
	return allowedContainerCommands[strings.TrimSpace(cmd)]
}

// getDir 获取路径的目录部分
func getDir(path string) string {
	dir := filepath.Dir(path)
	if dir == "." || dir == "/" {
		return ""
	}
	return dir
}

