// Package executor 命令执行器（白名单机制）
package executor

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// DefaultTimeout 命令执行默认超时时间
const DefaultTimeout = 30 * time.Second

// dockerContainerNameRe 校验 docker 容器名/ID（防止 docker exec 命令注入）
// docker 命名规则：首字符为字母数字，其后允许字母数字与 _ . -
var dockerContainerNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

// allowedDockerInnerCommands docker exec 允许在容器内执行的测试/重载命令
// 仅放行固定的 Web 服务器测试与重载命令，容器名单独做字符白名单校验
var allowedDockerInnerCommands = map[string]bool{
	"nginx -t":            true,
	"nginx -s reload":     true,
	"apachectl -t":        true,
	"apachectl graceful":  true,
	"apache2ctl -t":       true,
	"apache2ctl graceful": true,
	"httpd -t":            true,
	"httpd -k graceful":   true,
}

// parseDockerExec 解析 "docker exec <container> <inner...>"
// 返回容器名与内层命令；非 docker exec 命令返回 ok=false
func parseDockerExec(cmdStr string) (container, inner string, ok bool) {
	fields := strings.Fields(cmdStr)
	if len(fields) < 4 || fields[0] != "docker" || fields[1] != "exec" {
		return "", "", false
	}
	return fields[2], strings.Join(fields[3:], " "), true
}

// IsDockerExecCommand 判断命令是否为受支持的 docker exec 容器重载命令
func IsDockerExecCommand(cmdStr string) bool {
	container, inner, ok := parseDockerExec(cmdStr)
	return ok && dockerContainerNameRe.MatchString(container) && allowedDockerInnerCommands[inner]
}

// IsValidDockerContainerName 校验容器名是否符合 docker 命名规则。
// 供命令构建方前置校验，使非法容器名在构建时就被发现，
// 而不是拼成命令后在执行期被白名单拒绝（错误指向白名单，掩盖真实原因）。
func IsValidDockerContainerName(name string) bool {
	return dockerContainerNameRe.MatchString(name)
}

// AllowedCommands 允许的命令白名单（支持多发行版和 Windows）
var AllowedCommands = map[string]bool{
	// ========== Nginx 扫描命令 ==========
	"nginx -V": true, // 获取版本信息
	"nginx -T": true, // 获取合并配置

	// ========== Nginx 部署命令 ==========
	// Linux - 通用
	"nginx -t":        true,
	"nginx -s reload": true,
	// Linux - systemd (Ubuntu/Debian/CentOS 7+/RHEL 7+/Fedora)
	"systemctl reload nginx":  true,
	"systemctl restart nginx": true,
	// Linux - SysVinit (CentOS 6/旧系统)
	"service nginx reload":  true,
	"service nginx restart": true,
	// Linux - OpenRC (Alpine/Gentoo)
	"rc-service nginx reload":  true,
	"rc-service nginx restart": true,
	// Linux - 直接信号
	"/usr/sbin/nginx -s reload": true,
	// Windows - Nginx
	"net stop nginx":                 true,
	"net start nginx":                true,
	"C:\\nginx\\nginx.exe -t":        true,
	"C:\\nginx\\nginx.exe -s reload": true,

	// ========== Apache 命令 ==========
	// Linux - apachectl (通用)
	"apachectl -t":       true,
	"apachectl graceful": true,
	"apachectl restart":  true,
	// Linux - apache2ctl (Debian/Ubuntu)
	"apache2ctl -t":       true,
	"apache2ctl graceful": true,
	"apache2ctl restart":  true,
	// Linux - httpd (CentOS/RHEL/Fedora)
	"httpd -t":          true,
	"httpd -k graceful": true,
	"httpd -k restart":  true,
	// Linux - systemd (Ubuntu/Debian)
	"systemctl reload apache2":  true,
	"systemctl restart apache2": true,
	// Linux - systemd (CentOS/RHEL/Fedora)
	"systemctl reload httpd":  true,
	"systemctl restart httpd": true,
	// Linux - SysVinit (Debian/Ubuntu 旧版)
	"service apache2 reload":  true,
	"service apache2 restart": true,
	// Linux - SysVinit (CentOS/RHEL 旧版)
	"service httpd reload":  true,
	"service httpd restart": true,
	// Linux - OpenRC (Alpine/Gentoo)
	"rc-service apache2 reload":  true,
	"rc-service apache2 restart": true,
	"rc-service httpd reload":    true,
	"rc-service httpd restart":   true,
	// Windows - Apache Lounge / XAMPP
	"httpd.exe -t":                            true,
	"httpd.exe -k restart":                    true,
	"C:\\Apache24\\bin\\httpd.exe -t":         true,
	"C:\\Apache24\\bin\\httpd.exe -k restart": true,
	"net stop Apache2.4":                      true,
	"net start Apache2.4":                     true,
	// ========== 系统扫描命令（只读） ==========
	"ps -C nginx -o pid=":   true, // 查找 nginx 进程
	"ps -C httpd -o pid=":   true, // 查找 Apache 进程 (CentOS/RHEL)
	"ps -C apache2 -o pid=": true, // 查找 Apache 进程 (Debian/Ubuntu)
	"ss -tlnp":              true, // 查看监听端口
	"netstat -tlnp":         true, // 查看监听端口（备用）

	// ========== sslctl 服务管理命令 ==========
	// Linux - systemd
	"systemctl daemon-reload":     true,
	"systemctl start sslctl":      true,
	"systemctl stop sslctl":       true,
	"systemctl restart sslctl":    true,
	"systemctl enable sslctl":     true,
	"systemctl disable sslctl":    true,
	"systemctl is-enabled sslctl": true,
	"systemctl is-active sslctl":  true,
	// Linux - SysVinit
	"service sslctl start":         true,
	"service sslctl stop":          true,
	"service sslctl restart":       true,
	"service sslctl status":        true,
	"chkconfig sslctl on":          true,
	"chkconfig sslctl off":         true,
	"update-rc.d sslctl defaults":  true,
	"update-rc.d sslctl enable":    true,
	"update-rc.d sslctl disable":   true,
	"update-rc.d -f sslctl remove": true,
	// Linux - OpenRC
	"rc-service sslctl start":      true,
	"rc-service sslctl stop":       true,
	"rc-service sslctl restart":    true,
	"rc-service sslctl status":     true,
	"rc-update add sslctl default": true,
	"rc-update del sslctl default": true,
}

// AllowedScanExecutables 扫描器允许的可执行文件（用于动态路径）
var AllowedScanExecutables = map[string]bool{
	"nginx":               true,
	"nginx.exe":           true,
	"/usr/sbin/nginx":     true,
	"httpd":               true,
	"httpd.exe":           true,
	"apachectl":           true,
	"apache2ctl":          true,
	"/usr/sbin/httpd":     true,
	"/usr/sbin/apachectl": true,
}

// AllowedScanArgs 允许的参数（用于动态路径命令）
var AllowedScanArgs = map[string]bool{
	"-t": true, // 测试配置
	"-T": true, // 获取合并配置
	"-V": true, // 获取版本信息
	"-S": true, // 虚拟主机列表（Apache）
	"-s": true, // 信号控制（如 -s reload）
	"-v": true, // 版本号
	"-p": true, // prefix 路径（Windows 上指定 nginx 工作目录）
	"-k": true, // Apache 信号控制（如 -k graceful）

	"reload":   true, // reload 信号参数
	"graceful": true, // Apache graceful 重载
	"restart":  true, // Apache restart
}

// argsWithValueParam 带值参数（下一个参数是值，跳过白名单检查）
var argsWithValueParam = map[string]bool{
	"-p": true, // -p <prefix_path>
	"-k": true, // -k <signal>（graceful/restart）
}

// ParseCommand 解析命令字符串为可执行文件和参数
func ParseCommand(cmdStr string) (string, []string) {
	parts := strings.Fields(cmdStr)
	if len(parts) == 0 {
		return "", nil
	}
	return parts[0], parts[1:]
}

// Run 执行命令（直接执行，不通过 shell）
// 使用白名单机制防止命令注入，默认超时 30 秒
func Run(cmdStr string) error {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()
	return RunContext(ctx, cmdStr)
}

// RunWithin 在父 ctx 之下执行命令，同时保留默认单命令上限。
// 直接把上游 ctx 交给 RunContext 会在上游无 deadline 时丢掉 30s 保护；
// 直接用 Run 又让上游取消无法中断命令。取二者更早者。
func RunWithin(ctx context.Context, cmdStr string) error {
	c, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()
	return RunContext(c, cmdStr)
}

// RunContext 执行命令（带 context 超时控制）
// 优先匹配静态白名单，不匹配时回退到动态路径校验（basename + args 白名单）
// 动态路径校验支持 nginx 安装在非标准路径的场景（如 /usr/local/nginx/sbin/nginx -t）
func RunContext(ctx context.Context, cmdStr string) error {
	if AllowedCommands[cmdStr] {
		executable, args := ParseCommand(cmdStr)
		cmd := exec.CommandContext(ctx, executable, args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s", err, string(output))
		}
		return nil
	}

	// docker exec 容器内重载：容器名做字符白名单校验，内层命令做固定白名单校验
	if container, inner, ok := parseDockerExec(cmdStr); ok {
		if !dockerContainerNameRe.MatchString(container) {
			return fmt.Errorf("invalid docker container name: %s", container)
		}
		if !allowedDockerInnerCommands[inner] {
			return fmt.Errorf("docker inner command not in whitelist: %s", inner)
		}
		args := append([]string{"exec", container}, strings.Fields(inner)...)
		cmd := exec.CommandContext(ctx, "docker", args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s", err, string(output))
		}
		return nil
	}

	// 回退：动态路径校验（复用 RunScan 的 basename + args 白名单机制）
	executable, args := ParseCommand(cmdStr)
	if executable != "" && len(args) > 0 {
		output, err := RunScanContext(ctx, executable, args...)
		if err != nil {
			return fmt.Errorf("%w: %s", err, string(output))
		}
		return nil
	}

	return fmt.Errorf("command not in whitelist: %s", cmdStr)
}

// IsAllowed 检查命令是否在白名单中
func IsAllowed(cmdStr string) bool {
	return AllowedCommands[cmdStr]
}

// RunOutput 执行命令并返回输出（直接执行，不通过 shell）
// 使用白名单机制防止命令注入，默认超时 30 秒
func RunOutput(cmdStr string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()
	return RunOutputContext(ctx, cmdStr)
}

// RunOutputContext 执行命令并返回输出（带 context 超时控制）
// 使用白名单机制防止命令注入
func RunOutputContext(ctx context.Context, cmdStr string) ([]byte, error) {
	if !AllowedCommands[cmdStr] {
		return nil, fmt.Errorf("command not in whitelist: %s", cmdStr)
	}

	executable, args := ParseCommand(cmdStr)
	cmd := exec.CommandContext(ctx, executable, args...)
	return cmd.CombinedOutput()
}

// RunScan 执行扫描命令（用于动态路径的可执行文件）
// 只允许预定义的可执行文件和参数组合，默认超时 30 秒
func RunScan(executable string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()
	return RunScanContext(ctx, executable, args...)
}

// RunScanContext 执行扫描命令（带 context 超时控制）
// 只允许预定义的可执行文件和参数组合
// executable: 可执行文件路径（如 nginx 或 /usr/sbin/nginx）
// args: 参数（如 -T）
func RunScanContext(ctx context.Context, executable string, args ...string) ([]byte, error) {
	// 检查可执行文件名（提取 basename）
	basename := executable
	if idx := strings.LastIndex(executable, "/"); idx >= 0 {
		basename = executable[idx+1:]
	}
	if idx := strings.LastIndex(basename, "\\"); idx >= 0 {
		basename = basename[idx+1:]
	}

	// 检查是否为允许的可执行文件
	if !AllowedScanExecutables[basename] && !AllowedScanExecutables[executable] {
		return nil, fmt.Errorf("executable not in scan whitelist: %s", executable)
	}

	// 检查参数是否允许
	for i := 0; i < len(args); i++ {
		if !AllowedScanArgs[args[i]] {
			return nil, fmt.Errorf("argument not in scan whitelist: %s", args[i])
		}
		// 带值参数（如 -p <path>）：跳过下一个参数的白名单检查
		if argsWithValueParam[args[i]] && i+1 < len(args) {
			i++
		}
	}

	cmd := exec.CommandContext(ctx, executable, args...)
	return cmd.CombinedOutput()
}

// RunDetached 后台启动进程（不等待退出）
// 仅用于 Windows 上重启非服务模式的 Web 服务器
func RunDetached(executable string, args ...string) error {
	basename := executable
	if idx := strings.LastIndexAny(basename, "/\\"); idx >= 0 {
		basename = basename[idx+1:]
	}
	if !AllowedScanExecutables[basename] && !AllowedScanExecutables[executable] {
		return fmt.Errorf("executable not in whitelist: %s", executable)
	}

	cmd := exec.Command(executable, args...)
	cmd.SysProcAttr = detachedProcAttr()
	return cmd.Start()
}
