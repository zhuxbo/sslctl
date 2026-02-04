// Package executor 命令执行器（白名单机制）
package executor

import (
	"fmt"
	"os/exec"
	"strings"
)

// AllowedCommands 允许的命令白名单（支持多发行版和 Windows）
var AllowedCommands = map[string]bool{
	// ========== Nginx 扫描命令 ==========
	"nginx -V":                true, // 获取版本信息
	"nginx -T":                true, // 获取合并配置

	// ========== Nginx 部署命令 ==========
	// Linux - 通用
	"nginx -t":                true,
	"nginx -s reload":         true,
	// Linux - systemd (Ubuntu/Debian/CentOS 7+/RHEL 7+/Fedora)
	"systemctl reload nginx":  true,
	"systemctl restart nginx": true,
	// Linux - SysVinit (CentOS 6/旧系统)
	"service nginx reload":   true,
	"service nginx restart":  true,
	// Linux - OpenRC (Alpine/Gentoo)
	"rc-service nginx reload":  true,
	"rc-service nginx restart": true,
	// Linux - 直接信号
	"/usr/sbin/nginx -s reload": true,
	// Windows - Nginx
	"net stop nginx":             true,
	"net start nginx":            true,
	"C:\\nginx\\nginx.exe -t":        true,
	"C:\\nginx\\nginx.exe -s reload": true,

	// ========== Apache 命令 ==========
	// Linux - apachectl (通用)
	"apachectl -t":        true,
	"apachectl graceful":  true,
	"apachectl restart":   true,
	// Linux - apache2ctl (Debian/Ubuntu)
	"apache2ctl -t":       true,
	"apache2ctl graceful": true,
	"apache2ctl restart":  true,
	// Linux - httpd (CentOS/RHEL/Fedora)
	"httpd -t": true,
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
	"ps -C nginx -o pid=": true, // 查找 nginx 进程
	"ss -tlnp":            true, // 查看监听端口
	"netstat -tlnp":       true, // 查看监听端口（备用）
}

// AllowedScanExecutables 扫描器允许的可执行文件（用于动态路径）
var AllowedScanExecutables = map[string]bool{
	"nginx":          true,
	"nginx.exe":      true,
	"/usr/sbin/nginx": true,
}

// AllowedScanArgs 扫描器允许的参数组合
var AllowedScanArgs = map[string]bool{
	"-t": true, // 测试配置
	"-T": true, // 获取合并配置
	"-V": true, // 获取版本信息
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
// 使用白名单机制防止命令注入
func Run(cmdStr string) error {
	if !AllowedCommands[cmdStr] {
		return fmt.Errorf("command not in whitelist: %s", cmdStr)
	}

	executable, args := ParseCommand(cmdStr)
	cmd := exec.Command(executable, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(output))
	}

	return nil
}

// IsAllowed 检查命令是否在白名单中
func IsAllowed(cmdStr string) bool {
	return AllowedCommands[cmdStr]
}

// RunOutput 执行命令并返回输出（直接执行，不通过 shell）
// 使用白名单机制防止命令注入
func RunOutput(cmdStr string) ([]byte, error) {
	if !AllowedCommands[cmdStr] {
		return nil, fmt.Errorf("command not in whitelist: %s", cmdStr)
	}

	executable, args := ParseCommand(cmdStr)
	cmd := exec.Command(executable, args...)
	return cmd.CombinedOutput()
}

// RunScan 执行扫描命令（用于动态路径的可执行文件）
// 只允许预定义的可执行文件和参数组合
// executable: 可执行文件路径（如 nginx 或 /usr/sbin/nginx）
// args: 参数（如 -T）
func RunScan(executable string, args ...string) ([]byte, error) {
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
	for _, arg := range args {
		if !AllowedScanArgs[arg] {
			return nil, fmt.Errorf("argument not in scan whitelist: %s", arg)
		}
	}

	cmd := exec.Command(executable, args...)
	return cmd.CombinedOutput()
}
