// Package webserver Web 服务器检测
package webserver

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DetectLocalServer 检测本地 Web 服务器类型
func DetectLocalServer() ServerType {
	// 检测 Nginx
	if isNginxInstalled() {
		return TypeNginx
	}

	// 检测 Apache
	if isApacheInstalled() {
		return TypeApache
	}

	return TypeUnknown
}

// DetectDockerServer 检测 Docker 中的 Web 服务器类型
func DetectDockerServer(containerID string) ServerType {
	// 尝试检测 Nginx
	cmd := exec.Command("docker", "exec", containerID, "nginx", "-v")
	if cmd.Run() == nil {
		return TypeDockerNginx
	}

	// 尝试检测 Apache
	for _, apacheCmd := range []string{"httpd", "apache2", "apache2ctl"} {
		cmd = exec.Command("docker", "exec", containerID, apacheCmd, "-v")
		if cmd.Run() == nil {
			return TypeDockerApache
		}
	}

	return TypeUnknown
}

// isNginxInstalled 检查 Nginx 是否已安装
func isNginxInstalled() bool {
	// 检查命令是否存在
	if _, err := exec.LookPath("nginx"); err == nil {
		return true
	}

	// 检查常见安装路径
	nginxPaths := []string{
		"/usr/sbin/nginx",
		"/usr/local/nginx/sbin/nginx",
		"/opt/nginx/sbin/nginx",
	}

	for _, p := range nginxPaths {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}

	return false
}

// isApacheInstalled 检查 Apache 是否已安装
func isApacheInstalled() bool {
	// 检查命令是否存在
	apacheCommands := []string{"httpd", "apache2", "apache2ctl"}
	for _, cmd := range apacheCommands {
		if _, err := exec.LookPath(cmd); err == nil {
			return true
		}
	}

	// 检查常见安装路径
	apachePaths := []string{
		"/usr/sbin/httpd",
		"/usr/sbin/apache2",
		"/opt/apache/bin/httpd",
	}

	for _, p := range apachePaths {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}

	return false
}

// GetNginxConfigPath 获取 Nginx 配置文件路径
func GetNginxConfigPath() string {
	// 尝试从 nginx -t 输出获取
	cmd := exec.Command("nginx", "-t")
	output, _ := cmd.CombinedOutput()
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "configuration file") {
			parts := strings.Split(line, " ")
			for _, part := range parts {
				if strings.HasSuffix(part, ".conf") {
					return strings.TrimSpace(part)
				}
			}
		}
	}

	// 检查常见路径
	commonPaths := []string{
		"/etc/nginx/nginx.conf",
		"/usr/local/nginx/conf/nginx.conf",
		"/opt/nginx/conf/nginx.conf",
	}

	for _, p := range commonPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return ""
}

// GetApacheConfigPath 获取 Apache 配置文件路径
func GetApacheConfigPath() string {
	// 检查常见路径
	commonPaths := []string{
		"/etc/httpd/conf/httpd.conf",
		"/etc/apache2/apache2.conf",
		"/opt/apache/conf/httpd.conf",
	}

	for _, p := range commonPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return ""
}

// GetNginxSitesDir 获取 Nginx 站点配置目录
func GetNginxSitesDir() string {
	// 检查常见目录
	commonDirs := []string{
		"/etc/nginx/sites-enabled",
		"/etc/nginx/conf.d",
		"/usr/local/nginx/conf/conf.d",
	}

	for _, d := range commonDirs {
		if info, err := os.Stat(d); err == nil && info.IsDir() {
			return d
		}
	}

	// 回退到主配置目录
	configPath := GetNginxConfigPath()
	if configPath != "" {
		return filepath.Dir(configPath)
	}

	return ""
}

// GetApacheSitesDir 获取 Apache 站点配置目录
func GetApacheSitesDir() string {
	// 检查常见目录
	commonDirs := []string{
		"/etc/httpd/conf.d",
		"/etc/apache2/sites-enabled",
		"/opt/apache/conf/extra",
	}

	for _, d := range commonDirs {
		if info, err := os.Stat(d); err == nil && info.IsDir() {
			return d
		}
	}

	return ""
}
