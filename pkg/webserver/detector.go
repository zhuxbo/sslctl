// Package webserver Web 服务器检测
package webserver

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/zhuxbo/sslctl/internal/executor"
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

// DetectWebServerType 检测 Web 服务器类型并返回字符串（"nginx"、"apache" 或 ""）
// 优先检测 Nginx，因为它更常用
func DetectWebServerType() string {
	serverType := DetectLocalServer()
	switch serverType {
	case TypeNginx:
		return "nginx"
	case TypeApache:
		return "apache"
	default:
		return ""
	}
}

// DetectDockerServer 检测 Docker 中的 Web 服务器类型
// 注意：此函数使用 exec.Command 而非 executor，因为 docker exec 命令需要动态容器 ID，
// 无法放入静态白名单。安全性由 exec.Command 直接执行（非 shell）保证，避免命令注入。
func DetectDockerServer(containerID string) ServerType {
	// 长度限制：Docker ID 最长 64 字符，容器名最长 128 字符
	if len(containerID) == 0 || len(containerID) > 128 {
		return TypeUnknown
	}

	// 验证容器 ID 格式（仅允许字母数字和部分特殊字符）
	for _, c := range containerID {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.') {
			return TypeUnknown
		}
	}

	// 尝试检测 Nginx
	cmd := exec.Command("docker", "exec", containerID, "nginx", "-v")
	if cmd.Run() == nil {
		return TypeDockerNginx
	}

	// 尝试检测 Apache
	for _, apacheCmd := range []string{"httpd", "apache2", "apache2ctl", "apachectl"} {
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

	if runtime.GOOS == "windows" {
		// Windows: nginx 可安装在任意路径，通过进程检测最可靠
		// tasklist 是所有 Windows 版本内置命令，输出格式用 CSV 避免语言差异
		cmd := exec.Command("tasklist", "/FI", "IMAGENAME eq nginx.exe", "/FO", "CSV", "/NH")
		if output, err := cmd.Output(); err == nil {
			if strings.Contains(strings.ToLower(string(output)), "nginx.exe") {
				return true
			}
		}
		return false
	}

	// Linux/macOS: 检查常见安装路径
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

	// 兜底：检查进程是否在运行（处理非标准安装路径）
	if output, err := executor.RunOutput("ps -C nginx -o pid="); err == nil && len(strings.TrimSpace(string(output))) > 0 {
		return true
	}

	return false
}

// isApacheInstalled 检查 Apache 是否已安装
func isApacheInstalled() bool {
	// 检查命令是否存在
	apacheCommands := []string{"httpd", "apache2", "apache2ctl", "apachectl"}
	for _, cmd := range apacheCommands {
		if _, err := exec.LookPath(cmd); err == nil {
			return true
		}
	}

	if runtime.GOOS == "windows" {
		// Windows: 通过进程检测
		cmd := exec.Command("tasklist", "/FI", "IMAGENAME eq httpd.exe", "/FO", "CSV", "/NH")
		if output, err := cmd.Output(); err == nil {
			if strings.Contains(strings.ToLower(string(output)), "httpd.exe") {
				return true
			}
		}
		return false
	}

	// Linux/macOS: 检查常见安装路径
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

	// 兜底：检查进程是否在运行
	for _, name := range []string{"ps -C httpd -o pid=", "ps -C apache2 -o pid="} {
		if output, err := executor.RunOutput(name); err == nil && len(strings.TrimSpace(string(output))) > 0 {
			return true
		}
	}

	return false
}

// GetNginxConfigPath 获取 Nginx 配置文件路径
func GetNginxConfigPath() string {
	// 尝试从 nginx -t 输出获取
	// 优先使用动态路径（处理 Windows nginx 不在 PATH 或需要 -p 的情况）
	nginxBin := findNginxBin()
	var output []byte
	if filepath.IsAbs(nginxBin) {
		// 动态路径：构建带 -p 的参数
		args := []string{"-t"}
		if runtime.GOOS == "windows" {
			dir := filepath.Dir(nginxBin)
			if _, err := os.Stat(filepath.Join(dir, "conf", "nginx.conf")); err == nil {
				args = []string{"-p", dir + string(filepath.Separator), "-t"}
			}
		}
		output, _ = executor.RunScan(nginxBin, args...)
	}
	if len(output) == 0 {
		output, _ = executor.RunOutput("nginx -t")
	}

	if len(output) > 0 {
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
	}

	// 检查常见路径
	commonPaths := []string{
		"/etc/nginx/nginx.conf",
		"/usr/local/nginx/conf/nginx.conf",
		"/opt/nginx/conf/nginx.conf",
	}
	if runtime.GOOS == "windows" && filepath.IsAbs(nginxBin) {
		// Windows: 优先检查 nginx 安装目录
		commonPaths = append([]string{filepath.Join(filepath.Dir(nginxBin), "conf", "nginx.conf")}, commonPaths...)
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

// ServerCommands Web 服务器测试和重载命令
type ServerCommands struct {
	TestCmd   string // 配置测试命令，如 "nginx -t"
	ReloadCmd string // 服务重载命令，如 "nginx -s reload"
}

// WinSvcReloadPrefix 标识 ReloadCmd 走 Windows 服务重启路径的哨兵前缀。
// 完整形态：winsvc:<service-name>|<fallback-command>
// 由 internal/deployer.Base.ReloadService 解析：先尝试 SCM Stop+Start，
// SCM 失败时回退执行 fallback 命令、再失败走进程重启。
// 旧形态 winsvc:<service-name>（无 fallback）也兼容。
const WinSvcReloadPrefix = "winsvc:"

// WinSvcFallbackSep 哨兵串中"服务名"与"fallback 命令"的分隔符。
// 选用 '|' 是因为 nginx/apache reload 命令本身不会出现该字符。
const WinSvcFallbackSep = "|"

// DetectNginxCommands 检测当前系统可用的 Nginx 命令
// 查找 nginx 实际路径，避免 nginx 不在 PATH 时命令执行失败
// Windows 上自动添加 -p prefix（nginx 默认用当前目录作为 prefix）
// Windows 上若检测到 nginx 已注册为服务且与当前运行进程匹配，ReloadCmd 改为
// winsvc:<服务名>|<reload 命令> 哨兵；部署层先走 SCM 控制路径，失败时回退到
// reload 命令，避免误命中残留服务或 SCM 异常时无法部署。
func DetectNginxCommands() ServerCommands {
	return DetectNginxCommandsFor(findNginxBin())
}

// DetectNginxCommandsFor 为已经扫描到的 Nginx 实例生成命令。
// executable 非空时不得再次从 PATH 或运行进程选择另一套 Nginx。
func DetectNginxCommandsFor(executable string) ServerCommands {
	return detectNginxCommandsFor(executable, runtime.GOOS, findNginxBin, FindWebServerServiceForExecutable, FindWebServerService)
}

func detectNginxCommandsFor(executable, goos string, findBin func() string, findExact func(string, string) string, findService func(string, string) string) ServerCommands {
	nginxBin := executable
	if nginxBin == "" {
		nginxBin = findBin()
	}
	prefixArgs := getNginxPrefixArgs(nginxBin)
	reloadCmd := nginxBin + prefixArgs + " -s reload"
	cmds := ServerCommands{
		TestCmd:   nginxBin + prefixArgs + " -t",
		ReloadCmd: reloadCmd,
	}
	if goos == "windows" {
		var svc string
		if executable != "" {
			svc = findExact("nginx", nginxBin)
		} else {
			svc = findService("nginx", "nginx.exe")
		}
		if svc != "" {
			cmds.ReloadCmd = WinSvcReloadPrefix + svc + WinSvcFallbackSep + reloadCmd
		}
	}
	return cmds
}

// getNginxPrefixArgs 获取 nginx -p 参数（含前导空格）
// Windows 上 nginx 默认用当前工作目录作为 prefix，需显式指定 -p
// 返回 " -p D:\path\to\nginx\" 或 ""
func getNginxPrefixArgs(nginxBin string) string {
	if runtime.GOOS != "windows" || !filepath.IsAbs(nginxBin) {
		return ""
	}
	dir := filepath.Dir(nginxBin)
	confPath := filepath.Join(dir, "conf", "nginx.conf")
	if _, err := os.Stat(confPath); err == nil {
		return " -p " + dir + string(filepath.Separator)
	}
	return ""
}

// findNginxBin 查找 nginx 可执行文件路径
func findNginxBin() string {
	// 1. PATH 查找
	if path, err := exec.LookPath("nginx"); err == nil {
		return path
	}

	if runtime.GOOS == "windows" {
		// 从运行中的进程获取路径
		cmd := exec.Command("wmic", "process", "where", "name='nginx.exe'", "get", "ExecutablePath")
		if output, err := cmd.Output(); err == nil {
			for _, line := range strings.Split(string(output), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && line != "ExecutablePath" && strings.HasSuffix(strings.ToLower(line), "nginx.exe") {
					return line
				}
			}
		}
		// 常见安装路径
		paths := []string{
			`C:\nginx\nginx.exe`,
			`C:\Program Files\nginx\nginx.exe`,
		}
		// Windows 集成面板
		if matches, _ := filepath.Glob(`C:\phpstudy_pro\Extensions\Nginx*\nginx.exe`); len(matches) > 0 {
			paths = append(paths, matches...)
		}
		for _, p := range paths {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
		return "nginx"
	}

	// Linux/macOS: 检查常见路径
	for _, p := range []string{
		"/usr/sbin/nginx",
		"/usr/local/nginx/sbin/nginx",
		"/opt/nginx/sbin/nginx",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	// 从运行中的进程获取路径
	if output, err := executor.RunOutput("ps -C nginx -o pid="); err == nil {
		if pid := strings.TrimSpace(string(output)); pid != "" {
			pids := strings.Fields(pid)
			if len(pids) > 0 {
				if realPath, err := os.Readlink("/proc/" + pids[0] + "/exe"); err == nil {
					if _, err := os.Stat(realPath); err == nil {
						return realPath
					}
				}
			}
		}
	}

	return "nginx"
}

// DetectApacheCommands 检测当前系统可用的 Apache 命令
// 检测顺序：apache2ctl (Debian/Ubuntu) → apachectl (CentOS/RHEL/通用) → httpd (CentOS/RHEL) → 完整路径查找
// Windows 上若检测到 Apache 已注册为服务且与当前运行进程匹配，ReloadCmd 改为
// winsvc:<服务名>|<reload 命令> 哨兵；部署层先走 SCM，失败回退到 reload 命令。
func DetectApacheCommands() ServerCommands {
	cmds := detectApacheCommandsRaw()
	if runtime.GOOS == "windows" {
		if name := findApacheWindowsService(); name != "" {
			cmds.ReloadCmd = WinSvcReloadPrefix + name + WinSvcFallbackSep + cmds.ReloadCmd
		}
	}
	return cmds
}

// DetectDockerCommands 构建 Docker 容器内的测试/重载命令
// 命令通过 `docker exec <容器名> <Web 服务器命令>` 在容器内执行，
// 容器内 nginx/apache 二进制在标准 PATH 中，无需宿主机路径探测。
// containerName 为空或不符合 docker 命名规则时返回空命令，表示无法构建
// （调用方据此判定绑定不可部署）——与 executor 共用同一套容器名规则，
// 避免拼出必然被执行期白名单拒绝的命令。
func DetectDockerCommands(serverType ServerType, containerName string) ServerCommands {
	if !executor.IsValidDockerContainerName(containerName) {
		return ServerCommands{}
	}
	prefix := "docker exec " + containerName + " "
	if serverType == TypeDockerApache {
		return ServerCommands{
			TestCmd:   prefix + "apachectl -t",
			ReloadCmd: prefix + "apachectl graceful",
		}
	}
	// 默认按 docker-nginx 处理
	return ServerCommands{
		TestCmd:   prefix + "nginx -t",
		ReloadCmd: prefix + "nginx -s reload",
	}
}

// findApacheWindowsService 优先匹配二进制路径含 httpd 的服务，其次匹配 apache。
// 拆分两次匹配避免 nginx/apache 二进制路径互相误命中。
func findApacheWindowsService() string {
	if name := FindWebServerService("httpd", "httpd.exe"); name != "" {
		return name
	}
	return FindWebServerService("apache", "httpd.exe")
}

func detectApacheCommandsRaw() ServerCommands {
	// Debian/Ubuntu: apache2ctl
	if _, err := exec.LookPath("apache2ctl"); err == nil {
		return ServerCommands{
			TestCmd:   "apache2ctl -t",
			ReloadCmd: "apache2ctl graceful",
		}
	}

	// CentOS/RHEL/通用: apachectl
	if _, err := exec.LookPath("apachectl"); err == nil {
		return ServerCommands{
			TestCmd:   "apachectl -t",
			ReloadCmd: "apachectl graceful",
		}
	}

	// CentOS/RHEL: httpd
	if _, err := exec.LookPath("httpd"); err == nil {
		return ServerCommands{
			TestCmd:   "httpd -t",
			ReloadCmd: "httpd -k graceful",
		}
	}

	// PATH 中找不到，尝试完整路径查找（集成面板等非标准安装）
	if bin := findApacheBin(); bin != "apachectl" {
		return ServerCommands{
			TestCmd:   bin + " -t",
			ReloadCmd: bin + " -k graceful",
		}
	}

	// 回退默认值
	return ServerCommands{
		TestCmd:   "apachectl -t",
		ReloadCmd: "apachectl graceful",
	}
}

// findApacheBin 查找 Apache 可执行文件路径
func findApacheBin() string {
	if runtime.GOOS == "windows" {
		// 常见安装路径
		paths := []string{
			`C:\Apache24\bin\httpd.exe`,
			`C:\Apache\bin\httpd.exe`,
			`C:\Program Files\Apache24\bin\httpd.exe`,
			`C:\xampp\apache\bin\httpd.exe`,
		}
		// Windows 集成面板（路径含版本号，需 glob）
		if matches, _ := filepath.Glob(`C:\phpstudy_pro\Extensions\Apache*\bin\httpd.exe`); len(matches) > 0 {
			paths = append(paths, matches...)
		}
		for _, p := range paths {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}

		// 从进程查找
		cmd := exec.Command("wmic", "process", "where", "name='httpd.exe'", "get", "ExecutablePath")
		if output, err := cmd.Output(); err == nil {
			for _, line := range strings.Split(string(output), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && line != "ExecutablePath" && strings.HasSuffix(strings.ToLower(line), "httpd.exe") {
					return line
				}
			}
		}
		return "apachectl"
	}

	// Linux/macOS: 检查常见路径
	for _, p := range []string{
		"/usr/sbin/apachectl",
		"/usr/sbin/httpd",
		"/usr/local/apache2/bin/httpd",
		"/usr/local/apache2/bin/apachectl",
		"/www/server/apache/bin/httpd",
		"/www/server/apache/bin/apachectl",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return "apachectl"
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
