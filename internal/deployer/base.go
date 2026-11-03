// Package deployer 提供部署器公共功能
package deployer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/zhuxbo/sslctl/internal/executor"
	"github.com/zhuxbo/sslctl/pkg/errors"
	"github.com/zhuxbo/sslctl/pkg/util"
	"github.com/zhuxbo/sslctl/pkg/webserver"
)

// restartWindowsServiceFunc 包一层方便测试替换；默认调用 webserver.RestartWindowsService。
var restartWindowsServiceFunc = webserver.RestartWindowsService

// reloadFallbackCommandFunc winsvc 哨兵 SCM 失败后执行 fallback 命令的钩子，
// 默认指向 runReloadCommandWindows，测试时可替换以避免触达 executor。
var reloadFallbackCommandFunc = runReloadCommandWindows

var (
	listProcessIDsByExecutableFunc = executor.ListProcessIDsByExecutable
	terminateProcessByPIDFunc      = executor.TerminateProcessByPID
)

// Config 部署器配置
type Config struct {
	CertPath      string // 证书文件路径
	KeyPath       string // 私钥文件路径
	ChainPath     string // 中间证书链路径（仅 Apache）
	TestCommand   string // 配置测试命令
	ReloadCommand string // 服务重载命令
}

// Base 部署器基础功能
type Base struct {
	certificateFiles map[string]*util.CertificateFile
	TestCommand      string
	ReloadCommand    string
}

// TestConfig 测试配置
func (b *Base) TestConfig(ctx context.Context) error {
	if b.TestCommand == "" {
		return nil
	}
	return executor.RunWithin(ctx, b.TestCommand)
}

// NeedsProcessRestart 检测是否需要通过进程重启方式重载（Windows 非服务模式）
// 返回 true 时部署过程会短暂中断服务
// 注意：若 ReloadCommand 是 winsvc: 哨兵（已识别为 Windows 服务），走 SCM 路径
// 也会有 stop+start 的短暂中断，因此一并视为需要进程级重启。
func (b *Base) NeedsProcessRestart() bool {
	if runtime.GOOS != "windows" || b.ReloadCommand == "" {
		return false
	}
	if strings.HasPrefix(b.ReloadCommand, webserver.WinSvcReloadPrefix) {
		return true
	}
	// 尝试执行 reload 命令的 dry run：解析命令但不执行，
	// 通过命令特征判断是否依赖服务注册（-k graceful / -s reload）
	cmd := b.ReloadCommand
	return strings.Contains(cmd, "-k ") || strings.Contains(cmd, "-s reload")
}

// ReloadService 重载服务
// 优先使用服务管理命令；失败时尝试回退策略：
//   - Windows 已识别为服务（winsvc: 哨兵）：先走 SCM Stop+Start；失败则回退执行
//     哨兵中编入的 reload 命令，再失败走进程重启
//   - Linux 容器环境（无 systemd）：优先发送 SIGUSR1 并等待新 generation；失败再执行 reload 命令
//   - Windows 非服务模式：reload 命令失败时回退到进程重启
func (b *Base) ReloadService(ctx context.Context) error {
	if b.ReloadCommand == "" {
		return nil
	}

	// Windows 服务路径：detector 已识别 nginx/apache 为 Windows 服务
	if strings.HasPrefix(b.ReloadCommand, webserver.WinSvcReloadPrefix) {
		return b.reloadWinSvc(ctx)
	}

	// docker exec 重载命令直接在容器内执行，宿主机侧的 SIGUSR1/进程重启回退不适用
	// （Apache/nginx master 进程在容器内，宿主机没有对应进程）
	if executor.IsDockerExecCommand(b.ReloadCommand) {
		return executor.RunWithin(ctx, b.ReloadCommand)
	}

	// Linux 容器环境预检：如果 systemd 不可用且命令涉及 httpd/apache，
	// 先尝试通过 SIGUSR1 信号 reload（避免 httpd -k graceful 因无 dbus 导致进程异常退出）
	if runtime.GOOS != "windows" && !isSystemdAvailable() && b.isApacheReload() {
		if err := b.reloadFallbackLinux(ctx); err == nil {
			return nil
		}
	}

	if runtime.GOOS == "windows" {
		return runReloadCommandWindows(ctx, b.ReloadCommand, nil)
	}
	return executor.RunWithin(ctx, b.ReloadCommand)
}

// parseWinSvcSentinel 解析 winsvc:<service-name>[|<fallback>] 哨兵串。
// 兼容旧形态 winsvc:<service-name>（无 fallback）。
func parseWinSvcSentinel(s string) (svcName, fallback string) {
	rest := strings.TrimPrefix(s, webserver.WinSvcReloadPrefix)
	if i := strings.Index(rest, webserver.WinSvcFallbackSep); i >= 0 {
		return rest[:i], rest[i+1:]
	}
	return rest, ""
}

// reloadWinSvc 处理 winsvc: 哨兵：
//  1. 先尝试 SCM Stop+Start
//  2. 失败时回退执行 fallback 命令（nginx -s reload / httpd -k graceful）
//  3. 命令仍失败且属于已知白名单错误，走进程重启
//
// 三层失败时返回最后一步的错误，并在错误链中保留前置 SCM 错误以便排查。
func (b *Base) reloadWinSvc(ctx context.Context) error {
	svcName, fallback := parseWinSvcSentinel(b.ReloadCommand)
	if svcName == "" {
		if fallback != "" {
			return runReloadCommandWindows(ctx, fallback, nil)
		}
		return fmt.Errorf("invalid winsvc sentinel: %s", b.ReloadCommand)
	}
	scmErr := restartWindowsServiceFunc(ctx, svcName)
	if scmErr == nil {
		return nil
	}
	if fallback == "" {
		return scmErr
	}
	return reloadFallbackCommandFunc(ctx, fallback, scmErr)
}

// runReloadCommandWindows 在 Windows 上执行 reload 命令；失败时按已知白名单错误
// 回退到进程重启（taskkill+守护进程拉起+手动启动）。
//
// prevErr 为可选的前置错误（如 SCM 失败错误），返回错误时一起带回上下文，
// 但不影响白名单判定（白名单只看 reload 命令本身的错误信息）。
func runReloadCommandWindows(ctx context.Context, reloadCmd string, prevErr error) error {
	err := executor.RunWithin(ctx, reloadCmd)
	if err == nil {
		return nil
	}
	msg := err.Error()
	// "Access is denied" 兜底：调用方与 nginx/apache master 进程权限不一致时
	// （典型：master 由 SYSTEM 启动，sslctl 由 Administrator 调用），
	// OpenEvent 会被 Windows 拒绝；此时 reload 命令必败，进程重启可恢复。
	if !strings.Contains(msg, "No installed service") &&
		!strings.Contains(msg, "could not open error log") &&
		!strings.Contains(msg, "Access is denied") {
		return wrapWithPrev(err, prevErr)
	}
	exe, args := executor.ParseCommand(reloadCmd)
	if exe == "" {
		return wrapWithPrev(err, prevErr)
	}
	if rerr := restartProcessWindows(ctx, exe, args, err); rerr != nil {
		return wrapWithPrev(rerr, prevErr)
	}
	return nil
}

// wrapWithPrev 把前置错误（如 SCM 失败）附加到主错误信息后面，方便排查。
func wrapWithPrev(err, prev error) error {
	if prev == nil {
		return err
	}
	return fmt.Errorf("%w（前置 SCM 错误：%v）", err, prev)
}

// isSystemdAvailable 检测 systemd 是否可用（通过 /run/systemd/system 目录判断）
func isSystemdAvailable() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

// isApacheReload 检查 reload 命令是否与 Apache 相关
func (b *Base) isApacheReload() bool {
	cmd := strings.ToLower(b.ReloadCommand)
	return strings.Contains(cmd, "httpd") || strings.Contains(cmd, "apache")
}

// reloadFallbackLinux 在 Linux 容器中通过 SIGUSR1 信号实现 Apache graceful reload
func (b *Base) reloadFallbackLinux(ctx context.Context) error {
	exe, _ := executor.ParseCommand(b.ReloadCommand)
	if exe == "" {
		return fmt.Errorf("cannot parse reload command: %s", b.ReloadCommand)
	}
	// apachectl/apache2ctl 是 shell wrapper，实际进程名是 httpd/apache2
	processName := apacheProcessName(filepath.Base(exe))

	// 通过 /proc 扫描查找 master 进程 PID（不依赖 pidof 等外部命令）
	pid := findMasterPIDByName(processName)
	if pid <= 0 {
		return fmt.Errorf("process %s not found", processName)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process %d: %w", pid, err)
	}
	childrenBefore := childPIDs(pid)

	// 发送 SIGUSR1（Apache: graceful restart）
	if err := signalUSR1(proc); err != nil {
		return fmt.Errorf("send SIGUSR1 to %d: %w", pid, err)
	}

	// SIGUSR1 只负责通知 master，信号发送成功不代表 graceful reload 已完成。
	// 必须等到新一代 worker 出现后再允许下一绑定改写另一组证书文件；否则
	// Apache 可能在读取配置时撞上“新私钥 + 旧证书”的瞬时状态并退出。
	if err := waitForApacheReload(ctx, pid, childrenBefore, apacheReloadTimeout); err != nil {
		return fmt.Errorf("wait for apache reload: %w", err)
	}
	return nil
}

// Apache graceful reload 等待参数。
// graceful 会立即 fork 新一代 worker，正常情况下毫秒级完成；期限取得宽裕些，
// 避免负载高的机器上把"只是慢"误判成 reload 失败而触发回滚——回滚会再改写一次
// 证书文件，比多等一会儿更容易制造错配。
const (
	apacheReloadTimeout      = 15 * time.Second
	apacheReloadPollInterval = 50 * time.Millisecond
)

// waitForApacheReload 等待 Apache master 创建至少一个新 worker，证明 graceful
// reload 已读取完配置并进入新 generation。master 退出或超时均按 reload 失败处理
// （静默放行会掩盖真正没 reload 成功的情况，让站点挂着旧证书却报部署成功）。
func waitForApacheReload(ctx context.Context, masterPID int, childrenBefore map[int]struct{}, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("wait aborted: %w", err)
		}
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", masterPID)); err != nil {
			return fmt.Errorf("apache master %d exited", masterPID)
		}
		if hasNewPID(childrenBefore, childPIDs(masterPID)) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("apache master %d did not create a new worker within %s", masterPID, timeout)
		}
		time.Sleep(apacheReloadPollInterval)
	}
}

func hasNewPID(before, after map[int]struct{}) bool {
	for pid := range after {
		if _, exists := before[pid]; !exists {
			return true
		}
	}
	return false
}

// childPIDs 返回 parentPID 的直接子进程集合。
// 优先读 /proc/<pid>/task/<pid>/children：内核直接给出子进程列表，一次读取即可；
// 该文件需要 CONFIG_PROC_CHILDREN，不可用时回退到扫描整个 /proc——后者要逐个读取
// 所有进程的 status，在进程数多的机器上每轮轮询开销显著，仅作兜底。
func childPIDs(parentPID int) map[int]struct{} {
	if children, ok := childPIDsFromProcChildren(parentPID); ok {
		return children
	}
	return childPIDsByScan(parentPID)
}

// childPIDsFromProcChildren 读取 /proc/<pid>/task/<pid>/children（空格分隔的 PID 列表）
func childPIDsFromProcChildren(parentPID int) (map[int]struct{}, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", parentPID, parentPID))
	if err != nil {
		return nil, false
	}
	children := make(map[int]struct{})
	for _, field := range strings.Fields(string(data)) {
		if pid, err := strconv.Atoi(field); err == nil {
			children[pid] = struct{}{}
		}
	}
	return children, true
}

// childPIDsByScan 扫描 /proc 逐个比对 PPid（兜底路径）
func childPIDsByScan(parentPID int) map[int]struct{} {
	children := make(map[int]struct{})
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return children
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(status), "\n") {
			if !strings.HasPrefix(line, "PPid:") {
				continue
			}
			ppid, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
			if err == nil && ppid == parentPID {
				children[pid] = struct{}{}
			}
			break
		}
	}
	return children
}

// apacheProcessName 将 apachectl/apache2ctl 等 wrapper 脚本名映射到实际进程名
func apacheProcessName(name string) string {
	switch name {
	case "apachectl", "apache2ctl":
		// 尝试 httpd 和 apache2 两种可能的进程名
		if findMasterPIDByName("httpd") > 0 {
			return "httpd"
		}
		return "apache2"
	default:
		return name
	}
}

// findMasterPIDByName 通过扫描 /proc 查找指定进程名的 master 进程 PID
// 优先返回 PPID=1 的进程（master），否则返回最小 PID（通常是 master）
func findMasterPIDByName(name string) int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}

	minPID := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(comm)) != name {
			continue
		}

		// 检查 PPID：master 进程的 PPID 通常是 1（init/容器入口）
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err == nil {
			for _, line := range strings.Split(string(status), "\n") {
				if strings.HasPrefix(line, "PPid:") {
					ppidStr := strings.TrimSpace(strings.TrimPrefix(line, "PPid:"))
					if ppid, _ := strconv.Atoi(ppidStr); ppid <= 1 {
						return pid // PPID=0 或 1，确定是 master
					}
					break
				}
			}
		}

		// 记录最小 PID 作为后备
		if minPID == 0 || pid < minPID {
			minPID = pid
		}
	}
	return minPID
}

// restartProcessWindows 通过终止进程+重启实现重载（适用于 Apache/Nginx 非服务模式）
// 流程：终止进程 → 等待退出 → 等守护进程自动拉起 → 否则手动启动
func restartProcessWindows(ctx context.Context, exe string, reloadArgs []string, origErr error) error {
	// 提取进程名（如 httpd.exe、nginx.exe）
	processName := filepath.Base(exe)
	if !isAbsoluteWindowsExecutablePath(exe) {
		return fmt.Errorf("拒绝按进程名重启 %s：无法确定目标可执行文件的绝对路径（原始错误: %v）", processName, origErr)
	}

	// 只终止目标可执行路径对应的进程，避免多套 Nginx/Apache 共存时误杀其他实例。
	fmt.Fprintf(os.Stderr, "正在停止 %s 进程...\n", processName)
	if err := stopExecutableProcesses(ctx, exe); err != nil {
		return fmt.Errorf("停止目标进程失败: %w（原始错误: %v）", err, origErr)
	}

	// 等待进程退出（最多 10 秒）
	stopped := false
	for i := 0; i < 20; i++ {
		time.Sleep(500 * time.Millisecond)
		running, err := isExecutableRunning(ctx, exe)
		if err != nil {
			return fmt.Errorf("确认目标进程退出失败: %w", err)
		}
		if !running {
			stopped = true
			break
		}
	}
	if !stopped {
		return fmt.Errorf("目标进程在等待停止后仍运行: %s", exe)
	}

	// 等待守护进程自动拉起（面板等管理工具），最多 10 秒
	fmt.Fprintf(os.Stderr, "等待 %s 重新启动...\n", processName)
	for i := 0; i < 10; i++ {
		time.Sleep(time.Second)
		running, err := isExecutableRunning(ctx, exe)
		if err != nil {
			return fmt.Errorf("确认目标进程恢复失败: %w", err)
		}
		if running {
			fmt.Fprintf(os.Stderr, "%s 已恢复运行\n", processName)
			return nil
		}
	}

	// 守护进程未拉起，手动启动
	fmt.Fprintf(os.Stderr, "守护进程未自动拉起，手动启动 %s...\n", processName)
	args := restartProcessArgs(exe, reloadArgs)
	if strings.Contains(strings.ToLower(processName), "httpd") {
		if !containsCommandArg(args, "-d") {
			// Apache 需要 -d 指定 ServerRoot
			serverRoot := filepath.Dir(filepath.Dir(exe))
			args = append(args, "-d", serverRoot)
		}
	}
	if startErr := executor.RunDetached(exe, args...); startErr != nil {
		return fmt.Errorf("重启失败: %w（原始错误: %v）", startErr, origErr)
	}

	// 确认启动成功
	time.Sleep(2 * time.Second)
	running, err := isExecutableRunning(ctx, exe)
	if err != nil {
		return fmt.Errorf("确认目标进程启动失败: %w", err)
	}
	if !running {
		return fmt.Errorf("进程启动后退出（原始错误: %v）", origErr)
	}
	return nil
}

func stopExecutableProcesses(ctx context.Context, executable string) error {
	pids, err := listProcessIDsByExecutableFunc(ctx, executable)
	if err != nil {
		return err
	}
	for _, pid := range pids {
		if err := terminateProcessByPIDFunc(ctx, pid); err != nil {
			return err
		}
	}
	return nil
}

func isExecutableRunning(ctx context.Context, executable string) (bool, error) {
	probeCtx, cancel := context.WithTimeout(ctx, processProbeTimeout)
	defer cancel()
	pids, err := listProcessIDsByExecutableFunc(probeCtx, executable)
	return len(pids) > 0, err
}

func isAbsoluteWindowsExecutablePath(path string) bool {
	if filepath.IsAbs(path) {
		return true
	}
	return len(path) >= 3 && path[1] == ':' && (path[2] == '\\' || path[2] == '/')
}

// restartProcessArgs 去掉 reload 信号参数，保留 -p/-d 等实例定位参数。
func restartProcessArgs(_ string, reloadArgs []string) []string {
	args := make([]string, 0, len(reloadArgs))
	for i := 0; i < len(reloadArgs); i++ {
		arg := reloadArgs[i]
		if (arg == "-s" || arg == "-k") && i+1 < len(reloadArgs) {
			i++
			continue
		}
		args = append(args, arg)
	}
	return args
}

func containsCommandArg(args []string, target string) bool {
	for _, arg := range args {
		if arg == target {
			return true
		}
	}
	return false
}

// TestAndReload 测试配置并重载服务
func (b *Base) TestAndReload(ctx context.Context) error {
	if err := b.CheckFiles(); err != nil {
		return err
	}
	if err := b.TestConfig(ctx); err != nil {
		return errors.NewStructuredDeployError(
			errors.DeployErrorConfig, errors.PhaseTest,
			"config test failed", err,
		)
	}
	if err := b.CheckFiles(); err != nil {
		return err
	}
	if err := b.ReloadService(ctx); err != nil {
		return errors.NewStructuredDeployError(
			errors.DeployErrorReload, errors.PhaseReload,
			"reload failed", err,
		)
	}
	return b.CheckFiles()
}

// TestAndReloadForRollback 回滚后测试配置并重载服务
func (b *Base) TestAndReloadForRollback(ctx context.Context) error {
	if err := b.CheckFiles(); err != nil {
		return err
	}
	if b.TestCommand != "" {
		if err := executor.RunWithin(ctx, b.TestCommand); err != nil {
			return errors.NewStructuredDeployError(
				errors.DeployErrorConfig, errors.PhaseRollback,
				"config test failed after rollback", err,
			)
		}
	}
	if b.ReloadCommand != "" {
		if err := b.CheckFiles(); err != nil {
			return err
		}
		if err := b.ReloadService(ctx); err != nil {
			return errors.NewStructuredDeployError(
				errors.DeployErrorReload, errors.PhaseRollback,
				"reload failed after rollback", err,
			)
		}
	}
	return b.CheckFiles()
}

// processProbeTimeout 单次进程探测超时。
// tasklist 在 WMI 异常或域环境下可能长时间不返回，而它被重载等待循环反复调用，
// 无超时会让整个部署卡死在这里。
const processProbeTimeout = 5 * time.Second

// RestoreFile 恢复单个文件
func RestoreFile(backupPath, targetPath string) error {
	return util.CopyFile(backupPath, targetPath)
}
