package executor

import (
	"strconv"
	"strings"
)

type windowsProcess struct {
	PID            int
	ExecutablePath string
}

func parseWindowsProcessList(output string) []windowsProcess {
	var processes []windowsProcess
	for _, line := range strings.Split(output, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "|", 2)
		if len(parts) != 2 {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		path := strings.TrimSpace(parts[1])
		if err != nil || pid <= 0 {
			continue
		}
		processes = append(processes, windowsProcess{PID: pid, ExecutablePath: path})
	}
	return processes
}

func hasUnknownExecutablePath(processes []windowsProcess) bool {
	for _, process := range processes {
		if strings.TrimSpace(process.ExecutablePath) == "" {
			return true
		}
	}
	return false
}

func processIDsForExecutable(processes []windowsProcess, executable string) []int {
	target := normalizeWindowsExecutablePath(executable)
	if target == "" {
		return nil
	}
	var pids []int
	for _, process := range processes {
		if normalizeWindowsExecutablePath(process.ExecutablePath) == target {
			pids = append(pids, process.PID)
		}
	}
	return pids
}

func normalizeWindowsExecutablePath(path string) string {
	path = strings.TrimSpace(strings.Trim(path, `"`))
	path = strings.ReplaceAll(path, "/", `\`)
	return strings.ToLower(strings.TrimRight(path, `\`))
}
