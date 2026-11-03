package webserver

import "strings"

// extractServiceExePath 从 Windows 服务的 BinaryPathName 中提取实际 exe 路径。
// SCM 中常见格式：
//   - 带引号："C:\Program Files\App\bin.exe" -arg
//   - 不带引号：C:\App\bin.exe -arg
//
// 解析失败返回 ""。
func extractServiceExePath(binaryPath string) string {
	s := strings.TrimSpace(binaryPath)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, `"`) {
		end := strings.Index(s[1:], `"`)
		if end < 0 {
			return ""
		}
		return s[1 : 1+end]
	}
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i]
	}
	return s
}

// normalizeWindowsPath 规范化 Windows 路径以便大小写不敏感比较：
// 统一分隔符、合并重复反斜杠、去末尾反斜杠（保留 UNC 前缀和盘符根）、转小写。
// 不依赖 filepath.Clean，确保在非 Windows 平台编译/测试时行为一致。
func normalizeWindowsPath(p string) string {
	if p == "" {
		return ""
	}
	p = strings.ReplaceAll(p, "/", `\`)
	prefix := ""
	if strings.HasPrefix(p, `\\`) {
		prefix = `\\`
		p = p[2:]
	}
	for strings.Contains(p, `\\`) {
		p = strings.ReplaceAll(p, `\\`, `\`)
	}
	// 末尾反斜杠去掉（盘符根如 "C:\" 长度 3，跳过）
	if len(p) > 3 {
		p = strings.TrimRight(p, `\`)
	}
	return strings.ToLower(prefix + p)
}

func serviceExecutableMatchesTarget(serviceExecutable, targetExecutable string) bool {
	servicePath := normalizeWindowsPath(serviceExecutable)
	targetPath := normalizeWindowsPath(targetExecutable)
	return servicePath != "" && servicePath == targetPath
}
