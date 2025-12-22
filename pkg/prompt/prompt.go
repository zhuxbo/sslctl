// Package prompt 提供交互式命令行输入功能
package prompt

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"
)

var reader = bufio.NewReader(os.Stdin)

// IsInteractive 检查是否在交互式终端中运行
func IsInteractive() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// Confirm 确认提示，默认 Yes
// 返回 true 表示用户确认，false 表示取消
func Confirm(message string) bool {
	if !IsInteractive() {
		return false
	}

	fmt.Printf("%s [Y/n]: ", message)
	input, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	input = strings.TrimSpace(strings.ToLower(input))
	return input == "" || input == "y" || input == "yes"
}

// ConfirmDefault 确认提示，可指定默认值
func ConfirmDefault(message string, defaultYes bool) bool {
	if !IsInteractive() {
		return defaultYes
	}

	hint := "[Y/n]"
	if !defaultYes {
		hint = "[y/N]"
	}

	fmt.Printf("%s %s: ", message, hint)
	input, err := reader.ReadString('\n')
	if err != nil {
		return defaultYes
	}

	input = strings.TrimSpace(strings.ToLower(input))
	if input == "" {
		return defaultYes
	}
	return input == "y" || input == "yes"
}

// Select 选择列表，返回选中索引 (0-based)
// 如果非交互模式，返回 -1
func Select(message string, options []string) int {
	if !IsInteractive() || len(options) == 0 {
		return -1
	}

	fmt.Println()
	for i, opt := range options {
		fmt.Printf("  %d. %s\n", i+1, opt)
	}
	fmt.Println()

	for {
		fmt.Printf("%s [1-%d]: ", message, len(options))
		input, err := reader.ReadString('\n')
		if err != nil {
			return -1
		}

		idx, err := strconv.Atoi(strings.TrimSpace(input))
		if err == nil && idx >= 1 && idx <= len(options) {
			return idx - 1
		}
		fmt.Println("请输入有效数字")
	}
}

// SelectWithCancel 选择列表，支持取消选项
// 返回 -1 表示取消
func SelectWithCancel(message string, options []string) int {
	if !IsInteractive() || len(options) == 0 {
		return -1
	}

	fmt.Println()
	for i, opt := range options {
		fmt.Printf("  %d. %s\n", i+1, opt)
	}
	fmt.Printf("  0. 取消\n")
	fmt.Println()

	for {
		fmt.Printf("%s [0-%d]: ", message, len(options))
		input, err := reader.ReadString('\n')
		if err != nil {
			return -1
		}

		idx, err := strconv.Atoi(strings.TrimSpace(input))
		if err == nil && idx >= 0 && idx <= len(options) {
			if idx == 0 {
				return -1
			}
			return idx - 1
		}
		fmt.Println("请输入有效数字")
	}
}

// Input 文本输入，支持默认值
func Input(message, defaultVal string) string {
	if !IsInteractive() {
		return defaultVal
	}

	if defaultVal != "" {
		fmt.Printf("%s [%s]: ", message, defaultVal)
	} else {
		fmt.Printf("%s: ", message)
	}

	input, err := reader.ReadString('\n')
	if err != nil {
		return defaultVal
	}

	input = strings.TrimSpace(input)
	if input == "" {
		return defaultVal
	}
	return input
}

// InputRequired 必填文本输入
func InputRequired(message string) string {
	if !IsInteractive() {
		return ""
	}

	for {
		fmt.Printf("%s: ", message)
		input, err := reader.ReadString('\n')
		if err != nil {
			return ""
		}

		input = strings.TrimSpace(input)
		if input != "" {
			return input
		}
		fmt.Println("此项为必填")
	}
}

// InputPath 路径输入，验证文件是否存在
func InputPath(message, defaultVal string, mustExist bool) string {
	if !IsInteractive() {
		return defaultVal
	}

	for {
		var input string
		if defaultVal != "" {
			fmt.Printf("%s [%s]: ", message, defaultVal)
		} else {
			fmt.Printf("%s: ", message)
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			return defaultVal
		}

		input = strings.TrimSpace(line)
		if input == "" {
			input = defaultVal
		}

		if input == "" {
			if mustExist {
				fmt.Println("此项为必填")
				continue
			}
			return ""
		}

		if mustExist {
			if _, err := os.Stat(input); os.IsNotExist(err) {
				fmt.Printf("文件不存在: %s\n", input)
				continue
			}
		}

		return input
	}
}
