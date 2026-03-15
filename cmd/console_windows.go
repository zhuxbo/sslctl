//go:build windows

package main

import (
	"golang.org/x/sys/windows"
)

func init() {
	setupWindowsConsole()
}

func setupWindowsConsole() {
	// 设置控制台编码为 UTF-8，解决中文乱码
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	setConsoleOutputCP := kernel32.NewProc("SetConsoleOutputCP")
	setConsoleCP := kernel32.NewProc("SetConsoleCP")
	setConsoleOutputCP.Call(65001)
	setConsoleCP.Call(65001)

	// 启用虚拟终端处理，支持 ANSI 转义序列（颜色输出）
	handle, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil {
		return
	}
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return
	}
	_ = windows.SetConsoleMode(handle, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
}
