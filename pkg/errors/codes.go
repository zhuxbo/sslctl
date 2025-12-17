// Package errors 定义应用错误码
package errors

import "fmt"

// 错误码常量
const (
	CodeSuccess       = 0  // 成功
	CodeConfigError   = 10 // 配置错误
	CodeAuthError     = 20 // 认证失败
	CodeValidateError = 30 // 证书校验失败
	CodeWriteError    = 40 // 文件写入失败
	CodeReloadError   = 41 // Reload 失败
	CodeDeployError   = 42 // 部署错误
	CodeNetworkError  = 50 // 网络错误
	CodeUnknownError  = 99 // 未知错误
)

// AppError 应用错误类型
type AppError struct {
	Code    int
	Message string
	Err     error
}

// Error 实现 error 接口
func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("code=%d, msg=%s, err=%v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("code=%d, msg=%s", e.Code, e.Message)
}

// Unwrap 支持 errors.Is/As
func (e *AppError) Unwrap() error {
	return e.Err
}

// 便捷构造函数

func NewConfigError(msg string, err error) *AppError {
	return &AppError{Code: CodeConfigError, Message: msg, Err: err}
}

func NewAuthError(msg string, err error) *AppError {
	return &AppError{Code: CodeAuthError, Message: msg, Err: err}
}

func NewValidateError(msg string, err error) *AppError {
	return &AppError{Code: CodeValidateError, Message: msg, Err: err}
}

func NewWriteError(msg string, err error) *AppError {
	return &AppError{Code: CodeWriteError, Message: msg, Err: err}
}

func NewReloadError(msg string, err error) *AppError {
	return &AppError{Code: CodeReloadError, Message: msg, Err: err}
}

func NewNetworkError(msg string, err error) *AppError {
	return &AppError{Code: CodeNetworkError, Message: msg, Err: err}
}

func NewDeployError(msg string, err error) *AppError {
	return &AppError{Code: CodeDeployError, Message: msg, Err: err}
}
