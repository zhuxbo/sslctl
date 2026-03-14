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

// DeployErrorType 部署错误类型
type DeployErrorType int

const (
	DeployErrorUnknown    DeployErrorType = iota // 未知错误
	DeployErrorConfig                            // 配置错误（不可重试）
	DeployErrorPermission                        // 权限错误（不可重试）
	DeployErrorNetwork                           // 网络错误（可重试）
	DeployErrorValidation                        // 验证错误（不可重试）
	DeployErrorReload                            // 重载错误（可重试）
)

func (t DeployErrorType) String() string {
	switch t {
	case DeployErrorConfig:
		return "config"
	case DeployErrorPermission:
		return "permission"
	case DeployErrorNetwork:
		return "network"
	case DeployErrorValidation:
		return "validation"
	case DeployErrorReload:
		return "reload"
	default:
		return "unknown"
	}
}

// DeployPhase 部署阶段
type DeployPhase string

const (
	PhaseValidate   DeployPhase = "validate"     // 证书验证阶段
	PhaseBackup     DeployPhase = "backup"       // 备份阶段
	PhaseWriteCert  DeployPhase = "write_cert"   // 写入证书阶段
	PhaseWriteKey   DeployPhase = "write_key"    // 写入私钥阶段
	PhaseWriteChain DeployPhase = "write_chain"  // 写入证书链阶段
	PhaseTest       DeployPhase = "test_config"  // 测试配置阶段
	PhaseReload     DeployPhase = "reload"       // 重载服务阶段
	PhaseRollback   DeployPhase = "rollback"     // 回滚阶段
)

// StructuredDeployError 结构化部署错误
type StructuredDeployError struct {
	Type    DeployErrorType // 错误类型
	Phase   DeployPhase     // 发生阶段
	Message string          // 错误信息
	Cause   error           // 原始错误
}

func (e *StructuredDeployError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s:%s] %s: %v", e.Type, e.Phase, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s:%s] %s", e.Type, e.Phase, e.Message)
}

func (e *StructuredDeployError) Unwrap() error {
	return e.Cause
}

// Retryable 判断错误是否可重试
func (e *StructuredDeployError) Retryable() bool {
	switch e.Type {
	case DeployErrorNetwork, DeployErrorReload:
		return true
	default:
		return false
	}
}

// NewStructuredDeployError 创建结构化部署错误
func NewStructuredDeployError(errType DeployErrorType, phase DeployPhase, msg string, cause error) *StructuredDeployError {
	return &StructuredDeployError{
		Type:    errType,
		Phase:   phase,
		Message: msg,
		Cause:   cause,
	}
}
