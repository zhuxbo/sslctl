// Package errors 错误码测试
package errors

import (
	"errors"
	"testing"
)

// TestAppError_Error 测试错误消息格式化
func TestAppError_Error(t *testing.T) {
	// 无底层错误
	err := &AppError{
		Code:    CodeConfigError,
		Message: "配置文件不存在",
		Err:     nil,
	}
	errStr := err.Error()
	if errStr == "" {
		t.Error("Error() 不应返回空字符串")
	}
	if !containsAll(errStr, "code=10", "配置文件不存在") {
		t.Errorf("Error() = %s, 应包含 code 和 message", errStr)
	}

	// 有底层错误
	baseErr := errors.New("file not found")
	err = &AppError{
		Code:    CodeWriteError,
		Message: "写入失败",
		Err:     baseErr,
	}
	errStr = err.Error()
	if !containsAll(errStr, "code=40", "写入失败", "file not found") {
		t.Errorf("Error() = %s, 应包含 code、message 和底层错误", errStr)
	}
}

// TestAppError_Unwrap 测试错误解包
func TestAppError_Unwrap(t *testing.T) {
	baseErr := errors.New("base error")
	appErr := &AppError{
		Code:    CodeNetworkError,
		Message: "网络错误",
		Err:     baseErr,
	}

	// 测试 Unwrap
	unwrapped := appErr.Unwrap()
	if unwrapped != baseErr {
		t.Error("Unwrap() 应返回底层错误")
	}

	// 测试 errors.Is
	if !errors.Is(appErr, baseErr) {
		t.Error("errors.Is 应匹配底层错误")
	}

	// 无底层错误时
	appErr2 := &AppError{Code: CodeAuthError, Message: "认证失败"}
	if appErr2.Unwrap() != nil {
		t.Error("无底层错误时 Unwrap() 应返回 nil")
	}
}

// TestNewConfigError 测试配置错误构造
func TestNewConfigError(t *testing.T) {
	baseErr := errors.New("invalid format")
	err := NewConfigError("配置格式错误", baseErr)

	if err.Code != CodeConfigError {
		t.Errorf("Code = %d, 期望 %d", err.Code, CodeConfigError)
	}
	if err.Message != "配置格式错误" {
		t.Errorf("Message = %s, 期望 配置格式错误", err.Message)
	}
	if err.Err != baseErr {
		t.Error("Err 应为传入的底层错误")
	}
}

// TestNewAuthError 测试认证错误构造
func TestNewAuthError(t *testing.T) {
	err := NewAuthError("token 无效", nil)

	if err.Code != CodeAuthError {
		t.Errorf("Code = %d, 期望 %d", err.Code, CodeAuthError)
	}
	if err.Message != "token 无效" {
		t.Errorf("Message = %s", err.Message)
	}
}

// TestNewValidateError 测试验证错误构造
func TestNewValidateError(t *testing.T) {
	err := NewValidateError("证书已过期", nil)

	if err.Code != CodeValidateError {
		t.Errorf("Code = %d, 期望 %d", err.Code, CodeValidateError)
	}
}

// TestNewWriteError 测试写入错误构造
func TestNewWriteError(t *testing.T) {
	err := NewWriteError("权限不足", nil)

	if err.Code != CodeWriteError {
		t.Errorf("Code = %d, 期望 %d", err.Code, CodeWriteError)
	}
}

// TestNewReloadError 测试重载错误构造
func TestNewReloadError(t *testing.T) {
	err := NewReloadError("nginx 配置错误", nil)

	if err.Code != CodeReloadError {
		t.Errorf("Code = %d, 期望 %d", err.Code, CodeReloadError)
	}
}

// TestNewNetworkError 测试网络错误构造
func TestNewNetworkError(t *testing.T) {
	err := NewNetworkError("连接超时", nil)

	if err.Code != CodeNetworkError {
		t.Errorf("Code = %d, 期望 %d", err.Code, CodeNetworkError)
	}
}

// TestNewDeployError 测试部署错误构造
func TestNewDeployError(t *testing.T) {
	err := NewDeployError("部署失败", nil)

	if err.Code != CodeDeployError {
		t.Errorf("Code = %d, 期望 %d", err.Code, CodeDeployError)
	}
}

// TestErrorCodes 测试错误码常量
func TestErrorCodes(t *testing.T) {
	tests := []struct {
		name     string
		code     int
		expected int
	}{
		{"CodeSuccess", CodeSuccess, 0},
		{"CodeConfigError", CodeConfigError, 10},
		{"CodeAuthError", CodeAuthError, 20},
		{"CodeValidateError", CodeValidateError, 30},
		{"CodeWriteError", CodeWriteError, 40},
		{"CodeReloadError", CodeReloadError, 41},
		{"CodeDeployError", CodeDeployError, 42},
		{"CodeNetworkError", CodeNetworkError, 50},
		{"CodeUnknownError", CodeUnknownError, 99},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.code != tt.expected {
				t.Errorf("%s = %d, 期望 %d", tt.name, tt.code, tt.expected)
			}
		})
	}
}

// TestAllErrorConstructors 测试所有错误构造函数
func TestAllErrorConstructors(t *testing.T) {
	baseErr := errors.New("test error")

	constructors := []struct {
		name     string
		fn       func(string, error) *AppError
		expected int
	}{
		{"NewConfigError", NewConfigError, CodeConfigError},
		{"NewAuthError", NewAuthError, CodeAuthError},
		{"NewValidateError", NewValidateError, CodeValidateError},
		{"NewWriteError", NewWriteError, CodeWriteError},
		{"NewReloadError", NewReloadError, CodeReloadError},
		{"NewNetworkError", NewNetworkError, CodeNetworkError},
		{"NewDeployError", NewDeployError, CodeDeployError},
	}

	for _, tc := range constructors {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.fn("test message", baseErr)
			if err.Code != tc.expected {
				t.Errorf("Code = %d, 期望 %d", err.Code, tc.expected)
			}
			if err.Message != "test message" {
				t.Errorf("Message = %s", err.Message)
			}
			if err.Err != baseErr {
				t.Error("Err 应为传入的底层错误")
			}
		})
	}
}

// TestStructuredDeployError_Error 测试结构化部署错误格式化
func TestStructuredDeployError_Error(t *testing.T) {
	// 有 Cause
	cause := errors.New("permission denied")
	err := NewStructuredDeployError(DeployErrorPermission, PhaseWriteCert, "写入证书失败", cause)
	errStr := err.Error()
	if !containsAll(errStr, "permission", "write_cert", "写入证书失败", "permission denied") {
		t.Errorf("Error() = %s, 应包含类型、阶段、消息和原因", errStr)
	}

	// 无 Cause
	err2 := NewStructuredDeployError(DeployErrorConfig, PhaseValidate, "配置无效", nil)
	errStr2 := err2.Error()
	if !containsAll(errStr2, "config", "validate", "配置无效") {
		t.Errorf("Error() = %s, 应包含类型、阶段和消息", errStr2)
	}
	// 无 Cause 时不应包含多余的 ": <nil>"
	if containsAll(errStr2, "<nil>") {
		t.Errorf("Error() 无 Cause 时不应包含 <nil>: %s", errStr2)
	}
}

// TestStructuredDeployError_Unwrap 测试结构化部署错误解包
func TestStructuredDeployError_Unwrap(t *testing.T) {
	cause := errors.New("network timeout")
	err := NewStructuredDeployError(DeployErrorNetwork, PhaseReload, "重载失败", cause)

	// Unwrap 应返回 Cause
	if err.Unwrap() != cause {
		t.Error("Unwrap() 应返回 Cause")
	}

	// errors.Is 应能匹配
	if !errors.Is(err, cause) {
		t.Error("errors.Is 应匹配 Cause")
	}

	// 无 Cause 时 Unwrap 返回 nil
	err2 := NewStructuredDeployError(DeployErrorConfig, PhaseValidate, "test", nil)
	if err2.Unwrap() != nil {
		t.Error("无 Cause 时 Unwrap() 应返回 nil")
	}
}

// TestStructuredDeployError_Retryable 测试可重试判断
func TestStructuredDeployError_Retryable(t *testing.T) {
	tests := []struct {
		name      string
		errType   DeployErrorType
		retryable bool
	}{
		{"Network 可重试", DeployErrorNetwork, true},
		{"Reload 可重试", DeployErrorReload, true},
		{"Config 不可重试", DeployErrorConfig, false},
		{"Permission 不可重试", DeployErrorPermission, false},
		{"Validation 不可重试", DeployErrorValidation, false},
		{"Unknown 不可重试", DeployErrorUnknown, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewStructuredDeployError(tt.errType, PhaseReload, "test", nil)
			if err.Retryable() != tt.retryable {
				t.Errorf("Retryable() = %v, 期望 %v", err.Retryable(), tt.retryable)
			}
		})
	}
}

// TestDeployErrorType_String 测试所有部署错误类型的字符串表示
func TestDeployErrorType_String(t *testing.T) {
	tests := []struct {
		errType DeployErrorType
		want    string
	}{
		{DeployErrorUnknown, "unknown"},
		{DeployErrorConfig, "config"},
		{DeployErrorPermission, "permission"},
		{DeployErrorNetwork, "network"},
		{DeployErrorValidation, "validation"},
		{DeployErrorReload, "reload"},
		{DeployErrorType(999), "unknown"}, // 未知枚举值
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.errType.String()
			if got != tt.want {
				t.Errorf("DeployErrorType(%d).String() = %s, 期望 %s", tt.errType, got, tt.want)
			}
		})
	}
}

// TestDeployPhase_Values 测试部署阶段常量值
func TestDeployPhase_Values(t *testing.T) {
	phases := map[DeployPhase]string{
		PhaseValidate:   "validate",
		PhaseBackup:     "backup",
		PhaseWriteCert:  "write_cert",
		PhaseWriteKey:   "write_key",
		PhaseWriteChain: "write_chain",
		PhaseTest:       "test_config",
		PhaseReload:     "reload",
		PhaseRollback:   "rollback",
	}

	for phase, want := range phases {
		if string(phase) != want {
			t.Errorf("Phase %s 值 = %s, 期望 %s", phase, string(phase), want)
		}
	}
}

// TestNewStructuredDeployError 测试结构化部署错误构造
func TestNewStructuredDeployError(t *testing.T) {
	cause := errors.New("test error")
	err := NewStructuredDeployError(DeployErrorNetwork, PhaseReload, "重载超时", cause)

	if err.Type != DeployErrorNetwork {
		t.Errorf("Type = %v, 期望 DeployErrorNetwork", err.Type)
	}
	if err.Phase != PhaseReload {
		t.Errorf("Phase = %v, 期望 PhaseReload", err.Phase)
	}
	if err.Message != "重载超时" {
		t.Errorf("Message = %s, 期望 重载超时", err.Message)
	}
	if err.Cause != cause {
		t.Error("Cause 不匹配")
	}
}

// TestStructuredDeployError_ErrorsAs 测试 errors.As 类型断言
func TestStructuredDeployError_ErrorsAs(t *testing.T) {
	cause := errors.New("base")
	err := NewStructuredDeployError(DeployErrorPermission, PhaseWriteKey, "权限不足", cause)

	// 将其作为 error 接口传递
	var target *StructuredDeployError
	if !errors.As(err, &target) {
		t.Error("errors.As 应能匹配 *StructuredDeployError")
	}
	if target.Type != DeployErrorPermission {
		t.Error("类型断言后 Type 不匹配")
	}
}

// containsAll 检查字符串是否包含所有子串
func containsAll(s string, substrs ...string) bool {
	for _, sub := range substrs {
		found := false
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
