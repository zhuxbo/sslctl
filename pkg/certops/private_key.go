// Package certops 私钥获取逻辑
package certops

import (
	"fmt"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/logger"
	"github.com/zhuxbo/sslctl/pkg/util"
)

// GetPrivateKey 统一获取私钥逻辑
// 优先使用 API 返回的私钥，否则从本地读取
// cert: 证书配置（包含绑定信息）
// apiPrivateKey: API 返回的私钥（可为空）
// log: 日志实例（可为 nil）
//
// 注意：返回的私钥以 string 类型传递，Go 的 string 不可变，GC 回收后内存中可能残留私钥数据。
// 本地读取的 []byte 原始数据会在转换后立即清零以减少内存中的副本数量。
// 设计说明：彻底解决需将整个私钥传递链改为 []byte，改动面大且 Go GC 仍不保证及时回收。
// 业界 Go 项目普遍接受此限制，当前 clear(keyData) 是在语言约束下的最佳努力。
func GetPrivateKey(cert *config.CertConfig, apiPrivateKey string, log *logger.Logger) (string, error) {
	// 优先使用 API 返回的私钥
	if apiPrivateKey != "" {
		return apiPrivateKey, nil
	}

	// 从绑定中获取私钥路径
	keyPath := pickKeyPath(cert)
	if keyPath == "" {
		return "", fmt.Errorf("缺少私钥路径")
	}

	// 使用安全读取函数，防止符号链接攻击和 TOCTOU
	keyData, err := util.SafeReadFile(keyPath, config.MaxPrivateKeySize)
	if err != nil {
		return "", fmt.Errorf("读取本地私钥失败: %w", err)
	}

	result := string(keyData)
	clear(keyData) // 清零原始字节切片，减少内存中私钥副本

	if log != nil {
		log.Debug("使用本地私钥: %s", keyPath)
	}

	return result, nil
}

// GetPrivateKeyFromBindings 从绑定列表获取私钥
// 用于 setup/deploy CLI 场景，直接传入绑定列表
// bindings: 站点绑定列表
// apiPrivateKey: API 返回的私钥（可为空）
//
// 注意：私钥内存残留风险同 GetPrivateKey
func GetPrivateKeyFromBindings(bindings []config.SiteBinding, apiPrivateKey string) (string, error) {
	// 优先使用 API 返回的私钥
	if apiPrivateKey != "" {
		return apiPrivateKey, nil
	}

	// 从绑定中获取私钥路径
	keyPath := pickKeyPathFromBindings(bindings)
	if keyPath == "" {
		return "", fmt.Errorf("缺少私钥路径")
	}

	// 使用安全读取函数，防止符号链接攻击和 TOCTOU
	keyData, err := util.SafeReadFile(keyPath, config.MaxPrivateKeySize)
	if err != nil {
		return "", fmt.Errorf("读取本地私钥失败: %w", err)
	}

	result := string(keyData)
	clear(keyData) // 清零原始字节切片

	return result, nil
}

// pickKeyPathFromBindings 从绑定列表选择私钥路径
// 优先选择已启用绑定的私钥路径
func pickKeyPathFromBindings(bindings []config.SiteBinding) string {
	for i := range bindings {
		// 使用值拷贝而非指针，与 DeployOne 保持一致
		binding := bindings[i]
		if binding.Enabled && binding.Paths.PrivateKey != "" {
			return binding.Paths.PrivateKey
		}
	}
	if len(bindings) > 0 {
		return bindings[0].Paths.PrivateKey
	}
	return ""
}
