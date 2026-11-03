// Package certops 私钥获取逻辑
package certops

import (
	"context"
	"fmt"
	"github.com/zhuxbo/sslctl/internal/nginx/docker"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/logger"
	"github.com/zhuxbo/sslctl/pkg/util"
	"github.com/zhuxbo/sslctl/pkg/validator"
)

// GetPrivateKey 统一获取私钥逻辑
// 优先使用 API 返回的私钥，否则从绑定的实际部署位置读取
// cert: 证书配置（包含绑定信息）
// apiPrivateKey: API 返回的私钥（可为空）
// log: 日志实例（可为 nil）
//
// 注意：返回的私钥以 string 类型传递，Go 的 string 不可变，GC 回收后内存中可能残留私钥数据。
// 本地读取的 []byte 原始数据会在转换后立即清零以减少内存中的副本数量。
// 设计说明：彻底解决需将整个私钥传递链改为 []byte，改动面大且 Go GC 仍不保证及时回收。
// 业界 Go 项目普遍接受此限制，当前 clear(keyData) 是在语言约束下的最佳努力。
func GetPrivateKey(ctx context.Context, cert *config.CertConfig, apiPrivateKey string, log *logger.Logger) (string, error) {
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
	keyData, err := ReadBindingPrivateKey(ctx, pickKeyBinding(cert))
	if err != nil {
		return "", fmt.Errorf("读取已有私钥失败: %w", err)
	}

	result := consumePrivateKey(keyData)

	if log != nil {
		log.Debug("使用绑定私钥: %s", keyPath)
	}

	return result, nil
}

// GetPrivateKeyForCert 获取与目标证书配对的私钥（pending 感知）。
// 优先级：API 返回的私钥 → 正式位置私钥（配对校验通过）→ pending-keys/ 待确认私钥（配对校验通过才用）。
// 场景：local 续签签发成功但当日部署全部失败时，pending 私钥尚未转正（规范 3.8 部署成功后才转正），
// 正式位置仍是旧私钥；重试/手动部署若只读正式位置会与新证书配对必败，须能回退到 pending 私钥补救。
// certPEM 为空时退化为原有行为（读正式位置，不做配对校验）。
// 使用 pending 私钥部署成功后，调用方应通过 CommitPendingKeyIfMatches 补转正。
func GetPrivateKeyForCert(ctx context.Context, workDir string, cert *config.CertConfig, certPEM, apiPrivateKey string, log *logger.Logger) (string, error) {
	// 优先使用 API 返回的私钥
	if apiPrivateKey != "" {
		return apiPrivateKey, nil
	}

	formalKey, formalErr := GetPrivateKey(ctx, cert, "", log)

	// 无证书内容时无法校验配对，保持原有行为
	if certPEM == "" {
		return formalKey, formalErr
	}

	v := validator.New("")
	if formalErr == nil {
		if err := v.ValidateCertKeyPair(certPEM, formalKey); err == nil {
			return formalKey, nil
		}
	}

	if hasDockerCopyBinding(cert) {
		for i := range cert.Bindings {
			binding := &cert.Bindings[i]
			if !binding.Enabled || binding == pickKeyBinding(cert) {
				continue
			}
			data, err := ReadBindingPrivateKey(ctx, binding)
			candidate := consumePrivateKey(data)
			if err == nil && v.ValidateCertKeyPair(certPEM, candidate) == nil {
				return candidate, nil
			}
		}
	}

	// 正式私钥缺失或与目标证书不配对：尝试 pending 私钥（续签部署全失败后未转正的场景）
	if pendingKey, pendingErr := readPendingKey(workDir, cert.CertName); pendingErr == nil {
		if err := v.ValidateCertKeyPair(certPEM, pendingKey); err == nil {
			if log != nil {
				log.Info("证书 %s 正式私钥与目标证书不配对，使用 pending 私钥（部署成功后将转正）", cert.CertName)
			}
			return pendingKey, nil
		}
	}

	if formalErr != nil {
		return "", formalErr
	}
	return "", fmt.Errorf("证书 %s 的正式私钥与目标证书不配对，且无可用的 pending 私钥", cert.CertName)
}

// ReadBindingPrivateKey 从绑定实际部署的位置读取私钥，copy 路径只在容器内解释。
func ReadBindingPrivateKey(ctx context.Context, binding *config.SiteBinding) ([]byte, error) {
	if binding == nil {
		return nil, fmt.Errorf("缺少私钥绑定")
	}
	if config.IsDockerCopyBinding(binding) {
		client, err := docker.NewRunningClient(ctx, binding.Docker.ContainerName)
		if err != nil {
			return nil, err
		}
		file, err := client.ReadRegularFile(ctx, binding.Paths.PrivateKey, config.MaxPrivateKeySize)
		return file.Data, err
	}
	return util.ReadCertificateFile(binding.Paths.PrivateKey, config.MaxPrivateKeySize)
}

func pickKeyBinding(cert *config.CertConfig) *config.SiteBinding {
	for i := range cert.Bindings {
		if cert.Bindings[i].Enabled && cert.Bindings[i].Paths.PrivateKey != "" {
			return &cert.Bindings[i]
		}
	}
	if len(cert.Bindings) > 0 {
		return &cert.Bindings[0]
	}
	return nil
}

func hasDockerCopyBinding(cert *config.CertConfig) bool {
	for i := range cert.Bindings {
		if cert.Bindings[i].Enabled && config.IsDockerCopyBinding(&cert.Bindings[i]) {
			return true
		}
	}
	return false
}

// consumePrivateKey 在取得独立字符串后清零读取缓冲区，供各取钥入口共用。
func consumePrivateKey(data []byte) string {
	key := string(data)
	clear(data)
	return key
}

// matchPrivateKeyAndClear 比较后立即清零缓冲区，不保留额外私钥字符串。
func matchPrivateKeyAndClear(data []byte, expected string) bool {
	matches := string(data) == expected
	clear(data)
	return matches
}
