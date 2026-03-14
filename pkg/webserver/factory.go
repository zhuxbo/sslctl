// Package webserver Web 服务器工厂
// 使用注册机制避免 pkg 依赖 internal
package webserver

import (
	"fmt"
	"sync"
)

var (
	scannerRegistry   = make(map[ServerType]ScannerFactory)
	deployerRegistry  = make(map[ServerType]DeployerFactory)
	installerRegistry = make(map[ServerType]InstallerFactory)
	registryMu        sync.RWMutex
)

// RegisterScanner 注册扫描器工厂（由 internal 包在 init 时调用）
func RegisterScanner(serverType ServerType, factory ScannerFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	scannerRegistry[serverType] = factory
}

// RegisterDeployer 注册部署器工厂（由 internal 包在 init 时调用）
func RegisterDeployer(serverType ServerType, factory DeployerFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	deployerRegistry[serverType] = factory
}

// RegisterInstaller 注册安装器工厂（由 internal 包在 init 时调用）
func RegisterInstaller(serverType ServerType, factory InstallerFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	installerRegistry[serverType] = factory
}

// NewInstaller 创建安装器
// Docker 类型回退到普通安装器（与 Deployer 一致）
func NewInstaller(serverType ServerType, configPath, certPath, keyPath, chainPath, serverName, testCmd string) (Installer, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()

	// Docker 类型回退到普通安装器
	baseType := serverType
	switch serverType {
	case TypeDockerNginx:
		baseType = TypeNginx
	case TypeDockerApache:
		baseType = TypeApache
	}

	factory, ok := installerRegistry[baseType]
	if !ok {
		return nil, fmt.Errorf("installer not registered for type: %s", serverType)
	}
	return factory(configPath, certPath, keyPath, chainPath, serverName, testCmd), nil
}

// NewScanner 创建扫描器
func NewScanner(serverType ServerType) (Scanner, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()

	// 统一处理 Docker 变体
	baseType := serverType
	switch serverType {
	case TypeDockerNginx:
		baseType = TypeNginx
	case TypeDockerApache:
		baseType = TypeApache
	}

	factory, ok := scannerRegistry[baseType]
	if !ok {
		return nil, fmt.Errorf("scanner not registered for type: %s", serverType)
	}
	return factory(), nil
}

// NewDeployer 创建部署器
// 注意：Docker 类型（docker-nginx, docker-apache）会回退到普通部署器。
// Docker 专用部署器（internal/nginx/docker）需要容器上下文，
// 应通过 docker.NewDeployer() 直接创建，不通过此工厂方法。
func NewDeployer(serverType ServerType, certPath, keyPath, chainPath, testCmd, reloadCmd string) (Deployer, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()

	// Docker 类型回退到普通部署器
	// Docker 专用部署器需要 Client 和 context，接口签名不同
	baseType := serverType
	switch serverType {
	case TypeDockerNginx:
		baseType = TypeNginx
	case TypeDockerApache:
		baseType = TypeApache
	}

	factory, ok := deployerRegistry[baseType]
	if !ok {
		return nil, fmt.Errorf("deployer not registered for type: %s", serverType)
	}
	return factory(certPath, keyPath, chainPath, testCmd, reloadCmd), nil
}

// ListRegisteredTypes 列出已注册的服务器类型（用于调试）
func ListRegisteredTypes() (scanners, deployers, installers []ServerType) {
	registryMu.RLock()
	defer registryMu.RUnlock()

	for t := range scannerRegistry {
		scanners = append(scanners, t)
	}
	for t := range deployerRegistry {
		deployers = append(deployers, t)
	}
	for t := range installerRegistry {
		installers = append(installers, t)
	}
	return
}
