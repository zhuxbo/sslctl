// Package deployer 定义部署器接口
package deployer

// Deployer 部署器接口
type Deployer interface {
	// Deploy 部署证书
	// cert: 服务器证书 PEM
	// intermediate: 中间证书 PEM
	// key: 私钥 PEM
	Deploy(cert, intermediate, key string) error
}

// RollbackableDeployer 支持回滚的部署器接口
type RollbackableDeployer interface {
	Deployer
	// Rollback 回滚到备份的证书
	// backupPaths: 备份文件路径 (certPath, keyPath, [chainPath])
	Rollback(backupPaths ...string) error
}
