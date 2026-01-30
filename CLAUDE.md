# cert-deploy

SSL 证书自动部署工具，Go 语言实现，支持 Nginx、Apache、Docker。

## 项目结构

```
cmd/           # CLI 入口
pkg/           # 可复用包（fetcher/config/backup/util/logger）
internal/      # 内部实现（nginx/apache 扫描/部署）
build/         # 构建/发布脚本
skills/        # 开发规范
```

## 核心命令

```bash
cert-deploy setup --url <url> --token <token> --domain <domain>  # 一键部署
cert-deploy scan                       # 扫描站点（自动检测 Web 服务器）
cert-deploy scan --ssl-only            # 仅扫描 SSL 站点
cert-deploy deploy --site example.com  # 部署证书
cert-deploy status                     # 查看服务状态
cert-deploy upgrade                    # 升级工具
cert-deploy uninstall                  # 卸载
```

## 测试

```bash
# Linux 发行版容器测试（需要 Docker）
bash build/test-linux.sh
```

测试覆盖：Ubuntu、Debian、AlmaLinux (systemd)、Alpine (OpenRC)、Devuan (SysVinit)

## 开发规范

详见 `skills/` 目录。
