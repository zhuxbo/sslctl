# sslctl Skills

本目录包含项目开发规范和知识库，按领域组织。

## Skill 列表

| Skill | 目录 | 触发场景 |
|-------|------|---------|
| Go 开发 | `go-dev/` | Go 代码、包结构、错误处理 |
| Nginx/Apache | `nginx-apache/` | 配置解析、证书部署、服务重载 |
| 部署运维 | `deploy-ops/` | Linux 部署、systemd、daemon 模式 |
| 构建发布 | `build-release/` | 版本发布、交叉编译、CI/CD |

## 使用方式

根据当前任务类型，读取对应 skill 获取详细规范：

```
skills/go-dev/SKILL.md         # Go 开发任务
skills/nginx-apache/SKILL.md   # Nginx/Apache 相关任务
skills/deploy-ops/SKILL.md     # 部署运维任务
skills/build-release/SKILL.md  # 构建发布任务
```

## 知识积累

开发过程中遇到以下情况时，将信息写入对应 skill：

- 发现新的架构约定或设计模式
- 解决了疑难问题（记录原因和解决方案）
- 确定了最佳实践
- 发现文档中缺失的重要信息

写入规则：

- 只记录已确定且经过验证的信息
- 保持简洁，避免冗余
- 按对应领域写入正确的 skill 文件
