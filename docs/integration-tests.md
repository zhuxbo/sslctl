# 集成测试方案

## 目标

覆盖证书获取、更新、部署、回调、续签等核心业务流，并提供可控的写入型测试开关，避免误操作生产数据。

## 环境配置

建议在仓库根目录维护 `.env` 文件（已加入 `.gitignore`），集成测试会自动加载。

必填变量：
- `TEST_API_URL`：部署 API 地址（例：`https://xxx/api/deploy`）
- `TEST_API_TOKEN`：部署 Token
- `TEST_API_DOMAIN`：用于校验的域名（例：`*.example.com`）

可选变量（写入型测试）：
- `TEST_API_ALLOW_WRITE=1`：允许调用更新接口
- `TEST_API_METHOD=http`：更新时的验证方式（默认 `http`）
- `TEST_API_DOMAINS`：更新时提交的域名列表（逗号分隔）
- `TEST_API_ALLOW_CALLBACK=1`：允许回调接口测试

## 覆盖的业务流

只读/安全测试（默认执行）：
- 获取证书信息（Info）
- 按域名查询（Query）
- 按订单号查询（QueryOrder）
- API 响应解析与字段格式校验
- 本地部署写入与权限校验
- 备份/回滚路径校验
- 扫描站点配置
- 续签流程（自动签发、本机提交）

写入型测试（需显式打开开关）：
- 更新/续费（Update + CSR 生成）
- 回调通知（CallbackNew）

## 运行方式

```bash
# 运行全部测试（包含集成测试，默认跳过写入型）
go test ./...

# 仅运行证书相关集成测试（只读）
go test ./pkg/certops -run TestIntegration

# 启用写入型集成测试（Update/Callback）
TEST_API_ALLOW_WRITE=1 TEST_API_ALLOW_CALLBACK=1 go test ./pkg/certops -run TestIntegration
```

## 风险控制

- 写入型测试必须显式设置 `TEST_API_ALLOW_WRITE=1`，否则自动跳过。
- 回调测试需额外设置 `TEST_API_ALLOW_CALLBACK=1`。
- 不建议在生产环境执行写入型测试。

