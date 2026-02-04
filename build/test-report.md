# sslctl Linux 测试报告

生成时间: 2026-01-30 11:32:57

## 测试环境

- 主机系统: Linux 6.8.0-90-generic
- Docker 版本: 29.1.3
- 测试架构: amd64

## 测试结果

| 发行版 | Init | TC-01 | TC-02 | TC-03 | TC-04 | TC-05 | TC-06 |
|--------|------|-------|-------|-------|-------|-------|-------|
| ubuntu | systemd | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| debian | systemd | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| almalinux | systemd | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| alpine | openrc | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| devuan | sysvinit | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

## 总结

- 通过: 30/30
- 失败: 0/30

## 测试用例说明

| 编号 | 名称 | 描述 |
|------|------|------|
| TC-01 | 安装测试 | 验证二进制安装、服务创建和自启动 |
| TC-02 | status 命令 | 验证版本和状态显示 |
| TC-03 | service repair | 验证服务修复功能 |
| TC-04 | upgrade --check | 验证升级检查功能 |
| TC-05 | uninstall | 验证标准卸载 |
| TC-06 | uninstall --purge | 验证完全卸载 |
