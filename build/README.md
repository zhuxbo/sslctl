# 构建与发布

## 脚本说明

| 脚本 | 用途 |
|------|------|
| `build.sh` | 构建多平台二进制 |
| `git-release.sh` | 更新版本号、打 tag |
| `local-release.sh` | 发布到本地目录 |
| `remote-release.sh` | 发布到远程服务器 |

## 远程发布

### 服务器配置

1. **添加 release 用户**
```bash
useradd -m -s /bin/bash release
```

2. **配置 SSH 密钥**
```bash
mkdir -p /home/release/.ssh
cat >> /home/release/.ssh/authorized_keys << 'EOF'
ssh-ed25519 AAAA... your-key
EOF
chmod 700 /home/release/.ssh
chmod 600 /home/release/.ssh/authorized_keys
chown -R release:release /home/release/.ssh
```

3. **创建发布目录并设置权限**
```bash
mkdir -p /www/wwwroot/cert-deploy-cn.cnssl.com
chown -R release:release /www/wwwroot/cert-deploy-cn.cnssl.com
```

4. **安装 Python3**（用于更新 releases.json）
```bash
apt install python3  # Debian/Ubuntu
yum install python3  # CentOS/RHEL
```

### 本地配置

1. 复制配置文件
```bash
cp remote-release.conf.example remote-release.conf
chmod 600 remote-release.conf
```

2. 编辑 `remote-release.conf`，配置服务器列表和 SSH 密钥

### 发布命令

```bash
# 测试连接
./remote-release.sh --test

# 发布指定版本
./remote-release.sh 0.0.1-beta

# 只发布到指定服务器
./remote-release.sh --server cn 0.0.1-beta

# 跳过构建，只上传
./remote-release.sh --upload-only 0.0.1-beta
```

### 发布通道

- `stable`: 正式版（如 `1.0.0`）
- `dev`: 开发版（如 `0.0.1-beta`、`1.0.0-rc1`）

版本号包含 `-` 时自动归入 dev 通道。
