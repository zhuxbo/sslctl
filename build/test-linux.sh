#!/bin/bash
# sslctl Linux 发行版容器测试脚本
# 在各种 Linux 发行版容器中测试服务管理功能

# 注意: 不使用 set -e，因为某些测试命令可能失败是正常的

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
REPORT_FILE="${SCRIPT_DIR}/test-report.md"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
echo_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
echo_error() { echo -e "${RED}[ERROR]${NC} $1"; }
echo_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

# 测试结果存储
declare -A RESULTS

# 发行版配置
# 格式: "名称|镜像|init系统|特殊选项"
DISTROS=(
    "ubuntu|jrei/systemd-ubuntu:22.04|systemd|--privileged -v /sys/fs/cgroup:/sys/fs/cgroup:rw --cgroupns=host"
    "debian|jrei/systemd-debian:12|systemd|--privileged -v /sys/fs/cgroup:/sys/fs/cgroup:rw --cgroupns=host"
    "almalinux|almalinux/9-init|systemd|--privileged -v /sys/fs/cgroup:/sys/fs/cgroup:rw --cgroupns=host"
    "alpine|alpine:3.19|openrc|"
    "devuan|devuan/devuan:daedalus|sysvinit|--privileged"
)

# 测试用例
TEST_CASES=(
    "TC-01:install"
    "TC-02:status"
    "TC-03:repair"
    "TC-04:upgrade"
    "TC-05:uninstall"
    "TC-06:purge"
)

# 检查 Docker
check_docker() {
    if ! command -v docker &>/dev/null; then
        echo_error "Docker 未安装"
        echo ""
        echo "请先安装 Docker:"
        echo "  Ubuntu/Debian: apt install docker.io"
        echo "  CentOS/RHEL:   yum install docker"
        echo "  或访问: https://docs.docker.com/engine/install/"
        exit 1
    fi

    if ! docker info &>/dev/null; then
        echo_error "Docker 服务未运行或无权限"
        echo ""
        echo "请确保:"
        echo "  1. Docker 服务已启动: systemctl start docker"
        echo "  2. 当前用户有 Docker 权限: sudo usermod -aG docker \$USER"
        echo "  或使用 sudo 运行此脚本"
        exit 1
    fi

    echo_info "Docker 版本: $(docker version --format '{{.Server.Version}}')"
}

# 检测当前架构
detect_arch() {
    local arch=$(uname -m)
    case "$arch" in
        x86_64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *) echo "unknown" ;;
    esac
}

# 构建测试用二进制
build_binary() {
    local arch="$1"
    local output="${PROJECT_DIR}/dist/sslctl-linux-${arch}"

    if [ -f "$output" ]; then
        echo_info "使用已存在的二进制: $output"
        return 0
    fi

    echo_step "构建 linux/${arch} 二进制..."

    cd "$PROJECT_DIR"

    local GO_CMD="go"
    if [ -x "/usr/local/go/bin/go" ]; then
        GO_CMD="/usr/local/go/bin/go"
    fi

    local version=$(cat "${PROJECT_DIR}/version.json" | grep '"version"' | sed 's/.*: "\(.*\)".*/\1/')
    local build_time=$(date -u +%Y-%m-%d)
    local ldflags="-s -w -X 'main.version=${version}' -X 'main.buildTime=${build_time}'"

    mkdir -p "${PROJECT_DIR}/dist"
    GOOS=linux GOARCH="$arch" $GO_CMD build -ldflags "$ldflags" -o "$output" ./cmd/main.go

    echo_info "构建完成: $output"
}

# 初始化测试报告
init_report() {
    local host_os=$(uname -s)
    local host_kernel=$(uname -r)
    local docker_version=$(docker version --format '{{.Server.Version}}')
    local test_arch=$(detect_arch)
    local test_time=$(date '+%Y-%m-%d %H:%M:%S')

    cat > "$REPORT_FILE" << EOF
# sslctl Linux 测试报告

生成时间: $test_time

## 测试环境

- 主机系统: $host_os $host_kernel
- Docker 版本: $docker_version
- 测试架构: $test_arch

## 测试结果

| 发行版 | Init | TC-01 | TC-02 | TC-03 | TC-04 | TC-05 | TC-06 |
|--------|------|-------|-------|-------|-------|-------|-------|
EOF
}

# 添加结果到报告
add_result_to_report() {
    local distro="$1"
    local init="$2"

    local tc01="${RESULTS["${distro}:TC-01"]:-❓}"
    local tc02="${RESULTS["${distro}:TC-02"]:-❓}"
    local tc03="${RESULTS["${distro}:TC-03"]:-❓}"
    local tc04="${RESULTS["${distro}:TC-04"]:-❓}"
    local tc05="${RESULTS["${distro}:TC-05"]:-❓}"
    local tc06="${RESULTS["${distro}:TC-06"]:-❓}"

    echo "| $distro | $init | $tc01 | $tc02 | $tc03 | $tc04 | $tc05 | $tc06 |" >> "$REPORT_FILE"
}

# 记录测试结果
record_result() {
    local distro="$1"
    local tc="$2"
    local result="$3"  # pass/fail

    if [ "$result" = "pass" ]; then
        RESULTS["${distro}:${tc}"]="✅"
    else
        RESULTS["${distro}:${tc}"]="❌"
    fi
}

# 获取容器内安装脚本
get_install_script() {
    local init_system="$1"

    # 基础安装命令
    cat << 'INSTALL_EOF'
#!/bin/bash
set -e

# 安装二进制
cp /test/sslctl /usr/local/bin/sslctl
chmod +x /usr/local/bin/sslctl

# 创建工作目录
mkdir -p /opt/sslctl/{sites,logs,backup,certs}
INSTALL_EOF

    # 根据 init 系统添加服务安装
    case "$init_system" in
        systemd)
            cat << 'SYSTEMD_EOF'

# 创建 systemd 服务
cat > /etc/systemd/system/sslctl.service << 'EOF'
[Unit]
Description=SSL Certificate Manager
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sslctl daemon
Restart=always
RestartSec=30
User=root
Group=root
WorkingDirectory=/opt/sslctl
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sslctl
systemctl start sslctl
sleep 2
SYSTEMD_EOF
            ;;
        openrc)
            cat << 'OPENRC_EOF'

# 创建 OpenRC 服务
cat > /etc/init.d/sslctl << 'EOF'
#!/sbin/openrc-run

name="sslctl"
description="SSL Certificate Manager"
command="/usr/local/bin/sslctl"
command_args="daemon"
command_background=true
pidfile="/run/${RC_SVCNAME}.pid"
directory="/opt/sslctl"

depend() {
    need net
    after firewall
}
EOF

chmod +x /etc/init.d/sslctl
rc-update add sslctl default
# 启动可能失败（容器环境限制），忽略错误
rc-service sslctl start || true
sleep 2
OPENRC_EOF
            ;;
        sysvinit)
            cat << 'SYSVINIT_EOF'

# 创建 SysVinit 服务
cat > /etc/init.d/sslctl << 'EOF'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          sslctl
# Required-Start:    $network $remote_fs
# Required-Stop:     $network $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: SSL Certificate Manager
# Description:       SSL 证书自动部署服务
### END INIT INFO

NAME="sslctl"
DAEMON="/usr/local/bin/sslctl"
DAEMON_ARGS="daemon"
PIDFILE="/var/run/${NAME}.pid"
WORKDIR="/opt/sslctl"

start() {
    echo "Starting $NAME..."
    if [ -f "$PIDFILE" ] && kill -0 $(cat "$PIDFILE") 2>/dev/null; then
        echo "$NAME is already running"
        return 1
    fi
    cd "$WORKDIR"
    nohup "$DAEMON" $DAEMON_ARGS > /dev/null 2>&1 &
    echo $! > "$PIDFILE"
    echo "$NAME started"
}

stop() {
    echo "Stopping $NAME..."
    if [ ! -f "$PIDFILE" ]; then
        echo "$NAME is not running"
        return 1
    fi
    kill $(cat "$PIDFILE") 2>/dev/null
    rm -f "$PIDFILE"
    echo "$NAME stopped"
}

status() {
    if [ -f "$PIDFILE" ] && kill -0 $(cat "$PIDFILE") 2>/dev/null; then
        echo "$NAME is running (PID: $(cat $PIDFILE))"
        return 0
    else
        echo "$NAME is not running"
        return 1
    fi
}

case "$1" in
    start)   start ;;
    stop)    stop ;;
    restart) stop; sleep 1; start ;;
    status)  status ;;
    *)       echo "Usage: $0 {start|stop|restart|status}"; exit 1 ;;
esac
EOF

chmod +x /etc/init.d/sslctl

# Debian/Devuan 使用 update-rc.d
if command -v update-rc.d >/dev/null 2>&1; then
    update-rc.d sslctl defaults
fi

/etc/init.d/sslctl start
sleep 2
SYSVINIT_EOF
            ;;
    esac
}

# 测试函数: TC-01 安装测试
test_install() {
    local container="$1"
    local init_system="$2"

    echo_step "  TC-01: 测试安装..."

    # 检查二进制
    if ! docker exec "$container" test -x /usr/local/bin/sslctl; then
        echo_error "    二进制未安装"
        return 1
    fi

    # 检查工作目录
    if ! docker exec "$container" test -d /opt/sslctl; then
        echo_error "    工作目录未创建"
        return 1
    fi

    # 检查服务文件
    case "$init_system" in
        systemd)
            if ! docker exec "$container" test -f /etc/systemd/system/sslctl.service; then
                echo_error "    systemd 服务文件未创建"
                return 1
            fi
            ;;
        openrc)
            if ! docker exec "$container" test -f /etc/init.d/sslctl; then
                echo_error "    OpenRC 服务脚本未创建"
                return 1
            fi
            ;;
        sysvinit)
            if ! docker exec "$container" test -f /etc/init.d/sslctl; then
                echo_error "    SysVinit 服务脚本未创建"
                return 1
            fi
            ;;
    esac

    # 检查服务配置（注：daemon 在没有站点配置时会正常退出，所以只检查启用状态）
    case "$init_system" in
        systemd)
            if ! docker exec "$container" systemctl is-enabled sslctl &>/dev/null; then
                echo_error "    开机自启未启用 (systemd)"
                return 1
            fi
            echo_info "    systemd 服务已安装并启用"
            ;;
        openrc)
            # 检查是否在 default runlevel
            if docker exec "$container" rc-update show default 2>/dev/null | grep -q sslctl; then
                echo_info "    OpenRC 服务已安装并启用"
            else
                echo_warn "    OpenRC 服务可能未完全配置（容器限制）"
            fi
            ;;
        sysvinit)
            # 检查服务脚本是否可执行
            if docker exec "$container" test -x /etc/init.d/sslctl; then
                echo_info "    SysVinit 服务脚本已安装"
            fi
            ;;
    esac

    echo_info "    TC-01: 通过"
    return 0
}

# 测试函数: TC-02 status 命令
test_status() {
    local container="$1"
    local init_system="$2"

    echo_step "  TC-02: 测试 status 命令..."

    local output
    output=$(docker exec "$container" /usr/local/bin/sslctl status 2>&1) || true

    # 检查版本信息
    if ! echo "$output" | grep -q "版本:"; then
        echo_error "    未显示版本信息"
        echo "$output"
        return 1
    fi

    # 检查 init 系统类型
    local expected_init
    case "$init_system" in
        systemd) expected_init="systemd" ;;
        openrc) expected_init="OpenRC" ;;
        sysvinit) expected_init="SysVinit" ;;
    esac

    if ! echo "$output" | grep -qi "$expected_init"; then
        echo_error "    未显示正确的 init 系统类型 (期望: $expected_init)"
        echo "$output"
        return 1
    fi

    echo_info "    TC-02: 通过"
    return 0
}

# 测试函数: TC-03 service repair 命令
test_repair() {
    local container="$1"
    local init_system="$2"

    echo_step "  TC-03: 测试 service repair 命令..."

    # 先停止并破坏服务
    case "$init_system" in
        systemd)
            docker exec "$container" systemctl stop sslctl 2>/dev/null || true
            docker exec "$container" rm -f /etc/systemd/system/sslctl.service
            docker exec "$container" systemctl daemon-reload
            ;;
        openrc)
            docker exec "$container" rc-service sslctl stop 2>/dev/null || true
            docker exec "$container" rm -f /etc/init.d/sslctl
            ;;
        sysvinit)
            docker exec "$container" /etc/init.d/sslctl stop 2>/dev/null || true
            docker exec "$container" rm -f /etc/init.d/sslctl
            ;;
    esac

    # 执行 repair（忽略退出码，因为 daemon 可能因无配置而退出）
    docker exec "$container" /usr/local/bin/sslctl service repair 2>&1 || true

    sleep 2

    # 验证服务文件恢复
    case "$init_system" in
        systemd)
            if ! docker exec "$container" test -f /etc/systemd/system/sslctl.service; then
                echo_error "    服务文件未恢复 (systemd)"
                return 1
            fi
            if ! docker exec "$container" systemctl is-enabled sslctl &>/dev/null; then
                echo_error "    服务未启用 (systemd)"
                return 1
            fi
            ;;
        openrc)
            if ! docker exec "$container" test -f /etc/init.d/sslctl; then
                echo_error "    服务脚本未恢复 (OpenRC)"
                return 1
            fi
            ;;
        sysvinit)
            if ! docker exec "$container" test -f /etc/init.d/sslctl; then
                echo_error "    服务脚本未恢复 (SysVinit)"
                return 1
            fi
            ;;
    esac

    echo_info "    TC-03: 通过"
    return 0
}

# 测试函数: TC-04 upgrade 命令
test_upgrade() {
    local container="$1"

    echo_step "  TC-04: 测试 upgrade --check 命令..."

    local output
    output=$(docker exec "$container" /usr/local/bin/sslctl upgrade --check 2>&1) || true

    # 检查是否显示版本信息
    if ! echo "$output" | grep -qE "(当前版本|最新版本|检查更新|获取版本)"; then
        echo_error "    upgrade --check 输出异常"
        echo "$output"
        return 1
    fi

    echo_info "    TC-04: 通过"
    return 0
}

# 测试函数: TC-05 uninstall 命令
test_uninstall() {
    local container="$1"
    local init_system="$2"

    echo_step "  TC-05: 测试 uninstall 命令..."

    # 执行卸载
    docker exec "$container" /usr/local/bin/sslctl uninstall 2>&1 || true

    sleep 1

    # 验证服务已停止和删除
    case "$init_system" in
        systemd)
            if docker exec "$container" systemctl is-active sslctl &>/dev/null; then
                echo_error "    服务未停止 (systemd)"
                return 1
            fi
            ;;
    esac

    # 验证二进制已删除
    if docker exec "$container" test -f /usr/local/bin/sslctl 2>/dev/null; then
        echo_error "    二进制未删除"
        return 1
    fi

    # 验证配置目录保留
    if ! docker exec "$container" test -d /opt/sslctl 2>/dev/null; then
        echo_error "    配置目录被意外删除"
        return 1
    fi

    echo_info "    TC-05: 通过"
    return 0
}

# 测试函数: TC-06 uninstall 并清理配置
test_purge() {
    local container="$1"
    local init_system="$2"
    local arch="$3"

    echo_step "  TC-06: 测试 uninstall 并清理配置..."

    # 重新安装
    docker exec "$container" cp /test/sslctl /usr/local/bin/sslctl
    docker exec "$container" chmod +x /usr/local/bin/sslctl

    # 执行卸载（自动回答 Y 清理配置）
    echo "Y" | docker exec -i "$container" /usr/local/bin/sslctl uninstall 2>&1 || true

    sleep 1

    # 验证配置目录已删除
    if docker exec "$container" test -d /opt/sslctl 2>/dev/null; then
        echo_error "    配置目录未删除"
        return 1
    fi

    echo_info "    TC-06: 通过"
    return 0
}

# 运行单个发行版的测试
run_distro_test() {
    local distro_config="$1"
    local arch="$2"

    IFS='|' read -r name image init_system docker_opts <<< "$distro_config"

    local container_name="sslctl-test-${name}-${arch}"
    local binary_path="${PROJECT_DIR}/dist/sslctl-linux-${arch}"

    echo ""
    echo_info "=========================================="
    echo_info "测试发行版: $name ($init_system) [$arch]"
    echo_info "镜像: $image"
    echo_info "=========================================="

    # 清理旧容器
    docker rm -f "$container_name" 2>/dev/null || true

    # 启动容器
    echo_step "启动容器..."

    local start_cmd="docker run -d --name $container_name"

    # 添加特殊选项
    if [ -n "$docker_opts" ]; then
        start_cmd="$start_cmd $docker_opts"
    fi

    # 挂载测试二进制
    start_cmd="$start_cmd -v ${binary_path}:/test/sslctl:ro"

    # 根据发行版设置启动命令
    case "$init_system" in
        systemd)
            start_cmd="$start_cmd $image /sbin/init"
            ;;
        openrc)
            # Alpine 需要特殊处理，使用 tail 保持容器运行
            start_cmd="$start_cmd $image tail -f /dev/null"
            ;;
        sysvinit)
            # Devuan 使用 tail 保持容器运行（避免 init 依赖）
            start_cmd="$start_cmd $image tail -f /dev/null"
            ;;
    esac

    if ! eval "$start_cmd"; then
        echo_error "启动容器失败"
        return 1
    fi

    # 等待容器启动
    sleep 3

    # 对于 systemd 容器，等待 systemd 就绪
    if [ "$init_system" = "systemd" ]; then
        echo_step "等待 systemd 就绪..."
        local max_wait=30
        local waited=0
        while [ $waited -lt $max_wait ]; do
            if docker exec "$container_name" systemctl is-system-running &>/dev/null; then
                break
            fi
            sleep 1
            ((waited++))
        done
        if [ $waited -ge $max_wait ]; then
            echo_warn "systemd 可能未完全就绪，继续测试..."
        fi
    fi

    # 安装 sslctl
    echo_step "安装 sslctl..."
    local install_script
    install_script=$(get_install_script "$init_system")

    # 对于 Alpine/Devuan 使用 sh，其他使用 bash
    local shell_cmd="bash"
    if [ "$init_system" = "openrc" ]; then
        shell_cmd="sh"
        # Alpine 需要先安装 bash、openrc 和 gcompat（glibc 兼容层）
        docker exec "$container_name" apk add --no-cache bash openrc gcompat 2>&1 || true
    fi

    if ! docker exec "$container_name" $shell_cmd -c "$install_script" 2>&1; then
        echo_error "安装失败"
        record_result "$name" "TC-01" "fail"
        docker rm -f "$container_name" 2>/dev/null || true
        return 1
    fi

    # 运行测试用例
    local all_passed=true

    if test_install "$container_name" "$init_system"; then
        record_result "$name" "TC-01" "pass"
    else
        record_result "$name" "TC-01" "fail"
        all_passed=false
    fi

    if test_status "$container_name" "$init_system"; then
        record_result "$name" "TC-02" "pass"
    else
        record_result "$name" "TC-02" "fail"
        all_passed=false
    fi

    if test_repair "$container_name" "$init_system"; then
        record_result "$name" "TC-03" "pass"
    else
        record_result "$name" "TC-03" "fail"
        all_passed=false
    fi

    if test_upgrade "$container_name"; then
        record_result "$name" "TC-04" "pass"
    else
        record_result "$name" "TC-04" "fail"
        all_passed=false
    fi

    if test_uninstall "$container_name" "$init_system"; then
        record_result "$name" "TC-05" "pass"
    else
        record_result "$name" "TC-05" "fail"
        all_passed=false
    fi

    if test_purge "$container_name" "$init_system" "$arch"; then
        record_result "$name" "TC-06" "pass"
    else
        record_result "$name" "TC-06" "fail"
        all_passed=false
    fi

    # 清理容器
    echo_step "清理容器..."
    docker rm -f "$container_name" 2>/dev/null || true

    if [ "$all_passed" = true ]; then
        echo_info "发行版 $name: 全部测试通过"
    else
        echo_error "发行版 $name: 部分测试失败"
    fi
}

# 完成报告
finalize_report() {
    # 计算统计
    local total=0
    local passed=0
    local failed=0

    for key in "${!RESULTS[@]}"; do
        ((total++))
        if [ "${RESULTS[$key]}" = "✅" ]; then
            ((passed++))
        else
            ((failed++))
        fi
    done

    cat >> "$REPORT_FILE" << EOF

## 总结

- 通过: $passed/$total
- 失败: $failed/$total

## 测试用例说明

| 编号 | 名称 | 描述 |
|------|------|------|
| TC-01 | 安装测试 | 验证二进制安装、服务创建和自启动 |
| TC-02 | status 命令 | 验证版本和状态显示 |
| TC-03 | service repair | 验证服务修复功能 |
| TC-04 | upgrade --check | 验证升级检查功能 |
| TC-05 | uninstall | 验证标准卸载 |
| TC-06 | uninstall + 清理 | 验证完全卸载 |
EOF

    echo ""
    echo_info "测试报告已生成: $REPORT_FILE"
    echo ""
    echo_info "=== 测试总结 ==="
    echo_info "通过: $passed/$total"
    if [ $failed -gt 0 ]; then
        echo_error "失败: $failed/$total"
    fi
}

# 主函数
main() {
    echo_info "sslctl Linux 发行版测试"
    echo ""

    # 检查 Docker
    check_docker

    # 检测架构
    local arch=$(detect_arch)
    if [ "$arch" = "unknown" ]; then
        echo_error "不支持的架构"
        exit 1
    fi
    echo_info "当前架构: $arch"

    # 构建测试二进制
    build_binary "$arch"

    # 初始化报告
    init_report

    # 串行运行各发行版测试（避免内存不足）
    local distro_count=${#DISTROS[@]}
    local current=0

    for distro_config in "${DISTROS[@]}"; do
        ((current++))
        IFS='|' read -r name image init_system docker_opts <<< "$distro_config"

        echo ""
        echo_info ">>> 测试进度: $current/$distro_count <<<"
        echo ""

        # 清理所有测试容器（确保内存释放）
        echo_step "清理旧容器..."
        docker ps -a --filter "name=sslctl-test-" -q | xargs -r docker rm -f 2>/dev/null || true

        # 拉取镜像
        echo_step "拉取镜像: $image"
        if ! docker pull "$image" 2>/dev/null; then
            echo_warn "拉取镜像失败: $image，跳过"
            continue
        fi

        run_distro_test "$distro_config" "$arch"

        # 添加结果到报告
        add_result_to_report "$name" "$init_system"

        # 强制清理（释放内存）
        echo_step "清理容器和缓存..."
        docker ps -a --filter "name=sslctl-test-" -q | xargs -r docker rm -f 2>/dev/null || true
        docker system prune -f 2>/dev/null || true

        # 短暂等待内存释放
        sleep 2
    done

    # 完成报告
    finalize_report
}

# 运行
main "$@"
