# sslctl Makefile
# 构建证书部署工具

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%d %H:%M:%S')
LDFLAGS := -s -w -X 'main.version=$(VERSION)' -X 'main.buildTime=$(BUILD_TIME)'
GCFLAGS := -trimpath=$(shell pwd)
BUILD_FLAGS := -ldflags "$(LDFLAGS)" -gcflags "$(GCFLAGS)"

# 输出目录
DIST_DIR := dist

# 目标平台
LINUX_PLATFORMS := linux/amd64 linux/arm64
WINDOWS_PLATFORMS := windows/amd64

.PHONY: all clean build build-all build-linux build-windows test lint deps help compress

# 默认目标
all: build

# 帮助信息
help:
	@echo "sslctl 构建工具"
	@echo ""
	@echo "使用方法:"
	@echo "  make build           构建当前平台"
	@echo "  make build-all       构建所有平台"
	@echo "  make build-linux     构建 Linux (amd64/arm64)"
	@echo "  make build-windows   构建 Windows (amd64)"
	@echo "  make clean           清理构建产物"
	@echo "  make compress        gzip 压缩所有二进制文件"
	@echo "  make test            运行测试"
	@echo "  make lint            代码检查"
	@echo "  make deps            下载依赖"
	@echo ""
	@echo "构建说明:"
	@echo "  - 统一二进制文件: sslctl"
	@echo "  - 支持 Nginx 和 Apache"
	@echo "  - 使用子命令: sslctl nginx scan / sslctl apache deploy"
	@echo ""
	@echo "环境变量:"
	@echo "  VERSION              版本号 (默认: git tag)"

# 下载依赖
deps:
	go mod download
	go mod tidy

# 构建当前平台
build:
	@mkdir -p $(DIST_DIR)
	go build $(BUILD_FLAGS) -o $(DIST_DIR)/sslctl$(if $(filter Windows_NT,$(OS)),.exe,) ./cmd
	@echo "Built: $(DIST_DIR)/sslctl"

# 构建所有平台
build-all: clean build-linux build-windows
	@echo "All platforms built successfully"

# 构建 Linux (amd64 + arm64)
build-linux:
	@mkdir -p $(DIST_DIR)
	@echo "Building for Linux..."
	GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) -o $(DIST_DIR)/sslctl-linux-amd64 ./cmd
	GOOS=linux GOARCH=arm64 go build $(BUILD_FLAGS) -o $(DIST_DIR)/sslctl-linux-arm64 ./cmd
	@echo "Built: Linux amd64/arm64"

# 构建 Windows (amd64)
build-windows:
	@mkdir -p $(DIST_DIR)
	@echo "Building for Windows..."
	GOOS=windows GOARCH=amd64 go build $(BUILD_FLAGS) -o $(DIST_DIR)/sslctl-windows-amd64.exe ./cmd
	@echo "Built: Windows amd64"

# 运行测试
test:
	go test -v -race ./...

# 代码检查
lint:
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not installed"; exit 1; }
	golangci-lint run ./...

# gzip 压缩所有二进制文件
compress:
	@echo "Compressing binaries with gzip..."
	@for f in $(DIST_DIR)/sslctl-*; do \
		if [ -f "$$f" ] && [ ! -f "$$f.gz" ] && ! echo "$$f" | grep -q "\.gz$$"; then \
			echo "Compressing: $$f"; \
			gzip -k -f "$$f"; \
		fi \
	done
	@echo "Compression complete"
	@ls -lh $(DIST_DIR)/*.gz 2>/dev/null || true

# 清理
clean:
	rm -rf $(DIST_DIR)
	go clean

# 显示构建信息
info:
	@echo "Version: $(VERSION)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "LDFLAGS: $(LDFLAGS)"
