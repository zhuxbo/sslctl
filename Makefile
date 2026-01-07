# cert-deploy Makefile
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

.PHONY: all clean build build-nginx build-apache build-iis build-all build-linux build-windows test lint deps help compress

# 默认目标
all: build

# 帮助信息
help:
	@echo "cert-deploy 构建工具"
	@echo ""
	@echo "使用方法:"
	@echo "  make build           构建当前平台的所有二进制文件"
	@echo "  make build-nginx     仅构建 Nginx 客户端"
	@echo "  make build-apache    仅构建 Apache 客户端"
	@echo "  make build-iis       仅构建 IIS 客户端 (仅 Windows)"
	@echo "  make build-all       构建所有平台的二进制文件"
	@echo "  make build-linux     构建 Linux (amd64/arm64)"
	@echo "  make build-windows   构建 Windows (amd64)"
	@echo "  make clean           清理构建产物"
	@echo "  make compress        UPX 压缩所有二进制文件 (6.4MB -> 2MB)"
	@echo "  make test            运行测试"
	@echo "  make lint            代码检查"
	@echo "  make deps            下载依赖"
	@echo ""
	@echo "构建说明:"
	@echo "  - Nginx/Apache: 支持 Linux, Windows"
	@echo "  - IIS: 仅支持 Windows"
	@echo ""
	@echo "环境变量:"
	@echo "  VERSION              版本号 (默认: git tag)"
	@echo "  UPX=1                启用 UPX 压缩 (需要安装 upx)"

# 下载依赖
deps:
	go mod download
	go mod tidy

# 构建当前平台（自动判断是否构建 IIS）
build: build-nginx build-apache
ifeq ($(OS),Windows_NT)
	$(MAKE) build-iis
endif

# 构建 Nginx 客户端 (当前平台)
build-nginx:
	@mkdir -p $(DIST_DIR)
	go build $(BUILD_FLAGS) -o $(DIST_DIR)/cert-deploy-nginx$(if $(filter Windows_NT,$(OS)),.exe,) ./cmd/nginx
	@echo "Built: $(DIST_DIR)/cert-deploy-nginx"
ifdef UPX
	@command -v upx >/dev/null 2>&1 && upx -9 $(DIST_DIR)/cert-deploy-nginx$(if $(filter Windows_NT,$(OS)),.exe,) || echo "UPX not found, skipping compression"
endif

# 构建 Apache 客户端 (当前平台)
build-apache:
	@mkdir -p $(DIST_DIR)
	go build $(BUILD_FLAGS) -o $(DIST_DIR)/cert-deploy-apache$(if $(filter Windows_NT,$(OS)),.exe,) ./cmd/apache
	@echo "Built: $(DIST_DIR)/cert-deploy-apache"
ifdef UPX
	@command -v upx >/dev/null 2>&1 && upx -9 $(DIST_DIR)/cert-deploy-apache$(if $(filter Windows_NT,$(OS)),.exe,) || echo "UPX not found, skipping compression"
endif

# 构建 IIS 客户端 (仅 Windows)
build-iis:
	@mkdir -p $(DIST_DIR)
	GOOS=windows GOARCH=amd64 go build $(BUILD_FLAGS) -o $(DIST_DIR)/cert-deploy-iis.exe ./cmd/iis
	@echo "Built: $(DIST_DIR)/cert-deploy-iis.exe (Windows only)"

# 构建所有平台
build-all: clean build-linux build-windows
	@echo "All platforms built successfully"

# 构建 Linux (amd64 + arm64)
build-linux:
	@mkdir -p $(DIST_DIR)
	@echo "Building for Linux..."
	GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) -o $(DIST_DIR)/cert-deploy-nginx-linux-amd64 ./cmd/nginx
	GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) -o $(DIST_DIR)/cert-deploy-apache-linux-amd64 ./cmd/apache
	GOOS=linux GOARCH=arm64 go build $(BUILD_FLAGS) -o $(DIST_DIR)/cert-deploy-nginx-linux-arm64 ./cmd/nginx
	GOOS=linux GOARCH=arm64 go build $(BUILD_FLAGS) -o $(DIST_DIR)/cert-deploy-apache-linux-arm64 ./cmd/apache
	@echo "Built: Linux amd64/arm64 (Nginx, Apache)"

# 构建 Windows (amd64) - 包含 IIS
build-windows:
	@mkdir -p $(DIST_DIR)
	@echo "Building for Windows..."
	GOOS=windows GOARCH=amd64 go build $(BUILD_FLAGS) -o $(DIST_DIR)/cert-deploy-nginx-windows-amd64.exe ./cmd/nginx
	GOOS=windows GOARCH=amd64 go build $(BUILD_FLAGS) -o $(DIST_DIR)/cert-deploy-apache-windows-amd64.exe ./cmd/apache
	GOOS=windows GOARCH=amd64 go build $(BUILD_FLAGS) -o $(DIST_DIR)/cert-deploy-iis-windows-amd64.exe ./cmd/iis
	@echo "Built: Windows amd64 (Nginx, Apache, IIS)"

# 运行测试
test:
	go test -v -race ./...

# 代码检查
lint:
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not installed"; exit 1; }
	golangci-lint run ./...

# UPX 压缩所有二进制文件
compress:
	@command -v upx >/dev/null 2>&1 || { echo "UPX not installed. Install with: apt install upx / brew install upx"; exit 1; }
	@echo "Compressing binaries with UPX..."
	@for f in $(DIST_DIR)/cert-deploy-*; do \
		if [ -f "$$f" ] && file "$$f" | grep -q "executable"; then \
			echo "Compressing: $$f"; \
			upx --best --lzma "$$f" 2>/dev/null || upx -9 "$$f" 2>/dev/null || true; \
		fi \
	done
	@echo "Compression complete"
	@ls -lh $(DIST_DIR)/cert-deploy-* 2>/dev/null || true

# 清理
clean:
	rm -rf $(DIST_DIR)
	go clean

# 显示构建信息
info:
	@echo "Version: $(VERSION)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "LDFLAGS: $(LDFLAGS)"
