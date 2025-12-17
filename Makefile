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
PLATFORMS := linux/amd64 linux/arm64 windows/amd64 darwin/amd64 darwin/arm64

.PHONY: all clean build build-nginx build-apache build-iis build-all test lint deps help

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
	@echo "  make build-iis       仅构建 IIS 客户端"
	@echo "  make build-all       构建所有平台的二进制文件"
	@echo "  make build-linux     构建 Linux amd64"
	@echo "  make build-windows   构建 Windows amd64"
	@echo "  make clean           清理构建产物"
	@echo "  make test            运行测试"
	@echo "  make lint            代码检查"
	@echo "  make deps            下载依赖"
	@echo ""
	@echo "环境变量:"
	@echo "  VERSION              版本号 (默认: git tag)"
	@echo "  UPX=1                启用 UPX 压缩 (需要安装 upx)"

# 下载依赖
deps:
	go mod download
	go mod tidy

# 构建当前平台
build: build-nginx build-apache build-iis

# 构建 Nginx 客户端 (当前平台)
build-nginx:
	@mkdir -p $(DIST_DIR)
	go build $(BUILD_FLAGS) -o $(DIST_DIR)/cert-deploy-nginx ./cmd/nginx
	@echo "Built: $(DIST_DIR)/cert-deploy-nginx"
ifdef UPX
	@command -v upx >/dev/null 2>&1 && upx -9 $(DIST_DIR)/cert-deploy-nginx || echo "UPX not found, skipping compression"
endif

# 构建 Apache 客户端 (当前平台)
build-apache:
	@mkdir -p $(DIST_DIR)
	go build $(BUILD_FLAGS) -o $(DIST_DIR)/cert-deploy-apache ./cmd/apache
	@echo "Built: $(DIST_DIR)/cert-deploy-apache"
ifdef UPX
	@command -v upx >/dev/null 2>&1 && upx -9 $(DIST_DIR)/cert-deploy-apache || echo "UPX not found, skipping compression"
endif

# 构建 IIS 客户端 (当前平台)
build-iis:
	@mkdir -p $(DIST_DIR)
	go build $(BUILD_FLAGS) -o $(DIST_DIR)/cert-deploy-iis ./cmd/iis
	@echo "Built: $(DIST_DIR)/cert-deploy-iis"
ifdef UPX
	@command -v upx >/dev/null 2>&1 && upx -9 $(DIST_DIR)/cert-deploy-iis || echo "UPX not found, skipping compression"
endif

# 构建所有平台
build-all: clean
	@mkdir -p $(DIST_DIR)
	@for platform in $(PLATFORMS); do \
		GOOS=$${platform%/*} GOARCH=$${platform#*/} $(MAKE) build-platform; \
	done

# 构建单个平台 (内部使用)
build-platform:
	@echo "Building for $(GOOS)/$(GOARCH)..."
	@EXT=""; \
	if [ "$(GOOS)" = "windows" ]; then EXT=".exe"; fi; \
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(BUILD_FLAGS) \
		-o $(DIST_DIR)/cert-deploy-nginx-$(GOOS)-$(GOARCH)$$EXT ./cmd/nginx; \
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(BUILD_FLAGS) \
		-o $(DIST_DIR)/cert-deploy-apache-$(GOOS)-$(GOARCH)$$EXT ./cmd/apache; \
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(BUILD_FLAGS) \
		-o $(DIST_DIR)/cert-deploy-iis-$(GOOS)-$(GOARCH)$$EXT ./cmd/iis; \
	echo "Built: $(GOOS)/$(GOARCH)"

# 仅构建 Linux amd64
build-linux:
	@mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) -o $(DIST_DIR)/cert-deploy-nginx-linux-amd64 ./cmd/nginx
	GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) -o $(DIST_DIR)/cert-deploy-apache-linux-amd64 ./cmd/apache
	GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) -o $(DIST_DIR)/cert-deploy-iis-linux-amd64 ./cmd/iis
	@echo "Built: Linux amd64 binaries"

# 仅构建 Windows amd64
build-windows:
	@mkdir -p $(DIST_DIR)
	GOOS=windows GOARCH=amd64 go build $(BUILD_FLAGS) -o $(DIST_DIR)/cert-deploy-nginx-windows-amd64.exe ./cmd/nginx
	GOOS=windows GOARCH=amd64 go build $(BUILD_FLAGS) -o $(DIST_DIR)/cert-deploy-apache-windows-amd64.exe ./cmd/apache
	GOOS=windows GOARCH=amd64 go build $(BUILD_FLAGS) -o $(DIST_DIR)/cert-deploy-iis-windows-amd64.exe ./cmd/iis
	@echo "Built: Windows amd64 binaries"

# 运行测试
test:
	go test -v -race ./...

# 代码检查
lint:
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not installed"; exit 1; }
	golangci-lint run ./...

# 清理
clean:
	rm -rf $(DIST_DIR)
	go clean

# 显示构建信息
info:
	@echo "Version: $(VERSION)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "LDFLAGS: $(LDFLAGS)"
