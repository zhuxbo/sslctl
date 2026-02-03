#!/bin/bash
# 版本发布脚本 - 更新版本号、打 tag、推送
# 用法: ./git-release.sh <version>
# 示例: ./git-release.sh v0.0.10-beta

set -e

if [ -z "$1" ]; then
    echo "用法: $0 <version>"
    echo "示例: $0 v0.0.10-beta"
    exit 1
fi

VERSION="$1"
# 确保版本号带 v 前缀
if [[ "$VERSION" != v* ]]; then
    VERSION="v$VERSION"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "发布版本: ${VERSION}"

# 1. 生成 version.json（本地文件，不提交）
BUILD_DATE=$(date -u +%Y-%m-%d)
cat > "${PROJECT_DIR}/version.json" << EOF
{
  "version": "${VERSION}",
  "build_date": "${BUILD_DATE}"
}
EOF

echo "已生成 version.json（本地文件，不提交到 git）"

# 2. 创建 tag
cd "$PROJECT_DIR"
git tag -a "${VERSION}" -m "Release ${VERSION}"

echo ""
echo "已创建 tag: ${VERSION}"
echo ""
echo "下一步操作:"
echo "  git push origin dev         # 推送分支"
echo "  git push origin ${VERSION}  # 推送 tag"
echo "  ./build/build.sh            # 构建发布包"
