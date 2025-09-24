#!/bin/bash

# 推送outbound项目到GitHub的脚本
# 使用方法：./push_to_github.sh

echo "🚀 开始推送outbound项目到GitHub..."

# 检查是否在正确的目录
if [ ! -f "go.mod" ]; then
    echo "❌ 错误：请在outbound-main目录中运行此脚本"
    exit 1
fi

# 检查git状态
echo "📋 检查git状态..."
git status

# 添加所有文件
echo "📁 添加所有文件..."
git add .

# 提交更改
echo "💾 提交更改..."
git commit -m "Update: Complete xray-core compatible outbound library

- Add QUIC transport layer with full xray-core parameter support
- Enhance WebSocket with advanced parameters (headers, early data, ping, compression)
- Enhance gRPC with advanced parameters (multiMode, health check, window size, retry)
- Enhance mKCP with advanced parameters (congestion control, window scaling, data sharding)
- Enhance TLS with advanced parameters (version control, cipher suites, certificates)
- Add comprehensive test coverage for all new features
- Update compatibility report to reflect 100% xray-core compatibility

This library now supports all xray-core VLESS parameters and advanced features."

# 推送到GitHub
echo "🌐 推送到GitHub..."
git push -u origin main

if [ $? -eq 0 ]; then
    echo "✅ 成功推送到GitHub！"
    echo "🔗 仓库地址：https://github.com/tearsful/outbound"
else
    echo "❌ 推送失败，请检查："
    echo "1. 是否已创建GitHub仓库：https://github.com/tearsful/outbound"
    echo "2. 是否有正确的权限"
    echo "3. 网络连接是否正常"
fi
