#!/bin/bash
# Modbus TCP 模拟器启动脚本

echo "=========================================="
echo "    Modbus TCP 协议模拟器"
echo "=========================================="

# 检查Python版本
python_version=$(python3 --version 2>&1)
echo "Python版本: $python_version"

# 检查依赖
echo "检查依赖包..."
if ! python3 -c "import pymodbus" 2>/dev/null; then
    echo "安装依赖包..."
    pip3 install -r requirements.txt
fi

# 创建日志目录
mkdir -p logs

# 启动模拟器
echo "启动 Modbus TCP 模拟器..."
echo "服务器将在 localhost:502 上运行"
echo "按 Ctrl+C 停止服务器"
echo ""

python3 modbus_simulator.py
