@echo off
REM Modbus TCP 模拟器启动脚本 (Windows)

echo ==========================================
echo     Modbus TCP 协议模拟器
echo ==========================================

REM 检查Python版本
python --version
if %errorlevel% neq 0 (
    echo 错误: 未找到Python，请先安装Python 3.7+
    pause
    exit /b 1
)

REM 检查依赖
echo 检查依赖包...
python -c "import pymodbus" 2>nul
if %errorlevel% neq 0 (
    echo 安装依赖包...
    pip install -r requirements.txt
)

REM 创建日志目录
if not exist logs mkdir logs

REM 启动模拟器
echo 启动 Modbus TCP 模拟器...
echo 服务器将在 localhost:502 上运行
echo 按 Ctrl+C 停止服务器
echo.

python modbus_simulator.py

pause
