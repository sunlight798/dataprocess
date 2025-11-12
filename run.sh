#!/bin/bash

# CVE-Commit匹配工具快速启动脚本

echo "===================================="
echo "CVE-Commit提取工具"
echo "===================================="
echo ""

# 检查Python是否安装
if ! command -v python3 &> /dev/null; then
    echo "错误: 未找到Python3,请先安装Python3"
    exit 1
fi

echo "Python版本:"
python3 --version
echo ""

# 检查是否已安装依赖
echo "检查Python依赖包..."
if ! python3 -c "import psycopg2" 2>/dev/null; then
    echo "警告: psycopg2未安装,正在安装依赖..."
    pip3 install -r requirements.txt
else
    echo "✓ 依赖包已安装"
fi
echo ""

# 检查配置文件
echo "检查配置文件..."
if grep -q "your_password_here" config.py; then
    echo "⚠ 警告: 请先在config.py中配置数据库密码"
fi

if grep -q "your_github_token_here" config.py; then
    echo "⚠ 警告: 请先在config.py中配置GitHub API Token"
fi
echo ""

# 询问用户要处理多少个CVE
echo "请选择运行模式:"
echo "  1) 测试模式 (处理5个CVE)"
echo "  2) 小批量 (处理50个CVE)"
echo "  3) 中批量 (处理500个CVE)"
echo "  4) 全量处理 (处理所有CVE)"
echo "  5) 自定义数量"
echo ""

read -p "请输入选项 [1-5]: " choice

case $choice in
    1)
        echo "启动测试模式,处理5个CVE..."
        python3 -c "
from main import CVECommitExtractor
extractor = CVECommitExtractor()
extractor.process_cves(limit=5)
"
        ;;
    2)
        echo "启动小批量模式,处理50个CVE..."
        python3 -c "
from main import CVECommitExtractor
extractor = CVECommitExtractor()
extractor.process_cves(limit=50)
"
        ;;
    3)
        echo "启动中批量模式,处理500个CVE..."
        python3 -c "
from main import CVECommitExtractor
extractor = CVECommitExtractor()
extractor.process_cves(limit=500)
"
        ;;
    4)
        echo "启动全量处理模式,处理所有CVE..."
        python3 -c "
from main import CVECommitExtractor
extractor = CVECommitExtractor()
extractor.process_cves()
"
        ;;
    5)
        read -p "请输入要处理的CVE数量: " custom_limit
        read -p "请输入起始偏移量 (默认0): " custom_offset
        custom_offset=${custom_offset:-0}
        echo "启动自定义模式,处理${custom_limit}个CVE (偏移${custom_offset})..."
        python3 -c "
from main import CVECommitExtractor
extractor = CVECommitExtractor()
extractor.process_cves(limit=${custom_limit}, offset=${custom_offset})
"
        ;;
    *)
        echo "无效选项,退出"
        exit 1
        ;;
esac

echo ""
echo "===================================="
echo "处理完成"
echo "===================================="
echo "查看结果:"
echo "  - 日志文件: cve_commit_matching.log"
echo "  - 结果文件: cve_commit_results_final_*.json"
