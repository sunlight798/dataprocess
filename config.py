"""
配置文件
存储数据库连接信息和GitHub API配置
"""
import os
from dotenv import load_dotenv

load_dotenv()

# 数据库配置
DB_CONFIG = {
    'host': os.getenv('DB_HOST', '10.108.119.152'),
    'port': os.getenv('DB_PORT', '5432'),
    'database': os.getenv('DB_NAME', 'top_5k'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD')  # 请填写实际密码
}

# GitHub API 配置
GITHUB_CONFIG = {
    'api_token': os.getenv('GITHUB_TOKEN'),  # 请填写你的GitHub Personal Access Token
    'api_base_url': 'https://api.github.com',
    'requests_per_hour': 5000,  # 认证后的限制
    'timeout': 30  # API请求超时时间(秒)
}

# 时间范围配置(相对于CVE披露时间)
TIME_RANGE_CONFIG = {
    'months_before': 6,  # CVE披露前6个月
    'months_after': 6    # CVE披露后6个月
}

# 日志配置
LOG_CONFIG = {
    'log_file': 'cve_commit_matching.log',
    'log_level': 'INFO'
}

# 批处理配置
BATCH_CONFIG = {
    'batch_size': 10,  # 每批处理的CVE数量
    'retry_times': 3,  # API失败重试次数
    'retry_delay': 5   # 重试延迟(秒)
}
