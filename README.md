# CVE-Commit匹配工具

这是一个用于在GitHub仓库中查找CVE修复commit的自动化工具。

## 功能特性

- 从PostgreSQL数据库读取CVE信息
- 使用GitHub API在指定时间范围内搜索commits
- 智能匹配和评分潜在的修复commits
- 支持批量处理和断点续传
- 完整的日志记录和统计信息

## 项目结构

```
dataprocess/
├── config.py           # 配置文件(数据库、API、时间范围等)
├── database.py         # 数据库操作模块
├── github_api.py       # GitHub API交互模块
├── time_utils.py       # 时间处理工具
├── commit_matcher.py   # Commit匹配与分析模块
├── main.py            # 主程序入口
├── requirements.txt    # Python依赖包列表
├── README.md          # 本文件
└── top_5k.sql         # 数据库结构文件
```

## 安装步骤

### 1. 安装Python依赖

```bash
pip install -r requirements.txt
```

### 2. 配置文件设置

编辑 `config.py` 文件,填写以下配置:

#### 数据库配置
```python
DB_CONFIG = {
    'host': '10.108.119.152',
    'port': 5433,
    'database': 'top_5k',
    'user': 'postgrescvedumper',
    'password': 'your_password_here'  # 填写实际密码
}
```

#### GitHub API配置
```python
GITHUB_CONFIG = {
    'api_token': 'your_github_token_here',  # 填写GitHub Token
    'api_base_url': 'https://api.github.com',
    'requests_per_hour': 5000,
    'timeout': 30
}
```

**获取GitHub Token:**
1. 访问 https://github.com/settings/tokens
2. 点击 "Generate new token (classic)"
3. 选择权限: `repo` (可选) 和 `public_repo`
4. 生成后复制token到配置文件

#### 时间范围配置
```python
TIME_RANGE_CONFIG = {
    'months_before': 6,  # CVE披露前6个月
    'months_after': 6    # CVE披露后6个月
}
```

## 使用方法

### 基本使用

```bash
python main.py
```

### 测试运行(处理5个CVE)

在 `main.py` 中修改:
```python
matcher.process_cves(limit=5)
```

### 批量处理(处理所有CVE)

```python
matcher.process_cves()
```

### 分批处理(处理100个CVE,从偏移量0开始)

```python
matcher.process_cves(limit=100, offset=0)
```

## 模块说明

### 1. config.py - 配置管理
- 数据库连接配置
- GitHub API配置
- 时间范围配置
- 日志和批处理配置

### 2. database.py - 数据库操作
主要功能:
- `get_cve_with_repos()` - 获取CVE及关联的GitHub仓库
- `get_known_fixes_for_cve()` - 获取已知修复commit(仅供参考)
- `get_cve_count()` - 获取CVE总数

### 3. github_api.py - GitHub API交互
主要功能:
- `parse_repo_url()` - 解析GitHub仓库URL
- `check_repo_exists()` - 检查仓库是否存在
- `get_all_commits_in_time_range()` - 获取指定时间范围的commits
- `get_rate_limit_status()` - 查看API速率限制状态

### 4. time_utils.py - 时间处理
主要功能:
- `parse_cve_published_date()` - 解析CVE披露时间
- `calculate_time_range()` - 计算搜索时间范围
- `is_commit_in_range()` - 检查commit是否在时间范围内

### 5. commit_matcher.py - Commit匹配
主要功能:
- `extract_cve_ids()` - 从commit消息中提取CVE编号
- `calculate_match_score()` - 计算commit与CVE的匹配分数
- `get_top_candidates()` - 获取最可能的修复commit候选

匹配评分标准:
- 直接提到目标CVE: +100分
- 包含修复关键词(fix, patch, security等): +10~50分
- 包含排除关键词(test, doc等): -5~30分
- 提到其他CVE: +20分

### 6. main.py - 主程序
主要功能:
- 协调各模块完成完整流程
- 批量处理CVE
- 保存结果到JSON文件
- 统计和日志记录

## 输出结果

### 日志文件
- 文件名: `cve_commit_matching.log`
- 包含详细的处理过程和错误信息

### 结果文件
- 中间结果: `cve_commit_results_intermediate_YYYYMMDD_HHMMSS.json`
- 最终结果: `cve_commit_results_final_YYYYMMDD_HHMMSS.json`

结果JSON格式:
```json
{
  "metadata": {
    "timestamp": "2025-11-12T10:30:00",
    "total_cves": 1000,
    "processed_cves": 1000,
    "found_commits": 500,
    "repo_not_found": 50,
    "api_errors": 10
  },
  "results": [
    {
      "cve_id": "CVE-2020-7221",
      "repo_url": "https://github.com/MariaDB/server",
      "status": "success",
      "message": "找到 3 个可能的修复commit",
      "commits": [
        {
          "sha": "9d18b6246755472c8324bf3e20e234e08ac45618",
          "message": "Fix CVE-2020-7221: privilege escalation in mysql_install_db",
          "author": "John Doe",
          "date": "2020-02-05T10:30:00Z",
          "score": 120,
          "matched_cve": true,
          "matched_patterns": ["直接提到CVE: CVE-2020-7221", "修复关键词: fix"]
        }
      ]
    }
  ]
}
```

## 注意事项

### 1. API速率限制
- 未认证: 60次/小时
- 已认证: 5000次/小时
- 程序会自动检测并等待速率限制重置

### 2. 仓库状态
程序会处理以下情况:
- 仓库不存在(404)
- 仓库被废弃
- 仓库为空(409)
- 访问权限问题(403)

### 3. 时间范围
- 默认搜索CVE披露前后各6个月的commits
- 可在 `config.py` 中调整时间范围

### 4. 匹配准确性
- 匹配算法基于关键词和模式识别
- 高分commit更可能是真实的修复commit
- 建议人工复核高分结果

## 测试模块

每个模块都包含测试代码,可以单独测试:

```bash
# 测试数据库模块
python database.py

# 测试GitHub API模块
python github_api.py

# 测试时间处理模块
python time_utils.py

# 测试Commit匹配模块
python commit_matcher.py
```

## 故障排查

### 数据库连接失败
- 检查数据库配置是否正确
- 确认数据库服务器可访问
- 验证用户名和密码

### GitHub API错误
- 检查API Token是否有效
- 确认网络可以访问github.com
- 查看API速率限制状态

### 找不到commits
- 检查CVE披露时间是否正确
- 尝试扩大时间范围
- 确认仓库在该时间段有提交记录

## 扩展功能建议

1. **将结果写入数据库**
   - 可以创建新表存储匹配结果
   - 但不应修改现有的fixes表(它包含正确样本)

2. **增强匹配算法**
   - 使用机器学习模型
   - 分析commit diff内容
   - 结合已知修复commit训练模型

3. **并行处理**
   - 使用多线程或多进程
   - 提高处理速度

4. **定期更新**
   - 定时检查新的CVE
   - 自动更新匹配结果

## 许可证

本项目仅供学术研究使用。

## 联系方式

如有问题,请查看日志文件或联系开发团队。
