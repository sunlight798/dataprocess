# CVE-Commit提取工具 - 简要说明

## 功能
从PostgreSQL数据库读取CVE信息，使用GitHub API提取CVE披露时间前后半年内的所有commits。

**注意：本工具只提取commits，不进行匹配和评分。**

## 快速开始

### 1. 安装依赖
```bash
pip install -r requirements.txt
```

### 2. 配置已完成 ✓
- 数据库密码: 已配置
- GitHub API Token: 已配置

### 3. 运行程序

#### 方法1: 使用启动脚本（推荐）
```bash
bash run.sh
```

#### 方法2: 直接运行
```bash
python main.py
```

## 输出结果

### 结果文件格式
```json
{
  "metadata": {
    "timestamp": "2025-11-12T18:00:00",
    "total_cves": 100,
    "processed_cves": 100,
    "total_commits": 5000,
    "repo_not_found": 5,
    "api_errors": 2
  },
  "results": [
    {
      "cve_id": "CVE-2020-7221",
      "published_date": "2020-02-04T17:15Z",
      "repo_url": "https://github.com/MariaDB/server",
      "status": "success",
      "message": "成功提取 50 个commits",
      "time_range": {
        "since": "2019-08-04T17:15:00Z",
        "until": "2020-08-04T17:15:00Z"
      },
      "commits": [
        {
          "sha": "9d18b6246755472c8324bf3e20e234e08ac45618",
          "message": "Fix privilege escalation in mysql_install_db",
          "author": "Developer Name",
          "author_email": "dev@example.com",
          "date": "2020-02-05T10:30:00Z",
          "committer": "Committer Name",
          "committer_date": "2020-02-05T10:30:00Z",
          "html_url": "https://github.com/MariaDB/server/commit/9d18b624..."
        }
      ]
    }
  ]
}
```

## 时间范围

- **默认**: CVE披露前6个月 ~ CVE披露后6个月
- **可配置**: 编辑 `config.py` 中的 `TIME_RANGE_CONFIG`

## 性能

- 处理速度: 2-5秒/CVE
- API限制: 5000次/小时（已认证）
- 100个CVE: 约5-10分钟

## 主要模块

- `database.py` - 数据库操作（只读）
- `github_api.py` - GitHub API交互
- `time_utils.py` - 时间处理
- `main.py` - 主程序

## 日志

- 文件: `cve_commit_matching.log`
- 级别: INFO

## 自定义处理数量

编辑 `main.py` 最后一行:
```python
# 处理5个CVE
extractor.process_cves(limit=5)

# 处理100个CVE
extractor.process_cves(limit=100)

# 处理所有CVE
extractor.process_cves()

# 从第100个开始处理50个
extractor.process_cves(limit=50, offset=100)
```

## 故障排查

### 数据库连接失败
- 检查config.py中的数据库配置

### GitHub API错误
- 检查API Token是否有效
- 查看速率限制状态

### 找不到commits
- 检查CVE披露时间是否正确
- 尝试扩大时间范围（修改config.py）

## 注意事项

1. **只读操作**: 不会修改数据库中的任何表
2. **API限制**: 程序会自动处理速率限制
3. **仓库状态**: 某些仓库可能已删除或设为私有（正常现象）
4. **结果保存**: 每处理10个CVE自动保存一次中间结果
