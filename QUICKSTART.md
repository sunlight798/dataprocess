# 快速开始指南

## 第一步: 安装依赖

```bash
cd /home/ziyang/SPL/dataprocess
pip install -r requirements.txt
```

或者如果使用pip3:

```bash
pip3 install -r requirements.txt
```

## 第二步: 配置

编辑 `config.py` 文件,填写以下两个关键配置:

### 1. 数据库密码

找到这一行:
```python
'password': 'your_password_here'  # 请填写实际密码
```

改为:
```python
'password': '你的实际密码'
```

### 2. GitHub API Token

找到这一行:
```python
'api_token': 'your_github_token_here',  # 请填写你的GitHub Personal Access Token
```

改为:
```python
'api_token': 'ghp_xxxxxxxxxxxxxxxxxxxx',  # 你的实际Token
```

**如何获取GitHub Token:**

1. 打开浏览器,访问: https://github.com/settings/tokens
2. 点击 "Generate new token (classic)"
3. 给Token起个名字,比如 "CVE Commit Matcher"
4. 勾选权限: `public_repo` (如果只访问公开仓库)
5. 点击 "Generate token"
6. 复制生成的token(注意:只显示一次!)

## 第三步: 测试配置

运行配置验证脚本:

```bash
python test_config.py
```

如果所有测试通过,会看到:
```
✓ 所有测试通过! 可以开始运行主程序
```

## 第四步: 运行程序

### 方法1: 使用启动脚本(推荐)

```bash
bash run.sh
```

然后选择运行模式:
- 1) 测试模式 (5个CVE) - **推荐首次运行**
- 2) 小批量 (50个CVE)
- 3) 中批量 (500个CVE)
- 4) 全量处理 (所有CVE)
- 5) 自定义数量

### 方法2: 直接运行Python脚本

```bash
# 测试模式 (处理5个CVE)
python main.py

# 如果要修改处理数量,编辑main.py的最后一行:
# matcher.process_cves(limit=5)  改为你想要的数量
```

### 方法3: 使用Python交互式

```python
from main import CVECommitMatcher

matcher = CVECommitMatcher()

# 处理5个CVE(测试)
matcher.process_cves(limit=5)

# 处理100个CVE
matcher.process_cves(limit=100)

# 处理所有CVE
matcher.process_cves()

# 从第100个开始处理50个
matcher.process_cves(limit=50, offset=100)
```

## 第五步: 查看结果

### 日志文件
```bash
# 查看实时日志
tail -f cve_commit_matching.log

# 查看所有日志
cat cve_commit_matching.log
```

### 结果文件
```bash
# 列出所有结果文件
ls -lh cve_commit_results_*.json

# 查看最新的结果文件
ls -t cve_commit_results_final_*.json | head -1 | xargs cat | less
```

## 常见问题

### 1. 数据库连接失败
```
错误: 数据库连接失败
```

**解决方法:**
- 检查数据库配置中的host、port、database、user、password
- 确认数据库服务器正在运行
- 测试网络连接: `ping 10.108.119.152`

### 2. GitHub API速率限制
```
警告: API速率限制即将用尽
```

**解决方法:**
- 程序会自动等待并继续
- 或者等待1小时后重新运行
- 查看剩余次数: 运行程序会自动显示

### 3. 仓库不存在
```
警告: 仓库不存在或无法访问
```

**这是正常的:**
- 某些GitHub仓库可能已被删除或设为私有
- 程序会记录并继续处理下一个CVE

### 4. 找不到commits
```
消息: 在指定时间范围内未找到任何commit
```

**可能原因:**
- 仓库在该时间段没有提交
- 时间范围太窄,可以在config.py中调整:
  ```python
  TIME_RANGE_CONFIG = {
      'months_before': 12,  # 改为12个月
      'months_after': 12    # 改为12个月
  }
  ```

## 理解结果

### 结果JSON结构

```json
{
  "cve_id": "CVE-2020-7221",
  "repo_url": "https://github.com/MariaDB/server",
  "status": "success",
  "commits": [
    {
      "sha": "9d18b6246755472c8324bf3e20e234e08ac45618",
      "message": "Fix CVE-2020-7221: privilege escalation",
      "score": 120,
      "matched_cve": true
    }
  ]
}
```

### 分数含义

- **100+分**: 直接提到CVE编号,很可能是修复commit
- **50-100分**: 包含多个修复关键词,可能是修复commit
- **0-50分**: 包含一些修复关键词,需要人工判断
- **负分**: 包含排除关键词(如test、doc),不太可能是修复commit

### Status状态

- `success`: 成功处理,找到了候选commits
- `repo_not_found`: 仓库不存在或无法访问
- `error`: 处理过程中发生错误

## 进阶使用

### 调整时间范围
编辑 `config.py`:
```python
TIME_RANGE_CONFIG = {
    'months_before': 12,  # CVE披露前12个月
    'months_after': 3     # CVE披露后3个月
}
```

### 调整批处理大小
编辑 `config.py`:
```python
BATCH_CONFIG = {
    'batch_size': 20,     # 每处理20个CVE保存一次
    'retry_times': 5,     # API失败重试5次
    'retry_delay': 10     # 重试延迟10秒
}
```

### 查看特定CVE的已知修复
```python
from database import DatabaseManager

db = DatabaseManager()
db.connect()

fixes = db.get_known_fixes_for_cve("CVE-2020-7221")
print(fixes)

db.disconnect()
```

## 性能估算

- **处理速度**: 约2-5秒/CVE (取决于仓库大小和commit数量)
- **API限制**: 5000次/小时 (已认证)
- **预计时间**: 
  - 100个CVE: 约5-10分钟
  - 1000个CVE: 约1-2小时
  - 10000个CVE: 约10-20小时

## 下一步

1. **首次运行**: 使用测试模式处理5个CVE,验证一切正常
2. **查看结果**: 检查日志和结果文件,确认格式符合预期
3. **批量处理**: 逐步增加处理数量
4. **结果分析**: 使用Python或其他工具分析结果JSON文件

## 需要帮助?

- 查看完整文档: `README.md`
- 查看日志: `cve_commit_matching.log`
- 运行测试: `python test_config.py`
