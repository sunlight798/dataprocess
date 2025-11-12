"""
配置验证脚本
用于测试数据库连接和GitHub API配置是否正确
"""

import sys
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


def test_imports():
    """测试依赖包是否已安装"""
    logger.info("测试依赖包导入...")
    
    try:
        import psycopg2
        logger.info("  ✓ psycopg2 已安装")
    except ImportError:
        logger.error("  ✗ psycopg2 未安装,请运行: pip install psycopg2-binary")
        return False
    
    try:
        import requests
        logger.info("  ✓ requests 已安装")
    except ImportError:
        logger.error("  ✗ requests 未安装,请运行: pip install requests")
        return False
    
    try:
        from dateutil import relativedelta
        logger.info("  ✓ python-dateutil 已安装")
    except ImportError:
        logger.error("  ✗ python-dateutil 未安装,请运行: pip install python-dateutil")
        return False
    
    return True


def test_config():
    """测试配置文件是否正确填写"""
    logger.info("\n测试配置文件...")
    
    try:
        from config import DB_CONFIG, GITHUB_CONFIG
        
        # 检查数据库配置
        if DB_CONFIG['password'] == 'your_password_here':
            logger.warning("  ⚠ 数据库密码未配置,请在config.py中填写")
            return False
        else:
            logger.info("  ✓ 数据库密码已配置")
        
        # 检查GitHub配置
        if GITHUB_CONFIG['api_token'] == 'your_github_token_here':
            logger.warning("  ⚠ GitHub API Token未配置,请在config.py中填写")
            return False
        else:
            logger.info("  ✓ GitHub API Token已配置")
        
        return True
        
    except Exception as e:
        logger.error(f"  ✗ 配置文件读取失败: {e}")
        return False


def test_database():
    """测试数据库连接"""
    logger.info("\n测试数据库连接...")
    
    try:
        from database import DatabaseManager
        
        db = DatabaseManager()
        db.connect()
        logger.info("  ✓ 数据库连接成功")
        
        # 测试查询
        count = db.get_cve_count()
        logger.info(f"  ✓ 查询成功,数据库中有 {count} 个CVE")
        
        # 获取一条样本数据
        cves = db.get_cve_with_repos(limit=1)
        if cves:
            cve = cves[0]
            logger.info(f"  ✓ 样本数据: {cve['cve_id']} -> {cve['repo_url']}")
        
        db.disconnect()
        return True
        
    except Exception as e:
        logger.error(f"  ✗ 数据库连接失败: {e}")
        return False


def test_github_api():
    """测试GitHub API"""
    logger.info("\n测试GitHub API...")
    
    try:
        from github_api import GitHubAPIClient
        
        client = GitHubAPIClient()
        
        # 测试速率限制查询
        status = client.get_rate_limit_status()
        logger.info(f"  ✓ API可访问,剩余请求次数: {status['remaining']}/{status['limit']}")
        logger.info(f"    重置时间: {status['reset']}")
        
        # 测试解析仓库URL
        test_url = "https://github.com/torvalds/linux"
        result = client.parse_repo_url(test_url)
        if result:
            owner, repo = result
            logger.info(f"  ✓ URL解析成功: {test_url} -> {owner}/{repo}")
        
        # 测试检查仓库存在性
        exists = client.check_repo_exists("torvalds", "linux")
        if exists:
            logger.info(f"  ✓ 仓库检查成功: torvalds/linux 存在")
        
        return True
        
    except Exception as e:
        logger.error(f"  ✗ GitHub API测试失败: {e}")
        return False


def test_time_utils():
    """测试时间处理工具"""
    logger.info("\n测试时间处理工具...")
    
    try:
        from time_utils import TimeRangeCalculator
        
        calc = TimeRangeCalculator()
        
        # 测试时间解析
        test_date = "2020-02-04T17:15Z"
        dt = calc.parse_cve_published_date(test_date)
        logger.info(f"  ✓ 时间解析成功: {test_date} -> {dt}")
        
        # 测试时间范围计算
        since, until = calc.calculate_time_range(test_date)
        logger.info(f"  ✓ 时间范围计算成功:")
        logger.info(f"    开始: {since}")
        logger.info(f"    结束: {until}")
        
        return True
        
    except Exception as e:
        logger.error(f"  ✗ 时间处理工具测试失败: {e}")
        return False


def test_commit_matcher():
    """测试Commit匹配器"""
    logger.info("\n测试Commit匹配器...")
    
    try:
        from commit_matcher import CommitMatcher
        
        matcher = CommitMatcher()
        
        # 测试CVE提取
        test_message = "Fix CVE-2020-1234: buffer overflow in auth module"
        cves = matcher.extract_cve_ids(test_message)
        logger.info(f"  ✓ CVE提取成功: '{test_message[:50]}...' -> {cves}")
        
        # 测试分数计算
        score, patterns = matcher.calculate_match_score(test_message, "CVE-2020-1234")
        logger.info(f"  ✓ 分数计算成功: 分数={score}, 匹配模式数={len(patterns)}")
        
        return True
        
    except Exception as e:
        logger.error(f"  ✗ Commit匹配器测试失败: {e}")
        return False


def main():
    """主函数"""
    logger.info("="*60)
    logger.info("CVE-Commit匹配工具 - 配置验证")
    logger.info("="*60)
    
    all_passed = True
    
    # 依赖包测试
    if not test_imports():
        logger.error("\n依赖包未完全安装,请运行: pip install -r requirements.txt")
        all_passed = False
        return
    
    # 配置文件测试
    if not test_config():
        logger.error("\n配置文件未正确填写,请编辑config.py")
        all_passed = False
        return
    
    # 数据库测试
    if not test_database():
        logger.error("\n数据库连接失败,请检查配置")
        all_passed = False
    
    # GitHub API测试
    if not test_github_api():
        logger.error("\nGitHub API测试失败,请检查Token和网络")
        all_passed = False
    
    # 时间工具测试
    if not test_time_utils():
        all_passed = False
    
    # Commit匹配器测试
    if not test_commit_matcher():
        all_passed = False
    
    # 输出总结
    logger.info("\n" + "="*60)
    if all_passed:
        logger.info("✓ 所有测试通过! 可以开始运行主程序")
        logger.info("运行命令: python main.py")
        logger.info("或使用: bash run.sh")
    else:
        logger.error("✗ 部分测试未通过,请修复后再运行")
    logger.info("="*60)


if __name__ == "__main__":
    main()
