"""
时间处理工具模块
负责处理CVE披露时间和commit时间的相关操作
"""

from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
import logging
from typing import Tuple
from config import TIME_RANGE_CONFIG

logger = logging.getLogger(__name__)


class TimeRangeCalculator:
    """时间范围计算类"""
    
    @staticmethod
    def parse_cve_published_date(published_date: str) -> datetime:
        """
        解析CVE披露时间字符串
        
        Args:
            published_date: CVE披露时间字符串,格式如"2020-02-04T17:15Z"
            
        Returns:
            datetime对象
        """
        try:
            # 处理多种可能的时间格式
            formats = [
                '%Y-%m-%dT%H:%MZ',          # 2020-02-04T17:15Z
                '%Y-%m-%dT%H:%M:%SZ',       # 2020-02-04T17:15:30Z
                '%Y-%m-%dT%H:%M:%S.%fZ',    # 2020-02-04T17:15:30.123Z
                '%Y-%m-%d %H:%M:%S',        # 2020-02-04 17:15:30
                '%Y-%m-%d',                 # 2020-02-04
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(published_date, fmt)
                except ValueError:
                    continue
            
            # 如果所有格式都失败,尝试ISO格式解析
            return datetime.fromisoformat(published_date.replace('Z', '+00:00'))
            
        except Exception as e:
            logger.error(f"解析时间失败: {published_date}, 错误: {e}")
            raise
    
    @staticmethod
    def calculate_time_range(
        published_date: str,
        months_before: int = None,
        months_after: int = None
    ) -> Tuple[str, str]:
        """
        根据CVE披露时间计算搜索时间范围
        
        Args:
            published_date: CVE披露时间字符串
            months_before: 披露前几个月(默认从配置读取)
            months_after: 披露后几个月(默认从配置读取)
            
        Returns:
            (since, until)元组,都是ISO 8601格式字符串
        """
        if months_before is None:
            months_before = TIME_RANGE_CONFIG['months_before']
        if months_after is None:
            months_after = TIME_RANGE_CONFIG['months_after']
        
        # 解析CVE披露时间
        publish_time = TimeRangeCalculator.parse_cve_published_date(published_date)
        
        # 计算时间范围
        since_time = publish_time - relativedelta(months=months_before)
        until_time = publish_time + relativedelta(months=months_after)
        
        # 转换为ISO 8601格式(GitHub API要求的格式)
        since_str = since_time.strftime('%Y-%m-%dT%H:%M:%SZ')
        until_str = until_time.strftime('%Y-%m-%dT%H:%M:%SZ')
        
        logger.debug(f"时间范围: {since_str} ~ {until_str} (基于 {published_date})")
        
        return (since_str, until_str)
    
    @staticmethod
    def format_datetime_for_github(dt: datetime) -> str:
        """
        将datetime对象格式化为GitHub API要求的格式
        
        Args:
            dt: datetime对象
            
        Returns:
            ISO 8601格式字符串
        """
        return dt.strftime('%Y-%m-%dT%H:%M:%SZ')
    
    @staticmethod
    def parse_github_commit_date(commit_date: str) -> datetime:
        """
        解析GitHub commit时间字符串
        
        Args:
            commit_date: GitHub返回的commit时间字符串
            
        Returns:
            datetime对象
        """
        try:
            # GitHub API返回的时间格式通常是ISO 8601
            return datetime.fromisoformat(commit_date.replace('Z', '+00:00'))
        except Exception as e:
            logger.error(f"解析GitHub commit时间失败: {commit_date}, 错误: {e}")
            raise
    
    @staticmethod
    def is_commit_in_range(
        commit_date: str,
        since: str,
        until: str
    ) -> bool:
        """
        检查commit时间是否在指定范围内
        
        Args:
            commit_date: commit时间字符串
            since: 开始时间字符串
            until: 结束时间字符串
            
        Returns:
            True表示在范围内,False表示不在
        """
        try:
            commit_dt = TimeRangeCalculator.parse_github_commit_date(commit_date)
            since_dt = TimeRangeCalculator.parse_cve_published_date(since)
            until_dt = TimeRangeCalculator.parse_cve_published_date(until)
            
            return since_dt <= commit_dt <= until_dt
        except Exception as e:
            logger.error(f"检查commit时间范围失败: {e}")
            return False
    
    @staticmethod
    def format_time_delta(seconds: float) -> str:
        """
        格式化时间差为可读字符串
        
        Args:
            seconds: 秒数
            
        Returns:
            格式化的时间字符串
        """
        if seconds < 60:
            return f"{seconds:.1f}秒"
        elif seconds < 3600:
            return f"{seconds/60:.1f}分钟"
        elif seconds < 86400:
            return f"{seconds/3600:.1f}小时"
        else:
            return f"{seconds/86400:.1f}天"


if __name__ == "__main__":
    # 测试代码
    logging.basicConfig(level=logging.DEBUG)
    
    calc = TimeRangeCalculator()
    
    # 测试解析CVE时间
    test_dates = [
        "2020-02-04T17:15Z",
        "2020-02-04T17:15:30Z",
        "2020-02-04T17:15:30.123Z"
    ]
    
    print("测试时间解析:")
    for date_str in test_dates:
        try:
            dt = calc.parse_cve_published_date(date_str)
            print(f"  {date_str} -> {dt}")
        except Exception as e:
            print(f"  {date_str} -> 解析失败: {e}")
    
    # 测试计算时间范围
    print("\n测试时间范围计算:")
    test_date = "2020-02-04T17:15Z"
    since, until = calc.calculate_time_range(test_date)
    print(f"  CVE时间: {test_date}")
    print(f"  搜索范围: {since} ~ {until}")
    
    # 测试时间差格式化
    print("\n测试时间差格式化:")
    test_seconds = [30, 90, 3600, 7200, 86400, 172800]
    for sec in test_seconds:
        formatted = calc.format_time_delta(sec)
        print(f"  {sec}秒 -> {formatted}")
