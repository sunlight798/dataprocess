"""
时间窗口分析脚本
分析fixes表中正确匹配的CVE-Commit对，计算时间差分布
用于确定合适的时间窗口大小
"""

import logging
from datetime import datetime
from typing import List, Dict, Tuple
import statistics
from database import DatabaseManager

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class TimeWindowAnalyzer:
    """时间窗口分析器"""
    
    def __init__(self):
        """初始化分析器"""
        self.db = DatabaseManager()
        self.time_diffs = []  # 存储所有时间差(天数)
        
    def parse_cve_time(self, time_str: str) -> datetime:
        """
        解析CVE披露时间
        格式: "2020-12-11T19:15Z"
        """
        from datetime import timezone
        
        formats = [
            '%Y-%m-%dT%H:%MZ',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%dT%H:%M:%S.%fZ',
        ]
        
        for fmt in formats:
            try:
                dt = datetime.strptime(time_str, fmt)
                # 添加UTC时区信息
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        
        # 尝试ISO格式
        try:
            return datetime.fromisoformat(time_str.replace('Z', '+00:00'))
        except Exception as e:
            logger.error(f"无法解析CVE时间: {time_str}, 错误: {e}")
            raise
    
    def parse_commit_time(self, time_str: str) -> datetime:
        """
        解析Commit时间
        格式: "2024-05-26 21:01:08+00"
        """
        from datetime import timezone
        
        try:
            # 处理带时区的格式
            if '+' in time_str:
                # 格式: "2024-05-26 21:01:08+00"
                if time_str.endswith('+00'):
                    time_str = time_str[:-3] + '+00:00'
                return datetime.fromisoformat(time_str)
            elif time_str.endswith('00'):
                # 可能是 "2024-05-26 21:01:08+00" 格式
                time_str = time_str[:-2] + '+00:00'
                return datetime.fromisoformat(time_str)
            else:
                # 格式: "2024-05-26 21:01:08" (无时区，假设UTC)
                dt = datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S')
                return dt.replace(tzinfo=timezone.utc)
        except Exception as e:
            logger.error(f"无法解析Commit时间: {time_str}, 错误: {e}")
            raise
    
    def get_correct_fixes(self, min_score: int = 65) -> List[Dict]:
        """
        获取正确的CVE-Commit修复对
        
        Args:
            min_score: 最低分数阈值，默认65
            
        Returns:
            正确修复对列表
        """
        query = """
            SELECT 
                f.cve_id,
                f.hash,
                f.repo_url,
                f.score,
                c.published_date,
                cm.committer_date
            FROM fixes f
            INNER JOIN cve c ON f.cve_id = c.cve_id
            INNER JOIN commits cm ON f.hash = cm.hash AND f.repo_url = cm.repo_url
            WHERE f.score >= %s
                AND c.published_date IS NOT NULL
                AND c.published_date != ''
                AND cm.committer_date IS NOT NULL
        """
        
        try:
            self.db.cursor.execute(query, (min_score,))
            results = self.db.cursor.fetchall()
            logger.info(f"找到 {len(results)} 个正确的CVE-Commit修复对 (score >= {min_score})")
            return results
        except Exception as e:
            logger.error(f"查询失败: {e}")
            raise
    
    def calculate_time_diff(self, cve_time: str, commit_time: str) -> float:
        """
        计算CVE披露时间和Commit时间的差值
        
        Args:
            cve_time: CVE披露时间字符串
            commit_time: Commit提交时间字符串
            
        Returns:
            时间差(天数)，正数表示Commit在CVE之后，负数表示Commit在CVE之前
        """
        cve_dt = self.parse_cve_time(cve_time)
        commit_dt = self.parse_commit_time(commit_time)
        
        # 计算时间差(天数)
        diff = (commit_dt - cve_dt).total_seconds() / 86400
        
        return diff
    
    def analyze(self, min_score: int = 65):
        """
        分析时间窗口
        
        Args:
            min_score: 最低分数阈值
        """
        logger.info("="*60)
        logger.info("开始分析时间窗口")
        logger.info("="*60)
        
        try:
            # 连接数据库
            self.db.connect()
            
            # 获取正确的修复对
            fixes = self.get_correct_fixes(min_score)
            
            if not fixes:
                logger.warning("没有找到符合条件的修复对")
                return
            
            # 计算时间差
            logger.info("\n开始计算时间差...")
            self.time_diffs = []
            commit_before_cve = 0  # Commit在CVE之前
            commit_after_cve = 0   # Commit在CVE之后
            
            for idx, fix in enumerate(fixes, 1):
                try:
                    diff = self.calculate_time_diff(
                        fix['published_date'],
                        str(fix['committer_date'])
                    )
                    self.time_diffs.append(diff)
                    
                    if diff < 0:
                        commit_before_cve += 1
                    else:
                        commit_after_cve += 1
                    
                    if idx <= 5:  # 显示前5个样本
                        logger.info(f"  样本 {idx}: CVE={fix['cve_id']}, "
                                  f"时间差={diff:.1f}天, score={fix['score']}")
                    
                except Exception as e:
                    logger.warning(f"处理记录失败: {fix['cve_id']}, 错误: {e}")
                    continue
            
            # 统计分析
            self._print_statistics(commit_before_cve, commit_after_cve)
            
        except Exception as e:
            logger.error(f"分析过程出错: {e}", exc_info=True)
            
        finally:
            self.db.disconnect()
    
    def _print_statistics(self, commit_before_cve: int, commit_after_cve: int):
        """打印统计信息"""
        if not self.time_diffs:
            logger.warning("没有有效的时间差数据")
            return
        
        logger.info("\n" + "="*60)
        logger.info("统计结果")
        logger.info("="*60)
        
        # 基本统计
        logger.info(f"\n总样本数: {len(self.time_diffs)}")
        logger.info(f"Commit在CVE之前: {commit_before_cve} ({commit_before_cve/len(self.time_diffs)*100:.1f}%)")
        logger.info(f"Commit在CVE之后: {commit_after_cve} ({commit_after_cve/len(self.time_diffs)*100:.1f}%)")
        
        # 时间差统计(天数)
        abs_diffs = [abs(d) for d in self.time_diffs]
        
        logger.info(f"\n时间差统计 (天数):")
        logger.info(f"  平均值: {statistics.mean(abs_diffs):.1f} 天")
        logger.info(f"  中位数: {statistics.median(abs_diffs):.1f} 天")
        logger.info(f"  最小值: {min(abs_diffs):.1f} 天")
        logger.info(f"  最大值: {max(abs_diffs):.1f} 天")
        
        if len(abs_diffs) > 1:
            logger.info(f"  标准差: {statistics.stdev(abs_diffs):.1f} 天")
        
        # 百分位数
        sorted_diffs = sorted(abs_diffs)
        percentiles = [50, 75, 90, 95, 99]
        logger.info(f"\n百分位数:")
        for p in percentiles:
            idx = int(len(sorted_diffs) * p / 100)
            if idx >= len(sorted_diffs):
                idx = len(sorted_diffs) - 1
            logger.info(f"  {p}%: {sorted_diffs[idx]:.1f} 天")
        
        # 分布统计
        ranges = [
            (0, 7, "1周内"),
            (7, 30, "1周-1个月"),
            (30, 90, "1-3个月"),
            (90, 180, "3-6个月"),
            (180, 365, "6个月-1年"),
            (365, float('inf'), "1年以上")
        ]
        
        logger.info(f"\n时间差分布:")
        for min_days, max_days, label in ranges:
            count = sum(1 for d in abs_diffs if min_days <= d < max_days)
            percent = count / len(abs_diffs) * 100
            logger.info(f"  {label:15s}: {count:4d} ({percent:5.1f}%)")
        
        # 推荐时间窗口
        logger.info("\n" + "="*60)
        logger.info("推荐时间窗口")
        logger.info("="*60)
        
        avg_days = statistics.mean(abs_diffs)
        median_days = statistics.median(abs_diffs)
        p75_days = sorted_diffs[int(len(sorted_diffs) * 0.75)]
        p90_days = sorted_diffs[int(len(sorted_diffs) * 0.90)]
        p95_days = sorted_diffs[int(len(sorted_diffs) * 0.95)]
        
        logger.info(f"\n基于平均值: ±{avg_days:.0f} 天 (约 {avg_days/30:.1f} 个月)")
        logger.info(f"基于中位数: ±{median_days:.0f} 天 (约 {median_days/30:.1f} 个月)")
        logger.info(f"基于75%分位: ±{p75_days:.0f} 天 (约 {p75_days/30:.1f} 个月)")
        logger.info(f"基于90%分位: ±{p90_days:.0f} 天 (约 {p90_days/30:.1f} 个月)")
        logger.info(f"基于95%分位: ±{p95_days:.0f} 天 (约 {p95_days/30:.1f} 个月)")
        
        logger.info(f"\n建议:")
        logger.info(f"  • 如果追求覆盖率，使用 ±{p90_days:.0f} 天 (可覆盖90%的情况)")
        logger.info(f"  • 如果追求效率，使用 ±{median_days:.0f} 天 (可覆盖50%的情况)")
        logger.info(f"  • 平衡选择，使用 ±{p75_days:.0f} 天 (可覆盖75%的情况)")
        
        logger.info("\n" + "="*60)
    
    def export_results(self, filename: str = "time_window_analysis.txt"):
        """导出详细结果"""
        if not self.time_diffs:
            logger.warning("没有数据可导出")
            return
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("CVE-Commit时间差分析结果\n")
            f.write("="*60 + "\n\n")
            
            # 写入所有时间差
            f.write("详细数据:\n")
            f.write("索引,时间差(天)\n")
            for idx, diff in enumerate(self.time_diffs, 1):
                f.write(f"{idx},{diff:.2f}\n")
        
        logger.info(f"详细结果已导出到: {filename}")


def main():
    """主函数"""
    analyzer = TimeWindowAnalyzer()
    
    # 分析时间窗口（使用score >= 65的修复对）
    analyzer.analyze(min_score=65)
    
    # 导出详细结果
    analyzer.export_results()


if __name__ == "__main__":
    main()
