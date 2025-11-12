"""
主程序入口
协调各模块完成CVE到Commit的提取任务
"""

import logging
import time
import json
from datetime import datetime
from typing import List, Dict
from pathlib import Path

from config import LOG_CONFIG, BATCH_CONFIG
from database import DatabaseManager
from github_api import GitHubAPIClient
from time_utils import TimeRangeCalculator


class CVECommitExtractor:
    """CVE-Commit提取主类"""
    
    def __init__(self):
        """初始化提取器"""
        # 设置日志
        self._setup_logging()
        
        # 初始化各模块
        self.db = DatabaseManager()
        self.github = GitHubAPIClient()
        self.time_calc = TimeRangeCalculator()
        
        # 统计信息
        self.stats = {
            'total_cves': 0,
            'processed_cves': 0,
            'total_commits': 0,
            'repo_not_found': 0,
            'api_errors': 0,
            'start_time': None,
            'end_time': None
        }
        
        # 结果存储
        self.results = []
    
    def _setup_logging(self):
        """配置日志系统"""
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        log_file = LOG_CONFIG['log_file']
        log_level = getattr(logging, LOG_CONFIG['log_level'])
        
        # 同时输出到文件和控制台
        logging.basicConfig(
            level=log_level,
            format=log_format,
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger(__name__)
        self.logger.info("="*60)
        self.logger.info("CVE-Commit提取程序启动")
        self.logger.info("="*60)
    
    def process_single_cve(self, cve_id: str, published_date: str, repo_url: str) -> Dict:
        """
        处理单个CVE,提取时间范围内的所有commits
        
        Args:
            cve_id: CVE编号
            published_date: CVE披露时间
            repo_url: GitHub仓库URL
            
        Returns:
            处理结果字典
        """
        result = {
            'cve_id': cve_id,
            'published_date': published_date,
            'repo_url': repo_url,
            'status': 'success',
            'message': '',
            'time_range': {},
            'commits': []
        }
        
        try:
            self.logger.info(f"\n{'='*60}")
            self.logger.info(f"处理CVE: {cve_id}")
            self.logger.info(f"  仓库: {repo_url}")
            self.logger.info(f"  披露时间: {published_date}")
            
            # 1. 解析仓库URL
            repo_info = self.github.parse_repo_url(repo_url)
            if not repo_info:
                result['status'] = 'error'
                result['message'] = '无法解析仓库URL'
                self.stats['api_errors'] += 1
                return result
            
            owner, repo = repo_info
            self.logger.info(f"  解析仓库: {owner}/{repo}")
            
            # 2. 检查仓库是否存在
            if not self.github.check_repo_exists(owner, repo):
                result['status'] = 'repo_not_found'
                result['message'] = '仓库不存在或无法访问'
                self.stats['repo_not_found'] += 1
                self.logger.warning(f"  仓库不存在或无法访问: {owner}/{repo}")
                return result
            
            # 3. 计算时间范围
            since, until = self.time_calc.calculate_time_range(published_date)
            result['time_range'] = {
                'since': since,
                'until': until
            }
            self.logger.info(f"  搜索时间范围: {since} ~ {until}")
            
            # 4. 获取时间范围内的所有commits
            commits = self.github.get_all_commits_in_time_range(
                owner, repo, since, until, max_pages=10
            )
            
            if not commits:
                result['message'] = '在指定时间范围内未找到任何commit'
                self.logger.info(f"  未找到任何commit")
                return result
            
            self.logger.info(f"  找到 {len(commits)} 个commits")
            
            # 5. 提取所有commit信息
            for commit in commits:
                commit_info = {
                    'sha': commit.get('sha', ''),
                    'message': commit.get('commit', {}).get('message', ''),
                    'author': commit.get('commit', {}).get('author', {}).get('name', ''),
                    'author_email': commit.get('commit', {}).get('author', {}).get('email', ''),
                    'date': commit.get('commit', {}).get('author', {}).get('date', ''),
                    'committer': commit.get('commit', {}).get('committer', {}).get('name', ''),
                    'committer_date': commit.get('commit', {}).get('committer', {}).get('date', ''),
                    'html_url': commit.get('html_url', '')
                }
                result['commits'].append(commit_info)
            
            self.stats['total_commits'] += len(commits)
            result['message'] = f'成功提取 {len(commits)} 个commits'
            self.logger.info(f"  ✓ 成功提取 {len(commits)} 个commits")
            
        except Exception as e:
            result['status'] = 'error'
            result['message'] = f'处理异常: {str(e)}'
            self.stats['api_errors'] += 1
            self.logger.error(f"  处理CVE时发生异常: {e}", exc_info=True)
        
        return result
    
    def process_cves(self, limit: int = None, offset: int = 0):
        """
        批量处理CVEs
        
        Args:
            limit: 处理的CVE数量限制,None表示处理所有
            offset: 起始偏移量
        """
        try:
            # 连接数据库
            self.db.connect()
            
            # 获取CVE总数
            total_count = self.db.get_cve_count()
            self.stats['total_cves'] = total_count
            self.logger.info(f"数据库中共有 {total_count} 个CVE")
            
            # 获取待处理的CVEs
            cves = self.db.get_cve_with_repos(limit=limit, offset=offset)
            process_count = len(cves)
            self.logger.info(f"本次将处理 {process_count} 个CVE (偏移: {offset})")
            
            # 记录开始时间
            self.stats['start_time'] = time.time()
            
            # 检查API速率限制
            rate_status = self.github.get_rate_limit_status()
            self.logger.info(f"API速率限制状态: {rate_status['remaining']}/{rate_status['limit']}")
            
            # 逐个处理CVE
            for idx, cve_record in enumerate(cves, 1):
                cve_id = cve_record['cve_id']
                published_date = cve_record['published_date']
                repo_url = cve_record['repo_url']
                
                self.logger.info(f"\n进度: {idx}/{process_count}")
                
                # 处理单个CVE
                result = self.process_single_cve(cve_id, published_date, repo_url)
                self.results.append(result)
                self.stats['processed_cves'] += 1
                
                # 定期保存结果
                if idx % BATCH_CONFIG['batch_size'] == 0:
                    self._save_intermediate_results()
                    self.logger.info(f"已保存中间结果 (处理了 {idx} 个CVE)")
                
                # 短暂休眠,避免API速率限制
                time.sleep(0.5)
            
            # 记录结束时间
            self.stats['end_time'] = time.time()
            
            # 保存最终结果
            self._save_final_results()
            
            # 输出统计信息
            self._print_statistics()
            
        except KeyboardInterrupt:
            self.logger.warning("\n程序被用户中断")
            self._save_intermediate_results()
            self._print_statistics()
            
        except Exception as e:
            self.logger.error(f"程序执行出错: {e}", exc_info=True)
            
        finally:
            # 关闭数据库连接
            self.db.disconnect()
    
    def _save_intermediate_results(self):
        """保存中间结果"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'cve_commit_results_intermediate_{timestamp}.json'
        self._save_results_to_file(filename)
    
    def _save_final_results(self):
        """保存最终结果"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'cve_commit_results_final_{timestamp}.json'
        self._save_results_to_file(filename)
        self.logger.info(f"\n最终结果已保存到: {filename}")
    
    def _save_results_to_file(self, filename: str):
        """
        保存结果到JSON文件
        
        Args:
            filename: 文件名
        """
        output = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'total_cves': self.stats['total_cves'],
                'processed_cves': self.stats['processed_cves'],
                'total_commits': self.stats['total_commits'],
                'repo_not_found': self.stats['repo_not_found'],
                'api_errors': self.stats['api_errors']
            },
            'results': self.results
        }
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(output, f, indent=2, ensure_ascii=False)
            self.logger.info(f"结果已保存到: {filename}")
        except Exception as e:
            self.logger.error(f"保存结果失败: {e}")
    
    def _print_statistics(self):
        """打印统计信息"""
        self.logger.info("\n" + "="*60)
        self.logger.info("统计信息")
        self.logger.info("="*60)
        self.logger.info(f"总CVE数量:        {self.stats['total_cves']}")
        self.logger.info(f"已处理CVE数量:    {self.stats['processed_cves']}")
        self.logger.info(f"提取的Commit数量: {self.stats['total_commits']}")
        self.logger.info(f"仓库不存在:       {self.stats['repo_not_found']}")
        self.logger.info(f"API错误:          {self.stats['api_errors']}")
        
        if self.stats['start_time'] and self.stats['end_time']:
            duration = self.stats['end_time'] - self.stats['start_time']
            formatted_duration = self.time_calc.format_time_delta(duration)
            self.logger.info(f"总耗时:           {formatted_duration}")
            
            if self.stats['processed_cves'] > 0:
                avg_time = duration / self.stats['processed_cves']
                formatted_avg = self.time_calc.format_time_delta(avg_time)
                self.logger.info(f"平均每个CVE:      {formatted_avg}")
                
                avg_commits = self.stats['total_commits'] / self.stats['processed_cves']
                self.logger.info(f"平均每个CVE的commits: {avg_commits:.1f}")
        
        self.logger.info("="*60)


def main():
    """主函数"""
    # 创建提取器实例
    extractor = CVECommitExtractor()
    
    # 处理CVEs
    # 可以通过参数控制处理数量,例如:
    # extractor.process_cves(limit=10)  # 只处理10个CVE
    # extractor.process_cves(limit=100, offset=0)  # 处理前100个CVE
    # extractor.process_cves()  # 处理所有CVE
    
    # 示例: 先处理5个CVE进行测试
    extractor.process_cves(limit=5)


if __name__ == "__main__":
    main()
