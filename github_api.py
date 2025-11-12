"""
GitHub API交互模块
负责与GitHub API的通信和数据获取
"""

import requests
import time
import logging
from typing import List, Dict, Optional
from datetime import datetime
from config import GITHUB_CONFIG, BATCH_CONFIG

logger = logging.getLogger(__name__)


class GitHubAPIClient:
    """GitHub API客户端类,处理所有GitHub API调用"""
    
    def __init__(self, api_token: str = None):
        """
        初始化GitHub API客户端
        
        Args:
            api_token: GitHub Personal Access Token
        """
        self.api_token = api_token or GITHUB_CONFIG['api_token']
        self.base_url = GITHUB_CONFIG['api_base_url']
        self.timeout = GITHUB_CONFIG['timeout']
        self.headers = {
            'Authorization': f'token {self.api_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
    def _make_request(self, url: str, params: Dict = None) -> Optional[Dict]:
        """
        发送HTTP请求到GitHub API
        
        Args:
            url: API端点URL
            params: 查询参数
            
        Returns:
            响应JSON数据,失败返回None
        """
        retry_count = 0
        max_retries = BATCH_CONFIG['retry_times']
        retry_delay = BATCH_CONFIG['retry_delay']
        
        while retry_count < max_retries:
            try:
                response = requests.get(
                    url,
                    headers=self.headers,
                    params=params,
                    timeout=self.timeout
                )
                
                # 检查速率限制
                remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
                if remaining < 10:
                    reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
                    wait_time = reset_time - time.time() + 10
                    if wait_time > 0:
                        logger.warning(f"API速率限制即将用尽,等待 {wait_time:.0f} 秒")
                        time.sleep(wait_time)
                
                # 处理响应
                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 404:
                    logger.warning(f"资源不存在(404): {url}")
                    return None
                elif response.status_code == 403:
                    logger.error("API速率限制超出或访问被拒绝")
                    return None
                elif response.status_code == 409:
                    logger.warning(f"仓库为空或正在初始化(409): {url}")
                    return None
                else:
                    logger.warning(f"请求失败,状态码: {response.status_code}, URL: {url}")
                    
            except requests.exceptions.Timeout:
                logger.warning(f"请求超时,重试 {retry_count + 1}/{max_retries}")
            except requests.exceptions.RequestException as e:
                logger.error(f"请求异常: {e}")
            
            retry_count += 1
            if retry_count < max_retries:
                time.sleep(retry_delay)
        
        logger.error(f"请求失败,已重试 {max_retries} 次: {url}")
        return None
    
    def parse_repo_url(self, repo_url: str) -> Optional[tuple]:
        """
        解析GitHub仓库URL,提取owner和repo名称
        
        Args:
            repo_url: GitHub仓库URL
            
        Returns:
            (owner, repo)元组,解析失败返回None
        """
        try:
            # 支持多种URL格式
            # https://github.com/owner/repo
            # https://github.com/owner/repo.git
            # github.com/owner/repo
            
            url = repo_url.strip()
            
            # 移除协议前缀
            if url.startswith('http://') or url.startswith('https://'):
                url = url.split('://', 1)[1]
            
            # 移除github.com前缀
            if url.startswith('github.com/'):
                url = url[11:]
            
            # 移除.git后缀
            if url.endswith('.git'):
                url = url[:-4]
            
            # 分割owner和repo
            parts = url.split('/')
            if len(parts) >= 2:
                owner = parts[0]
                repo = parts[1]
                return (owner, repo)
            else:
                logger.warning(f"无法解析仓库URL: {repo_url}")
                return None
                
        except Exception as e:
            logger.error(f"解析仓库URL失败: {repo_url}, 错误: {e}")
            return None
    
    def check_repo_exists(self, owner: str, repo: str) -> bool:
        """
        检查GitHub仓库是否存在
        
        Args:
            owner: 仓库所有者
            repo: 仓库名称
            
        Returns:
            True表示存在,False表示不存在或访问失败
        """
        url = f"{self.base_url}/repos/{owner}/{repo}"
        response = self._make_request(url)
        
        if response:
            logger.info(f"仓库存在: {owner}/{repo}")
            return True
        else:
            logger.warning(f"仓库不存在或无法访问: {owner}/{repo}")
            return False
    
    def get_commits_in_time_range(
        self,
        owner: str,
        repo: str,
        since: str,
        until: str,
        page: int = 1,
        per_page: int = 100
    ) -> List[Dict]:
        """
        获取指定时间范围内的commits
        
        Args:
            owner: 仓库所有者
            repo: 仓库名称
            since: 开始时间(ISO 8601格式)
            until: 结束时间(ISO 8601格式)
            page: 页码
            per_page: 每页数量(最大100)
            
        Returns:
            commit列表
        """
        url = f"{self.base_url}/repos/{owner}/{repo}/commits"
        params = {
            'since': since,
            'until': until,
            'page': page,
            'per_page': per_page
        }
        
        response = self._make_request(url, params)
        
        if response:
            logger.info(f"获取到 {len(response)} 个commits: {owner}/{repo}")
            return response
        else:
            return []
    
    def get_all_commits_in_time_range(
        self,
        owner: str,
        repo: str,
        since: str,
        until: str,
        max_pages: int = 10
    ) -> List[Dict]:
        """
        获取指定时间范围内的所有commits(处理分页)
        
        Args:
            owner: 仓库所有者
            repo: 仓库名称
            since: 开始时间(ISO 8601格式)
            until: 结束时间(ISO 8601格式)
            max_pages: 最大页数限制
            
        Returns:
            所有commit列表
        """
        all_commits = []
        page = 1
        
        while page <= max_pages:
            commits = self.get_commits_in_time_range(
                owner, repo, since, until, page=page, per_page=100
            )
            
            if not commits:
                break
            
            all_commits.extend(commits)
            
            # 如果返回的commit数量少于100,说明已经是最后一页
            if len(commits) < 100:
                break
            
            page += 1
        
        logger.info(f"共获取到 {len(all_commits)} 个commits: {owner}/{repo} ({since} ~ {until})")
        return all_commits
    
    def get_commit_detail(self, owner: str, repo: str, sha: str) -> Optional[Dict]:
        """
        获取单个commit的详细信息
        
        Args:
            owner: 仓库所有者
            repo: 仓库名称
            sha: commit的SHA值
            
        Returns:
            commit详细信息
        """
        url = f"{self.base_url}/repos/{owner}/{repo}/commits/{sha}"
        response = self._make_request(url)
        
        if response:
            logger.debug(f"获取commit详情成功: {sha}")
            return response
        else:
            logger.warning(f"获取commit详情失败: {sha}")
            return None
    
    def get_rate_limit_status(self) -> Dict:
        """
        获取API速率限制状态
        
        Returns:
            速率限制信息
        """
        url = f"{self.base_url}/rate_limit"
        response = self._make_request(url)
        
        if response:
            core = response.get('resources', {}).get('core', {})
            remaining = core.get('remaining', 0)
            limit = core.get('limit', 0)
            reset = core.get('reset', 0)
            reset_time = datetime.fromtimestamp(reset).strftime('%Y-%m-%d %H:%M:%S')
            
            logger.info(f"API速率限制: {remaining}/{limit}, 重置时间: {reset_time}")
            return {
                'remaining': remaining,
                'limit': limit,
                'reset': reset_time
            }
        else:
            return {'remaining': 0, 'limit': 0, 'reset': 'Unknown'}


if __name__ == "__main__":
    # 测试代码
    logging.basicConfig(level=logging.INFO)
    
    # 创建客户端(需要配置API token)
    client = GitHubAPIClient()
    
    # 测试解析仓库URL
    test_urls = [
        "https://github.com/MariaDB/server",
        "github.com/torvalds/linux",
        "https://github.com/nodejs/node.git"
    ]
    
    print("测试URL解析:")
    for url in test_urls:
        result = client.parse_repo_url(url)
        print(f"  {url} -> {result}")
    
    # 测试获取速率限制状态
    print("\n测试API速率限制:")
    status = client.get_rate_limit_status()
    print(f"  {status}")
