"""
数据库操作模块
负责与PostgreSQL数据库的交互
"""

import psycopg2
from psycopg2.extras import RealDictCursor
from typing import List, Dict, Optional
import logging
from config import DB_CONFIG

logger = logging.getLogger(__name__)


class DatabaseManager:
    """数据库管理类,处理所有数据库操作"""
    
    def __init__(self, config: Dict = None):
        """
        初始化数据库连接
        
        Args:
            config: 数据库配置字典,如果为None则使用默认配置
        """
        self.config = config or DB_CONFIG
        self.connection = None
        self.cursor = None
        
    def connect(self):
        """建立数据库连接"""
        try:
            self.connection = psycopg2.connect(**self.config)
            self.cursor = self.connection.cursor(cursor_factory=RealDictCursor)
            logger.info("数据库连接成功")
        except Exception as e:
            logger.error(f"数据库连接失败: {e}")
            raise
    
    def disconnect(self):
        """关闭数据库连接"""
        if self.cursor:
            self.cursor.close()
        if self.connection:
            self.connection.close()
        logger.info("数据库连接已关闭")
    
    def get_cve_with_repos(self, limit: int = None, offset: int = 0) -> List[Dict]:
        """
        获取CVE及其关联的GitHub仓库信息
        
        Args:
            limit: 限制返回的记录数,None表示不限制
            offset: 偏移量,用于分页
            
        Returns:
            包含CVE和仓库信息的字典列表
        """
        query = """
            SELECT DISTINCT
                c.cve_id,
                c.published_date,
                cp.project_url as repo_url
            FROM cve c
            INNER JOIN cve_project cp ON c.cve_id = cp.cve
            WHERE cp.project_url LIKE '%github.com%'
                AND c.published_date IS NOT NULL
                AND c.published_date != ''
            ORDER BY c.cve_id
        """
        
        if limit:
            query += f" LIMIT {limit} OFFSET {offset}"
        
        try:
            self.cursor.execute(query)
            results = self.cursor.fetchall()
            logger.info(f"查询到 {len(results)} 条CVE-仓库关联记录")
            return results
        except Exception as e:
            logger.error(f"查询CVE和仓库信息失败: {e}")
            raise
    
    def get_known_fixes_for_cve(self, cve_id: str) -> List[Dict]:
        """
        获取某个CVE已知的修复commit(从fixes表)
        注意:这些是正确的样本,仅用于参考对比,不会修改
        
        Args:
            cve_id: CVE编号
            
        Returns:
            已知修复commit列表
        """
        query = """
            SELECT hash, repo_url, rel_type, score
            FROM fixes
            WHERE cve_id = %s
        """
        
        try:
            self.cursor.execute(query, (cve_id,))
            results = self.cursor.fetchall()
            logger.debug(f"CVE {cve_id} 有 {len(results)} 个已知修复commit")
            return results
        except Exception as e:
            logger.error(f"查询已知修复commit失败: {e}")
            raise
    
    def get_commit_details(self, commit_hash: str, repo_url: str) -> Optional[Dict]:
        """
        从commits表获取commit的详细信息
        
        Args:
            commit_hash: commit的hash值
            repo_url: 仓库URL
            
        Returns:
            commit详细信息字典,如果不存在返回None
        """
        query = """
            SELECT *
            FROM commits
            WHERE hash = %s AND repo_url = %s
        """
        
        try:
            self.cursor.execute(query, (commit_hash, repo_url))
            result = self.cursor.fetchone()
            return result
        except Exception as e:
            logger.error(f"查询commit详情失败: {e}")
            raise
    
    def check_repo_exists(self, repo_url: str) -> bool:
        """
        检查仓库是否已在repository表中
        
        Args:
            repo_url: 仓库URL
            
        Returns:
            True表示存在,False表示不存在
        """
        query = """
            SELECT 1
            FROM repository
            WHERE repo_url = %s
        """
        
        try:
            self.cursor.execute(query, (repo_url,))
            return self.cursor.fetchone() is not None
        except Exception as e:
            logger.error(f"检查仓库是否存在失败: {e}")
            raise
    
    def get_cve_count(self) -> int:
        """
        获取数据库中CVE的总数
        
        Returns:
            CVE总数
        """
        query = """
            SELECT COUNT(DISTINCT c.cve_id)
            FROM cve c
            INNER JOIN cve_project cp ON c.cve_id = cp.cve
            WHERE cp.project_url LIKE '%github.com%'
                AND c.published_date IS NOT NULL
                AND c.published_date != ''
        """
        
        try:
            self.cursor.execute(query)
            result = self.cursor.fetchone()
            count = result['count'] if result else 0
            logger.info(f"数据库中共有 {count} 个有效CVE")
            return count
        except Exception as e:
            logger.error(f"获取CVE总数失败: {e}")
            raise


if __name__ == "__main__":
    # 测试代码
    logging.basicConfig(level=logging.INFO)
    
    db = DatabaseManager()
    try:
        db.connect()
        
        # 测试获取CVE总数
        total = db.get_cve_count()
        print(f"CVE总数: {total}")
        
        # 测试获取前5条CVE
        cves = db.get_cve_with_repos(limit=5)
        print(f"\n前5条CVE记录:")
        for cve in cves:
            print(f"  {cve['cve_id']}: {cve['published_date']} -> {cve['repo_url']}")
        
    finally:
        db.disconnect()
