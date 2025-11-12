"""
Commit匹配与分析模块
负责分析commit信息,判断是否可能是修复漏洞的commit
"""

import re
import logging
from typing import List, Dict, Set
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class CommitMatchResult:
    """Commit匹配结果数据类"""
    sha: str
    message: str
    author: str
    date: str
    score: int
    matched_patterns: List[str]
    matched_cve: bool


class CommitMatcher:
    """Commit匹配器类,用于分析commit是否可能修复某个CVE"""
    
    # CVE相关的关键词模式
    CVE_PATTERNS = [
        r'CVE-\d{4}-\d{4,7}',  # CVE编号
        r'cve-\d{4}-\d{4,7}',  # 小写CVE编号
    ]
    
    # 修复相关的关键词
    FIX_KEYWORDS = [
        'fix', 'fixes', 'fixed', 'fixing',
        'patch', 'patched', 'patching',
        'resolve', 'resolves', 'resolved',
        'address', 'addresses', 'addressed',
        'repair', 'repaired',
        'correct', 'corrected',
        'security',
        'vulnerability', 'vulnerabilities',
        'exploit',
        'buffer overflow', 'use after free', 'null pointer',
        'injection', 'xss', 'csrf',
        'memory leak', 'memory corruption',
        'dos', 'denial of service',
        'privilege escalation',
        'authentication bypass',
        'directory traversal',
        'remote code execution', 'rce',
        'sql injection',
        'cross-site scripting',
    ]
    
    # 不太可能是修复的关键词(排除模式)
    EXCLUDE_KEYWORDS = [
        'test', 'tests', 'testing',
        'doc', 'docs', 'documentation',
        'readme',
        'comment', 'comments',
        'typo', 'typos',
        'style', 'format', 'formatting',
        'refactor', 'refactoring',
        'cleanup',
        'update version',
        'bump version',
        'merge',
    ]
    
    def __init__(self):
        """初始化Commit匹配器"""
        self.cve_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.CVE_PATTERNS]
    
    def extract_cve_ids(self, text: str) -> Set[str]:
        """
        从文本中提取CVE编号
        
        Args:
            text: 要分析的文本(通常是commit message)
            
        Returns:
            提取到的CVE编号集合
        """
        cve_ids = set()
        
        for regex in self.cve_regex:
            matches = regex.findall(text)
            # 统一转换为大写格式
            cve_ids.update([m.upper() for m in matches])
        
        return cve_ids
    
    def calculate_match_score(
        self,
        commit_message: str,
        target_cve_id: str
    ) -> tuple:
        """
        计算commit与CVE的匹配分数
        
        Args:
            commit_message: commit消息
            target_cve_id: 目标CVE编号
            
        Returns:
            (score, matched_patterns)元组
        """
        score = 0
        matched_patterns = []
        
        message_lower = commit_message.lower()
        
        # 1. 检查是否直接提到目标CVE (最高优先级)
        cve_ids = self.extract_cve_ids(commit_message)
        if target_cve_id.upper() in cve_ids:
            score += 100
            matched_patterns.append(f"直接提到CVE: {target_cve_id}")
            logger.debug(f"Commit直接提到目标CVE: {target_cve_id}")
        
        # 2. 检查修复相关关键词
        fix_keyword_count = 0
        for keyword in self.FIX_KEYWORDS:
            if keyword.lower() in message_lower:
                fix_keyword_count += 1
                matched_patterns.append(f"修复关键词: {keyword}")
        
        # 根据关键词数量增加分数
        if fix_keyword_count > 0:
            score += min(fix_keyword_count * 10, 50)  # 最多加50分
        
        # 3. 检查排除关键词(减分)
        exclude_keyword_count = 0
        for keyword in self.EXCLUDE_KEYWORDS:
            if keyword.lower() in message_lower:
                exclude_keyword_count += 1
                matched_patterns.append(f"排除关键词: {keyword}")
        
        if exclude_keyword_count > 0:
            score -= min(exclude_keyword_count * 5, 30)  # 最多减30分
        
        # 4. 检查commit消息长度(太短可能不够详细)
        if len(commit_message) < 20:
            score -= 10
            matched_patterns.append("消息过短")
        
        # 5. 检查是否提到其他CVE(可能是批量修复)
        other_cves = cve_ids - {target_cve_id.upper()}
        if other_cves:
            score += 20
            matched_patterns.append(f"提到其他CVE: {', '.join(other_cves)}")
        
        logger.debug(f"匹配分数: {score}, 匹配模式: {matched_patterns}")
        
        return (score, matched_patterns)
    
    def analyze_commit(
        self,
        commit: Dict,
        target_cve_id: str
    ) -> CommitMatchResult:
        """
        分析单个commit,判断是否可能修复目标CVE
        
        Args:
            commit: GitHub API返回的commit对象
            target_cve_id: 目标CVE编号
            
        Returns:
            CommitMatchResult对象
        """
        # 提取commit信息
        sha = commit.get('sha', '')
        message = commit.get('commit', {}).get('message', '')
        author_info = commit.get('commit', {}).get('author', {})
        author = author_info.get('name', 'Unknown')
        date = author_info.get('date', '')
        
        # 计算匹配分数
        score, matched_patterns = self.calculate_match_score(message, target_cve_id)
        
        # 检查是否直接匹配CVE
        cve_ids = self.extract_cve_ids(message)
        matched_cve = target_cve_id.upper() in cve_ids
        
        result = CommitMatchResult(
            sha=sha,
            message=message,
            author=author,
            date=date,
            score=score,
            matched_patterns=matched_patterns,
            matched_cve=matched_cve
        )
        
        logger.debug(f"分析commit: {sha[:8]}, 分数: {score}, 匹配CVE: {matched_cve}")
        
        return result
    
    def filter_commits(
        self,
        commits: List[Dict],
        target_cve_id: str,
        min_score: int = 0
    ) -> List[CommitMatchResult]:
        """
        过滤并分析commits列表
        
        Args:
            commits: GitHub API返回的commits列表
            target_cve_id: 目标CVE编号
            min_score: 最低分数阈值
            
        Returns:
            CommitMatchResult列表,按分数降序排列
        """
        results = []
        
        for commit in commits:
            result = self.analyze_commit(commit, target_cve_id)
            if result.score >= min_score:
                results.append(result)
        
        # 按分数降序排序
        results.sort(key=lambda x: x.score, reverse=True)
        
        logger.info(f"过滤后剩余 {len(results)} 个可能的修复commit (最低分数: {min_score})")
        
        return results
    
    def get_top_candidates(
        self,
        commits: List[Dict],
        target_cve_id: str,
        top_n: int = 10
    ) -> List[CommitMatchResult]:
        """
        获取最可能的修复commit候选
        
        Args:
            commits: GitHub API返回的commits列表
            target_cve_id: 目标CVE编号
            top_n: 返回前N个候选
            
        Returns:
            CommitMatchResult列表,按分数降序排列
        """
        results = self.filter_commits(commits, target_cve_id, min_score=0)
        
        # 返回分数最高的前N个
        top_results = results[:top_n]
        
        logger.info(f"Top {len(top_results)} 候选commits:")
        for i, result in enumerate(top_results, 1):
            logger.info(f"  {i}. {result.sha[:8]} (分数: {result.score}) - {result.message[:60]}")
        
        return top_results


if __name__ == "__main__":
    # 测试代码
    logging.basicConfig(level=logging.DEBUG)
    
    matcher = CommitMatcher()
    
    # 测试提取CVE编号
    test_messages = [
        "Fix CVE-2020-1234: buffer overflow in auth module",
        "Security patch for cve-2020-5678 and CVE-2020-9012",
        "Update documentation",
        "Fix memory leak in parser"
    ]
    
    print("测试CVE提取:")
    for msg in test_messages:
        cves = matcher.extract_cve_ids(msg)
        print(f"  '{msg}' -> {cves}")
    
    # 测试分数计算
    print("\n测试分数计算:")
    target_cve = "CVE-2020-1234"
    for msg in test_messages:
        score, patterns = matcher.calculate_match_score(msg, target_cve)
        print(f"  '{msg}'")
        print(f"    分数: {score}, 匹配模式: {patterns}")
