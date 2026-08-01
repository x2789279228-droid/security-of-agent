"""
CAPEC 知识库导入器

从 MITRE 官方 STIX 数据源获取完整的 CAPEC (Common Attack Pattern Enumeration
and Classification) 攻击模式，导入到本地知识库供 RAG 检索使用。

数据源:
  - CAPEC: https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json

导入内容:
  - 所有 attack-pattern (攻击模式)
  - 包含描述、前提条件、严重度、缓解措施、示例
"""
import json
import logging
import re
from typing import Optional

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from .knowledge_base import kb_manager
from .chunker import security_chunker

logger = logging.getLogger(__name__)

CAPEC_URL = (
    "https://raw.githubusercontent.com/mitre/cti/"
    "master/capec/2.1/stix-capec.json"
)

# CAPEC 分类 → 系统威胁类型映射
CAPEC_THREAT_MAP: dict[str, list[str]] = {
    "reconnaissance": ["DISCOVERY", "PORT_SCAN"],
    "resource depletion": ["DDoS_TRAFFIC"],
    "injection": ["WEB_ATTACK"],
    "data leakage": ["DATA_EXFIL"],
    "authentication": ["BRUTE_FORCE", "CREDENTIAL_ACCESS"],
    "command execution": ["MALWARE_DETECT", "WEB_ATTACK"],
    "privilege escalation": ["PRIVILEGE_ESCALATION"],
    "persistence": ["PERSISTENCE"],
    "lateral movement": ["LATERAL_MOVE"],
    "communications": ["C2_BEACON"],
    "time and state": ["DDoS_TRAFFIC"],
}

CAPEC_SEVERITY_MAP: dict[str, str] = {
    "very low": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "very high": "critical",
}


class CAPECImportResult:
    def __init__(self):
        self.total_found = 0
        self.imported = 0
        self.skipped = 0
        self.errors = 0
        self.error_details: list[str] = []

    def to_dict(self):
        return {
            "source": "capec",
            "total_found": self.total_found,
            "imported": self.imported,
            "skipped": self.skipped,
            "errors": self.errors,
            "error_details": self.error_details[:5],
        }


def _extract_capec_id(stix_obj: dict) -> str:
    """提取 CAPEC ID (如 CAPEC-123)"""
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == "capec":
            return ref.get("external_id", "")
    return stix_obj.get("name", "")


def _get_category(stix_obj: dict) -> str:
    """获取攻击模式分类"""
    labels = stix_obj.get("labels", [])
    categories = [l for l in labels if l != "attack-pattern"]
    return categories[0] if categories else "unknown"


def _build_capec_content(stix_obj: dict) -> str:
    """构建 CAPEC 知识文档内容"""
    parts = []

    desc = stix_obj.get("description", "")
    if desc:
        parts.append("## 描述\n" + desc)

    # 前提条件
    prereq = stix_obj.get("x_capec_prerequisites", "")
    if prereq:
        parts.append("## 前提条件\n" + prereq)

    # 严重度
    severity = stix_obj.get("x_capec_typical_severity", "")
    if severity:
        parts.append("## 典型严重度\n" + severity)

    # 所需技能
    skills = stix_obj.get("x_capec_skills_required", {})
    if skills:
        skills_text = "\n".join(
            f"- {level}: {desc}" for level, desc in skills.items()
        )
        parts.append("## 所需技能\n" + skills_text)

    # 缓解措施
    mitigations = stix_obj.get("x_capec_mitigations", "")
    if mitigations:
        clean = re.sub(r"<[^>]+>", "", mitigations)
        parts.append("## 缓解措施\n" + clean)

    # 示例
    examples = stix_obj.get("x_capec_examples", "")
    if examples:
        clean = re.sub(r"<[^>]+>", "", examples)
        parts.append("## 示例\n" + clean)

    # 后果
    consequences = stix_obj.get("x_capec_consequences", {})
    if consequences:
        cons_text = "\n".join(
            f"- {scope}: {impact}"
            for scope, impact in consequences.items()
        )
        parts.append("## 后果\n" + cons_text)

    return "\n\n".join(parts)


async def import_capec(
    session: AsyncSession,
    source_url: str = CAPEC_URL,
    limit: int = 0,
) -> CAPECImportResult:
    """
    从 MITRE 官方 STIX 数据源导入 CAPEC 攻击模式。

    Args:
        session: 数据库会话
        source_url: STIX JSON 数据源 URL
        limit: 最大导入数量 (0=全部)

    Returns:
        CAPECImportResult 导入结果
    """
    result = CAPECImportResult()

    logger.info(f"Fetching CAPEC from {source_url}...")
    try:
        async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
            resp = await client.get(source_url)
            resp.raise_for_status()
            bundle = resp.json()
    except Exception as e:
        result.errors = 1
        result.error_details.append(f"Failed to fetch CAPEC data: {e}")
        logger.error(f"CAPEC fetch failed: {e}")
        return result

    objects = bundle.get("objects", [])
    attack_patterns = [
        obj for obj in objects
        if obj.get("type") == "attack-pattern"
        and obj.get("revoked") is not True
        and obj.get("deprecated") is not True
    ]
    result.total_found = len(attack_patterns)
    logger.info(f"Found {len(attack_patterns)} CAPEC attack patterns")

    if limit > 0:
        attack_patterns = attack_patterns[:limit]

    for obj in attack_patterns:
        try:
            capec_id = _extract_capec_id(obj)
            name = obj.get("name", "")
            category = _get_category(obj)

            title = f"{capec_id} - {name}"
            content = _build_capec_content(obj)
            if not content.strip():
                result.skipped += 1
                continue

            # 确定威胁类型
            threat_types = CAPEC_THREAT_MAP.get(category, ["ANY"])

            # 确定严重度
            severity_str = obj.get("x_capec_typical_severity", "").lower()
            severity = CAPEC_SEVERITY_MAP.get(severity_str, "medium")

            tags = [capec_id, category]
            likelihood = obj.get("x_capec_likelihood_of_attack", "")
            if likelihood:
                tags.append(likelihood.lower().replace(" ", "-"))

            # 检查是否已存在
            existing = await kb_manager.search_documents(
                session, query=capec_id, limit=1
            )
            if existing:
                result.skipped += 1
                continue

            doc = await kb_manager.add_document(
                session=session,
                title=title,
                content=content[:5000],
                source="capec",
                threat_types=threat_types,
                severity=severity,
                tags=tags,
                metadata={
                    "capec_id": capec_id,
                    "category": category,
                    "url": f"https://capec.mitre.org/data/definitions/{capec_id.replace('CAPEC-', '')}.html",
                },
            )

            # 分块并写入向量
            from models import KnowledgeChunk

            chunks = security_chunker.chunk_document(
                doc_id=doc["id"],
                title=title,
                content=content[:5000],
                source="capec",
                threat_types=threat_types,
                severity=severity,
                tags=tags,
            )
            for chunk_data in chunks:
                chunk = KnowledgeChunk(
                    doc_id=chunk_data["doc_id"],
                    chunk_id=chunk_data["chunk_id"],
                    content=chunk_data["content"],
                    title=title,
                    source="capec",
                    threat_types=threat_types,
                    severity=severity,
                    tags=tags,
                    embedding=[0.0],
                    token_count=chunk_data["token_count"],
                )
                session.add(chunk)

            result.imported += 1

        except Exception as e:
            result.errors += 1
            result.error_details.append(f"Error importing {obj.get('name', '?')}: {e}")
            logger.warning(f"Failed to import CAPEC pattern {obj.get('name')}: {e}")

    await session.commit()
    logger.info(
        f"CAPEC import complete: "
        f"{result.imported} imported, {result.skipped} skipped, {result.errors} errors"
    )

    # 异步计算 embedding
    if result.imported > 0:
        from .seeder import _compute_missing_embeddings
        asyncio_create = __import__("asyncio").create_task
        asyncio_create(_compute_missing_embeddings(session))

    return result
