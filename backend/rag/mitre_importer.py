"""
MITRE ATT&CK 知识库导入器

从 MITRE 官方 STIX 数据源获取完整的 ATT&CK 企业攻击技术，
导入到本地知识库供 RAG 检索使用。

数据源:
  - Enterprise ATT&CK: https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json

导入内容:
  - 所有 attack-pattern (技术/子技术)
  - 映射 kill_chain_phases → threat_types
  - 包含检测规则、缓解措施、平台信息
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

# MITRE ATT&CK 官方数据源 URL
ENTERPRISE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

# Kill Chain Phase → 系统威胁类型映射
TACTIC_MAP = {
    "reconnaissance": "DISCOVERY",
    "resource-development": "DISCOVERY",
    "initial-access": "WEB_ATTACK",
    "execution": "MALWARE_DETECT",
    "persistence": "PERSISTENCE",
    "privilege-escalation": "PRIVILEGE_ESCALATION",
    "defense-evasion": "DEFENSE_EVASION",
    "credential-access": "CREDENTIAL_ACCESS",
    "discovery": "DISCOVERY",
    "lateral-movement": "LATERAL_MOVE",
    "collection": "DATA_EXFIL",
    "command-and-control": "C2_BEACON",
    "exfiltration": "DATA_EXFIL",
    "impact": "DDoS_TRAFFIC",
}

SEVERITY_MAP = {
    "reconnaissance": "low",
    "resource-development": "medium",
    "initial-access": "high",
    "execution": "high",
    "persistence": "medium",
    "privilege-escalation": "high",
    "defense-evasion": "high",
    "credential-access": "critical",
    "discovery": "low",
    "lateral-movement": "high",
    "collection": "medium",
    "command-and-control": "critical",
    "exfiltration": "critical",
    "impact": "high",
}


class MITREImportResult:
    def __init__(self):
        self.total_found = 0
        self.imported = 0
        self.skipped = 0
        self.errors = 0
        self.error_details: list[str] = []

    def to_dict(self):
        return {
            "source": "mitre-attack",
            "total_found": self.total_found,
            "imported": self.imported,
            "skipped": self.skipped,
            "errors": self.errors,
            "error_details": self.error_details[:5],
        }


def _extract_technique_id(stix_obj: dict) -> str:
    """从 external_references 中提取 ATT&CK ID (如 T1071.001)"""
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return stix_obj.get("name", "")


def _get_tactic(stix_obj: dict) -> Optional[str]:
    """获取主要战术阶段"""
    phases = stix_obj.get("kill_chain_phases", [])
    for p in phases:
        if p.get("kill_chain_name") == "mitre-attack":
            return p.get("phase_name", "")
    return None


def _build_content(stix_obj: dict) -> str:
    """构建知识文档内容"""
    parts = []
    desc = stix_obj.get("description", "")
    if desc:
        parts.append("## 描述\n" + desc)

    detection = stix_obj.get("x_mitre_detection", "")
    if detection:
        # 清理 HTML 标签
        clean = re.sub(r"<[^>]+>", "", detection)
        parts.append("## 检测规则\n" + clean)

    platforms = stix_obj.get("x_mitre_platforms", [])
    if platforms:
        parts.append("## 受影响平台\n" + ", ".join(platforms))

    data_sources = stix_obj.get("x_mitre_data_sources", [])
    if data_sources:
        parts.append("## 数据源\n" + ", ".join(data_sources))

    defenses = stix_obj.get("x_mitre_defense_bypassed", [])
    if defenses:
        parts.append("## 可绕过的防御\n" + ", ".join(defenses))

    permissions = stix_obj.get("x_mitre_permissions_required", [])
    if permissions:
        parts.append("## 所需权限\n" + ", ".join(permissions))

    return "\n\n".join(parts)


async def import_enterprise_attack(
    session: AsyncSession,
    source_url: str = ENTERPRISE_ATTACK_URL,
    limit: int = 0,
) -> MITREImportResult:
    """
    从 MITRE 官方 STIX 数据源导入企业 ATT&CK 技术。

    Args:
        session: 数据库会话
        source_url: STIX JSON 数据源 URL
        limit: 最大导入数量 (0=全部)

    Returns:
        MITREImportResult 导入结果
    """
    result = MITREImportResult()

    logger.info(f"Fetching MITRE ATT&CK from {source_url}...")
    try:
        async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
            resp = await client.get(source_url)
            resp.raise_for_status()
            bundle = resp.json()
    except Exception as e:
        result.errors = 1
        result.error_details.append(f"Failed to fetch data: {e}")
        logger.error(f"MITRE ATT&CK fetch failed: {e}")
        return result

    objects = bundle.get("objects", [])
    attack_patterns = [
        obj for obj in objects
        if obj.get("type") == "attack-pattern"
        and obj.get("revoked") is not True
        and obj.get("deprecated") is not True
    ]
    result.total_found = len(attack_patterns)
    logger.info(f"Found {len(attack_patterns)} ATT&CK attack patterns")

    # 按 kill_chain_phases 排序，确保技术有战术分类
    attack_patterns.sort(
        key=lambda x: (
            x.get("kill_chain_phases", [{}])[0].get("phase_name", "zzz")
            if x.get("kill_chain_phases")
            else "zzz"
        )
    )

    if limit > 0:
        attack_patterns = attack_patterns[:limit]

    for obj in attack_patterns:
        try:
            tech_id = _extract_technique_id(obj)
            name = obj.get("name", "")
            tactic = _get_tactic(obj)
            if not tactic:
                result.skipped += 1
                continue

            title = f"{tech_id} - {name} ({tactic})"
            content = _build_content(obj)
            if not content.strip():
                content = obj.get("description", "暂无详细描述")
                if not content:
                    result.skipped += 1
                    continue

            threat_types = [TACTIC_MAP.get(tactic, "ANY")]
            severity = SEVERITY_MAP.get(tactic, "medium")

            platforms = obj.get("x_mitre_platforms", [])
            tags = [tech_id, tactic] + [p.lower() for p in platforms]

            # 检查是否已存在相似标题的文档
            existing = await kb_manager.search_documents(
                session, query=tech_id, limit=1
            )
            if existing:
                result.skipped += 1
                continue

            doc = await kb_manager.add_document(
                session=session,
                title=title,
                content=content[:5000],
                source="mitre-attack",
                threat_types=threat_types,
                severity=severity,
                tags=tags,
                metadata={
                    "attack_id": tech_id,
                    "tactic": tactic,
                    "platforms": platforms,
                    "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
                },
            )

            # 分块并写入向量
            from models import KnowledgeChunk

            chunks = security_chunker.chunk_document(
                doc_id=doc["id"],
                title=title,
                content=content[:5000],
                source="mitre-attack",
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
                    source="mitre-attack",
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
            logger.warning(f"Failed to import ATT&CK technique {obj.get('name')}: {e}")

    await session.commit()
    logger.info(
        f"MITRE ATT&CK import complete: "
        f"{result.imported} imported, {result.skipped} skipped, {result.errors} errors"
    )

    # 异步计算 embedding
    if result.imported > 0:
        from .seeder import _compute_missing_embeddings
        asyncio_create = __import__("asyncio").create_task
        asyncio_create(_compute_missing_embeddings(session))

    return result
