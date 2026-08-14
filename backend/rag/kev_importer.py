"""
CISA KEV 导入器（0day / 已知被利用漏洞库）

数据源: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

策略（用户确认）:
  - 0day 知识库 = CISA KEV 自动导入 + 手工条目（vuln_seed 的 known_exploited 条目）
  - 按 cve_id 联动 upsert（幂等）：
      已存在（source∈cve/kev/vulnerability）→ metadata 合并 exploit 标记 + tags 加 kev-exploited + 严重度最低 high
      不存在（老 CVE 不在 NVD 聚焦窗口）→ 用 CISA 描述新建 source="kev" 文档
  - _parse_kev_entry 为纯函数，可离线单测
"""
import asyncio
import json
import logging
from typing import Optional

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from .knowledge_base import kb_manager
from .chunker import security_chunker
from .kb_types import (
    SOURCE_CVE, SOURCE_KEV, SOURCE_VULN,
    build_content_prefix, cwe_to_threat_types,
)

logger = logging.getLogger(__name__)

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

# 联动更新只作用于这几类文档（不碰 mitre/capec/policy/playbook）
_LINK_SOURCES = [SOURCE_CVE, SOURCE_KEV, SOURCE_VULN]


class KEVImportResult:
    def __init__(self):
        self.total_found = 0
        self.imported = 0          # 新建 kev 文档数
        self.updated = 0           # 联动标记已有文档数
        self.skipped = 0
        self.errors = 0
        self.error_details: list[str] = []

    def to_dict(self):
        return {
            "source": "kev",
            "total_found": self.total_found,
            "imported": self.imported,
            "updated": self.updated,
            "skipped": self.skipped,
            "errors": self.errors,
            "error_details": self.error_details[:5],
        }


def _parse_kev_entry(entry: dict) -> dict:
    """纯函数：从 CISA KEV 目录条目提取结构化字段"""
    return {
        "cve_id": entry.get("cveID", ""),
        "vendor": entry.get("vendorProject", ""),
        "product": entry.get("product", ""),
        "name": entry.get("vulnerabilityName", ""),
        "date_added": entry.get("dateAdded", ""),
        "due_date": entry.get("dueDate", ""),
        "required_action": entry.get("requiredAction", ""),
        "known_ransomware": entry.get("knownRansomwareCampaignUse", ""),
        "short_description": entry.get("shortDescription", ""),
        "notes": entry.get("notes", ""),
        "cwes": entry.get("cwes", []),
    }


def _build_kev_content(p: dict) -> str:
    """构建 KEV 文档正文（新建文档用）"""
    parts = []
    if p["name"]:
        parts.append("## 漏洞名称\n" + p["name"])
    if p["short_description"]:
        parts.append("## 漏洞描述\n" + p["short_description"])
    if p["required_action"]:
        parts.append("## 必须采取的处置\n" + p["required_action"])
    if p["due_date"]:
        parts.append("## 处置截止日期\n" + p["due_date"])
    if p["known_ransomware"]:
        parts.append("## 勒索软件利用\n" + p["known_ransomware"])
    if p["notes"]:
        parts.append("## 备注\n" + p["notes"])
    return "\n\n".join(parts)


async def import_kev(
    session: AsyncSession,
    source_url: str = "",
    fixture_path: str = "",
) -> KEVImportResult:
    """
    从 CISA KEV 导入已知被利用漏洞，按 cve_id 与既有文档联动标记。

    Args:
        session: 数据库会话
        source_url: KEV 数据源 URL（默认取 config）
        fixture_path: 本地 JSON fixture（离线测试用）

    Returns:
        KEVImportResult
    """
    result = KEVImportResult()
    source_url = source_url or settings.kev_url

    if fixture_path:
        with open(fixture_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        entries = data.get("vulnerabilities", [])
        logger.info(f"[kev] offline fixture: {len(entries)} entries from {fixture_path}")
    else:
        proxy = settings.nvd_proxy or None
        try:
            async with httpx.AsyncClient(
                timeout=60, follow_redirects=True,
                trust_env=not proxy, proxy=proxy,
            ) as client:
                resp = await client.get(source_url)
                resp.raise_for_status()
                data = resp.json()
        except Exception as e:
            result.errors = 1
            result.error_details.append(f"KEV fetch failed: {e}")
            logger.error(f"KEV fetch failed: {e}")
            return result
        entries = data.get("vulnerabilities", [])
        result.total_found = len(entries)
        logger.info(f"[kev] fetched {len(entries)} KEV entries")

    for i, entry in enumerate(entries):
        try:
            parsed = _parse_kev_entry(entry)
        except Exception as e:
            result.errors += 1
            result.error_details.append(f"parse error: {e}")
            continue

        cve_id = parsed["cve_id"]
        if not cve_id:
            result.skipped += 1
            continue

        existing = await kb_manager.find_doc_by_metadata(
            session, {"cve_id": cve_id}, sources=_LINK_SOURCES
        )

        patch = {
            "exploit_available": True,
            "kev_date_added": parsed["date_added"],
            "kev_due_date": parsed["due_date"],
            "known_ransomware": parsed["known_ransomware"],
            "kev_required_action": parsed["required_action"],
        }

        if existing:
            # 联动标记已有文档（幂等；不覆盖原正文）
            await kb_manager.update_metadata_by_metadata(
                session, {"cve_id": cve_id}, patch, sources=_LINK_SOURCES, commit=False
            )
            await kb_manager.add_tag_by_metadata(
                session, {"cve_id": cve_id}, "kev-exploited", sources=_LINK_SOURCES, commit=False
            )
            result.updated += 1
        else:
            # 老 CVE 不在聚焦窗口：新建 kev 文档
            products = []
            if parsed["vendor"] and parsed["product"]:
                products = [f"{parsed['vendor'].lower()}:{parsed['product'].lower()}"]
            meta = {
                "cve_id": cve_id,
                "exploit_available": True,
                "kev_date_added": parsed["date_added"],
                "kev_due_date": parsed["due_date"],
                "known_ransomware": parsed["known_ransomware"],
                "kev_required_action": parsed["required_action"],
                "vendor": parsed["vendor"],
                "product": parsed["product"],
                "products": products,
                "published": parsed["date_added"],
                "cwes": parsed["cwes"],
            }
            threat_types = cwe_to_threat_types(parsed["cwes"])
            title = f"{cve_id} - {parsed['name']}"
            content = build_content_prefix(meta) + _build_kev_content(parsed)
            tags = [cve_id, "kev", "kev-exploited"]

            from models import KnowledgeDoc, KnowledgeChunk
            doc = KnowledgeDoc(
                title=title, content=content[:10000], source=SOURCE_KEV,
                threat_types=threat_types, severity="high", tags=tags, metadata_=meta,
            )
            session.add(doc)
            await session.flush()

            chunks = security_chunker.chunk_document(
                doc_id=doc.id, title=title, content=content[:10000], source=SOURCE_KEV,
                threat_types=threat_types, severity="high", tags=tags,
            )
            for cd in chunks:
                session.add(KnowledgeChunk(
                    doc_id=cd["doc_id"], chunk_id=cd["chunk_id"], content=cd["content"],
                    title=title, source=SOURCE_KEV, threat_types=threat_types,
                    severity="high", tags=tags, embedding=None, token_count=cd["token_count"],
                ))
            result.imported += 1

        # 批量提交（合并 update_metadata / add_tag 的 commit=False）
        if (result.imported + result.updated) % 500 == 0:
            await session.commit()

    await session.commit()
    logger.info(
        f"KEV import complete: {result.imported} new docs, "
        f"{result.updated} linked, {result.skipped} skipped, {result.errors} errors"
    )

    if result.imported > 0:
        from .seeder import _compute_missing_embeddings
        asyncio.create_task(_compute_missing_embeddings(None))

    return result
