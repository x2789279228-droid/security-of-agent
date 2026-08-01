"""
安全专用分块器 — 将安全知识文档分割为适合检索的块

分块策略（参考旅游助手的 chunker，针对安全内容优化）:
  1. 按攻击阶段分块 (ATT&CK 阶段)
  2. 按威胁类型分块
  3. 按段落/步骤分块 (playbook 的每个步骤)
  4. 回退: 固定大小 + 重叠

安全文档的常见结构:
  - MITRE ATT&CK 技术: 名称 → 描述 → 检测 → 缓解
  - Playbook: 步骤 1 → 步骤 2 → ...
  - CVE: 描述 → 影响 → 修复
"""
import re
import uuid
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ChunkResult:
    """分块结果"""
    chunks: list[dict] = field(default_factory=list)  # [{id, content, metadata, index}]
    strategy: str = ""


class SecurityChunker:
    """安全知识分块器"""

    def __init__(
        self,
        chunk_size: int = 600,
        chunk_overlap: int = 80,
    ):
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

    def chunk_document(
        self,
        doc_id: int,
        title: str,
        content: str,
        source: str = "",
        threat_types: Optional[list[str]] = None,
        severity: str = "medium",
        tags: Optional[list[str]] = None,
    ) -> list[dict]:
        """
        将文档分割为检索块

        Returns:
            [{id, doc_id, content, metadata: {title, source, threat_types, severity, tags, chunk_index}, token_count}]
        """
        if not content.strip():
            return []

        # 尝试按结构分块
        chunks = self._try_structured_chunking(content, title, source, threat_types, severity, tags)
        if chunks:
            for i, c in enumerate(chunks):
                c["metadata"]["chunk_index"] = i
            # 添加 doc_id 和 id
            for c in chunks:
                c["doc_id"] = doc_id
                c["chunk_id"] = f"chk_{doc_id}_{c['metadata']['chunk_index']}_{uuid.uuid4().hex[:6]}"
            return chunks

        # 回退: 固定大小分块
        return self._fallback_chunk(doc_id, content, title, source, threat_types, severity, tags)

    def _try_structured_chunking(
        self, content: str, title: str, source: str,
        threat_types, severity, tags,
    ) -> Optional[list[dict]]:
        """尝试按安全文档结构分块"""
        sections = []

        # 1. 按 "步骤 N" / "Step N" 分割 (playbook)
        step_pattern = re.split(r"(?:步骤|Step|阶段)\s*[：:\d]+", content)
        if len(step_pattern) > 2:
            for i, seg in enumerate(step_pattern):
                if seg.strip():
                    sections.append(seg.strip())
        else:
            # 2. 按 "##" / "###" markdown 标题分割
            md_sections = re.split(r"\n#{1,3}\s+", content)
            if len(md_sections) > 2:
                for seg in md_sections:
                    if seg.strip():
                        sections.append(seg.strip())
            else:
                # 3. 按段落分割（双换行）
                paras = re.split(r"\n\s*\n", content)
                sections = [p.strip() for p in paras if p.strip()]

        # 合并小段落
        return self._merge_sections(
            sections, title, source, threat_types, severity, tags
        )

    def _merge_sections(
        self, sections: list[str], title: str, source: str,
        threat_types, severity, tags,
    ) -> list[dict]:
        """合并小段落为合适大小的块"""
        chunks = []
        current = ""
        for sec in sections:
            candidate = current + ("\n" if current else "") + sec
            if len(candidate) > self.chunk_size and current:
                chunks.append({
                    "content": current,
                    "metadata": {
                        "title": title,
                        "source": source or "",
                        "threat_types": threat_types or [],
                        "severity": severity,
                        "tags": tags or [],
                    },
                    "token_count": self._count_tokens(current),
                })
                # overlap
                overlap_text = current[-self.chunk_overlap:] if len(current) > self.chunk_overlap else current
                current = overlap_text + "\n" + sec
            else:
                current = candidate
        if current.strip():
            chunks.append({
                "content": current.strip(),
                "metadata": {
                    "title": title,
                    "source": source or "",
                    "threat_types": threat_types or [],
                    "severity": severity,
                    "tags": tags or [],
                },
                "token_count": self._count_tokens(current),
            })
        return chunks

    def _fallback_chunk(
        self, doc_id: int, content: str, title: str, source: str,
        threat_types, severity, tags,
    ) -> list[dict]:
        """固定大小滑动窗口分块"""
        chunks = []
        start = 0
        index = 0
        while start < len(content):
            end = min(start + self.chunk_size, len(content))
            chunk_text = content[start:end].strip()
            if chunk_text:
                chunk_id = f"chk_{doc_id}_{index}_{uuid.uuid4().hex[:6]}"
                chunks.append({
                    "chunk_id": chunk_id,
                    "doc_id": doc_id,
                    "content": chunk_text,
                    "metadata": {
                        "title": title,
                        "source": source or "",
                        "threat_types": threat_types or [],
                        "severity": severity,
                        "tags": tags or [],
                        "chunk_index": index,
                    },
                    "token_count": self._count_tokens(chunk_text),
                })
                index += 1
            start += self.chunk_size - self.chunk_overlap
        return chunks

    def _count_tokens(self, text: str) -> int:
        """估算 token 数"""
        chinese = len(re.findall(r"[\u4e00-\u9fff]", text))
        other = len(text) - chinese
        return chinese + int(other / 2) + 1


security_chunker = SecurityChunker()
