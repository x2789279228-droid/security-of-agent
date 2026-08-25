"""B 类高级能力总览 — 能力启用状态 + Prometheus 指标聚合 (供前端统一 dashboard)"""

import logging
import re

from fastapi import APIRouter, Depends, Query
from prometheus_client import generate_latest

from auth import get_current_user, UserInfo
from config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["capabilities"])

# B 类能力名 → (metrics_key 前缀, 配置开关)
_CAPABILITIES = [
    ("ndr", "soc_ndr_flows_", lambda: settings.capture_enabled),
    ("edr", "soc_edr_events_", lambda: settings.edr_enabled),
    ("threat_intel", "soc_intel_ioc_", lambda: settings.intel_enabled),
    ("zeroday", "soc_sandbox_submissions_", lambda: settings.sandbox_enabled),
    ("phishing", "soc_phishing_detections_", lambda: True),  # PhishingGuard 常开
]


def _parse_metric_values(text: str, prefix: str) -> int:
    """从 Prometheus 文本提取以 prefix 开头(去 _total)的指标总值。"""
    total = 0
    key = prefix.rstrip("_")
    for m in re.finditer(rf"\n({re.escape(key)}(?:_total)?){{(.*?)}} ([0-9.]+)", "\n" + text):
        total += float(m.group(3))
    # 也匹配无 label 形式(如 soc_tls_sessions_total 1.0)
    for m in re.finditer(rf"\n{re.escape(key)}(?:_total)? ([0-9.]+)", "\n" + text):
        total += float(m.group(1))
    return int(total)


@router.get("/capabilities/status")
async def capabilities_status(user: UserInfo = Depends(get_current_user)):
    """返回各 B 类能力启用状态与 metrics 计数。"""
    text = generate_latest().decode()
    out = []
    for name, prefix, enabled in _CAPABILITIES:
        out.append({
            "name": name,
            "enabled": bool(enabled()),
            "count": _parse_metric_values(text, prefix),
        })
    return {"capabilities": out}
