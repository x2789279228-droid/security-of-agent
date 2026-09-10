"""Phishing mail recall via Microsoft Graph. Unconfigured live → fail, never fake SMTP."""
from __future__ import annotations

import logging
from typing import Optional
from urllib.parse import quote

from config import settings

from .types import BACKEND_GRAPH, STATUS_UNCONFIGURED

logger = logging.getLogger(__name__)


def _mode() -> str:
    return (getattr(settings, "execution_mode", "live") or "live").lower()


def graph_configured() -> bool:
    return bool(
        getattr(settings, "graph_tenant", "")
        and getattr(settings, "graph_client_id", "")
        and getattr(settings, "graph_client_secret", "")
    )


async def recall_email(
    internet_message_id: str = "",
    message_id: str = "",
    mailbox: str = "",
    reason: str = "",
    **kwargs,
) -> dict:
    mid = str(internet_message_id or message_id or "").strip()
    if not mid:
        return {"action": "recall_email", "success": False, "mode": "invalid",
                "error": "internet_message_id required"}
    if _mode() != "live":
        return {
            "action": "recall_email", "success": True, "mode": _mode(),
            "internet_message_id": mid, "mailbox": mailbox,
            "backend": BACKEND_GRAPH, "would_execute": _mode() == "dry_run",
            "message": "simulated graph move to recoverableitemsdeletions",
        }
    if not graph_configured():
        return {
            "action": "recall_email", "success": False, "mode": STATUS_UNCONFIGURED,
            "error": "graph unconfigured", "internet_message_id": mid,
            "backend": BACKEND_GRAPH,
        }
    try:
        import httpx
        token = await _graph_token()
        user = mailbox or "me"
        filt = quote(f"internetMessageId eq '{mid}'", safe="")
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient(timeout=20) as client:
            search = await client.get(
                f"https://graph.microsoft.com/v1.0/users/{quote(user)}/messages?$filter={filt}",
                headers=headers,
            )
            search.raise_for_status()
            items = (search.json() or {}).get("value") or []
            if not items:
                return {"action": "recall_email", "success": False, "mode": "live",
                        "error": "message not found", "internet_message_id": mid}
            gid = items[0].get("id")
            moved = await client.post(
                f"https://graph.microsoft.com/v1.0/users/{quote(user)}/messages/{gid}/move",
                headers=headers,
                json={"destinationId": "recoverableitemsdeletions"},
            )
            moved.raise_for_status()
        return {
            "action": "recall_email", "success": True, "mode": "live",
            "internet_message_id": mid, "backend": BACKEND_GRAPH,
        }
    except Exception as e:
        logger.warning("recall_email failed: %s", e)
        return {"action": "recall_email", "success": False, "mode": "error",
                "error": str(e), "internet_message_id": mid}


async def _graph_token() -> str:
    import httpx
    tenant = settings.graph_tenant
    data = {
        "client_id": settings.graph_client_id,
        "client_secret": settings.graph_client_secret,
        "grant_type": "client_credentials",
        "scope": "https://graph.microsoft.com/.default",
    }
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.post(
            f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
            data=data,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]


def register(registry) -> None:
    if registry.get_action("recall_email"):
        return
    registry.register(
        "recall_email", recall_email,
        description="已投递钓鱼邮件撤回（Microsoft Graph move）",
        severity="high",
        category="mail",
        reversible=False,
        params_schema={
            "internet_message_id": "str (required)",
            "message_id": "str 别名",
            "mailbox": "str 可选 UPN",
            "reason": "str",
        },
    )
