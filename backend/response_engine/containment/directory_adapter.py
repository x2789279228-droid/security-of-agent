"""LDAP/AD account disable. Live requires ldap_url; mock/dry_run does not bind."""
from __future__ import annotations

import logging
from typing import Optional

from config import settings

from .types import BACKEND_LDAP, STATUS_UNCONFIGURED

logger = logging.getLogger(__name__)

PROTECTED_SAM = frozenset({"krbtgt", "administrator"})
PROTECTED_DN_NEEDLES = (
    "CN=DOMAIN ADMINS",
    "CN=ENTERPRISE ADMINS",
    "CN=SCHEMA ADMINS",
    "DOMAIN ADMINS",
    "ENTERPRISE ADMINS",
    "SCHEMA ADMINS",
)
ACCOUNTDISABLE = 2


def _mode() -> str:
    return (getattr(settings, "execution_mode", "live") or "live").lower()


def ldap_configured() -> bool:
    return bool(getattr(settings, "ldap_url", "") or "")


def is_protected_account(account: str, dn: str = "", rid: int = 0) -> bool:
    if int(rid or 0) == 500:
        return True
    sam = str(account or "").split("@")[0].strip().lower()
    if sam in PROTECTED_SAM:
        return True
    hay = str(dn or "").upper()
    return any(n in hay for n in PROTECTED_DN_NEEDLES)


def _unconfigured(action: str, **extra) -> dict:
    return {"action": action, "success": False, "mode": STATUS_UNCONFIGURED,
            "error": "ldap unconfigured", "backend": BACKEND_LDAP, **extra}


async def disable_account(
    account: str = "",
    domain: str = "",
    dn: str = "",
    rid: int = 0,
    override_protected: bool = False,
    reason: str = "",
    **kwargs,
) -> dict:
    acct = str(account or "").strip()
    if not acct:
        return {"action": "disable_account", "success": False, "mode": "invalid",
                "error": "account required"}
    if is_protected_account(acct, dn=dn, rid=rid) and not override_protected:
        return {"action": "disable_account", "success": False, "mode": "denied",
                "error": "protected account", "account": acct}
    if _mode() != "live":
        return {
            "action": "disable_account", "success": True, "mode": _mode(),
            "account": acct, "domain": domain, "backend": BACKEND_LDAP,
            "uac_bit": ACCOUNTDISABLE, "would_execute": _mode() == "dry_run",
        }
    if not ldap_configured():
        return _unconfigured("disable_account", account=acct, domain=domain)
    try:
        import ldap3  # optional
    except ImportError:
        return {**_unconfigured("disable_account", account=acct),
                "error": "ldap3 not installed"}
    url = settings.ldap_url
    bind_dn = settings.ldap_bind_dn
    password = settings.ldap_bind_password
    base = settings.ldap_base_dn
    try:
        server = ldap3.Server(url, get_info=ldap3.NONE)
        conn = ldap3.Connection(server, user=bind_dn, password=password, auto_bind=True)
        filt = f"(|(sAMAccountName={acct})(userPrincipalName={acct}))"
        conn.search(base, filt, attributes=["distinguishedName", "userAccountControl", "objectSid"])
        if not conn.entries:
            return {"action": "disable_account", "success": False, "mode": "live",
                    "error": "account not found", "account": acct}
        entry = conn.entries[0]
        found_dn = str(entry.distinguishedName)
        if is_protected_account(acct, dn=found_dn) and not override_protected:
            return {"action": "disable_account", "success": False, "mode": "denied",
                    "error": "protected account", "account": acct, "dn": found_dn}
        uac = int(entry.userAccountControl.value)
        new_uac = uac | ACCOUNTDISABLE
        ok = conn.modify(found_dn, {"userAccountControl": [(ldap3.MODIFY_REPLACE, [new_uac])]})
        return {
            "action": "disable_account", "success": bool(ok), "mode": "live",
            "account": acct, "dn": found_dn, "backend": BACKEND_LDAP,
        }
    except Exception as e:
        logger.warning("disable_account ldap failed: %s", e)
        return {"action": "disable_account", "success": False, "mode": "error",
                "error": str(e), "account": acct}


async def enable_account(account: str = "", dn: str = "", **kwargs) -> dict:
    acct = str(account or "").strip()
    if _mode() != "live":
        return {"action": "enable_account", "success": True, "mode": _mode(),
                "account": acct, "backend": BACKEND_LDAP}
    if not ldap_configured():
        return _unconfigured("enable_account", account=acct)
    return {"action": "enable_account", "success": False, "mode": "error",
            "error": "live enable requires ldap bind", "account": acct}


def register(registry) -> None:
    if registry.get_action("disable_account"):
        return
    registry.register(
        "disable_account", disable_account,
        description="通过 LDAP/AD 立即禁用失陷账户",
        severity="critical",
        category="identity",
        reversible=True,
        rollback_fn=enable_account,
        params_schema={
            "account": "str (required) sAMAccountName 或 UPN",
            "domain": "str 可选",
            "override_protected": "bool 仅审批工单可显式带 true",
            "reason": "str",
        },
    )
