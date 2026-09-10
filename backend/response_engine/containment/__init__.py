"""Endpoint / identity / mail containment adapters.

Network dual-stack isolate/block lives in ssh_firewall + response_registry.
This package registers host/LDAP/mail/snapshot actions onto the same registry.
"""
from .types import (
    BACKEND_DNS,
    BACKEND_FIREWALL,
    BACKEND_GRAPH,
    BACKEND_HOST_SSH,
    BACKEND_LDAP,
    CRITICAL_CONTAINMENT,
    SNAPSHOT_BEFORE_ACTIONS,
    STATUS_APPLIED,
    STATUS_FAILED,
    STATUS_PARTIAL,
    STATUS_ROLLED_BACK,
    STATUS_UNCONFIGURED,
)

__all__ = [
    "register_containment_actions",
    "SNAPSHOT_BEFORE_ACTIONS",
    "CRITICAL_CONTAINMENT",
    "STATUS_APPLIED",
    "STATUS_PARTIAL",
    "STATUS_FAILED",
    "STATUS_ROLLED_BACK",
    "STATUS_UNCONFIGURED",
    "BACKEND_FIREWALL",
    "BACKEND_HOST_SSH",
    "BACKEND_LDAP",
    "BACKEND_GRAPH",
    "BACKEND_DNS",
]


def register_containment_actions(registry) -> None:
    """Idempotent. Each adapter no-ops if already registered."""
    for mod_name in ("host_adapter", "directory_adapter", "mail_adapter"):
        try:
            mod = __import__(f"{__name__}.{mod_name}", fromlist=["register"])
        except ImportError:
            continue
        fn = getattr(mod, "register", None)
        if callable(fn):
            fn(registry)
