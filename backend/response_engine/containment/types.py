"""Containment action constants. Keep import-light (no SQLAlchemy / SSH)."""

STATUS_APPLIED = "applied"
STATUS_PARTIAL = "partial"
STATUS_FAILED = "failed"
STATUS_ROLLED_BACK = "rolled_back"
STATUS_UNCONFIGURED = "unconfigured"

BACKEND_FIREWALL = "firewall"
BACKEND_HOST_SSH = "host_ssh"
BACKEND_LDAP = "ldap"
BACKEND_GRAPH = "graph"
BACKEND_DNS = "dns"

# Batches containing these names prepend forensic_snapshot unless skip_snapshot=true.
SNAPSHOT_BEFORE_ACTIONS = frozenset({"isolate_host", "kill_process", "quarantine_file"})

# Never auto-execute; manual /api/response/execute must 403.
CRITICAL_CONTAINMENT = frozenset({"isolate_host", "disable_account"})

HOST_PROTECTED_PIDS = frozenset({0, 1, 2, 3, 4})
HOST_PROTECTED_NAMES = frozenset({
    "csrss", "smss", "wininit", "services", "lsass",
    "windows-log-collector",
})
HOST_PROTECTED_SVCHOST = "system32\\svchost.exe"

PERSISTENCE_KINDS = frozenset({"run", "runonce", "service", "startup_lnk"})
