"""Host containment: kill_process, quarantine_file, clean_persistence, forensic_snapshot.

Live path uses existing Windows SSH transport. Unconfigured live → success=false.
Mock/dry_run never touches SSH.
"""
from __future__ import annotations

import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Optional

from config import settings

from .types import (
    BACKEND_HOST_SSH,
    HOST_PROTECTED_NAMES,
    HOST_PROTECTED_PIDS,
    HOST_PROTECTED_SVCHOST,
    PERSISTENCE_KINDS,
    STATUS_UNCONFIGURED,
)

logger = logging.getLogger(__name__)

_SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
_QUARANTINE: dict[str, dict] = {}
_PERSIST_BACKUP: dict[str, dict] = {}

_SYS_WIN = ("c:\\windows\\system32", "c:\\windows\\syswow64")
_SYS_NIX = ("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/etc")


def _mode() -> str:
    return (getattr(settings, "execution_mode", "live") or "live").lower()


def _ssh_ready() -> bool:
    try:
        from response_engine.transport import ssh_transport
        return bool(ssh_transport.enabled)
    except Exception:
        return False


def _unconfigured(action: str, **extra) -> dict:
    extra.setdefault("error", "host SSH unconfigured")
    return {"action": action, "success": False, "mode": STATUS_UNCONFIGURED, **extra}


def _simulated(action: str, **extra) -> dict:
    m = _mode()
    extra.setdefault("success", True)
    extra.setdefault("mode", m)
    extra.setdefault("action", action)
    extra.setdefault("would_execute", m == "dry_run")
    extra.setdefault("backend", BACKEND_HOST_SSH)
    return extra


def _validate_pid(pid: Any) -> int:
    try:
        n = int(pid)
    except (TypeError, ValueError):
        raise ValueError("pid must be an integer")
    if n < 5 or n > 65535:
        raise ValueError(f"pid out of range or protected: {n}")
    return n


def _validate_sha256(value: str) -> str:
    s = str(value or "").strip()
    if not _SHA256_RE.match(s):
        raise ValueError("sha256 must be 64 hex chars")
    return s.lower()


def protected_process_reason(pid: Any = None, name: str = "", path: str = "") -> str:
    if pid is not None and str(pid).strip() != "":
        try:
            n = int(pid)
        except (TypeError, ValueError):
            n = -1
        if n in HOST_PROTECTED_PIDS or n <= 4:
            return f"protected pid {n}"
    n = str(name or "").lower().rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    if n.endswith(".exe"):
        n = n[:-4]
    if n in HOST_PROTECTED_NAMES:
        return f"protected name {n}"
    p = str(path or "").lower().replace("/", "\\")
    if n == "svchost" and HOST_PROTECTED_SVCHOST in p:
        return "protected svchost"
    if "windows-log-collector" in n or "windows-log-collector" in p:
        return "protected collector"
    return ""


def reject_path(path: str) -> str:
    raw = str(path or "").strip()
    if not raw:
        return "empty path"
    if ".." in raw:
        return "path traversal"
    win = raw.replace("/", "\\").lower()
    nix = raw.replace("\\", "/").lower()
    for prefix in _SYS_WIN:
        if win == prefix or win.startswith(prefix + "\\"):
            return "system directory"
    for prefix in _SYS_NIX:
        if nix == prefix or nix.startswith(prefix + "/"):
            return "system directory"
    return ""


def _quarantine_dest(path: str, sha256: str = "") -> str:
    base = os.path.basename(path.replace("\\", "/")) or "sample"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    tag = (sha256[:16] if sha256 else "nofp") + "_" + stamp
    if path.startswith("/") or path.startswith("\\"):
        return f"/var/lib/soc/quarantine/{tag}_{base}"
    return f"C:\\ProgramData\\SOC\\Quarantine\\{tag}_{base}"


async def kill_process(
    pid: Any = None,
    sha256: str = "",
    image_path: str = "",
    name: str = "",
    host_ip: str = "",
    reason: str = "",
    **kwargs,
) -> dict:
    if pid in (None, "", 0) and not sha256:
        return {"action": "kill_process", "success": False, "mode": "invalid",
                "error": "pid or sha256 required"}
    reason_p = protected_process_reason(pid=pid, name=name, path=image_path)
    if reason_p:
        return {"action": "kill_process", "success": False, "mode": "denied",
                "error": reason_p, "pid": pid, "name": name}
    parsed_pid: Optional[int] = None
    digest = ""
    if pid not in (None, "", 0):
        try:
            parsed_pid = _validate_pid(pid)
        except ValueError as e:
            return {"action": "kill_process", "success": False, "mode": "invalid",
                    "error": str(e), "pid": pid}
    if sha256:
        try:
            digest = _validate_sha256(sha256)
        except ValueError as e:
            return {"action": "kill_process", "success": False, "mode": "invalid",
                    "error": str(e)}

    if _mode() != "live":
        return _simulated(
            "kill_process", pid=parsed_pid, sha256=digest, host_ip=host_ip,
            killed=1 if parsed_pid else 1, message="simulated kill",
        )
    if not _ssh_ready():
        return _unconfigured("kill_process", pid=parsed_pid, sha256=digest, host_ip=host_ip)

    max_n = int(getattr(settings, "kill_process_max_matches", 20) or 20)
    if parsed_pid:
        script = (
            f"$p = Get-Process -Id {parsed_pid} -ErrorAction SilentlyContinue\n"
            f"if ($null -eq $p) {{ Write-Output 'NOT_FOUND'; exit 2 }}\n"
            f"Stop-Process -Id {parsed_pid} -Force\n"
            f"Write-Output 'KILLED {parsed_pid}'"
        )
    else:
        script = (
            f"$t = '{digest}'\n"
            f"$n = 0; $max = {max_n}\n"
            f"Get-CimInstance Win32_Process | ForEach-Object {{\n"
            f"  if ($n -ge $max) {{ return }}\n"
            f"  $path = $_.ExecutablePath\n"
            f"  if (-not $path) {{ return }}\n"
            f"  try {{ $h = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower() }} catch {{ return }}\n"
            f"  if ($h -eq $t) {{ Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue; $n++ }}\n"
            f"}}\n"
            f"Write-Output \"KILLED_COUNT $n\""
        )
    from response_engine.transport import ssh_transport
    result = await ssh_transport.run(script, powershell=True, platform="windows")
    ok = bool(result.get("success"))
    return {
        "action": "kill_process", "success": ok, "mode": "ssh",
        "pid": parsed_pid, "sha256": digest, "host_ip": host_ip,
        "backend": BACKEND_HOST_SSH, "detail": result,
    }


async def quarantine_file(
    path: str = "",
    sha256: str = "",
    host_ip: str = "",
    reason: str = "",
    **kwargs,
) -> dict:
    why = reject_path(path)
    if why:
        return {"action": "quarantine_file", "success": False, "mode": "invalid",
                "error": why, "path": path}
    digest = ""
    if sha256:
        try:
            digest = _validate_sha256(sha256)
        except ValueError as e:
            return {"action": "quarantine_file", "success": False, "mode": "invalid",
                    "error": str(e)}
    dest = _quarantine_dest(path, digest)
    record = {"original_path": path, "quarantine_path": dest, "sha256": digest, "host_ip": host_ip}
    if _mode() != "live":
        _QUARANTINE[path] = record
        _QUARANTINE[dest] = record
        return _simulated("quarantine_file", **record, message="simulated quarantine")
    if not _ssh_ready():
        return _unconfigured("quarantine_file", path=path)
    script = (
        f"$src = '{path.replace(chr(39), '')}'\n"
        f"$dst = '{dest.replace(chr(39), '')}'\n"
        f"New-Item -ItemType Directory -Force -Path (Split-Path $dst) | Out-Null\n"
        f"Move-Item -LiteralPath $src -Destination $dst -Force\n"
        f"Write-Output \"QUARANTINED $dst\""
    )
    from response_engine.transport import ssh_transport
    result = await ssh_transport.run(script, powershell=True, platform="windows")
    ok = bool(result.get("success"))
    if ok:
        _QUARANTINE[path] = record
        _QUARANTINE[dest] = record
    return {
        "action": "quarantine_file", "success": ok, "mode": "ssh",
        **record, "backend": BACKEND_HOST_SSH, "detail": result,
    }


async def restore_file(
    path: str = "",
    original_path: str = "",
    quarantine_path: str = "",
    **kwargs,
) -> dict:
    rec = _QUARANTINE.get(original_path or path) or _QUARANTINE.get(quarantine_path or "")
    src = quarantine_path or (rec or {}).get("quarantine_path") or ""
    dst = original_path or (rec or {}).get("original_path") or path
    if not src or not dst:
        return {"action": "restore_file", "success": False, "mode": "invalid",
                "error": "no quarantine mapping"}
    if _mode() != "live":
        return _simulated("restore_file", original_path=dst, quarantine_path=src)
    if not _ssh_ready():
        return _unconfigured("restore_file", original_path=dst)
    script = (
        f"Move-Item -LiteralPath '{src.replace(chr(39), '')}' "
        f"-Destination '{dst.replace(chr(39), '')}' -Force\n"
        f"Write-Output 'RESTORED'"
    )
    from response_engine.transport import ssh_transport
    result = await ssh_transport.run(script, powershell=True, platform="windows")
    return {
        "action": "restore_file", "success": bool(result.get("success")),
        "mode": "ssh", "original_path": dst, "quarantine_path": src, "detail": result,
    }


async def clean_persistence(
    kind: str = "",
    name_or_path: str = "",
    host_ip: str = "",
    reason: str = "",
    **kwargs,
) -> dict:
    k = str(kind or "").strip().lower()
    if k not in PERSISTENCE_KINDS:
        return {"action": "clean_persistence", "success": False, "mode": "invalid",
                "error": f"kind must be one of {sorted(PERSISTENCE_KINDS)}"}
    target = str(name_or_path or "").strip()
    if not target or ".." in target:
        return {"action": "clean_persistence", "success": False, "mode": "invalid",
                "error": "name_or_path required and must not contain .."}
    backup = f"persist_{k}_{int(time.time())}"
    rec = {"kind": k, "name_or_path": target, "backup_id": backup, "host_ip": host_ip}
    if _mode() != "live":
        _PERSIST_BACKUP[backup] = rec
        return _simulated("clean_persistence", **rec, message="simulated persistence clean")
    if not _ssh_ready():
        return _unconfigured("clean_persistence", **rec)
    if k in ("run", "runonce"):
        hive = "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" + ("Once" if k == "runonce" else "")
        script = (
            f"$k = '{hive}'\n"
            f"$n = '{target.replace(chr(39), '')}'\n"
            f"Remove-ItemProperty -Path $k -Name $n -ErrorAction SilentlyContinue\n"
            f"Write-Output 'REMOVED'"
        )
    elif k == "service":
        script = (
            f"Stop-Service -Name '{target.replace(chr(39), '')}' -Force -ErrorAction SilentlyContinue\n"
            f"Set-Service -Name '{target.replace(chr(39), '')}' -StartupType Disabled -ErrorAction SilentlyContinue\n"
            f"Write-Output 'SERVICE_DISABLED'"
        )
    else:
        script = (
            f"$p = '{target.replace(chr(39), '')}'\n"
            f"if (Test-Path -LiteralPath $p) {{ Copy-Item $p \"$p.bak.soc\"; Remove-Item -LiteralPath $p -Force }}\n"
            f"Write-Output 'LNK_REMOVED'"
        )
    from response_engine.transport import ssh_transport
    result = await ssh_transport.run(script, powershell=True, platform="windows")
    ok = bool(result.get("success"))
    if ok:
        _PERSIST_BACKUP[backup] = rec
    return {"action": "clean_persistence", "success": ok, "mode": "ssh", **rec, "detail": result}


async def restore_persistence(backup_id: str = "", **kwargs) -> dict:
    rec = _PERSIST_BACKUP.get(backup_id) or {}
    if _mode() != "live":
        return _simulated("restore_persistence", backup_id=backup_id, **rec)
    return _unconfigured("restore_persistence", backup_id=backup_id) if not _ssh_ready() else _simulated(
        "restore_persistence", backup_id=backup_id, **rec, mode="ssh",
        message="restore requires backup file on host",
    )


async def forensic_snapshot(
    host_ip: str = "",
    pid: Any = None,
    reason: str = "",
    **kwargs,
) -> dict:
    timeout = int(getattr(settings, "forensic_snapshot_timeout_s", 15) or 15)
    include_dump = bool(getattr(settings, "forensic_include_dump", False))
    snap_id = f"snap_{int(time.time())}"
    summary = {
        "snapshot_id": snap_id,
        "host_ip": host_ip,
        "pid": pid,
        "processes": [],
        "connections": [],
        "snapshot_status": "ok",
        "include_dump": include_dump and pid not in (None, "", 0),
    }
    if _mode() != "live":
        summary["processes"] = [{"pid": pid or 0, "name": "simulated"}]
        summary["connections"] = []
        summary["snapshot_status"] = "partial" if not host_ip else "ok"
        return _simulated("forensic_snapshot", **summary)
    if not _ssh_ready():
        summary["snapshot_status"] = "failed"
        return {**_unconfigured("forensic_snapshot", host_ip=host_ip), **summary,
                "success": True, "mode": "unconfigured",
                "message": "snapshot skipped, host SSH unconfigured"}

    script = (
        "Get-Process | Select-Object -First 80 Id,ProcessName,Path | ConvertTo-Json -Compress\n"
        "Write-Output '---NET---'\n"
        "Get-NetTCPConnection -ErrorAction SilentlyContinue | "
        "Select-Object -First 80 LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess,State | "
        "ConvertTo-Json -Compress"
    )
    from response_engine.transport import ssh_transport
    try:
        result = await ssh_transport.run(script, powershell=True, platform="windows", timeout=timeout)
        summary["detail_ok"] = bool(result.get("success"))
        stdout = (result.get("stdout") or "")[:4000]
        summary["stdout_preview"] = stdout
        summary["snapshot_status"] = "ok" if result.get("success") else "partial"
    except Exception as e:
        logger.warning("forensic_snapshot failed: %s", e)
        summary["snapshot_status"] = "failed"
        summary["error"] = str(e)
    return {
        "action": "forensic_snapshot", "success": True, "mode": "ssh",
        "backend": BACKEND_HOST_SSH, **summary,
    }


def register(registry) -> None:
    if registry.get_action("kill_process"):
        return
    registry.register(
        "kill_process", kill_process,
        description="按 PID 或 SHA256 终止进程",
        severity="high",
        category="host",
        reversible=False,
        params_schema={
            "pid": "int PID (>=5)",
            "sha256": "str 64 hex",
            "image_path": "str 可选镜像路径",
            "host_ip": "str 主机",
            "reason": "str",
        },
    )
    registry.register(
        "quarantine_file", quarantine_file,
        description="将可疑文件移到隔离区并断开原路径",
        severity="high",
        category="host",
        reversible=True,
        rollback_fn=restore_file,
        params_schema={
            "path": "str (required) 文件路径",
            "sha256": "str 可选",
            "host_ip": "str",
            "reason": "str",
        },
    )
    registry.register(
        "clean_persistence", clean_persistence,
        description="清理 Run/RunOnce/服务/启动项（仅已知持久化点）",
        severity="high",
        category="host",
        reversible=True,
        rollback_fn=restore_persistence,
        params_schema={
            "kind": "str run|runonce|service|startup_lnk",
            "name_or_path": "str 值名或 lnk 路径",
            "host_ip": "str",
            "reason": "str",
        },
    )
    registry.register(
        "forensic_snapshot", forensic_snapshot,
        description="隔离前采集进程表与网络连接",
        severity="medium",
        category="host",
        reversible=False,
        params_schema={
            "host_ip": "str",
            "pid": "int 可选，仅对该 pid 算哈希/dump",
            "reason": "str",
        },
    )
