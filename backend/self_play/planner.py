"""ExecutablePlanner — 把抽象 TTP 映射为 SimEnv 可执行 AttackStep (P2-B)。

职责:
- executable(spec, env): 目标角色在当前拓扑是否存在;
- map_spec: TTPSpec → AttackStep,缺失角色重映射到相似可用角色;
- constrain_steps: LLM 输出必须落在 RoundGoal 允许集内,否则拒绝;
  全部被拒时回退到 goal 金标,而不是放开课程目录。

只产生仿真日志描述,不执行真实攻击。
"""
from __future__ import annotations

import uuid
from typing import Optional

from self_play.catalog import TTPSpec, get_ttp
from self_play.sim_env import HOSTS, _ROLE_ALIAS
from self_play.types import AttackStep, RoundGoal

_ROLE_SIMILAR: dict[str, tuple[str, ...]] = {
    "web": ("app", "mail", "vpn", "ws"),
    "app": ("web", "mail", "ws"),
    "mail": ("web", "app"),
    "vpn": ("jump", "web"),
    "jump": ("vpn", "ws"),
    "ws": ("app", "web", "dc"),
    "dc": ("fs", "ws"),
    "fs": ("db", "dc"),
    "db": ("fs", "app"),
    "dev": ("ws", "app"),
    "proxy": ("web", "app"),
}


class ExecutablePlanner:
    """绑定一个 SimEnv 后,把课程/LLM 意图约束成拓扑可执行的步骤。"""

    def __init__(self, env: Optional[object] = None) -> None:
        self.env = env

    def bind(self, env: object) -> "ExecutablePlanner":
        self.env = env
        return self

    # ------------------------------------------------------------------ hosts
    def _hosts(self, env: Optional[object] = None) -> list[dict]:
        src = env if env is not None else self.env
        hosts = getattr(src, "hosts", None)
        if hosts:
            return list(hosts)
        return [dict(h) for h in HOSTS]

    def _normalize_role(self, role: str) -> str:
        r = str(role or "web").lower()
        return _ROLE_ALIAS.get(r, r)

    def role_available(self, role: str, env: Optional[object] = None) -> bool:
        want = self._normalize_role(role)
        return any(self._normalize_role(h.get("role")) == want for h in self._hosts(env))

    # ------------------------------------------------------------- executable
    def executable(self, spec: TTPSpec, env: Optional[object] = None) -> bool:
        src = env if env is not None else self.env
        if src is None:
            return True
        return self.role_available(getattr(spec, "dst_role", "") or "web", src)

    def similar_role(self, role: str, env: Optional[object] = None) -> str:
        """缺失角色 → 拓扑里可用的相似角色;都没有则取第一个可用角色。"""
        want = self._normalize_role(role)
        if self.role_available(want, env):
            return want
        available: list[str] = []
        seen: set[str] = set()
        for h in self._hosts(env):
            r = self._normalize_role(h.get("role"))
            if r and r not in seen:
                seen.add(r)
                available.append(r)
        for cand in _ROLE_SIMILAR.get(want, ()):
            if cand in available:
                return cand
        return available[0] if available else "web"

    # ---------------------------------------------------------------- map_spec
    def map_spec(
        self,
        spec: TTPSpec,
        coverage: Optional[list[str]] = None,
        goal: Optional[RoundGoal] = None,
        *,
        env: Optional[object] = None,
    ) -> AttackStep:
        cov = {str(c).upper() for c in (coverage or [])}
        event, message, protocol = spec.event_type, spec.message, spec.protocol
        evasion = False
        if spec.event_type.upper() in cov and spec.variants:
            var = spec.variants[0]
            event = str(var.get("event") or event)
            message = str(var.get("message") or message)
            protocol = str(var.get("protocol") or protocol)
            evasion = True
        dst_role = spec.dst_role
        if env is not None or self.env is not None:
            dst_role = self.similar_role(dst_role, env)
        return AttackStep(
            step_id=f"s-{uuid.uuid4().hex[:8]}",
            ttp_id=spec.ttp_id,
            mitre_id=spec.mitre_id,
            tactic=spec.tactic,
            kill_chain=spec.kill_chain,
            name=spec.name,
            event_type=event,
            severity=spec.severity,
            protocol=protocol,
            message=message,
            src_role="attacker",
            dst_role=dst_role,
            tool=spec.tool,
            evasion=evasion,
            variant_of=spec.event_type if evasion else "",
            is_attack=True,
            sub_technique_id=spec.sub_technique_id or "",
            behaviors=list(spec.behaviors),
            data_sources=list(spec.data_sources),
            extra={"goal": dict(goal.to_dict()) if goal is not None else {}},
        )

    # ---------------------------------------------------------- constrain_steps
    def constrain_steps(
        self,
        steps: list[AttackStep],
        goal: RoundGoal,
        allowed: Optional[list[TTPSpec]] = None,
    ) -> list[AttackStep]:
        """只保留落在 goal 家族 / allowed_ttps 内的步骤;全被拒则合成 goal 金标一步。"""
        gid = str(getattr(goal, "technique_id", "") or "").upper()
        gsub = str(getattr(goal, "sub_technique_id", "") or "").upper()

        def _family(mitre: str) -> bool:
            m = str(mitre or "").upper()
            if not m:
                return False
            if gid and (m == gid or m.startswith(gid + ".")):
                return True
            if gsub and (m == gsub or m.startswith(gsub + ".")):
                return True
            return False

        allowed_ids: set[str] = {str(a).upper() for a in (getattr(goal, "allowed_ttps", []) or []) if a}
        for t in (allowed or []):
            m = str(getattr(t, "mitre_id", "") or "").upper()
            if m and (_family(m) or m in allowed_ids):
                allowed_ids.add(m)

        def _keep(step: AttackStep) -> bool:
            if not getattr(step, "is_attack", True):
                return False
            m = str(getattr(step, "mitre_id", "") or "").upper()
            return _family(m) or m in allowed_ids

        kept = [s for s in (steps or []) if s is not None and _keep(s)]
        out: list[AttackStep] = []
        for s in kept:
            if self.env is not None and not self.role_available(s.dst_role):
                s.dst_role = self.similar_role(s.dst_role)
            out.append(s)

        if not out:
            spec: Optional[TTPSpec] = None
            for key in (
                getattr(goal, "ttp_id", ""),
                getattr(goal, "sub_technique_id", ""),
                getattr(goal, "technique_id", ""),
            ):
                spec = get_ttp(str(key or ""))
                if spec is not None:
                    break
            if spec is None:
                fam = [t for t in (allowed or []) if _family(t.mitre_id)]
                spec = fam[0] if fam else None
            if spec is not None:
                out = [self.map_spec(spec, goal=goal)]
        return out
