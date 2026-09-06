"""Self-Play 数据结构 — 全部 JSON 可序列化,供 Temporal Activity / API / 落库共用。"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional


@dataclass
class AttackStep:
    """红队单步攻击意图(仿真,不执行真实利用)。"""
    step_id: str
    ttp_id: str
    mitre_id: str
    tactic: str
    kill_chain: str
    name: str
    event_type: str
    severity: str
    protocol: str
    message: str
    src_role: str = "attacker"
    dst_role: str = "web"
    tool: str = "sim:probe"          # 仅仿真工具名,从不调用真实攻击工具
    evasion: bool = False
    variant_of: str = ""
    is_attack: bool = True
    sub_technique_id: str = ""
    behaviors: list = field(default_factory=list)
    data_sources: list = field(default_factory=list)
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AttackPlan:
    """红队一轮规划。"""
    plan_id: str
    match_id: str
    round_num: int
    curriculum_level: int
    rationale: str
    steps: list[AttackStep] = field(default_factory=list)
    decoys: list[AttackStep] = field(default_factory=list)
    rag_hints: list[str] = field(default_factory=list)
    blue_visible: list[str] = field(default_factory=list)
    goal: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "plan_id": self.plan_id,
            "match_id": self.match_id,
            "round_num": self.round_num,
            "curriculum_level": self.curriculum_level,
            "rationale": self.rationale,
            "steps": [s.to_dict() for s in self.steps],
            "decoys": [s.to_dict() for s in self.decoys],
            "rag_hints": list(self.rag_hints),
            "blue_visible": list(self.blue_visible),
            "goal": dict(self.goal or {}),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AttackPlan":
        data = dict(data or {})
        step_fields = set(AttackStep.__dataclass_fields__)  # type: ignore[attr-defined]

        def _step(raw: Any) -> AttackStep:
            if isinstance(raw, AttackStep):
                return raw
            payload = {k: v for k, v in dict(raw or {}).items() if k in step_fields}
            return AttackStep(**payload)

        return cls(
            plan_id=str(data.get("plan_id") or ""),
            match_id=str(data.get("match_id") or ""),
            round_num=int(data.get("round_num") or 0),
            curriculum_level=int(data.get("curriculum_level") or 0),
            rationale=str(data.get("rationale") or ""),
            steps=[_step(s) for s in (data.get("steps") or [])],
            decoys=[_step(s) for s in (data.get("decoys") or [])],
            rag_hints=list(data.get("rag_hints") or []),
            blue_visible=list(data.get("blue_visible") or []),
            goal=dict(data.get("goal") or {}),
        )


@dataclass
class MaterializedEvent:
    """仿真环境产出的安全日志(对接 ingest 的字段)。"""
    event: str
    severity: str
    protocol: str
    message: str
    src_ip: str
    dst_ip: str
    src_host: str = ""
    dst_host: str = ""
    url: str = ""
    method: str = ""
    dst_port: int = 0
    confidence: int = 70
    is_attack: bool = True
    ttp_id: str = ""
    mitre_id: str = ""
    sub_technique_id: str = ""
    fingerprint: str = ""
    injected_at: float = 0.0
    eval_channel: str = "sim"
    extra: dict = field(default_factory=dict)

    def to_log(self) -> dict:
        """转为 log_ingestion 可消费的事件字典。"""
        payload = {
            "event": self.event,
            "type": self.event,
            "severity": self.severity,
            "protocol": self.protocol,
            "message": self.message,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "url": self.url,
            "method": self.method,
            "dst_port": self.dst_port,
            "confidence": self.confidence,
            "threat_type": self.event,
            "_self_play": True,
            "_ground_truth": "attack" if self.is_attack else "benign",
            "_ttp_id": self.ttp_id,
            "_mitre_id": self.mitre_id,
            "_sub_technique_id": self.sub_technique_id,
            "_fingerprint": self.fingerprint,
            "_sim_src_host": self.src_host,
            "_sim_dst_host": self.dst_host,
            "_eval_channel": self.eval_channel or "sim",
        }
        payload.update(self.extra or {})
        return payload

    def to_dict(self) -> dict:
        d = asdict(self)
        d["log"] = self.to_log()
        return d


@dataclass
class EventObservation:
    detected: bool = False
    responded: bool = False
    detector: str = ""          # sigma | overlay | audit_llm | none
    rule_ids: list[str] = field(default_factory=list)
    attack_types: list[str] = field(default_factory=list)
    event_id: int = 0
    detected_at: float = 0.0
    mttd_ms: float = 0.0
    verdict: str = ""
    confidence: float = 0.0
    eval_channel: str = "sim"
    candidate_detected: bool = False
    candidate_rule_ids: list[str] = field(default_factory=list)
    audit_detected: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RoundMetrics:
    attacks: int = 0
    decoys: int = 0
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    asr: float = 0.0
    recall: float = 0.0
    precision: float = 0.0
    mttd_ms: float = 0.0
    novelty: float = 0.0
    compounding: float = 0.0
    overlay_hits: int = 0
    sigma_hits: int = 0
    fbeta: float = 0.0
    blue_score: float = 0.0
    red_score: float = 0.0
    mttc_ms: float = 0.0
    eval_channel: str = "sim"
    novelty_technique: float = 0.0
    novelty_parameter: float = 0.0
    novelty_sequence: float = 0.0
    novelty_scenario: float = 0.0
    candidate_tp: int = 0
    radar: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class LearnedRule:
    rule_id: str
    title: str
    attack_type: str
    mitre_id: str = ""
    severity: str = "medium"
    conditions: dict = field(default_factory=dict)
    condition_mode: str = "or"
    source_fingerprint: str = ""
    status: str = "candidate"
    version: int = 1
    parent_rule_id: str = ""
    generalized: bool = False
    validation: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class BlueView:
    """蓝队边界快照 — 回灌红队,使其打覆盖缺口而不是跟课程齐步走。"""
    last_outcome: str = ""
    recall: float = 0.0
    asr: float = 0.0
    covered_events: list[str] = field(default_factory=list)
    last_missed: list[str] = field(default_factory=list)
    overlay_rule_count: int = 0
    consecutive_blue_wins: int = 0
    learned_tokens: list[str] = field(default_factory=list)
    last_goal: dict = field(default_factory=dict)
    detection_gaps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Optional[dict] = None) -> "BlueView":
        data = dict(data or {})
        allowed = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in allowed})


@dataclass
class MatchConfig:
    rounds: int = 8
    curriculum: bool = True
    start_level: int = 0
    inject: bool = False
    wait_audit: bool = False
    wait_audit_s: float = 8.0
    use_llm: bool = False
    decoy_ratio: float = 0.2
    persist: bool = True
    persist_kb: bool = False
    match_id: str = ""
    diverse_env: bool = False
    env_seed: int = 0
    background_traffic: bool = False
    eval_channel: str = "sim"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Optional[dict] = None) -> "MatchConfig":
        data = dict(data or {})
        allowed = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in allowed})


def _from_dict(cls, data: Optional[dict] = None):
    data = dict(data or {})
    allowed = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
    return cls(**{k: v for k, v in data.items() if k in allowed})


@dataclass
class RoundGoal:
    """课程控制器每回合下发的训练目标。红队 LLM/目录路径都必须消费它。"""
    technique_id: str = ""
    sub_technique_id: str = ""
    ttp_id: str = ""
    event_type: str = ""
    scenario: str = ""
    difficulty: int = 0
    constraints: dict = field(default_factory=dict)
    prefer_gap: bool = False
    rationale: str = ""
    allowed_ttps: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Optional[dict] = None) -> "RoundGoal":
        return _from_dict(cls, data)


@dataclass
class LayeredNovelty:
    """分层新颖度：技术 / 参数 / 序列 / 场景，不混成一个分数。"""
    technique: float = 1.0
    parameter: float = 1.0
    sequence: float = 1.0
    scenario: float = 1.0
    combined: float = 1.0

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Optional[dict] = None) -> "LayeredNovelty":
        return _from_dict(cls, data)


@dataclass
class CapabilityState:
    """当前课程等级的能力模型。升级看 P(level_clear) 而不是连续 2 次 blue_win。"""
    level: int = 0
    technique_recalls: dict = field(default_factory=dict)
    technique_asrs: dict = field(default_factory=dict)
    recent_outcomes: list = field(default_factory=list)
    rounds_at_level: int = 0
    p_level_clear: float = 0.0
    blue_win_rate: float = 0.0
    seen_by_level: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Optional[dict] = None) -> "CapabilityState":
        return _from_dict(cls, data)
