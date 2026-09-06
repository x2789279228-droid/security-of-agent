"""论文级对抗指标: ASR / Recall / Precision / Fβ / MTTD / MTTC / Novelty / Compounding / blue_score / radar。"""
from __future__ import annotations

from dataclasses import fields as _dc_fields
from typing import Any, Optional

from self_play.novelty import NoveltyIndex, tokenize
from self_play.types import EventObservation, MaterializedEvent, RoundMetrics

BLUE_WEIGHTS = {
    "recall": 0.30,
    "precision": 0.20,
    "safety": 0.25,        # (1 - asr)
    "mttd": 0.10,          # (1 - min(mttd/5000, 1))
    "compounding": 0.10,
    "novelty": 0.05,
}
MTTD_NORM_MS = 5000.0
BLUE_WIN_SCORE = 0.62
RED_WIN_SCORE = 0.55
WIN_MARGIN = 0.08


def _safe_div(n: float, d: float) -> float:
    return float(n) / float(d) if d else 0.0


def _clip01(x: float) -> float:
    return max(0.0, min(1.0, float(x)))


def _mean(xs: list[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def _num(v: Any) -> float:
    try:
        return float(v or 0)
    except (TypeError, ValueError):
        return 0.0


def fbeta(precision: float, recall: float, beta: float = 1.5) -> float:
    """Fβ (β>1 偏向 recall)。"""
    p, r = _clip01(precision), _clip01(recall)
    b = float(beta or 0)
    if b <= 0 or p + r <= 0:
        return 0.0
    b2 = b * b
    denom = b2 * p + r
    if denom <= 0:
        return 0.0
    return _clip01((1 + b2) * p * r / denom)


def blue_score(metrics: dict) -> float:
    """P4-A: 加权综合分,蓝队视角,clip 0..1。"""
    m = metrics or {}
    recall = _num(m.get("recall"))
    precision = _num(m.get("precision"))
    asr = _num(m.get("asr"))
    mttd = _num(m.get("mttd_ms"))
    comp = _clip01(_num(m.get("compounding")))
    nov = _clip01(_num(m.get("novelty")))
    score = (
        BLUE_WEIGHTS["recall"] * recall
        + BLUE_WEIGHTS["precision"] * precision
        + BLUE_WEIGHTS["safety"] * (1.0 - asr)
        + BLUE_WEIGHTS["mttd"] * (1.0 - min(mttd / MTTD_NORM_MS, 1.0))
        + BLUE_WEIGHTS["compounding"] * comp
        + BLUE_WEIGHTS["novelty"] * nov
    )
    return _clip01(score)


def red_score(metrics: dict) -> float:
    m = metrics or {}
    asr = _clip01(_num(m.get("asr")))
    recall = _clip01(_num(m.get("recall")))
    return _clip01(0.7 * asr + 0.3 * (1.0 - recall))


def radar(metrics: dict) -> dict:
    """P4-D: 六维雷达 coverage/precision/mttd/novelty_response/compounding/robustness。"""
    m = metrics or {}
    recall = _clip01(_num(m.get("recall")))
    precision = _clip01(_num(m.get("precision")))
    asr = _clip01(_num(m.get("asr")))
    mttd = _num(m.get("mttd_ms"))
    comp = _clip01(_num(m.get("compounding")))
    nov = _clip01(_num(m.get("novelty")))
    evasions = _num(m.get("evasion_n"))
    return {
        "coverage": recall,
        "precision": precision,
        "mttd": 1.0 - min(mttd / MTTD_NORM_MS, 1.0),
        "novelty_response": comp if evasions > 0 else nov,
        "compounding": comp,
        "robustness": _clip01(precision * (1.0 - asr)),
    }


def score_round(
    events: list[MaterializedEvent],
    observations: list[EventObservation],
    novelty: Optional[NoveltyIndex] = None,
    *,
    novelty_threshold: float = 0.5,
) -> RoundMetrics:
    m = RoundMetrics()
    mttds: list[float] = []
    overlay_mttds: list[float] = []
    novelties: list[float] = []
    layered = {"technique": [], "parameter": [], "sequence": [], "scenario": []}
    evasion_n = 0
    evasion_overlay = 0

    for evt, obs in zip(events, observations):
        detected = bool(obs.detected)
        if evt.is_attack:
            m.attacks += 1
            tokens = tokenize(evt.event, evt.message, evt.mitre_id, evt.protocol)
            # 分层新颖度: 有 score_layered 用分层,否则退化为 token 层
            ln = None
            if novelty is not None and hasattr(novelty, "score_layered"):
                ln = novelty.score_layered(evt)
            if ln is not None:
                nov = ln.combined
                layered["technique"].append(ln.technique)
                layered["parameter"].append(ln.parameter)
                layered["sequence"].append(ln.sequence)
                layered["scenario"].append(ln.scenario)
            else:
                nov = novelty.score(tokens) if novelty is not None else 1.0
                layered["technique"].append(nov)
                layered["parameter"].append(1.0)
                layered["sequence"].append(1.0)
                layered["scenario"].append(1.0)
            novelties.append(nov)
            if detected:
                m.tp += 1
                mttds.append(float(obs.mttd_ms or 0.0))
                if "sigma" in (obs.detector or ""):
                    m.sigma_hits += 1
                if "overlay" in (obs.detector or ""):
                    m.overlay_hits += 1
                    overlay_mttds.append(float(obs.mttd_ms or 0.0))
            else:
                m.fn += 1
            # 自学习是否生效: 红队规避变体被 overlay(而非库存 Sigma)抓住
            if bool((evt.extra or {}).get("_evasion")):
                evasion_n += 1
                if detected and "overlay" in (obs.detector or ""):
                    evasion_overlay += 1
            # candidate 命中仅评估,不计入 tp/fn
            if bool(obs.candidate_detected):
                m.candidate_tp += 1
        else:
            m.decoys += 1
            if detected:
                m.fp += 1
            else:
                m.tn += 1

    m.asr = _safe_div(m.fn, m.attacks)
    m.recall = _safe_div(m.tp, m.attacks)
    m.precision = _safe_div(m.tp, m.tp + m.fp)
    m.mttd_ms = _mean(mttds)
    m.novelty = _mean(novelties)
    m.compounding = _safe_div(evasion_overlay, evasion_n)
    m.fbeta = fbeta(m.precision, m.recall, 1.5)
    m.red_score = red_score(m.to_dict())
    m.blue_score = blue_score(m.to_dict())
    m.mttc_ms = _mean(overlay_mttds)
    m.eval_channel = (str(events[0].eval_channel) if events else "") or "sim"
    m.novelty_technique = _mean(layered["technique"])
    m.novelty_parameter = _mean(layered["parameter"])
    m.novelty_sequence = _mean(layered["sequence"])
    m.novelty_scenario = _mean(layered["scenario"])
    view = m.to_dict()
    view["evasion_n"] = evasion_n
    m.radar = radar(view)
    return m


def round_metrics_from_dict(d: Optional[dict]) -> RoundMetrics:
    """用 dataclass 默认值补齐缺失键;radar 永远是 dict,不让 0 混进 dict 字段。"""
    data = dict(d or {})
    allowed = {f.name: f for f in _dc_fields(RoundMetrics)}
    payload: dict[str, Any] = {}
    for name in allowed:
        if name in data:
            payload[name] = data[name]
    if not isinstance(payload.get("radar"), dict):
        payload["radar"] = {}
    return RoundMetrics(**payload)


def merge_metrics(rows: list) -> dict:
    objs = [
        r if isinstance(r, RoundMetrics) else round_metrics_from_dict(r)
        for r in (rows or [])
    ]
    if not objs:
        out = RoundMetrics().to_dict()
        out["rounds"] = 0
        out["radar"] = {}
        return out
    attacks = sum(r.attacks for r in objs)
    decoys = sum(r.decoys for r in objs)
    tp = sum(r.tp for r in objs)
    fp = sum(r.fp for r in objs)
    fn = sum(r.fn for r in objs)
    tn = sum(r.tn for r in objs)
    mttds = [r.mttd_ms for r in objs if r.tp]
    mttcs = [r.mttc_ms for r in objs if r.overlay_hits]
    view = {
        "asr": _safe_div(fn, attacks),
        "recall": _safe_div(tp, attacks),
        "precision": _safe_div(tp, tp + fp),
        "mttd_ms": _mean(mttds),
        "novelty": _mean([r.novelty for r in objs]),
        "compounding": _mean([r.compounding for r in objs]),
    }
    out = {
        "rounds": len(objs),
        "attacks": attacks,
        "decoys": decoys,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "asr": view["asr"],
        "recall": view["recall"],
        "precision": view["precision"],
        "mttd_ms": view["mttd_ms"],
        "novelty": view["novelty"],
        "compounding": view["compounding"],
        "overlay_hits": sum(r.overlay_hits for r in objs),
        "sigma_hits": sum(r.sigma_hits for r in objs),
        "fbeta": fbeta(view["precision"], view["recall"], 1.5),
        "blue_score": blue_score(view),
        "red_score": red_score(view),
        "mttc_ms": _mean(mttcs),
        "eval_channel": (str(objs[0].eval_channel) or "sim"),
        "novelty_technique": _mean([r.novelty_technique for r in objs]),
        "novelty_parameter": _mean([r.novelty_parameter for r in objs]),
        "novelty_sequence": _mean([r.novelty_sequence for r in objs]),
        "novelty_scenario": _mean([r.novelty_scenario for r in objs]),
        "candidate_tp": sum(r.candidate_tp for r in objs),
    }
    # evasion 信息逐回合聚合后丢失,用 compounding>0 近似"有规避样本"
    out["radar"] = radar({**view, "evasion_n": 1 if view["compounding"] > 0 else 0})
    return out


def decide_winner(cum: Optional[dict]) -> str:
    """P4-B: 加权综合分 + 间隔阈值,不再只看 recall/asr 硬阈值。"""
    cum = dict(cum or {})
    if "blue_score" not in cum or "red_score" not in cum:
        view = {
            "recall": cum.get("recall", 0),
            "precision": cum.get("precision", 0),
            "asr": cum.get("asr", 0),
            "mttd_ms": cum.get("mttd_ms", 0),
            "compounding": cum.get("compounding", 0),
            "novelty": cum.get("novelty", 0),
        }
        blue = blue_score(view)
        red = red_score(view)
    else:
        blue = _num(cum.get("blue_score"))
        red = _num(cum.get("red_score"))
    if blue >= BLUE_WIN_SCORE and blue - red >= WIN_MARGIN:
        return "blue"
    if red >= RED_WIN_SCORE and red - blue >= WIN_MARGIN:
        return "red"
    return "draw"


def decide_winner_legacy(cum: Optional[dict]) -> str:
    """旧硬阈值: recall≥0.7 ∧ asr≤0.35 → blue;asr≥0.5 → red。"""
    cum = cum or {}
    recall = _num(cum.get("recall"))
    asr = _num(cum.get("asr"))
    if recall >= 0.7 and asr <= 0.35:
        return "blue"
    if asr >= 0.5:
        return "red"
    return "draw"
