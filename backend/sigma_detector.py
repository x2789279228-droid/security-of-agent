"""
Sigma 风格检测引擎 — 规则化安全检测（检测能力核心）

与现有统计异常检测（anomaly_detector.py）和 CEP 攻击链（Flink）互补：
  - 统计异常检测：基于历史基线的偏离度（适合未知威胁）
  - CEP 攻击链：基于时间窗口的多事件关联（适合 APT）
  - Sigma 规则：基于已知攻击特征的精确匹配（适合已知攻击模式）

内置 7 条规则覆盖 6 类攻击：
  SIG-001: HTTP 登录爆破
  SIG-002: 敏感信息探测
  SIG-003: 路径遍历攻击
  SIG-004: 越权访问尝试
  SIG-005: 敏感数据下载
  SIG-006: Elasticsearch 未授权访问
  SIG-007: SSH 暴力破解

集成点：
  log_ingestion.py → ingest() 中与 anomaly_detector 并行调用
  检测结果写入 event._sigma 字段，供 Audit-LLM 参考

用法：
    from sigma_detector import sigma_detector
    hits = sigma_detector.detect(event_dict)
    report = sigma_detector.detect_batch([event1, event2, ...])
"""
import logging
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class SigmaRule:
    """Sigma 检测规则（增强版）"""
    rule_id: str
    name: str
    description: str
    severity: str                       # critical/high/medium/low
    attack_type: str                    # 攻击分类
    confidence: str                     # high/medium/low
    action_recommend: str               # block_ip / require_confirmation / alert
    conditions: dict                    # 匹配条件
    boost_conditions: Optional[dict] = None  # 威胁加成条件
    # ── 增强字段 ──
    enabled: bool = True                # 启用/停用
    shadow_mode: bool = False           # 灰度模式（仅记录不告警）
    mitre_attack_id: str = ""           # ATT&CK 技术 ID (如 T1110)
    mitre_tactic: str = ""             # ATT&CK 战术 (如 credential-access)
    aggregation: Optional[dict] = None  # 聚合条件 {"func":"count","field":"src_ip","op":">","threshold":5,"timeframe":"5m"}


@dataclass
class DetectionResult:
    """单条规则命中结果"""
    rule_id: str
    rule_name: str
    severity: str
    attack_type: str
    confidence: str
    action_recommend: str
    matched_fields: dict
    description: str

    def to_dict(self) -> dict:
        return asdict(self)


class SigmaDetector:
    """
    Sigma 风格检测引擎（增强版）

    纯规则匹配，无 LLM 调用，延迟 < 1ms。
    增强: 聚合规则 + timeframe + 字段映射 + ATT&CK + 灰度。
    """

    # ── 字段映射表（日志源字段 → 标准字段）──
    FIELD_MAP = {
        "eventType": "event", "event_type": "event",
        "srcIp": "src_ip", "source_ip": "src_ip", "xffClientIp": "src_ip",
        "dstIp": "dst_ip", "dest_ip": "dst_ip", "host": "dst_ip",
        "msg": "message", "description": "message",
        "proto": "protocol",
        "sev": "severity", "level": "severity",
    }

    def __init__(self):
        self.rules: list[SigmaRule] = []
        # 聚合滑动窗口: {rule_id: {group_key: deque[(timestamp, value)]}}
        self._agg_windows: dict[str, dict[str, deque]] = defaultdict(lambda: defaultdict(deque))
        self._load_default_rules()
        logger.info(f"SigmaDetector: loaded {len(self.rules)} rules")

    def _load_default_rules(self):
        """加载内置规则（覆盖 6 类攻击）"""
        self.rules = [
            SigmaRule(
                rule_id="SIG-001",
                name="HTTP登录爆破检测",
                description="检测对登录接口的高频访问",
                severity="high",
                attack_type="brute_force",
                confidence="high",
                action_recommend="block_ip",
                conditions={
                    "url_contains": ["/api/auth/login", "/login", "/admin/login"],
                    "event_contains": ["BRUTE_FORCE", "LOGIN_FAIL", "暴力破解"],
                },
                mitre_attack_id="T1110",
                mitre_tactic="credential-access",
                aggregation={"func": "count", "field": "src_ip", "op": ">", "threshold": 5, "timeframe": "5m"},
            ),
            SigmaRule(
                rule_id="SIG-002",
                name="敏感信息探测",
                description="检测对系统信息接口的访问",
                severity="medium",
                attack_type="info_disclosure",
                confidence="high",
                action_recommend="block_ip",
                conditions={
                    "url_contains": ["/GetSystem", "/system/info", "/api/status"],
                    "event_contains": ["INFO_DISCLOSURE", "信息探测"],
                },
                boost_conditions={"target_is_internal": True, "new_severity": "high"},
                mitre_attack_id="T1595",
                mitre_tactic="reconnaissance",
            ),
            SigmaRule(
                rule_id="SIG-003",
                name="路径遍历攻击",
                description="检测对日志/敏感路径的访问",
                severity="critical",
                attack_type="path_traversal",
                confidence="high",
                action_recommend="block_ip",
                conditions={
                    "url_contains": ["/access.log", "/etc/passwd", "/../", "%2e%2e"],
                    "event_contains": ["PATH_TRAVERSAL", "路径遍历"],
                },
                mitre_attack_id="T1083",
                mitre_tactic="discovery",
            ),
            SigmaRule(
                rule_id="SIG-004",
                name="越权访问尝试",
                description="检测对记录详情接口的非授权访问",
                severity="high",
                attack_type="unauthorized_access",
                confidence="medium",
                action_recommend="block_ip",
                conditions={
                    "url_contains": ["/api/record/runDetail", "/api/admin/", "/api/internal/"],
                    "event_contains": ["UNAUTHORIZED_ACCESS", "UNAUTH_ACCESS", "越权"],
                },
                mitre_attack_id="T1078",
                mitre_tactic="privilege-escalation",
            ),
            SigmaRule(
                rule_id="SIG-005",
                name="敏感数据下载",
                description="检测对下载接口的可疑访问",
                severity="medium",
                attack_type="data_exfiltration",
                confidence="medium",
                action_recommend="require_confirmation",
                conditions={
                    "url_contains": ["/api/download", "/file/download", "/export"],
                    "event_contains": ["DATA_EXFIL", "DATA_DOWNLOAD", "数据外泄"],
                },
                mitre_attack_id="T1048",
                mitre_tactic="exfiltration",
            ),
            SigmaRule(
                rule_id="SIG-006",
                name="Elasticsearch未授权访问",
                description="检测对ES默认端口9200的访问",
                severity="critical",
                attack_type="unauthorized_access",
                confidence="high",
                action_recommend="block_ip",
                conditions={
                    "host_port": [9200],
                },
                mitre_attack_id="T1190",
                mitre_tactic="initial-access",
            ),
            SigmaRule(
                rule_id="SIG-007",
                name="SSH暴力破解",
                description="检测对SSH服务的异常连接",
                severity="high",
                attack_type="brute_force",
                confidence="medium",
                action_recommend="block_ip",
                conditions={
                    "host_port": [22],
                    "event_contains": ["BRUTE_FORCE", "SSH_BRUTE", "LOGIN_FAIL"],
                },
                mitre_attack_id="T1110.001",
                mitre_tactic="credential-access",
                aggregation={"func": "count", "field": "src_ip", "op": ">", "threshold": 3, "timeframe": "5m"},
            ),
            # ── 扩展规则：覆盖 platform 已有的事件类型 ──
            SigmaRule(
                rule_id="SIG-008",
                name="C2通信检测",
                description="检测 C2 信标通信特征",
                severity="critical",
                attack_type="c2_communication",
                confidence="high",
                action_recommend="block_ip",
                conditions={
                    "event_contains": ["C2_BEACON", "C2_COMM", "DNS_TUNNEL"],
                },
                mitre_attack_id="T1071",
                mitre_tactic="command-and-control",
            ),
            SigmaRule(
                rule_id="SIG-009",
                name="端口扫描检测",
                description="检测大规模端口扫描行为",
                severity="medium",
                attack_type="port_scan",
                confidence="high",
                action_recommend="alert",
                conditions={
                    "event_contains": ["PORT_SCAN", "SCAN_DETECT"],
                },
                mitre_attack_id="T1046",
                mitre_tactic="discovery",
            ),
            SigmaRule(
                rule_id="SIG-010",
                name="横向移动检测",
                description="检测内网横向移动特征",
                severity="high",
                attack_type="lateral_movement",
                confidence="medium",
                action_recommend="require_confirmation",
                conditions={
                    "event_contains": ["LATERAL_MOVE", "LATERAL_SSH", "PRIV_ESCALATION"],
                },
                mitre_attack_id="T1021",
                mitre_tactic="lateral-movement",
            ),
            SigmaRule(
                rule_id="SIG-011",
                name="恶意软件检测",
                description="检测已知恶意软件特征",
                severity="critical",
                attack_type="malware",
                confidence="high",
                action_recommend="block_ip",
                conditions={
                    "event_contains": ["MALWARE", "RANSOMWARE", "TROJAN", "WORM"],
                },
                mitre_attack_id="T1204",
                mitre_tactic="execution",
            ),
        ]

    def detect(self, event: dict) -> list[DetectionResult]:
        """
        单条事件检测（增强版）

        增强:
        - 跳过 enabled=False 的规则
        - shadow_mode 规则命中后标记 _shadow=True
        - 聚合规则检查滑动窗口条件
        - 字段映射标准化
        """
        results = []
        # 字段映射标准化
        normalized = self._normalize_fields(event)

        url = str(normalized.get("url", ""))
        host = str(normalized.get("dst_ip", ""))
        event_type = str(normalized.get("event", ""))
        message = str(normalized.get("message", ""))
        severity_raw = normalized.get("severity", 0)
        src_ip = str(normalized.get("src_ip", ""))
        event_text = f"{event_type} {message}".upper()

        for rule in self.rules:
            if not rule.enabled:
                continue

            if not self._match_conditions(rule, url, host, event_text, severity_raw):
                continue

            # 聚合条件检查
            if rule.aggregation:
                if not self._check_aggregation(rule, normalized):
                    continue

            # 威胁加成
            final_severity = rule.severity
            boost_hit = ""
            if rule.boost_conditions and self._match_boost(rule.boost_conditions, src_ip):
                final_severity = rule.boost_conditions.get("new_severity", final_severity)
                boost_hit = f" [内网加成→{final_severity}]"

            # 灰度标记
            shadow_tag = " [SHADOW]" if rule.shadow_mode else ""

            results.append(DetectionResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                severity=final_severity,
                attack_type=rule.attack_type,
                confidence=rule.confidence,
                action_recommend="alert" if rule.shadow_mode else rule.action_recommend,
                matched_fields={
                    "event_type": event_type,
                    "src_ip": src_ip,
                    "url": url[:100] if url else "",
                    "shadow_mode": rule.shadow_mode,
                    "mitre_attack_id": rule.mitre_attack_id,
                },
                description=rule.description + boost_hit + shadow_tag,
            ))

        return results

    def _normalize_fields(self, event: dict) -> dict:
        """字段映射标准化"""
        result = dict(event)
        for src_field, std_field in self.FIELD_MAP.items():
            if src_field in result and std_field not in result:
                result[std_field] = result[src_field]
        return result

    def _check_aggregation(self, rule: SigmaRule, event: dict) -> bool:
        """聚合条件检查（内存滑动窗口）"""
        agg = rule.aggregation
        func = agg.get("func", "count")
        group_field = agg.get("field", "src_ip")
        op = agg.get("op", ">")
        threshold = agg.get("threshold", 5)
        timeframe_str = agg.get("timeframe", "5m")

        # 解析 timeframe
        tf_seconds = self._parse_timeframe(timeframe_str)
        group_key = str(event.get(group_field, "unknown"))
        now = time.time()

        # 更新滑动窗口
        window = self._agg_windows[rule.rule_id][group_key]
        window.append((now, 1))

        # 清理过期数据
        cutoff = now - tf_seconds
        while window and window[0][0] < cutoff:
            window.popleft()

        # 计算聚合值
        if func == "count":
            agg_value = len(window)
        elif func == "avg":
            values = [v for _, v in window]
            agg_value = sum(values) / max(len(values), 1)
        else:
            agg_value = len(window)

        # 比较
        if op == ">":
            return agg_value > threshold
        elif op == ">=":
            return agg_value >= threshold
        elif op == "==":
            return agg_value == threshold
        return agg_value > threshold

    @staticmethod
    def _parse_timeframe(tf: str) -> int:
        """解析 timeframe 字符串 (5m → 300, 1h → 3600)"""
        tf = tf.strip().lower()
        if tf.endswith("m"):
            return int(tf[:-1]) * 60
        elif tf.endswith("h"):
            return int(tf[:-1]) * 3600
        elif tf.endswith("s"):
            return int(tf[:-1])
        return 300  # 默认 5 分钟

    def detect_batch(self, events: list[dict]) -> dict:
        """
        批量检测，返回统计报告

        Returns:
            {
                "total_events": int,
                "detected": int,
                "detection_rate": float,
                "by_attack_type": {攻击类型: 数量},
                "by_severity": {等级: 数量},
                "hits": [{event_index, rule_id, attack_type, severity}, ...]
            }
        """
        by_attack = {}
        by_severity = {}
        detected = 0
        hits = []

        for i, ev in enumerate(events):
            ev_hits = self.detect(ev)
            if ev_hits:
                detected += 1
                for h in ev_hits:
                    by_attack[h.attack_type] = by_attack.get(h.attack_type, 0) + 1
                    by_severity[h.severity] = by_severity.get(h.severity, 0) + 1
                    hits.append({
                        "event_index": i,
                        "rule_id": h.rule_id,
                        "attack_type": h.attack_type,
                        "severity": h.severity,
                    })

        total = len(events)
        return {
            "total_events": total,
            "detected": detected,
            "detection_rate": round(detected / max(total, 1), 4),
            "by_attack_type": by_attack,
            "by_severity": by_severity,
            "hits": hits[:50],
        }

    def detect_for_event(self, log_data: dict) -> dict:
        """
        为单条接入事件做 Sigma 检测（供 log_ingestion 调用）

        Returns:
            {
                "detected": bool,
                "hits": [DetectionResult.to_dict(), ...],
                "max_severity": str,
                "attack_types": [str, ...],
                "action_recommend": str,
            }
        """
        hits = self.detect(log_data)
        if not hits:
            return {"detected": False, "hits": [], "max_severity": "", "attack_types": [], "action_recommend": ""}

        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        max_sev = max(hits, key=lambda h: severity_order.get(h.severity, 0))
        attack_types = list(set(h.attack_type for h in hits))
        action = max_sev.action_recommend

        return {
            "detected": True,
            "hits": [h.to_dict() for h in hits],
            "max_severity": max_sev.severity,
            "attack_types": attack_types,
            "action_recommend": action,
            "rule_count": len(hits),
        }

    def _match_conditions(self, rule: SigmaRule, url: str, host: str,
                          event_text: str, severity_raw) -> bool:
        """匹配规则条件（同一规则内多条件为 OR 关系）"""
        for key, patterns in rule.conditions.items():
            if key == "url_contains":
                if any(p.upper() in url.upper() for p in patterns):
                    return True
            elif key == "event_contains":
                if any(p.upper() in event_text for p in patterns):
                    return True
            elif key == "host_port":
                port_str = host.rsplit(":", 1)[-1] if ":" in host else ""
                try:
                    port = int(port_str)
                    if any(p == port for p in patterns):
                        return True
                except ValueError:
                    pass
            elif key == "severity_min":
                try:
                    if int(severity_raw) >= int(patterns):
                        return True
                except (ValueError, TypeError):
                    pass
        return False

    def _match_boost(self, boost: dict, ip: str) -> bool:
        """威胁加成匹配"""
        if boost.get("target_is_internal"):
            return self._is_private_ip(ip)
        return False

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """判断是否为内网 IP"""
        if not ip:
            return False
        return (
            ip.startswith("10.")
            or ip.startswith("192.168.")
            or (ip.startswith("172.") and ip.split(".")[1].isdigit()
                and 16 <= int(ip.split(".")[1]) <= 31)
        )

    def stats(self) -> dict:
        """引擎状态（增强版）"""
        enabled = [r for r in self.rules if r.enabled]
        shadow = [r for r in self.rules if r.shadow_mode]
        return {
            "rules_count": len(self.rules),
            "enabled_count": len(enabled),
            "shadow_count": len(shadow),
            "attack_types": list(set(r.attack_type for r in self.rules)),
            "severity_distribution": {
                s: sum(1 for r in self.rules if r.severity == s)
                for s in ["critical", "high", "medium", "low"]
            },
            "mitre_coverage": {
                r.mitre_attack_id: r.mitre_tactic
                for r in self.rules if r.mitre_attack_id
            },
            "aggregation_rules": [
                r.rule_id for r in self.rules if r.aggregation
            ],
        }


# 全局单例（按配置选择引擎）
#   pySigma 档: 真 Sigma 引擎, 从 backend/sigma_engine/rules/*.yml 加载规则(pySigma + SQLite backend)
#   legacy 档:  原纯 dict 匹配(内置规则), 作为降级兜底
sigma_detector_legacy = SigmaDetector()   # 保留 legacy 实例供降级/切片测试


def _build_default_detector():
    try:
        from config import settings
        mode = (getattr(settings, "sigma_engine", "pySigma") or "pySigma").lower()
    except Exception:
        mode = "pySigma"
    if mode != "pysigma":
        logger.info(f"[Sigma] engine=legacy (cfg={mode})")
        return sigma_detector_legacy
    try:
        from sigma_engine import build_pysigma_detector
        det = build_pysigma_detector(enforce=True)
        if getattr(det, "_compiled", None):
            logger.info(f"[Sigma] engine=pySigma ({len(det._compiled)} rules from YAML)")
            return det
        logger.warning("[Sigma] pySigma enabled but no rules compiled; fallback legacy")
    except Exception as e:
        logger.warning(f"[Sigma] pySigma unavailable, fallback legacy: {e}")
    return sigma_detector_legacy


sigma_detector = _build_default_detector()
