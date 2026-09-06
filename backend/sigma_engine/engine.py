"""
sigma.engine — pySigma 封装（真 Sigma 规则引擎）

替代/增强原 sigma_detector 的“仿 Sigma”内存匹配：
  - 规则源改为 backend/sigma/rules/*.yml（标准 Sigma 1.x YAML，规则即证据，社区可复用）
  - 用 pySigma + SQLite backend 把每条规则编译成 SQL 谓词并缓存
  - 对单条事件（经字段规范化后的 dict）插入内存 sqlite 临时表逐规则求值命中
  - 返回与 sigma_detector 兼容的 DetectionResult 结构，log_ingestion/_sigma 不变

保底：若 pySigma 不可用(SHARED_MEMORY_SIGMA_ENGINE=legacy / import 失败)，自动降级到原
sigma_detector 纯 dict 匹配，保证检测链路不断。
"""
import logging
import os
import re
import sqlite3
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    from sigma.collection import SigmaCollection
    from sigma.backends.sqlite import sqliteBackend as SQLiteBackend
    # keywords 兼容 backend(继承 SQLiteBackend, 支持 value-only 全文搜索)。若不可用则退回原 backend。
    try:
        from sigma_engine.backend_keywords import SigmaKeywordsBackend
        _BACKEND_FACTORY = lambda: SigmaKeywordsBackend()  # noqa: E731
        _BACKEND_NAME = "SigmaKeywordsBackend"
    except Exception as _be:  # noqa: BLE001
        logger.warning(f"SigmaKeywordsBackend unavailable ({_be}); fallback SQLiteBackend")
        _BACKEND_FACTORY = lambda: SQLiteBackend()  # noqa: E731
        _BACKEND_NAME = "SQLiteBackend"
    PY_SIGMA_AVAILABLE = True
except Exception as _e:  # noqa: BLE001
    PY_SIGMA_AVAILABLE = False
    logger.warning(f"pySigma unavailable ({_e}); sigma engine will fallback to legacy detector")


# 平台专有扩展字段前缀（写入 Sigma YAML）
SOC_EXT = "x-soc-"


def _ext(rule: Any, key: str, default: Any = None) -> Any:
    """从 pySigma SigmaRule 读取 x-soc-* 自定义扩展字段(custom_attributes)。"""
    if not rule:
        return default
    d = getattr(rule, "custom_attributes", None) or {}
    if isinstance(d, dict):
        return d.get(f"{SOC_EXT}{key}", default)
    return default


class PySigmaDetector:
    """pySigma 单事件匹配引擎（返回与 sigma_detector 兼容结果）。"""

    TABLE = "events"

    # 最小字段桥接：平台归一化字段 → Sigma 规则可能引用的字段（后续接入 pipeline 再细化）
    FIELD_MAP = {
        "eventType": "event", "event_type": "event",
        "srcIp": "src_ip", "source_ip": "src_ip", "xffClientIp": "src_ip",
        "dstIp": "dst_ip", "dest_ip": "dst_ip", "host": "dst_ip",
        "msg": "message", "description": "message",
        "proto": "protocol",
        "sev": "severity", "level": "severity",
    }

    SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    def __init__(self, rules_dir: str, enforce: bool = False):
        self.rules_dir = rules_dir
        self._rules = []          # list[dict] 平台视角规则元数据（供 stats/前端）
        self._compiled = []       # list[(meta, sql)] 已编译谓词缓存
        self._conn = None
        self._table_columns: List[str] = []
        self._field_index: set = set()  # 所有已编译 SQL 引用的字段名(用于建列, 避免列不存在)
        self._legacy = None       # 降级目标
        self._enforce = enforce   # True: 强制 pySigma(失败抛错)；False: 失败降级 legacy
        if PY_SIGMA_AVAILABLE:
            try:
                self._load_and_compile()
            except Exception as e:
                logger.error(f"[Sigma/pySigma] init failed: {e}")
                if self._enforce:
                    raise

    # ── 加载与编译 ──
    def reload(self):
        """重载 rules 目录(CRUD 写回 YAML 后调用)。

        先编到临时结构,成功后再替换;失败保留上一份编译,避免一条坏 yml 把 SIG-001..011 清掉。
        """
        if not PY_SIGMA_AVAILABLE:
            return 0
        try:
            compiled, rules, field_index, conn = self._build_compiled()
        except Exception as e:
            logger.error(f"[Sigma/pySigma] reload failed: {e}")
            if self._enforce:
                raise
            return len(self._compiled)
        old_conn = self._conn
        self._compiled = compiled
        self._rules = rules
        self._field_index = field_index
        self._conn = conn
        if old_conn is not None and old_conn is not conn:
            try:
                old_conn.close()
            except Exception:
                pass
        return len(compiled)

    def _load_and_compile(self):
        compiled, rules, field_index, conn = self._build_compiled()
        self._compiled = compiled
        self._rules = rules
        self._field_index = field_index
        self._conn = conn
        return len(compiled)

    def _rule_files(self) -> list:
        import pathlib
        files: list = []
        p = pathlib.Path(self.rules_dir)
        if p.exists():
            files.extend(sorted(p.glob("*.yml")))
        parent = os.path.dirname(self.rules_dir)
        for extra in ("rules_community_active", "rules_selfplay_shadow"):
            d = os.path.join(parent, extra)
            if extra == "rules_selfplay_shadow":
                try:
                    from self_play.sigma_export import repair_selfplay_yaml
                    n = repair_selfplay_yaml(d)
                    if n:
                        logger.info(f"[Sigma/pySigma] repaired {n} self-play YAML ids under {d}")
                except Exception as e:
                    logger.warning(f"[Sigma/pySigma] self-play YAML repair skipped: {e}")
            if os.path.isdir(d):
                files.extend(sorted(pathlib.Path(d).glob("*.yml")))
        return files

    def _build_compiled(self):
        """按文件加载并编译。单文件失败只 skip,不拖垮整库。不改 self._compiled。"""
        files = self._rule_files()
        if not files:
            logger.warning(f"[Sigma/pySigma] no rules under {self.rules_dir}; using legacy fallback")
            return [], [], set(), None
        compiled: list = []
        rules: list = []
        field_index: set = set()
        be = _BACKEND_FACTORY()
        for fp in files:
            loaded = self._load_file(fp)
            if not loaded:
                continue
            for rule in loaded:
                meta = self._rule_meta(rule, fallback_n=len(compiled) + 1)
                try:
                    sql_list = be.convert_rule(rule)
                except Exception as e:
                    logger.warning(f"[Sigma/pySigma] compile {meta['rule_id']} failed: {e}; skipped")
                    continue
                sql = (sql_list[0] if isinstance(sql_list, list) and sql_list else str(sql_list))
                sql = sql.replace("<TABLE_NAME>", self.TABLE)
                for m in re.finditer(r"`([^`]+)`", sql):
                    field_index.add(m.group(1))
                for m in re.finditer(r"(?i)(?:\bWHERE\b|\bAND\b|\bOR\b|\()\s*([A-Za-z_][\w.\-]*)\s*(?:=|LIKE|IN|!=|<>)", sql):
                    col_name = m.group(1)
                    if col_name.upper() not in {"SELECT", "FROM", "WHERE", "AND", "OR", "LIKE", "IN", "NOT", "NULL"}:
                        field_index.add(col_name)
                compiled.append((meta, sql))
                rules.append(meta)
        conn = sqlite3.connect(":memory:") if compiled else None
        logger.info(f"[Sigma/pySigma] compiled {len(compiled)} rules from {self.rules_dir}")
        return compiled, rules, field_index, conn

    def _load_file(self, fp) -> list:
        try:
            with open(fp, "r", encoding="utf-8") as fh:
                text = fh.read()
        except Exception as e:
            logger.warning(f"[Sigma/pySigma] read {fp} failed: {e}; skipped")
            return []
        try:
            col = SigmaCollection.from_yaml(text, collect_errors=True)
        except Exception as e:
            logger.warning(f"[Sigma/pySigma] parse {fp} failed: {e}; skipped")
            return []
        out = []
        for rule in getattr(col, "rules", None) or []:
            errs = [e for e in (getattr(rule, "errors", None) or []) if e]
            if errs:
                logger.warning(f"[Sigma/pySigma] skip {fp}: {errs[0]}")
                continue
            out.append(rule)
        return out

    def _rule_meta(self, sigmarule: Any, fallback_n: int = 1) -> dict:
        title = getattr(sigmarule, "title", "") or ""
        rid = _ext(sigmarule, "id") or getattr(getattr(sigmarule, "id", None) or None, "value", None) or \
              f"SIG-{fallback_n:03d}"
        lvl = getattr(sigmarule, "level", None)
        lvl_str = getattr(lvl, "name", str(lvl)).lower() if lvl else "low"
        return {
            "rule_id": str(rid),
            "name": title,
            "description": getattr(sigmarule, "description", "") or "",
            "severity": str(_ext(sigmarule, "severity") or lvl_str),
            "attack_type": str(_ext(sigmarule, "attack_type", "custom")),
            "confidence": str(_ext(sigmarule, "confidence", "medium")),
            "action_recommend": str(_ext(sigmarule, "action", "alert")),
            "shadow_mode": bool(_ext(sigmarule, "shadow", False)),
            "enabled": _ext(sigmarule, "enabled", True),
            "mitre_attack_id": str(getattr(sigmarule, "tags", None) or "").replace("[", "").replace("]", "") or "",
            "yaml": _ext(sigmarule, "yaml", ""),
            "aggregation": _ext(sigmarule, "aggregation"),
            "boost": _ext(sigmarule, "boost"),
        }

    # ── 匹配 ──
    def _normalize(self, event: dict) -> dict:
        out = dict(event)
        for src, std in self.FIELD_MAP.items():
            if src in out and std not in out:
                out[std] = out[src]
        # 从 host:/ip:port 提取 dst_port(SIG-006/007 端口类规则)
        if "dst_port" not in out:
            dst = str(out.get("dst_ip", ""))
            if ":" in dst:
                host, _, port = dst.rpartition(":")
                if port.isdigit():
                    out["dst_ip"] = host
                    out["dst_port"] = int(port)
        return out

    def detect(self, event: dict) -> list:
        """命中返回列表(DetectionResult)。pySigma 不可用/无规则时降级 legacy。"""
        if not self._compiled:
            return self._legacy_detect(event)
        # 用 apply_mapping 同时提供平台字段(url/event/...)与 Sigma 社区字段(cs-uri-query/...),
        # 使内置规则与 SigmaHQ 子集规则都能命中。
        from sigma_engine.mapping import apply_mapping
        ev = apply_mapping(event)
        cols = list(ev.keys())
        if not cols:
            return []
        # 每事件重建单行表，避免历史行残留造成假命中
        self._ensure_table(cols, ev)
        results = []
        url = str(ev.get("url", ""))
        src_ip = str(ev.get("src_ip", ""))
        etype = str(ev.get("event", ""))
        try:
            cur = self._conn.cursor()
            for meta, sql in self._compiled:
                if not meta.get("enabled", True):
                    continue
                try:
                    row = cur.execute(sql)
                    hit = row.fetchone() is not None
                except Exception:
                    hit = False
                if hit:
                    sev = meta["severity"]
                    desc = meta["description"]
                    if meta.get("shadow_mode"):
                        desc += " [SHADOW]"
                        act = "alert"
                    else:
                        act = meta["action_recommend"]
                    results.append(self._mk_result(meta, ev, sev, act, desc))
                    # 命中聚合类规则(SIG-001/007 等带 x-soc-aggregation): 发布聚合候选 → Flink 阈值窗口
                    # 发布失败不得影响本条检测命中结果
                    agg = meta.get("aggregation")
                    if agg and isinstance(agg, dict):
                        try:
                            self._schedule_publish_agg(meta, ev, agg)
                        except Exception as pub_err:
                            logger.warning(
                                f"[Sigma/agg] publish skipped for {meta.get('rule_id')}: {pub_err}"
                            )
        finally:
            try:
                cur.close()
            except Exception:
                pass
        return results

    def _ensure_table(self, cols: List[str], ev: dict):
        """每次重建单行表：DROP → CREATE(当前事件列) → INSERT 当前事件。

        补齐所有已编译 SQL 引用的字段列(self._field_index), 事件缺省时值为空串,
        避免 SQL 引用不存在的列报错(空列不影响命中, 且 keywords 全文搜索需要这些列)。
        """
        # 平台常用字段：即使 SQL 解析未抽到，也预建列，避免 OR 条件因缺列整句失败
        standard = {
            "event", "message", "src_ip", "dst_ip", "dst_port", "src_port", "port",
            "protocol", "url", "severity", "host", "user", "username",
        }
        needed = set(cols) | set(self._field_index) | standard
        cols = sorted(needed)
        cur = self._conn.cursor()
        try:
            cur.execute(f"DROP TABLE IF EXISTS {self.TABLE}")
        except Exception:
            pass
        coldef = ", ".join(f'"{c}" TEXT' for c in cols)
        cur.execute(f'CREATE TABLE {self.TABLE} ({coldef})')
        ph = ", ".join("?" for _ in cols)
        quoted = ", ".join(f'"{c}"' for c in cols)
        # protocol=ssh 时补默认 dst_port=22，便于端口类规则在缺字段时仍可 OR 到 event 条件
        values = []
        for c in cols:
            v = ev.get(c, "")
            if (c == "dst_port" or c == "port") and (v is None or v == ""):
                proto = str(ev.get("protocol") or "").lower()
                if proto in ("ssh", "tcp/22"):
                    v = "22"
            values.append(str(v) if v is not None else "")
        cur.execute(f'INSERT INTO {self.TABLE} ({quoted}) VALUES ({ph})', values)
        self._conn.commit()

    def _schedule_publish_agg(self, meta, ev, agg: dict):
        """命中聚合类规则时, 若 Kafka 启用则异步发布聚合候选到 sigma-hit topic。
        仅调度(不阻塞检测); 无 running 事件循环(Kafka 未启用)时静默跳过。"""
        try:
            import asyncio
            from config import settings
            if not getattr(settings, "kafka_enabled", False):
                logger.info(f"[Sigma/agg] kafka disabled, skip publish {meta.get('rule_id')}")
                return
            from kafka_producer import kafka_producer
            logger.info(f"[Sigma/agg] producer.is_active={kafka_producer.is_active} rule={meta.get('rule_id')}")
            # is_active 是 property(属性 bool), 非方法
            if not kafka_producer.is_active:
                return
        except Exception as e:
            logger.warning(f"[Sigma/agg] pre-publish check err: {e}")
            return
        payload = {
            "src_ip": str(ev.get("src_ip", "")),
            "rule_id": meta["rule_id"],
            "threshold": int(agg.get("threshold", agg.get("threshold") or 0) or 0),
            "timestamp": int(ev.get("timestamp", ev.get("@timestamp", 0)) or 0) or int(time.time() * 1000),
        }
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(kafka_producer.publish_sigma_hit(payload))
        except Exception:
            pass

    def _mk_result(self, meta, ev, severity, action, description):
        from sigma_detector import DetectionResult
        return DetectionResult(
            rule_id=meta["rule_id"],
            rule_name=meta["name"],
            severity=severity,
            attack_type=meta["attack_type"],
            confidence=meta["confidence"],
            action_recommend=action,
            matched_fields={
                "event_type": str(ev.get("event", "")),
                "src_ip": str(ev.get("src_ip", "")),
                "url": str(ev.get("url", ""))[:100],
                "shadow_mode": meta.get("shadow_mode", False),
                "mitre_attack_id": meta.get("mitre_attack_id", ""),
            },
            description=description,
        )

    def _legacy_detect(self, event: dict) -> list:
        """降级：走原 sigma_detector 纯 dict 匹配(直接用 SigmaDetector 类，避免拿全局 pySigma 对象导致自递归)。"""
        if self._legacy is None:
            try:
                from sigma_detector import SigmaDetector
                self._legacy = SigmaDetector()
            except Exception as e:
                logger.warning(f"[Sigma] legacy fallback unavailable: {e}")
                return []
        return self._legacy.detect(event)

    # ── 对外兼容接口 ──
    def detect_batch(self, events: list[dict]) -> dict:
        """批量检测，返回与 sigma_detector.detect_batch 兼容的统计报告。"""
        by_attack, by_severity, hits = {}, {}, []
        detected = 0
        for i, ev in enumerate(events):
            ev_hits = self.detect(ev)
            if ev_hits:
                detected += 1
                for h in ev_hits:
                    by_attack[h.attack_type] = by_attack.get(h.attack_type, 0) + 1
                    by_severity[h.severity] = by_severity.get(h.severity, 0) + 1
                    hits.append({"event_index": i, "rule_id": h.rule_id,
                                 "attack_type": h.attack_type, "severity": h.severity})
        total = len(events)
        return {"total_events": total, "detected": detected,
                "detection_rate": round(detected / max(total, 1), 4),
                "by_attack_type": by_attack, "by_severity": by_severity, "hits": hits[:50]}

    def detect_for_event(self, log_data: dict) -> dict:
        hits = self.detect(log_data)
        if not hits:
            return {"detected": False, "hits": [], "max_severity": "", "attack_types": [], "action_recommend": ""}
        max_sev = max(hits, key=lambda h: self.SEVERITY_ORDER.get(h.severity, 0))
        return {
            "detected": True,
            "hits": [h.to_dict() for h in hits],
            "max_severity": max_sev.severity,
            "attack_types": list(set(h.attack_type for h in hits)),
            "action_recommend": max_sev.action_recommend,
            "rule_count": len(hits),
        }

    def stats(self) -> dict:
        if not self._rules:
            return {"rules_count": 0, "enabled_count": 0, "shadow_count": 0,
                    "engine": "legacy" if not PY_SIGMA_AVAILABLE else "pySigma(no rules)"}
        return {
            "rules_count": len(self._rules),
            "enabled_count": sum(1 for r in self._rules if r.get("enabled", True)),
            "shadow_count": sum(1 for r in self._rules if r.get("shadow_mode")),
            "attack_types": list(set(r["attack_type"] for r in self._rules)),
            "severity_distribution": {
                s: sum(1 for r in self._rules if r["severity"] == s)
                for s in ["critical", "high", "medium", "low"]
            },
            "engine": "pySigma",
            "rules_dir": self.rules_dir,
        }

    def list_rules(self) -> list[dict]:
        return [{"rule_id": r["rule_id"], "name": r["name"], "description": r["description"],
                 "severity": r["severity"], "attack_type": r["attack_type"],
                 "confidence": r["confidence"], "action_recommend": r["action_recommend"],
                 "enabled": r.get("enabled", True), "type": "sigma",
                 "conditions": {"sigma_yaml": r.get("yaml", "")}}
                for r in self._rules]

    def rules(self):
        return self._rules
