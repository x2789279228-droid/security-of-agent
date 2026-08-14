"""
分解者 (Decomposer) — Audit-LLM 第一层

职责：
  1. 分析安全事件的类型、严重度、异常分数
  2. 决定审核深度（quick / standard / deep）
  3. 按深度产生对应的子任务列表

决策逻辑：
  - LLM 分析事件特征 + 输出审核方案
  - 或：规则引擎快速决策（低风险走规则，高风险走LLM）

输出：
  - audit_depth: 审核深度
  - sub_tasks: list[SubTask]
  - analysis_summary: LLM 对事件的初步判断
"""
import json
import logging

from summary_compression import summary
from audit_types import (
    SubTask,
    AUDIT_DEPTH_QUICK, AUDIT_DEPTH_STANDARD, AUDIT_DEPTH_DEEP,
    SUBTASK_QUERY_EVENTS, SUBTASK_ANALYZE_IP, SUBTASK_FIND_CHAINS,
    SUBTASK_CHECK_MEMORY, SUBTASK_KNOWLEDGE_SEARCH,
    SUBTASK_DEEP_ANALYZE, SUBTASK_RECHECK,
    SUBTASK_GET_WINDOW, SUBTASK_ENTITY_LINK,
)

logger = logging.getLogger(__name__)

# ── 威胁类型 → 推荐知识库（RAG source，逗号分隔多库） ──
# 按需取库：漏洞/利用类查 cve+kev+vulnerability，手法类查 mitre+capec，DDoS 查 capec 等
SOURCE_BY_THREAT: dict[str, str] = {
    "WEB_ATTACK": "cve,vulnerability,capec",
    "MALWARE_DETECT": "cve,vulnerability,mitre-attack",
    "PRIVILEGE_ESCALATION": "cve,vulnerability,mitre-attack",
    "CREDENTIAL_ACCESS": "capec,mitre-attack",
    "BRUTE_FORCE": "capec,mitre-attack",
    "DDoS_TRAFFIC": "capec,mitre-attack",
    "C2_BEACON": "mitre-attack,playbook",
    "DATA_EXFIL": "mitre-attack,capec",
    "LATERAL_MOVE": "mitre-attack,playbook",
    "PERSISTENCE": "mitre-attack",
    "DISCOVERY": "mitre-attack,capec",
    "PORT_SCAN": "mitre-attack,capec",
    "DEFENSE_EVASION": "mitre-attack",
    "SUPPLY_CHAIN": "cve,vulnerability",
}


def _recommend_knowledge_source(event_type: str) -> str:
    """按事件/威胁类型推荐知识库来源（未命中返回空=全库检索）"""
    if not event_type:
        return ""
    et = event_type.upper()
    for key, sources in SOURCE_BY_THREAT.items():
        if key in et:
            return sources
    return ""


# ── 规则引擎（非LLM快速决策路径） ──

def _rule_based_depth(event: dict, anomaly_score: float) -> str:
    """基于规则的快速审核深度决策"""
    severity = event.get("severity", "info")
    event_type = event.get("event", event.get("type", ""))

    # 高危关键词 → 深度审核
    high_risk_types = {
        "C2_BEACON", "DATA_EXFIL", "MALWARE_DETECT",
        "RANSOMWARE", "LATERAL_MOVE", "PRIV_ESC",
    }
    if event_type in high_risk_types:
        return AUDIT_DEPTH_DEEP

    # 严重度 + 异常分 决策
    if severity in ("critical",) or anomaly_score > 0.7:
        return AUDIT_DEPTH_DEEP
    if severity in ("high", "medium") or anomaly_score > 0.4:
        return AUDIT_DEPTH_STANDARD
    if anomaly_score > 0.2:
        return AUDIT_DEPTH_STANDARD

    return AUDIT_DEPTH_QUICK


def _get_subtasks_quick(session_id: str, event: dict,
                        anomaly_score: float) -> list[SubTask]:
    """快速审核子任务"""
    src_ip = event.get("src_ip", "")
    tasks = []
    idx = 0

    # t1: 查询同IP近期事件
    idx += 1
    tasks.append(SubTask(
        task_id=f"t{idx}",
        type=SUBTASK_QUERY_EVENTS,
        params={"session_id": session_id, "src_ip": src_ip,
                "time_window_minutes": 30, "limit": 20},
        priority=3,
        description=f"快速查询 {src_ip} 近30分钟的事件",
    ))

    return tasks


def _get_subtasks_standard(session_id: str, event: dict,
                           anomaly_score: float) -> list[SubTask]:
    """标准审核子任务"""
    src_ip = event.get("src_ip", "")
    event_type = event.get("event", event.get("type", ""))
    tasks = []
    idx = 0

    # t1: 查询同IP近期事件
    idx += 1
    tasks.append(SubTask(
        task_id=f"t{idx}",
        type=SUBTASK_QUERY_EVENTS,
        params={"session_id": session_id, "src_ip": src_ip,
                "time_window_minutes": 120, "limit": 50},
        priority=4,
        description=f"查询 {src_ip} 近2小时事件",
    ))

    # t2: IP基线分析
    idx += 1
    tasks.append(SubTask(
        task_id=f"t{idx}",
        type=SUBTASK_ANALYZE_IP,
        params={"src_ip": src_ip},
        priority=3,
        description=f"{src_ip} 历史行为基线",
    ))

    # t3: 攻击链检测
    idx += 1
    tasks.append(SubTask(
        task_id=f"t{idx}",
        type=SUBTASK_FIND_CHAINS,
        params={"session_id": session_id, "time_window_minutes": 1440},
        priority=3,
        description="24小时内攻击链检测",
    ))

    # t4: 向量记忆检索
    idx += 1
    tasks.append(SubTask(
        task_id=f"t{idx}",
        type=SUBTASK_CHECK_MEMORY,
        params={"query": f"{event_type} {src_ip}"},
        priority=2,
        description="语义相关历史记忆",
    ))

    # t5: 安全知识库检索 (RAG)
    idx += 1
    tasks.append(SubTask(
        task_id=f"t{idx}",
        type=SUBTASK_KNOWLEDGE_SEARCH,
        params={"query": f"{event_type} 攻击特征 检测方法",
                "threat_type": event_type, "severity": event.get("severity", ""),
                "source": _recommend_knowledge_source(event_type)},
        priority=3,
        description=f"检索 {event_type} 相关安全知识 (多知识库)",
    ))

    return tasks


def _get_subtasks_deep(session_id: str, event: dict,
                       anomaly_score: float) -> list[SubTask]:
    """深度审核子任务"""
    src_ip = event.get("src_ip", "")
    dst_ip = event.get("dst_ip", "")
    event_type = event.get("event", event.get("type", ""))
    tasks = []
    idx = 0

    # t1: 全量事件查询
    idx += 1
    tasks.append(SubTask(
        task_id=f"t{idx}",
        type=SUBTASK_QUERY_EVENTS,
        params={"session_id": session_id, "src_ip": src_ip,
                "time_window_minutes": 1440, "limit": 200},
        priority=5,
        description=f"{src_ip} 24小时全量事件",
    ))

    # t2: IP基线
    idx += 1
    tasks.append(SubTask(
        task_id=f"t{idx}",
        type=SUBTASK_ANALYZE_IP,
        params={"src_ip": src_ip},
        priority=4,
        description=f"{src_ip} 基线分析",
    ))

    # t3: 如果目标IP存在，查目标事件
    if dst_ip:
        idx += 1
        tasks.append(SubTask(
            task_id=f"t{idx}",
            type=SUBTASK_QUERY_EVENTS,
            params={"session_id": session_id, "src_ip": dst_ip,
                    "time_window_minutes": 1440, "limit": 100},
            priority=4,
            description=f"目标 {dst_ip} 的事件",
        ))

    # t4: 攻击链
    idx += 1
    tasks.append(SubTask(
        task_id=f"t{idx}",
        type=SUBTASK_FIND_CHAINS,
        params={"session_id": session_id, "time_window_minutes": 2880},
        priority=4,
        description="48小时攻击链检测",
    ))

    # t5: 实体图关联
    idx += 1
    tasks.append(SubTask(
        task_id=f"t{idx}",
        type=SUBTASK_ENTITY_LINK,
        params={"session_id": session_id, "time_window_minutes": 1440},
        priority=3,
        description="实体关联分析",
    ))

    # t6: 记忆检索
    idx += 1
    tasks.append(SubTask(
        task_id=f"t{idx}",
        type=SUBTASK_CHECK_MEMORY,
        params={"query": f"{event_type} {src_ip} {dst_ip}"},
        priority=3,
        description="相关记忆",
    ))

    # t6b: 安全知识库检索 (RAG)
    idx += 1
    tasks.append(SubTask(
        task_id=f"t{idx}",
        type=SUBTASK_KNOWLEDGE_SEARCH,
        params={"query": f"{event_type} 攻击手法 检测指标 IOC 响应建议",
                "threat_type": event_type, "severity": event.get("severity", ""),
                "source": _recommend_knowledge_source(event_type)},
        priority=4,
        description=f"深度检索 {event_type} 安全知识 (多知识库)",
    ))

    # t7: 深度LLM分析（依赖前序结果）
    idx += 1
    tasks.append(SubTask(
        task_id=f"t{idx}",
        type=SUBTASK_DEEP_ANALYZE,
        params={"event": event},
        priority=2,
        depends_on=[f"t{i+1}" for i in range(idx - 1)],
        description="综合所有数据深度分析",
    ))

    # t8: 复核
    idx += 1
    tasks.append(SubTask(
        task_id=f"t{idx}",
        type=SUBTASK_RECHECK,
        params={},
        priority=1,
        depends_on=[f"t{idx - 1}"],
        description="复核审计结论",
    ))

    return tasks


# ── Decomposer 主类 ──

class Decomposer:
    """
    分解者

    decompose() 输出: {
        "audit_depth": "quick|standard|deep",
        "sub_tasks": [SubTask, ...],
        "llm_analysis": "LLM的初步判断（如需要）",
    }
    """

    async def decompose(
        self,
        event: dict,
        session_id: str,
        anomaly_score: float = 0.0,
        anomaly_reasons: list[str] = None,
        mode: str = "full",
        missed_threats: list[dict] = None,
    ) -> dict:
        """
        分解审核任务

        Args:
            event: 原始事件
            session_id: 会话ID
            anomaly_score: 异常检测分数
            anomaly_reasons: 异常原因列表
            mode: "full" | "supplement"
            missed_threats: 前序轮次遗漏的威胁列表（mode=supplement时传入）

        Returns:
            {"audit_depth": str, "sub_tasks": list[SubTask],
             "llm_analysis": str, "depth_reason": str}
        """
        missed_threats = missed_threats or []
        event_type = event.get("event", event.get("type", "UNKNOWN"))
        severity = event.get("severity", "info")
        src_ip = event.get("src_ip", "")
        anomaly_reasons = anomaly_reasons or []

        if mode == "supplement":
            return await self._decompose_supplement(
                event, session_id, anomaly_score, missed_threats
            )

        # ── 首次审核（full mode） ──
        depth = _rule_based_depth(event, anomaly_score)
        depth_reason = (
            f"severity={severity}, anomaly_score={anomaly_score:.3f}"
        )

        logger.info(
            f"Decomposer(full): depth={depth} type={event_type} "
            f"src={src_ip} score={anomaly_score:.3f}"
        )

        llm_analysis = ""
        if depth == AUDIT_DEPTH_DEEP:
            llm_analysis = await self._llm_pre_analyze(event, anomaly_score, anomaly_reasons)

        depth_to_tasks = {
            AUDIT_DEPTH_QUICK: _get_subtasks_quick,
            AUDIT_DEPTH_STANDARD: _get_subtasks_standard,
            AUDIT_DEPTH_DEEP: _get_subtasks_deep,
        }
        task_fn = depth_to_tasks.get(depth, _get_subtasks_standard)
        sub_tasks = task_fn(session_id, event, anomaly_score)

        logger.info(f"Decomposer(full): {len(sub_tasks)} sub-tasks")

        return {
            "audit_depth": depth,
            "sub_tasks": [st.to_dict() for st in sub_tasks],
            "llm_analysis": llm_analysis,
            "depth_reason": depth_reason,
            "mode": "full",
        }

    async def _decompose_supplement(
        self,
        event: dict,
        session_id: str,
        anomaly_score: float,
        missed_threats: list[dict],
    ) -> dict:
        """
        补审模式：只针对遗漏的威胁生成子任务
        """
        logger.info(
            f"Decomposer(supplement): {len(missed_threats)} missed threats to re-audit"
        )

        tasks = []
        idx = 0

        # 从遗漏威胁中提取需要关注的事件ID和IP
        target_ids = set()
        target_ips = set()
        for mt in missed_threats:
            desc = mt.get("description", "")
            evidence = mt.get("evidence", "")
            # 尝试从evidence中提取事件ID
            for part in evidence.split(","):
                part = part.strip()
                if part.isdigit():
                    target_ids.add(int(part))
            # 尝试从description中提取IP
            import re
            ips = re.findall(r'\d+\.\d+\.\d+\.\d+', desc)
            target_ips.update(ips)

        # t1: 按ID精确查询遗漏事件
        if target_ids:
            idx += 1
            tasks.append(SubTask(
                task_id=f"s{idx}",
                type=SUBTASK_QUERY_EVENTS,
                params={
                    "session_id": session_id,
                    "event_ids": list(target_ids),
                    "limit": len(target_ids),
                },
                priority=5,
                description=f"精确查询遗漏事件 ID={sorted(target_ids)}",
            ))

        # t2: 查询遗漏IP的完整活动
        for ip in list(target_ips)[:3]:
            idx += 1
            tasks.append(SubTask(
                task_id=f"s{idx}",
                type=SUBTASK_QUERY_EVENTS,
                params={
                    "session_id": session_id,
                    "src_ip": ip,
                    "time_window_minutes": 1440,
                    "limit": 100,
                },
                priority=4,
                description=f"遗漏IP {ip} 的24小时活动",
            ))

        # t3: 如果连IP和ID都没有，扩大时间窗口重查
        if not target_ids and not target_ips:
            idx += 1
            tasks.append(SubTask(
                task_id=f"s{idx}",
                type=SUBTASK_QUERY_EVENTS,
                params={
                    "session_id": session_id,
                    "time_window_minutes": 2880,
                    "limit": 200,
                },
                priority=3,
                description="扩大窗口至48小时重查所有事件",
            ))

        # t4: 攻击链补查
        idx += 1
        tasks.append(SubTask(
            task_id=f"s{idx}",
            type=SUBTASK_FIND_CHAINS,
            params={"session_id": session_id, "time_window_minutes": 2880},
            priority=3,
            description="扩大窗口攻击链补查",
        ))

        return {
            "audit_depth": "supplement",
            "sub_tasks": [st.to_dict() for st in tasks],
            "llm_analysis": "",
            "depth_reason": f"补审 {len(missed_threats)} 项遗漏威胁",
            "mode": "supplement",
        }

    async def _llm_pre_analyze(
        self, event: dict, anomaly_score: float,
        anomaly_reasons: list[str],
    ) -> str:
        """LLM 对事件的初步分析（仅深度审核）"""
        event_json = json.dumps(event, ensure_ascii=False, indent=2)
        reasons_str = "\n".join(anomaly_reasons) if anomaly_reasons else "无"

        prompt = f"""你是安全分析专家。请对以下安全事件做初步分析，输出 JSON。

## 安全事件
{event_json}

## 异常检测报告
分数: {anomaly_score:.3f}
原因: {reasons_str}

## 分析要求
1. 分析该事件是否可能是真实威胁
2. 判断需要调哪些工具来确认
3. 输出 JSON: {{"初步判断":"威胁/疑似/正常","需要关注的IP":[],"需要查询的方向":[],"分析理由":"..."}}"""

        from trace_hook import set_trace_context
        set_trace_context(operation="decompose")
        result = await summary.llm.chat([
            {"role": "system", "content": "你是安全分析专家，输出JSON格式。"},
            {"role": "user", "content": prompt},
        ])
        return result


decomposer = Decomposer()
