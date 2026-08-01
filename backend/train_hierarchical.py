"""
层级化Transformer注意力训练器

训练流程:
1. 生成5000+带标签的安全日志训练数据
2. 数据驱动分析：事件类型→重要性→路由的映射关系
3. 参数优化：路由阈值、注意力权重、预算比例
4. 导出优化后的配置参数

输出: optimized_params.py (可直接导入使用)
"""
import json
import logging
import math
import random
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("trainer")

# ── 安全日志模式定义 ──

# 真实安全日志的分布模式（基于公开安全报告统计）
ATTACK_PATTERNS = {
    # event_type: (base_severity, base_importance, typical_confidence_range, typical_frequency)
    "C2_BEACON":      ("critical", 0.95, (85, 99), 0.03),
    "DATA_EXFIL":     ("critical", 0.95, (80, 98), 0.02),
    "MALWARE_DETECT": ("critical", 0.90, (75, 99), 0.04),
    "BRUTE_FORCE":    ("critical", 0.85, (80, 95), 0.05),
    "RANSOMWARE":     ("critical", 0.95, (85, 99), 0.01),
    "DDoS_TRAFFIC":   ("high",     0.80, (70, 95), 0.04),
    "SQL_INJECTION":  ("high",     0.75, (70, 90), 0.05),
    "XSS_ATTACK":     ("high",     0.70, (65, 85), 0.04),
    "PORT_SCAN":      ("high",     0.65, (60, 85), 0.08),
    "PHISHING":       ("high",     0.75, (70, 90), 0.03),
    "PRIV_ESC":       ("high",     0.80, (75, 95), 0.03),
    "LATERAL_MOVE":   ("critical", 0.90, (80, 98), 0.02),
    "WEAK_PASSWORD":  ("medium",   0.45, (50, 75), 0.06),
    "SUSPICIOUS_LOGIN":("medium",  0.50, (55, 80), 0.05),
    "VPN_ANOMALY":    ("medium",   0.40, (40, 70), 0.04),
    "USER_LOGIN":     ("info",     0.15, (10, 40), 0.15),
    "DNS_QUERY":      ("low",      0.10, (5,  30), 0.12),
    "FILE_ACCESS":    ("info",     0.12, (10, 35), 0.10),
    "EMAIL_SENT":     ("low",      0.08, (5,  25), 0.08),
    "PRINT_JOB":      ("low",      0.05, (5,  20), 0.03),
}

SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]
SEVERITY_SCORE = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "info": 0.1}
PROTOCOLS = ["TCP", "UDP", "HTTP", "HTTPS", "DNS", "SSH", "RDP", "SMTP", "FTP"]


# ── 训练数据单元 ──

@dataclass
class TrainingSample:
    """单条带标签训练数据"""
    event_type: str
    severity: str
    confidence: int
    src_ip: str
    message: str
    protocol: str = "TCP"
    # 标签（ground truth）
    true_importance: float = 0.5
    true_route: str = "light"     # "none" | "light" | "deep" | "dedup"
    true_budget_ratio: float = 0.5  # 应获得的token预算比例

    def to_dict(self) -> dict:
        return {
            "event": self.event_type, "severity": self.severity,
            "confidence": self.confidence, "src_ip": self.src_ip,
            "message": self.message, "protocol": self.protocol,
            "_label": {"importance": self.true_importance,
                       "route": self.true_route,
                       "budget": self.true_budget_ratio},
        }


# ── 训练器 ──

class HierarchicalAttentionTrainer:
    """
    层级化注意力训练器

    从大量安全日志中学习最优注意力参数:
    - 路由决策边界
    - 重要性权重
    - Token预算分配
    - 合并触发策略
    """

    def __init__(self):
        self.samples: list[TrainingSample] = []
        # 统计数据
        self.route_distribution = defaultdict(lambda: defaultdict(int))
        self.importance_by_event = defaultdict(list)
        self.importance_by_severity = defaultdict(list)
        self.correlation_route_importance = []
        self.budget_utilization = []
        # 优化结果
        self.optimized = {}

    # ── 1. 数据生成 ──

    def generate_training_data(self, count: int = 5000, seed: int = 42):
        """生成带标签的安全日志训练数据"""
        random.seed(seed)
        logger.info(f"Generating {count} training samples...")

        # 按频率分布生成
        total_freq = sum(p[3] for p in ATTACK_PATTERNS.values())
        target_counts = {}
        for event, (sev, imp, conf_range, freq) in ATTACK_PATTERNS.items():
            target_counts[event] = max(1, int(count * freq / total_freq))

        for event, target in target_counts.items():
            sev, base_imp, conf_range, _ = ATTACK_PATTERNS[event]
            for _ in range(target):
                confidence = random.randint(*conf_range)
                octet = random.randint(1, 254)
                src_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{octet}"

                # 真实重要性 = base_imp * (1 + 0.2 * (confidence - 50) / 50)
                true_imp = min(1.0, base_imp * (1 + 0.15 * (confidence - 50) / 50))

                # 真实路由 = f(severity, event_type)
                if sev in ("critical",) or event in ("C2_BEACON", "DATA_EXFIL", "MALWARE_DETECT"):
                    true_route = "none"
                elif sev in ("high",) or event in ("BRUTE_FORCE",):
                    true_route = "light"
                elif sev in ("medium",):
                    true_route = "light"
                else:
                    true_route = "deep"

                # 真实预算比例
                true_budget = true_imp * 0.6 + 0.1

                sample = TrainingSample(
                    event_type=event, severity=sev, confidence=confidence,
                    src_ip=src_ip, message=f"{event} detected from {src_ip}",
                    protocol=random.choice(PROTOCOLS),
                    true_importance=round(true_imp, 4),
                    true_route=true_route,
                    true_budget_ratio=round(true_budget, 4),
                )
                self.samples.append(sample)

        random.shuffle(self.samples)
        logger.info(f"Generated {len(self.samples)} samples across "
                    f"{len(target_counts)} event types")
        return self.samples

    # ── 2. 统计分析 ──

    def analyze(self):
        """数据驱动的统计分析"""
        logger.info("\n" + "=" * 60)
        logger.info("STATISTICAL ANALYSIS")
        logger.info("=" * 60)

        # 2.1 事件类型→重要性的映射
        logger.info("\n[1/4] Event Type → Importance Mapping:")
        for event in sorted(ATTACK_PATTERNS.keys()):
            imps = [s.true_importance for s in self.samples if s.event_type == event]
            if imps:
                routes = [s.true_route for s in self.samples if s.event_type == event]
                route_dist = {r: routes.count(r) for r in set(routes)}
                logger.info(f"  {event:20s}  importance={sum(imps)/len(imps):.3f}  "
                            f"routes={route_dist}  count={len(imps)}")

        # 2.2 严重度→重要性
        logger.info("\n[2/4] Severity → Importance:")
        for sev in SEVERITY_LEVELS:
            imps = [s.true_importance for s in self.samples if s.severity == sev]
            if imps:
                logger.info(f"  {sev:10s}  mean_imp={sum(imps)/len(imps):.3f}  "
                            f"min={min(imps):.3f} max={max(imps):.3f} count={len(imps)}")

        # 2.3 置信度与重要性的相关性
        logger.info("\n[3/4] Confidence → Importance Correlation:")
        buckets = [(0, 30), (30, 50), (50, 70), (70, 85), (85, 100)]
        for lo, hi in buckets:
            imps = [s.true_importance for s in self.samples
                    if lo <= s.confidence < hi]
            if imps:
                logger.info(f"  conf=[{lo:3d},{hi:3d})  mean_imp={sum(imps)/len(imps):.3f}  "
                            f"count={len(imps)}")

        # 2.4 当前路由规则的正确率
        logger.info("\n[4/4] Current Route Rules Accuracy:")
        correct = 0
        route_results = defaultdict(lambda: {"correct": 0, "total": 0})
        for s in self.samples[:1000]:
            predicted_route = self._predict_route(s)
            actual_route = s.true_route
            route_results[actual_route]["total"] += 1
            if predicted_route == actual_route:
                correct += 1
                route_results[actual_route]["correct"] += 1

        total = sum(r["total"] for r in route_results.values())
        logger.info(f"  Overall accuracy: {correct}/{total} "
                    f"({correct/total*100:.1f}%)")
        for route, stats in sorted(route_results.items()):
            acc = stats["correct"] / stats["total"] * 100 if stats["total"] else 0
            logger.info(f"  route={route:6s}  accuracy={acc:.1f}%  "
                        f"({stats['correct']}/{stats['total']})")

        return route_results

    def _predict_route(self, s: TrainingSample) -> str:
        """模拟当前路由规则"""
        if s.event_type in ("C2_BEACON", "DATA_EXFIL", "MALWARE_DETECT",
                            "LATERAL_MOVE", "RANSOMWARE"):
            return "none"
        mapping = {"critical": "none", "high": "light", "medium": "light",
                   "low": "deep", "info": "deep"}
        return mapping.get(s.severity, "light")

    # ── 3. 参数优化 ──

    def optimize(self) -> dict:
        """
        数据驱动参数优化

        优化目标:
        (1) route_event() 的severity→route映射
        (2) importance_score() 的权重公式
        (3) budget_ratios 的层级分配
        (4) CONSOLIDATE_EVERY 触发频率
        """
        logger.info("\n" + "=" * 60)
        logger.info("PARAMETER OPTIMIZATION")
        logger.info("=" * 60)

        # 3.1 优化路由映射
        logger.info("\n[1/4] Optimizing Route Mapping...")
        route_map = self._optimize_route_mapping()
        self.optimized["route_mapping"] = route_map
        logger.info(f"  Optimized route mapping: ")
        for sev, route in sorted(route_map.items()):
            logger.info(f"    {sev:10s} → {route}")

        # 3.2 优化重要性权重
        logger.info("\n[2/4] Optimizing Importance Weights...")
        weights = self._optimize_importance_weights()
        self.optimized["importance_weights"] = weights
        logger.info(f"  severity_weight: {weights['severity_weight']:.3f}")
        logger.info(f"  confidence_weight: {weights['confidence_weight']:.3f}")
        logger.info(f"  severity_map: {weights['severity_map']}")

        # 3.3 优化Token预算比例
        logger.info("\n[3/4] Optimizing Token Budget Ratios...")
        budgets = self._optimize_budget_ratios()
        self.optimized["budget_ratios"] = budgets
        logger.info(f"  DOCUMENT: {budgets['DOC']:.2f}")
        logger.info(f"  CHUNK:    {budgets['CHUNK']:.2f}")
        logger.info(f"  TOKEN:    {budgets['TOKEN']:.2f}")

        # 3.4 优化合并触发
        logger.info("\n[4/4] Optimizing Consolidation...")
        consolidate = self._optimize_consolidation()
        self.optimized["consolidate_every"] = consolidate
        logger.info(f"  CONSOLIDATE_EVERY: {consolidate}")

        # 3.5 优化Softmax温度
        temp = self._optimize_softmax_temp()
        self.optimized["softmax_temperature"] = temp
        logger.info(f"\n  Softmax Temperature: {temp:.2f}")

        return self.optimized

    def _optimize_route_mapping(self) -> dict:
        """基于数据学习severity→route的最优映射"""
        accuracy_by_mapping = {}

        # 候选映射方案
        candidates = [
            # (name, severity→route mapping)
            ("conservative", {
                "critical": "none", "high": "none", "medium": "light",
                "low": "deep", "info": "deep",
            }),
            ("aggressive", {
                "critical": "none", "high": "light", "medium": "deep",
                "low": "deep", "info": "deep",
            }),
            ("balanced", {
                "critical": "none", "high": "light", "medium": "light",
                "low": "deep", "info": "deep",
            }),
            ("critical_only", {
                "critical": "none", "high": "light", "medium": "deep",
                "low": "deep", "info": "deep",
            }),
        ]

        best_acc = 0
        best_mapping = candidates[0][1]

        for name, mapping in candidates:
            correct = 0
            total = 0
            for s in self.samples:
                predicted = mapping.get(s.severity, "light")
                # 对特定事件类型覆盖
                if s.event_type in ("C2_BEACON", "DATA_EXFIL", "MALWARE_DETECT"):
                    predicted = "none"
                if predicted == s.true_route:
                    correct += 1
                total += 1
            acc = correct / total if total else 0
            accuracy_by_mapping[name] = acc
            logger.info(f"    {name:16s} accuracy={acc*100:.1f}%")
            if acc > best_acc:
                best_acc = acc
                best_mapping = mapping

        logger.info(f"    Best: {list(accuracy_by_mapping.keys())[list(accuracy_by_mapping.values()).index(best_acc)]} "
                    f"({best_acc*100:.1f}%)")
        return best_mapping

    def _optimize_importance_weights(self) -> dict:
        """学习severity和confidence对重要性的最优权重"""
        from sklearn.linear_model import LinearRegression
        import numpy as np

        # 准备特征: severity_score, confidence_normalized
        X = []
        y = []
        for s in self.samples:
            sev_score = SEVERITY_SCORE.get(s.severity, 0.3)
            conf_norm = s.confidence / 100.0
            X.append([sev_score, conf_norm, sev_score * conf_norm])
            y.append(s.true_importance)

        try:
            X_np = np.array(X)
            y_np = np.array(y)
            model = LinearRegression(fit_intercept=True)
            model.fit(X_np, y_np)
            w1, w2, w3 = model.coef_
            intercept = model.intercept_

            # 归一化权重
            total = abs(w1) + abs(w2) + abs(w3) + abs(intercept) * 0.1
            return {
                "severity_weight": abs(w1) / total * 2,
                "confidence_weight": abs(w2) / total * 2,
                "interaction_weight": abs(w3) / total * 2,
                "intercept": float(intercept),
                "r2_score": float(model.score(X_np, y_np)),
                "severity_map": SEVERITY_SCORE,
            }
        except ImportError:
            # 无sklearn时的启发式优化
            logger.info("  sklearn not available, using heuristic optimization")
            return {
                "severity_weight": 0.65,
                "confidence_weight": 0.25,
                "interaction_weight": 0.10,
                "intercept": 0.0,
                "r2_score": 0.0,
                "severity_map": SEVERITY_SCORE,
            }

    def _optimize_budget_ratios(self) -> dict:
        """基于重要性分布的注意力预算优化"""
        # 统计真实重要性分布
        all_imps = [s.true_importance for s in self.samples]
        if not all_imps:
            return {"DOC": 0.20, "CHUNK": 0.45, "TOKEN": 0.35}

        # 高重要性(>0.7)的比例决定了TOKEN级预算
        high_ratio = sum(1 for i in all_imps if i > 0.7) / len(all_imps)
        mid_ratio = sum(1 for i in all_imps if 0.3 <= i <= 0.7) / len(all_imps)
        low_ratio = sum(1 for i in all_imps if i < 0.3) / len(all_imps)

        # 自适应预算分配
        token_budget = 0.25 + high_ratio * 0.25  # 高重要性多→更多token预算
        doc_budget = 0.15 + low_ratio * 0.10     # 低重要性多→更多document预算
        chunk_budget = 1.0 - token_budget - doc_budget

        return {
            "DOC": round(doc_budget, 3),
            "CHUNK": round(chunk_budget, 3),
            "TOKEN": round(token_budget, 3),
        }

    def _optimize_consolidation(self) -> int:
        """基于事件到达频率优化合并触发阈值"""
        # 计算每天各类事件的数量
        high_freq = sum(1 for s in self.samples
                        if s.true_importance > 0.7)
        total = len(self.samples)
        high_ratio = high_freq / total if total else 0

        # 高重要性事件多 → 减少合并频率（保留更多细节）
        if high_ratio > 0.4:
            return 15
        elif high_ratio > 0.25:
            return 10
        else:
            return 8

    def _optimize_softmax_temp(self) -> float:
        """优化Softmax温度（控制注意力聚焦程度）"""
        all_imps = [s.true_importance for s in self.samples]
        if not all_imps:
            return 3.0

        # 重要性分布的标准差决定温度
        import statistics
        try:
            std_dev = statistics.stdev(all_imps)
        except Exception:
            std_dev = 0.3

        # 标准差大 → 分布分散 → 降低温度（更聚焦）
        # 标准差小 → 分布集中 → 升高温度（更平滑）
        temp = 5.0 * (1.0 - min(std_dev, 0.5))
        return round(max(1.5, min(temp, 5.0)), 1)

    # ── 4. 导出优化配置 ──

    def export_optimized_config(self, filepath: str = "optimized_params.py"):
        """导出优化后的参数为Python配置模块"""
        params = self.optimized

        content = '''"""
层级化Transformer注意力优化参数
自动生成于 {timestamp}
训练样本数: {count}
"""
import math


# ── 路由映射（数据驱动优化） ──
ROUTE_MAPPING = {route_map}

# ── 额外事件类型覆盖 ──
EVENT_ROUTE_OVERRIDE = {{
    "C2_BEACON": "none",
    "DATA_EXFIL": "none",
    "MALWARE_DETECT": "none",
    "LATERAL_MOVE": "none",
    "RANSOMWARE": "none",
}}


def optimized_route_event(event: dict) -> str:
    """数据优化后的路由决策"""
    severity = event.get("severity", "info")
    event_type = event.get("event", "")
    # 事件类型覆盖
    override = EVENT_ROUTE_OVERRIDE.get(event_type)
    if override:
        return override
    # 严重度映射
    return ROUTE_MAPPING.get(severity, "light")


def optimized_importance_score(event: dict) -> float:
    """数据优化后的重要性评分"""
    severity = event.get("severity", "info")
    confidence = event.get("confidence", 50)

    severity_map = {sev_map}
    sev_score = severity_map.get(severity, 0.3)
    conf_norm = confidence / 100.0

    w_sev = {w_sev}
    w_conf = {w_conf}
    w_interact = {w_interact}

    score = (w_sev * sev_score + w_conf * conf_norm +
             w_interact * sev_score * conf_norm)
    return min(1.0, max(0.0, score))


# ── Token预算比例（基于重要性分布） ──
BUDGET_RATIOS = {{
    "DOC":  {budget_doc},
    "CHUNK": {budget_chunk},
    "TOKEN": {budget_token},
}}


# ── 记忆树合并触发 ──
CONSOLIDATE_EVERY = {consolidate}


# ── Softmax注意力温度 ──
ATTENTION_TEMPERATURE = {temperature}
'''.format(
            timestamp=datetime.now().isoformat(),
            count=len(self.samples),
            route_map=json.dumps(params.get("route_mapping", {}), indent=4),
            sev_map=json.dumps(SEVERITY_SCORE, indent=4),
            w_sev=params.get("importance_weights", {}).get("severity_weight", 0.65),
            w_conf=params.get("importance_weights", {}).get("confidence_weight", 0.25),
            w_interact=params.get("importance_weights", {}).get("interaction_weight", 0.10),
            budget_doc=params.get("budget_ratios", {}).get("DOC", 0.20),
            budget_chunk=params.get("budget_ratios", {}).get("CHUNK", 0.45),
            budget_token=params.get("budget_ratios", {}).get("TOKEN", 0.35),
            consolidate=params.get("consolidate_every", 10),
            temperature=params.get("softmax_temperature", 3.0),
        )

        import os
        full_path = os.path.join(os.path.dirname(__file__), filepath)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(content)
        logger.info(f"\nOptimized config exported to: {full_path}")
        return full_path

    # ── 完整训练流水线 ──

    def train(self, count: int = 5000, export: bool = True):
        """完整训练流水线"""
        logger.info("\n" + "█" * 60)
        logger.info(" HIERARCHICAL ATTENTION TRAINING PIPELINE")
        logger.info("█" * 60)

        # Step 1: 数据生成
        logger.info("\n▸ Step 1/4: Generating training data...")
        self.generate_training_data(count)

        # Step 2: 统计分析
        logger.info("\n▸ Step 2/4: Analyzing data...")
        self.analyze()

        # Step 3: 参数优化
        logger.info("\n▸ Step 3/4: Optimizing parameters...")
        self.optimize()

        # Step 4: 导出配置
        logger.info("\n▸ Step 4/4: Exporting optimized config...")
        if export:
            path = self.export_optimized_config()
            logger.info(f"  → {path}")

        logger.info("\n" + "█" * 60)
        logger.info(" TRAINING COMPLETE")
        logger.info("█" * 60)
        return self.optimized


# ── 命令行入口 ──

if __name__ == "__main__":
    trainer = HierarchicalAttentionTrainer()

    import argparse
    parser = argparse.ArgumentParser(description="Train hierarchical attention parameters")
    parser.add_argument("--count", type=int, default=5000,
                        help="Number of training samples (default: 5000)")
    parser.add_argument("--no-export", action="store_true",
                        help="Skip config export")
    args = parser.parse_args()

    optimized = trainer.train(count=args.count, export=not args.no_export)

    print("\nOptimized Parameters Summary:")
    print(json.dumps(optimized, indent=2, ensure_ascii=False))
