"""多智能体红蓝自博弈 (Red vs Blue Self-Play)。

红队 Agent 在隔离仿真里生成对抗场景,蓝队复用 Decomposer→Executor→Reviewer
+ Sigma/overlay 实时响应,漏报样本反哺检测规则。
"""
from self_play.red_agent import RedAgent
from self_play.orchestrator import orchestrator, live_match, live_matches, request_stop
from self_play.sim_env import topology
from self_play.catalog import (
    catalog_summary, catalog_overview, enterprise_pool, MAX_CURRICULUM_LEVEL,
)
from self_play.types import MatchConfig, RoundGoal, CapabilityState

__all__ = [
    "RedAgent", "orchestrator", "live_match", "live_matches", "request_stop",
    "topology", "catalog_summary", "catalog_overview", "enterprise_pool",
    "MAX_CURRICULUM_LEVEL", "MatchConfig", "RoundGoal", "CapabilityState",
]
