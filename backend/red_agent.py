"""红队 Agent 入口(提案对接点)。

实现位于 self_play.red_agent。蓝队即现有 Decomposer→Executor→Reviewer 流水线,
由 self_play.orchestrator 驱动对抗循环。
"""
from self_play.red_agent import RedAgent

__all__ = ["RedAgent"]
