"""LLM 提示词集中管理(backend/prompts/**/*.j2, Jinja2)。

统一入口::

    from prompts import render
    system = render("audit/executor_synthesize", evidence=evidence, grounded=True)

模板按域组织: audit(4 层 Agent 审计) / analysis(摘要/研判) /
rag(检索实证) / security(AI 安全检测) / tooling(工具链)。
"""
from prompts.loader import PROMPTS_DIR, load, register, reload, render, strict_render

__all__ = ["PROMPTS_DIR", "load", "register", "reload", "render", "strict_render"]
