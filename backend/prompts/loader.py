"""
prompts.loader — Jinja2 LLM 提示词统一加载/渲染器
================================================

把散落在各业务文件里的 LLM 提示词集中到 backend/prompts/**/*.j2 模板,
统一由本模块加载并渲染。好处:
  - 提示词集中管理 / 可 Diff / 可版本化 / 可被存储到 DB 或审计
  - 变量用 Jinja2 语法 {{ var }}, 调用点不再手拼 f-string

用法::

    from prompts import render
    sys = render("audit/executor_synthesize", evidence=..., grounded=...)
    user = prompt                      # 非模板的动态副文本仍留业务侧

设计:
  - FileSystemLoader 指向 backend/prompts/
  - 模板懒加载并缓存; 渲染默认 __missing__ 不抛错(ChainableUndefined),
    便于渐进迁移; 上线稳定后可切 strict(见 strict_render)。
"""
import logging
import os

from jinja2 import ChainableUndefined, Environment, FileSystemLoader, StrictUndefined, TemplateNotFound

logger = logging.getLogger(__name__)

PROMPTS_DIR = os.path.dirname(os.path.abspath(__file__))

_env = Environment(
    loader=FileSystemLoader(PROMPTS_DIR),
    autoescape=False,          # LLM 提示词不需要 HTML 转义
    trim_blocks=True,
    lstrip_blocks=True,        # 去掉控制块行的缩进, 保证模板正文干净
    undefined=ChainableUndefined,
)
_cache: dict[str, "Template"] = {}

# 模板相对路径 → 变量说明 的注册表(供文档/审计/校验)
REGISTRY: dict[str, dict] = {}


def load(name: str):
    """按相对路径(不含 .j2, 如 'audit/executor_synthesize')加载模板(带缓存)。"""
    tpl = _cache.get(name)
    if tpl is None:
        try:
            tpl = _env.get_template(f"{name}.j2")
        except TemplateNotFound as e:
            raise FileNotFoundError(f"prompt template not found: {name}") from e
        _cache[name] = tpl
    return tpl


def render(name: str, **ctx) -> str:
    """渲染模板。缺省变量以空替代(ChainableUndefined), 利于渐进迁移。"""
    return load(name).render(**ctx)


def strict_render(name: str, **ctx) -> str:
    """严格渲染: 任何未提供变量直接抛错, 用于模板完善后的校验/测试。"""
    tpl = _cache.get(name)
    if tpl is None:
        tpl = _env.get_template(f"{name}.j2")
        _cache[name] = tpl
    # 用 loader.get_source 获取模板源码(兼容 Jinja2 Template 无 .source 属性)
    try:
        source, _filename, _uptodate = _env.loader.get_source(_env, f"{name}.j2")
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"prompt template source not readable: {name}") from e
    env2 = Environment(
        loader=FileSystemLoader(PROMPTS_DIR),
        autoescape=False, trim_blocks=True, lstrip_blocks=True,
        undefined=StrictUndefined,
    )
    return env2.from_string(source).render(**ctx)


def register(name: str, note: str = ""):
    """声明/登记一个模板的用途。"""
    REGISTRY[name] = {"path": f"{name}.j2", "note": note}
    return name


def reload():
    """清缓存, 便于开发期热更。"""
    _cache.clear()
