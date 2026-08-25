"""
sigma — 真 Sigma 检测引擎包（pySigma 后端）

规则源: backend/sigma/rules/*.yml（标准 Sigma 1.x YAML）
引擎:   PySigmaDetector（pySigma + SQLite backend 编译谓词 + 内存单行表求值）
降级:   pySigma 不可用/未启用时回退原 sigma_detector（纯 dict 匹配）
"""
import logging
import os

logger = logging.getLogger(__name__)

_DEFAULT_RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")

# 按配置返回默认引擎的分发函数（在 sigma_detector 单例处调用，避免改动 log_ingestion 引用点）
def build_pysigma_detector(enforce: bool = False):
    from .engine import PySigmaDetector
    return PySigmaDetector(_DEFAULT_RULES_DIR, enforce=enforce)
