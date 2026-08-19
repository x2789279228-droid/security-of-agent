"""
schema_registry.py — 跨运行时 Schema 契约 (Flink ↔ Python)

目的 (架构: Flink 唯一流处理事实源):
  Flink 与 Python 是两套运行时, 历史上靠"字段名直觉"对齐, 导致漂移
  (例如 _anomalyScore 嵌套 vs 顶层的兼容逻辑)。本模块把契约收敛为两份
  JSON Schema (与 flink-jobs/schemas/*.avsc 保持一致):

  1. 消费侧校验: kafka_consumer 在进入业务处理前按 topic 校验,
     不合规事件直接走 DLQ (故障可见), 不再静默吞掉。
  2. 注册到 Confluent Schema Registry (subject: <topic>-value,
     schemaType=JSON), 让 schema 成为集群级唯一事实源。
  3. 可选: 生产侧 (kafka_producer) 发送前校验, 从源头拦截。

本模块为纯标准库 + jsonschema, 不引入 confluent-kafka 重依赖。
"""
import json
import logging
from pathlib import Path
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)

_SCHEMAS_DIR = Path(__file__).parent / "schemas"

# topic 前缀 → schema 文件映射 (消费侧按 topic 前缀路由)
TOPIC_SCHEMA_MAP = {
    "security-events-enriched": "security_event.schema.json",
    "security-audit-queue": "security_event.schema.json",
    "security-alerts": "alert_event.schema.json",
}

try:
    from jsonschema import Draft7Validator
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False
    logger.warning("jsonschema not installed — Kafka schema validation disabled")


class SchemaRegistryClient:
    """轻量 Schema Registry 客户端 (REST API) + 本地 JSON Schema 校验"""

    def __init__(self):
        self._validators: dict[str, Draft7Validator] = {}
        self._schemas: dict[str, dict] = {}
        self._registry_base = None
        if settings.schema_registry_url:
            self._registry_base = settings.schema_registry_url.rstrip("/")
            if not self._registry_base.startswith("http"):
                self._registry_base = "http://" + self._registry_base

    # ── 本地校验 ──

    def _load_schema(self, schema_file: str) -> dict:
        if schema_file not in self._schemas:
            path = _SCHEMAS_DIR / schema_file
            if not path.exists():
                logger.error(f"[Schema] 找不到 schema 文件: {path}")
                return {}
            with open(path, encoding="utf-8") as f:
                self._schemas[schema_file] = json.load(f)
        return self._schemas[schema_file]

    def get_validator(self, topic: str) -> Optional[Draft7Validator]:
        """按 topic 前缀取校验器 (无对应 schema 时返回 None → 跳过校验)"""
        schema_file = None
        for prefix, file in TOPIC_SCHEMA_MAP.items():
            if topic == prefix or topic.startswith(prefix):
                schema_file = file
                break
        if not schema_file or not HAS_JSONSCHEMA:
            return None
        if schema_file not in self._validators:
            schema = self._load_schema(schema_file)
            if not schema:
                return None
            try:
                self._validators[schema_file] = Draft7Validator(schema)
            except Exception as e:
                logger.warning(f"[Schema] 校验器构建失败: {e}")
                return None
        return self._validators[schema_file]

    def validate(self, topic: str, event: dict) -> list[str]:
        """校验事件, 返回错误列表 (空 = 合规)"""
        validator = self.get_validator(topic)
        if validator is None:
            return []
        errors = [f"{list(e.path)}: {e.message}" for e in validator.iter_errors(event)]
        if errors:
            logger.warning(
                f"[Schema] topic={topic} 事件校验失败 ({len(errors)} 项): "
                f"{errors[0]} eventId={event.get('eventId', '?')}"
            )
        return errors

    # ── Schema Registry 注册 (集群级事实源, best-effort) ──

    async def register_all(self) -> None:
        """启动时把 JSON Schema 注册到 Confluent Schema Registry"""
        if not self._registry_base:
            logger.info("[Schema] schema_registry_url 未配置, 跳过注册")
            return
        try:
            import httpx

            async with httpx.AsyncClient(timeout=5) as client:
                for prefix, schema_file in TOPIC_SCHEMA_MAP.items():
                    subject = f"{prefix}-value"
                    schema = self._load_schema(schema_file)
                    if not schema:
                        continue
                    payload = {
                        "schemaType": "JSON",
                        "schema": json.dumps(schema),
                    }
                    # 幂等注册: 已存在则返回兼容性结果
                    url = f"{self._registry_base}/subjects/{subject}/versions"
                    resp = await client.post(url, json=payload)
                    if resp.status_code in (200, 201, 409):
                        logger.info(f"[Schema] 已注册 {subject} (HTTP {resp.status_code})")
                    else:
                        logger.warning(
                            f"[Schema] 注册 {subject} 失败: HTTP {resp.status_code} {resp.text[:200]}"
                        )
        except Exception as e:
            logger.warning(f"[Schema] Schema Registry 注册失败 (不影响消费): {e}")


schema_registry = SchemaRegistryClient()