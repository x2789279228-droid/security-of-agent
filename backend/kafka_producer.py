"""
Kafka 生产者 — 将审计结果回写到 Kafka 消息总线

后端 Audit-LLM 完成审计后，将结果发布到 security-audit-results topic，
供下游消费者（前端 SSE、响应引擎、归档系统）使用。

增强:
  - 所有消息携带 trace_id header，支持全链路追踪
  - 敏感字段加密（apiKey 等）在发送前自动处理
"""
import json
import logging
import uuid
from typing import Optional

from config import settings
from field_cipher import field_cipher

logger = logging.getLogger(__name__)

try:
    from aiokafka import AIOKafkaProducer
    HAS_KAFKA = True
except ImportError:
    HAS_KAFKA = False
    logger.warning("aiokafka not installed — Kafka producer disabled")


class KafkaProducerWrapper:
    """异步 Kafka 生产者封装（带 trace_id 传播）"""

    def __init__(self):
        self._producer: Optional[object] = None
        self._started = False

    async def start(self):
        if not HAS_KAFKA or not settings.kafka_enabled:
            logger.info("Kafka producer: disabled (kafka_enabled=False or aiokafka missing)")
            return
        try:
            self._producer = AIOKafkaProducer(
                bootstrap_servers=settings.kafka_bootstrap,
                value_serializer=lambda v: json.dumps(v, ensure_ascii=False).encode("utf-8"),
                key_serializer=lambda k: k.encode("utf-8") if k else None,
                acks="all",
                retries=3,
            )
            await self._producer.start()
            self._started = True
            logger.info(f"Kafka producer started: {settings.kafka_bootstrap}")
        except Exception as e:
            logger.error(f"Kafka producer failed to start: {e}")
            self._started = False

    async def stop(self):
        if self._producer and self._started:
            await self._producer.stop()
            self._started = False
            logger.info("Kafka producer stopped")

    @staticmethod
    def _trace_headers(trace_id: str = "") -> list:
        """构造 Kafka message headers（trace_id 传播）"""
        tid = trace_id or uuid.uuid4().hex
        return [("trace_id", tid.encode("utf-8"))]

    async def publish_audit_result(self, event_id: int, result: dict, trace_id: str = ""):
        """发布审计结果到 Kafka"""
        if not self._started:
            return
        try:
            encrypted = field_cipher.encrypt_message(result)
            await self._producer.send(
                settings.kafka_topic_audit_results,
                key=str(event_id),
                value={
                    "event_id": event_id,
                    **encrypted,
                },
                headers=self._trace_headers(trace_id),
            )
        except Exception as e:
            logger.warning(f"Kafka publish audit result failed: {e}")

    async def publish_alert(self, alert: dict, trace_id: str = ""):
        """发布告警到 Kafka"""
        if not self._started:
            return
        try:
            encrypted = field_cipher.encrypt_message(alert)
            await self._producer.send(
                settings.kafka_topic_alerts,
                key=alert.get("src_ip", ""),
                value=encrypted,
                headers=self._trace_headers(trace_id),
            )
        except Exception as e:
            logger.warning(f"Kafka publish alert failed: {e}")

    @property
    def is_active(self) -> bool:
        return self._started


kafka_producer = KafkaProducerWrapper()
