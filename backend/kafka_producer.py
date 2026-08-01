"""
Kafka 生产者 — 将审计结果回写到 Kafka 消息总线

后端 Audit-LLM 完成审计后，将结果发布到 security-audit-results topic，
供下游消费者（前端 SSE、响应引擎、归档系统）使用。
"""
import json
import logging
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)

try:
    from aiokafka import AIOKafkaProducer
    HAS_KAFKA = True
except ImportError:
    HAS_KAFKA = False
    logger.warning("aiokafka not installed — Kafka producer disabled")


class KafkaProducerWrapper:
    """异步 Kafka 生产者封装"""

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

    async def publish_audit_result(self, event_id: int, result: dict):
        """发布审计结果到 Kafka"""
        if not self._started:
            return
        try:
            await self._producer.send(
                settings.kafka_topic_audit_results,
                key=str(event_id),
                value={
                    "event_id": event_id,
                    **result,
                },
            )
        except Exception as e:
            logger.warning(f"Kafka publish audit result failed: {e}")

    async def publish_alert(self, alert: dict):
        """发布告警到 Kafka"""
        if not self._started:
            return
        try:
            await self._producer.send(
                settings.kafka_topic_alerts,
                key=alert.get("src_ip", ""),
                value=alert,
            )
        except Exception as e:
            logger.warning(f"Kafka publish alert failed: {e}")

    @property
    def is_active(self) -> bool:
        return self._started


kafka_producer = KafkaProducerWrapper()
