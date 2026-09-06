"""
Kafka 生产者 — 将审计结果回写到 Kafka 消息总线

后端 Audit-LLM 完成审计后，将结果发布到 security-audit-results topic，
供下游消费者（前端 SSE、响应引擎、归档系统）使用。

增强:
  - 所有消息携带 trace_id header，支持全链路追踪
  - 敏感字段加密（apiKey 等）在发送前自动处理
"""
import asyncio
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

    async def publish_sigma_hit(self, hit: dict, trace_id: str = ""):
        """发布 Sigma 聚合候选到 sigma-hit topic(供 Flink 阈值窗口聚合)。
        明文 JSON(聚合信号, 无敏感字段: src_ip/rule_id/threshold/timestamp)。"""
        if not self._started:
            return
        try:
            import json
            payload = {
                "src_ip": hit.get("src_ip", ""),
                "rule_id": hit.get("rule_id", ""),
                "threshold": int(hit.get("threshold", 0) or 0),
                "timestamp": int(hit.get("timestamp", 0) or 0),
            }
            await self._producer.send_and_wait(
                settings.kafka_topic_sigma_hit,
                key=payload["src_ip"],
                value=json.dumps(payload),
                headers=self._trace_headers(trace_id),
            )
        except Exception as e:
            logger.warning(f"Kafka publish_sigma_hit failed: {e}")

    # ── Kafka 解耦: Http 网关 → raw 入口直发 ──
    # 网关按 Flink raw 契约(camelCase avsc)归一化事件后投递到 security-logs-raw,
    # 由 Flink LogValidation → AnomalyDetection 转 validated/audit-queue/enriched/alerts。
    # 采用"批量 send + 一次性 await delivery"保证吞吐与 acks=all 持久化, 同时不阻塞上游。

    async def _deliver_batch(self, futures: list, label: str) -> int:
        """统一等待一批 send future 落盘(DeliveryGuarantee), 返回成功条数; 失败条记日志。

        P1: asyncio.gather(*futures, return_exceptions=True) 并发等待 ——
        禁止 for+await 串行。异常条目计入失败并打日志, 成功条目计数返回。
        """
        if not futures:
            return 0
        results = await asyncio.gather(*futures, return_exceptions=True)
        ok = 0
        for r in results:
            if isinstance(r, Exception):
                logger.warning(f"Kafka {label} message delivery failed: {r}")
            else:
                ok += 1
        return ok

    async def produce_raw_batch(
        self,
        events: list[dict],
        topic: str = "",
        key_field: str = "sourceId",
        trace_id: str = "",
    ) -> int:
        """批量写入 raw topic(网关用)。
        events: 已按 Flink raw 契约归一化的 camelCase dict。
        topic 缺省 = settings.kafka_topic_raw。
        返回成功投递条数; producer 未启动则返回 0(不应发生: 网关仅在 started 时调用)。
        """
        if not self._started or not events:
            return 0
        dst = topic or settings.kafka_topic_raw
        futures = []
        for ev in events:
            try:
                futures.append(self._producer.send(
                    dst,
                    key=str(ev.get(key_field) or ev.get("eventId") or ""),
                    value=ev,
                    headers=self._trace_headers(trace_id),
                ))
            except Exception as e:
                logger.warning(f"Kafka produce_raw send enqueue failed: {e}")
        return await self._deliver_batch(futures, dst)

    async def produce_raw(
        self,
        event: dict,
        topic: str = "",
        key_field: str = "sourceId",
        trace_id: str = "",
    ) -> bool:
        """包装单条 produce_raw_batch。"""
        n = await self.produce_raw_batch([event], topic=topic,
                                         key_field=key_field, trace_id=trace_id)
        return n == 1

    @property
    def is_active(self) -> bool:
        return self._started


kafka_producer = KafkaProducerWrapper()
