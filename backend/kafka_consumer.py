"""
Kafka 消费者 — 从 Flink 处理后的 topic 消费事件

替代原来的 HTTP 直连接入模式：
  - 消费 security-audit-queue → 送入 Audit-LLM 流水线
  - 消费 security-alerts → 触发响应引擎
  - 消费 security-events-enriched → 全量存储 + 记忆树索引

数据流:
  Kafka(security-audit-queue) → LogIngestor.ingest() → Audit-LLM
  Kafka(security-alerts)      → ResponseOrchestrator.on_threat_detected()
  Kafka(security-events-enriched) → EventStore.store() + MemoryTree
"""
import asyncio
import json
import logging
import time
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)

try:
    from aiokafka import AIOKafkaConsumer
    HAS_KAFKA = True
except ImportError:
    HAS_KAFKA = False
    logger.warning("aiokafka not installed — Kafka consumer disabled")


class KafkaConsumerManager:
    """
    Kafka 消费者管理器

    启动多个后台消费任务，分别消费不同 topic。
    所有消费到的事件最终汇入现有的 LogIngestor / ResponseOrchestrator。
    """

    def __init__(self):
        self._tasks: list[asyncio.Task] = []
        self._running = False
        self._stats = {
            "enriched_consumed": 0,
            "audit_consumed": 0,
            "alerts_consumed": 0,
            "errors": 0,
            "last_message_at": 0,
        }

    async def start(self):
        """启动所有消费者"""
        if not HAS_KAFKA or not settings.kafka_enabled:
            logger.info("Kafka consumer: disabled (kafka_enabled=False or aiokafka missing)")
            return

        self._running = True
        self._tasks = [
            asyncio.create_task(self._consume_enriched()),
            asyncio.create_task(self._consume_audit_queue()),
            asyncio.create_task(self._consume_alerts()),
        ]
        logger.info(
            f"Kafka consumer started: {settings.kafka_bootstrap}, "
            f"topics=[{settings.kafka_topic_enriched}, "
            f"{settings.kafka_topic_audit_queue}, "
            f"{settings.kafka_topic_alerts}]"
        )

    async def stop(self):
        """停止所有消费者"""
        self._running = False
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        logger.info("Kafka consumer stopped")

    async def _consume_enriched(self):
        """
        消费 security-events-enriched → 全量存储 + 记忆树索引

        这些事件已经过 Flink 验证和异常检测，带有 _anomalyScore。
        只做存储和索引，不再重复异常检测。
        """
        consumer = AIOKafkaConsumer(
            settings.kafka_topic_enriched,
            bootstrap_servers=settings.kafka_bootstrap,
            group_id=f"{settings.kafka_consumer_group}-enriched",
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            auto_offset_reset="earliest",
            enable_auto_commit=True,
        )
        try:
            await consumer.start()
            logger.info(f"Consuming {settings.kafka_topic_enriched}...")
            async for msg in consumer:
                if not self._running:
                    break
                try:
                    await self._handle_enriched(msg.value)
                    self._stats["enriched_consumed"] += 1
                    self._stats["last_message_at"] = time.time()
                except Exception as e:
                    self._stats["errors"] += 1
                    logger.error(f"Error processing enriched event: {e}")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Enriched consumer crashed: {e}")
        finally:
            await consumer.stop()

    async def _handle_enriched(self, event: dict):
        """处理 Flink 富化后的事件：存储 + 索引"""
        from models import async_session as db_session
        from event_store import event_store
        from memory_tree import memory_tree

        session_id = event.get("sourceId", event.get("session_id", "kafka-" + str(event.get("eventId", ""))))
        anomaly_score = event.get("_anomalyScore", event.get("anomalyScore", 0.0))

        # 归一化为内部格式
        log_data = {
            "event": event.get("eventType", event.get("event", "UNKNOWN")),
            "severity": event.get("severity", "info"),
            "src_ip": event.get("srcIp", event.get("src_ip", "")),
            "dst_ip": event.get("dstIp", event.get("dst_ip", "")),
            "protocol": event.get("protocol", ""),
            "message": event.get("message", ""),
            "confidence": event.get("confidence", 50),
            "_anomaly": {
                "score": anomaly_score,
                "is_anomaly": anomaly_score >= 0.6,
                "reasons": event.get("_anomalyReasons", []),
                "sigma": 0,
            },
            "_flink_processed": True,
            "_source_id": event.get("sourceId", ""),
        }

        async with db_session() as session:
            # 全量存储
            stored = await event_store.store(
                session, log_data, session_id,
                anomaly_score=anomaly_score,
            )
            # 记忆树索引
            event_text = json.dumps(log_data, ensure_ascii=False)
            await memory_tree.add_leaf(
                session, session_id, log_data, event_text,
                correlation_group="anomaly" if anomaly_score >= 0.6 else "",
            )

        # 发布到内部事件总线（SSE 推送）
        from event_bus import event_bus
        event_bus.publish("security_event", {
            "event_id": stored.id,
            "event_type": log_data["event"],
            "severity": log_data["severity"],
            "src_ip": log_data["src_ip"],
            "anomaly_score": anomaly_score,
            "source": "kafka-flink",
        })

    async def _consume_audit_queue(self):
        """
        消费 security-audit-queue → Audit-LLM 流水线

        Flink 将 anomalyScore >= 0.3 的事件路由到此 topic，
        表示需要 LLM 深度审计。
        """
        consumer = AIOKafkaConsumer(
            settings.kafka_topic_audit_queue,
            bootstrap_servers=settings.kafka_bootstrap,
            group_id=f"{settings.kafka_consumer_group}-audit",
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            auto_offset_reset="earliest",
            enable_auto_commit=True,
        )
        try:
            await consumer.start()
            logger.info(f"Consuming {settings.kafka_topic_audit_queue}...")
            async for msg in consumer:
                if not self._running:
                    break
                try:
                    await self._handle_audit(msg.value)
                    self._stats["audit_consumed"] += 1
                    self._stats["last_message_at"] = time.time()
                except Exception as e:
                    self._stats["errors"] += 1
                    logger.error(f"Error processing audit event: {e}")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Audit consumer crashed: {e}")
        finally:
            await consumer.stop()

    async def _handle_audit(self, event: dict):
        """将事件送入 Audit-LLM 流水线"""
        from log_ingestion import log_ingestor
        from models import async_session as db_session
        from anomaly_detector import AnomalyReport

        session_id = event.get("sourceId", event.get("session_id", "kafka-audit"))
        anomaly_score = event.get("_anomalyScore", event.get("anomalyScore", 0.3))

        log_data = {
            "event": event.get("eventType", event.get("event", "UNKNOWN")),
            "severity": event.get("severity", "info"),
            "src_ip": event.get("srcIp", event.get("src_ip", "")),
            "dst_ip": event.get("dstIp", event.get("dst_ip", "")),
            "protocol": event.get("protocol", ""),
            "message": event.get("message", ""),
            "confidence": event.get("confidence", 50),
            "_anomaly": {
                "score": anomaly_score,
                "is_anomaly": anomaly_score >= 0.6,
                "reasons": event.get("_anomalyReasons", []),
                "sigma": 0,
            },
            "_flink_processed": True,
        }

        # 构造 AnomalyReport（Flink 已做过异常检测，此处传递结果）
        report = AnomalyReport(
            event_id=0,
            anomaly_score=anomaly_score,
            is_anomaly=anomaly_score >= 0.6,
            deviation_sigma=anomaly_score * 5,
            reasons=event.get("_anomalyReasons", []),
        )

        async with db_session() as session:
            from event_store import event_store
            stored = await event_store.store(
                session, log_data, session_id,
                anomaly_score=anomaly_score,
            )

        # 异步触发 Audit-LLM（不阻塞消费）
        asyncio.create_task(
            log_ingestor._audit_pipeline(session_id, stored.id, log_data, report)
        )

        logger.info(
            f"[Kafka-Audit] Queued event #{stored.id} for Audit-LLM: "
            f"{log_data['event']} score={anomaly_score:.2f}"
        )

    async def _consume_alerts(self):
        """
        消费 security-alerts → 触发响应引擎

        Flink CEP 检测到攻击链或高异常事件时产生告警。
        """
        consumer = AIOKafkaConsumer(
            settings.kafka_topic_alerts,
            bootstrap_servers=settings.kafka_bootstrap,
            group_id=f"{settings.kafka_consumer_group}-alerts",
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            auto_offset_reset="earliest",
            enable_auto_commit=True,
        )
        try:
            await consumer.start()
            logger.info(f"Consuming {settings.kafka_topic_alerts}...")
            async for msg in consumer:
                if not self._running:
                    break
                try:
                    await self._handle_alert(msg.value)
                    self._stats["alerts_consumed"] += 1
                    self._stats["last_message_at"] = time.time()
                except Exception as e:
                    self._stats["errors"] += 1
                    logger.error(f"Error processing alert: {e}")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Alert consumer crashed: {e}")
        finally:
            await consumer.stop()

    async def _handle_alert(self, alert: dict):
        """处理 Flink 产生的告警 → 响应引擎"""
        from models import async_session as db_session
        from response_engine import get_orchestrator
        from event_bus import event_bus

        alert_type = alert.get("alertType", "ANOMALY")
        severity = alert.get("severity", "high")
        src_ip = alert.get("srcIp", alert.get("src_ip", ""))

        logger.warning(
            f"[Kafka-Alert] {alert_type}: {alert.get('eventType', '')} "
            f"from {src_ip} score={alert.get('anomalyScore', 0):.2f}"
        )

        # 发布到 SSE 事件总线
        event_bus.publish("alert", {
            "alert_type": alert_type,
            "event_type": alert.get("eventType", ""),
            "severity": severity,
            "src_ip": src_ip,
            "anomaly_score": alert.get("anomalyScore", 0),
            "reasons": alert.get("reasons", []),
            "source": "flink-cep",
        })

        # 高置信度告警直接触发响应引擎
        anomaly_score = alert.get("anomalyScore", 0)
        if anomaly_score >= 0.5 or severity in ("critical", "high"):
            try:
                resp_orch = get_orchestrator()
                threat_info = {
                    "threat_type": alert.get("eventType", "UNKNOWN"),
                    "confidence": min(1.0, anomaly_score * 1.2),
                    "severity": severity,
                    "src_ip": src_ip,
                    "dst_ip": alert.get("dstIp", alert.get("dst_ip", "")),
                    "message": alert.get("message", f"Flink {alert_type} alert"),
                    "session_id": "flink-alert",
                    "event_id": 0,
                    "policy_name": f"flink_{alert_type.lower()}",
                }
                async with db_session() as session:
                    await resp_orch.on_threat_detected(
                        session=session,
                        threat_info=threat_info,
                        event_id=None,
                        session_id="flink-alert",
                    )
            except Exception as e:
                logger.warning(f"[Kafka-Alert] Response trigger failed: {e}")

    def stats(self) -> dict:
        return {**self._stats, "running": self._running}


kafka_consumer_manager = KafkaConsumerManager()
