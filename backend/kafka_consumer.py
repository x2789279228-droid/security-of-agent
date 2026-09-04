"""
Kafka 消费者 — 从 Flink 处理后的 topic 消费事件

替代原来的 HTTP 直连接入模式：
  - 消费 security-audit-queue → 送入 Audit-LLM 流水线
  - 消费 security-alerts → 触发响应引擎
  - 消费 security-events-enriched → 全量存储 + 记忆树索引

数据流:
  Kafka(security-audit-queue) → LogIngestor.ingest() → Audit-LLM
  Kafka(security-alerts)      → ResponseOrchestrator.on_threat_detected()
  Kafka(security-behavior-alerts) → ResponseOrchestrator (BEHAVIOR_ANOMALY / L4)
  Kafka(security-events-enriched) → EventStore.store() + MemoryTree

可靠性保障:
  ① 手动 Offset 提交 — 处理成功后才 commit，崩溃重启不丢消息
  ② 最终幂等 — PG security_events.event_id 唯一索引兜底 (event_store.store 已实现,
     替换原 Redis 24h 去重; 跨重放同一条事件只落库一次)
  ③ 死信队列 (DLQ) — 连续失败的消息发送到 security-logs-dlq
  ④ 背压控制 — max_poll_records + 审计信号量，防止下游过载
  ⑤ 消费 Lag 监控 — 实时计算各分区 lag，暴露到 /api/kafka/status
  ⑥ trace_id 传播 — 从 Kafka headers 提取 trace_id，贯穿全链路

架构定位 (Flink 唯一流处理事实源):
  本模块是"薄消费者" — 只做 传输/存储/LLM审计/响应编排,
  不再重复实现校验/去重/异常评分 (这些由 Flink 作业负责)。
"""
import asyncio
import json
import logging
import time
from typing import Optional

from config import settings
from field_cipher import field_cipher
from metrics import inc_kafka_consumed
from schema_registry import schema_registry

logger = logging.getLogger(__name__)

try:
    from aiokafka import AIOKafkaConsumer, AIOKafkaProducer, TopicPartition
    HAS_KAFKA = True
except ImportError:
    HAS_KAFKA = False
    logger.warning("aiokafka not installed — Kafka consumer disabled")

# ── 常量 ──
DLQ_TOPIC = "security-logs-dlq"
MAX_RETRY = 3              # 单条消息最大重试次数
AUDIT_SEMAPHORE_LIMIT = 5  # Audit-LLM 并发上限（背压）
MAX_POLL_RECORDS = 50      # 每次 poll 最大消息数


class KafkaConsumerManager:
    """
    Kafka 消费者管理器

    启动多个后台消费任务，分别消费不同 topic。
    所有消费到的事件最终汇入现有的 LogIngestor / ResponseOrchestrator。

    可靠性特性:
    - 手动 offset 提交（处理成功后 commit）
    - 最终幂等（PG event_id 唯一索引, 替代 Redis 去重）
    - 死信队列（连续失败 → security-logs-dlq）
    - 背压控制（max_poll_records + 审计信号量）
    - 消费 lag 实时监控
    """

    def __init__(self):
        self._tasks: list[asyncio.Task] = []
        self._running = False
        self._dlq_producer = None
        self._audit_semaphore = asyncio.Semaphore(AUDIT_SEMAPHORE_LIMIT)
        self._rejection_log: list[dict] = []  # 最近 200 条拒绝记录
        self._rejection_by_type: dict[str, int] = {}  # 按类型聚合
        self._cep_partial: list[dict] = []  # 最近 100 条 CEP 部分匹配
        self._otel_tracer = self._make_tracer()
        self._stats = {
            "enriched_consumed": 0,
            "audit_consumed": 0,
            "alerts_consumed": 0,
            "python_ingest_consumed": 0,
            "behavior_alerts_consumed": 0,
            "rejected_consumed": 0,
            "errors": 0,
            "idempotent_skipped": 0,
            "dlq_sent": 0,
            "last_message_at": 0,
            "lag": {},
        }

    def _make_tracer(self):
        """返回 OTel tracer; OTel 不可用时返回空 tracer (start_as_current_span 空转)"""
        try:
            from opentelemetry import trace as otel_trace
            return otel_trace.get_tracer("soc-backend-kafka", "2.0.0")
        except ImportError:
            class _NullTracer:
                @staticmethod
                def start_as_current_span(name, context=None, attributes=None):
                    from contextlib import nullcontext
                    return nullcontext()
            return _NullTracer()

    async def start(self):
        """启动所有消费者"""
        if not HAS_KAFKA or not settings.kafka_enabled:
            logger.info("Kafka consumer: disabled (kafka_enabled=False or aiokafka missing)")
            return

        # 初始化 DLQ 生产者
        await self._init_dlq_producer()

        self._running = True
        self._tasks = [
            asyncio.create_task(self._consume_enriched()),
            asyncio.create_task(self._consume_audit_queue()),
            asyncio.create_task(self._consume_alerts()),
            asyncio.create_task(self._consume_behavior_alerts()),
            asyncio.create_task(self._consume_rejected()),
            asyncio.create_task(self._consume_cep_partial()),
            asyncio.create_task(self._lag_monitor()),
        ]
        if settings.python_process_ingest_queue and settings.kafka_enabled:
            self._tasks.append(asyncio.create_task(self._consume_python_ingest()))
        logger.info(
            f"Kafka consumer started: {settings.kafka_bootstrap}, "
            f"topics=[{settings.kafka_topic_enriched}, "
            f"{settings.kafka_topic_audit_queue}, "
            f"{settings.kafka_topic_alerts}], "
            f"DLQ={DLQ_TOPIC}, backpressure={AUDIT_SEMAPHORE_LIMIT}"
        )

    async def stop(self):
        """停止所有消费者"""
        self._running = False
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        if self._dlq_producer:
            await self._dlq_producer.stop()
        logger.info("Kafka consumer stopped")

    # ── 初始化 ──

    async def _init_dlq_producer(self):
        """初始化 DLQ 生产者"""
        try:
            self._dlq_producer = AIOKafkaProducer(
                bootstrap_servers=settings.kafka_bootstrap,
                value_serializer=lambda v: json.dumps(v, ensure_ascii=False).encode("utf-8"),
                key_serializer=lambda k: k.encode("utf-8") if k else None,
                acks="all",
            )
            await self._dlq_producer.start()
            logger.info(f"[Kafka] DLQ producer started → {DLQ_TOPIC}")
        except Exception as e:
            logger.warning(f"[Kafka] DLQ producer failed to start: {e}")
            self._dlq_producer = None

    # ── 死信队列 ──

    async def _send_to_dlq(self, topic: str, msg_value: dict, error: str, retry_count: int):
        """将失败消息发送到死信队列"""
        if not self._dlq_producer:
            logger.error(f"[Kafka-DLQ] Producer unavailable, message lost: {error}")
            return
        try:
            dlq_record = {
                "original_topic": topic,
                "original_message": msg_value,
                "error": str(error)[:1000],
                "retry_count": retry_count,
                "failed_at": time.time(),
                "trace_id": msg_value.get("_trace_id", ""),
            }
            await self._dlq_producer.send(
                DLQ_TOPIC,
                key=msg_value.get("eventId", ""),
                value=dlq_record,
            )
            self._stats["dlq_sent"] += 1
            logger.warning(
                f"[Kafka-DLQ] Sent to DLQ: topic={topic} "
                f"eventId={msg_value.get('eventId', '?')} error={error[:100]}"
            )
        except Exception as e:
            logger.error(f"[Kafka-DLQ] Failed to send to DLQ: {e}")

    # ── trace 头提取 ──

    @staticmethod
    def _extract_trace_carrier(msg) -> dict:
        """从 Kafka message headers 提取 W3C traceparent / 旧 trace_id"""
        carrier: dict = {}
        if msg.headers:
            for key, value in msg.headers:
                if not value:
                    continue
                v = value.decode("utf-8") if isinstance(value, bytes) else str(value)
                if key == "traceparent" and not carrier.get("traceparent"):
                    carrier["traceparent"] = v
                elif key == "trace_id" and not carrier.get("trace_id"):
                    carrier["trace_id"] = v
        return carrier

    # ── 消费 Lag 监控 ──

    async def _lag_monitor(self):
        """定期计算各 topic 的消费 lag"""
        while self._running:
            try:
                await asyncio.sleep(30)
                lag_info = {}
                topics = [
                    settings.kafka_topic_enriched,
                    settings.kafka_topic_audit_queue,
                    settings.kafka_topic_alerts,
                ]
                for topic_name in topics:
                    try:
                        consumer = AIOKafkaConsumer(
                            bootstrap_servers=settings.kafka_bootstrap,
                            group_id=f"{settings.kafka_consumer_group}-lag-probe",
                            enable_auto_commit=False,
                        )
                        await consumer.start()
                        partitions = consumer.partitions_for_topic(topic_name)
                        if partitions:
                            tps = [TopicPartition(topic_name, p) for p in partitions]
                            consumer.assign(tps)
                            end_offsets = await consumer.end_offsets(tps)
                            committed = {}
                            for tp in tps:
                                offset = await consumer.committed(tp)
                                committed[tp] = offset or 0
                            total_lag = sum(
                                max(0, end_offsets[tp] - committed[tp])
                                for tp in tps
                            )
                            lag_info[topic_name] = total_lag
                        await consumer.stop()
                    except Exception:
                        lag_info[topic_name] = -1
                self._stats["lag"] = lag_info
                total = sum(v for v in lag_info.values() if v > 0)
                if total > 100:
                    logger.warning(f"[Kafka-Lag] High consumer lag: {lag_info}")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"[Kafka-Lag] Monitor error: {e}")

    # ── 通用消费循环 ──

    async def _consume_loop(
        self,
        topic: str,
        group_suffix: str,
        handler,
        stat_key: str,
    ):
        """
        通用消费循环 — 手动提交 + PG 幂等 + DLQ + 背压

        Args:
            topic: 消费的 topic 名称
            group_suffix: 消费者组后缀
            handler: 异步处理函数 (event_dict, trace_id) → None
            stat_key: 统计计数器名称
        """
        consumer = AIOKafkaConsumer(
            topic,
            bootstrap_servers=settings.kafka_bootstrap,
            group_id=f"{settings.kafka_consumer_group}-{group_suffix}",
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            auto_offset_reset="earliest",
            enable_auto_commit=False,
            max_poll_records=MAX_POLL_RECORDS,
        )
        try:
            await consumer.start()
            logger.info(f"Consuming {topic} (manual-commit, PG-idempotent, DLQ={DLQ_TOPIC})...")
            async for msg in consumer:
                if not self._running:
                    break
                event = msg.value
                # trace: 优先 W3C traceparent header (Flink TraceIdHeaderProvider 写入),
                # 回退 payload._traceparent / trace_id header / payload traceId (兼容旧链路)
                carrier = self._extract_trace_carrier(msg)
                if not carrier.get("traceparent"):
                    payload_tp = event.get("_traceparent", "")
                    if not payload_tp:
                        rawd = event.get("rawData")
                        payload_tp = rawd.get("_traceparent", "") if isinstance(rawd, dict) else ""
                    if payload_tp:
                        carrier["traceparent"] = payload_tp
                trace_id = carrier.get("trace_id", "") or event.get("traceId", "")

                # OTel 根 span: 每条消息一个 trace (父 = 入站 traceparent)
                from otel_setup import extract_context
                ctx = extract_context(carrier) if carrier else None
                importance = "high" if topic in (
                    settings.kafka_topic_alerts, settings.kafka_topic_audit_queue
                ) else "normal"
                root = self._otel_tracer.start_as_current_span(
                    f"kafka.consume.{group_suffix}",
                    context=ctx,
                    attributes={
                        "messaging.system": "kafka",
                        "messaging.destination.name": topic,
                        "messaging.kafka.consumer.group": f"{settings.kafka_consumer_group}-{group_suffix}",
                        "soc.importance": importance,
                        "soc.event_id": event.get("eventId", ""),
                    },
                )
                try:
                    with root:
                        await self._process_message(msg, event, topic, trace_id, handler, stat_key)
                finally:
                    # 手动提交 offset（无论成功/失败都提交，避免无限重试阻塞）
                    await consumer.commit()

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"{topic} consumer crashed: {e}")
        finally:
            await consumer.stop()

    async def _process_message(self, msg, event, topic, trace_id, handler, stat_key):
        """单条消息处理 (解密 → Schema 校验 → 重试 handler → DLQ), 位于 OTel 根 span 内"""
        # ⓪ 解密敏感字段
        event = field_cipher.decrypt_message(event)

        # ① 幂等: 由 event_store.store 的 PG event_id 唯一索引兜底
        #    (同一条事件重放/双路径扇出只落库一次, 此处不再做 Redis 去重)

        # ② 跨运行时 Schema 校验 (Flink↔Python 契约, 不合规 → DLQ 可见)
        schema_errors = schema_registry.validate(topic, event)
        if schema_errors:
            # Schema 违规是确定性问题, 不重试 → 直接 DLQ + 提交 offset
            await self._send_to_dlq(
                topic, event,
                f"Schema 校验失败: {'; '.join(schema_errors[:5])}",
                MAX_RETRY,
            )
            self._mark_root_error(f"schema:{schema_errors[0][:200]}")
            return

        # ③ 注入 trace_id 到事件
        if trace_id:
            event["_trace_id"] = trace_id

        # ③ 处理（带重试）
        success = False
        last_error = ""
        for attempt in range(1, MAX_RETRY + 1):
            try:
                await handler(event, trace_id)
                success = True
                self._stats[stat_key] += 1
                self._stats["last_message_at"] = time.time()
                inc_kafka_consumed(topic)
                break
            except Exception as e:
                last_error = str(e)
                self._stats["errors"] += 1
                logger.error(
                    f"[Kafka] {topic} handler error (attempt {attempt}/{MAX_RETRY}): {e}"
                )
                if attempt < MAX_RETRY:
                    await asyncio.sleep(0.5 * attempt)

        # ④ 失败 → DLQ
        if not success:
            await self._send_to_dlq(topic, event, last_error, MAX_RETRY)
            self._mark_root_error(last_error[:500])

    def _mark_root_error(self, message: str):
        """把当前 OTel 根 span 标记为错误 (供 Tempo 排查)"""
        try:
            from opentelemetry import trace as otel_trace
            span = otel_trace.get_current_span()
            if span and span.is_recording():
                span.record_exception(Exception(message))
                span.set_status(otel_trace.Status(otel_trace.StatusCode.ERROR, message))
        except Exception:
            pass

    # ── 各 topic 消费入口 ──
    # ── Python 权威处理: HTTP 网关队列(security-events-ingest) ──
    async def _consume_python_ingest(self):
        # batching + concurrent park + batch commit for higher ingest-process drain speed
        if not settings.python_process_ingest_queue or not settings.kafka_enabled:
            logger.info("Python ingest queue consumer disabled")
            return
        import os as _os
        workers = max(1, int(_os.environ.get("KAFKA_INGEST_WORKERS", "8") or "8"))
        poll_ms = int(_os.environ.get("KAFKA_INGEST_POLL_MS", "500") or "500")
        consumer = AIOKafkaConsumer(
            settings.kafka_topic_ingest_process,
            bootstrap_servers=settings.kafka_bootstrap,
            group_id=f"{settings.kafka_consumer_group}-ingestpy",
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            auto_offset_reset="earliest",
            enable_auto_commit=False,
            max_poll_records=MAX_POLL_RECORDS,
        )
        try:
            await consumer.start()
            logger.info(f"Consuming python-ingest {settings.kafka_topic_ingest_process} "
                        f"(workers={workers}, poll={poll_ms}ms, batch-commit)")
            while self._running:
                try:
                    fetched = await consumer.getmany(timeout_ms=poll_ms,
                                                     max_records=MAX_POLL_RECORDS)
                except Exception as e:
                    logger.warning(f"Python-ingest poll error: {e}")
                    await asyncio.sleep(0.5)
                    continue
                msgs = [m for batch in fetched.values() for m in batch]
                if not msgs:
                    continue
                batch_failed = [False]

                async def _exe(m):
                    if not await self._safe_py_handle(m):
                        batch_failed[0] = True

                for i in range(0, len(msgs), workers):
                    chunk = msgs[i:i + workers]
                    await asyncio.gather(*[_exe(m) for m in chunk])
                # only advance offset when whole fetched batch processed OK;
                # transient DB/LLM outage -> leave offset -> replay on reconnect (no loss)
                if batch_failed[0]:
                    logger.warning(f"Python-ingest batch had failures: not committing, will retry/replay")
                    await asyncio.sleep(0.5)
                else:
                    await consumer.commit()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Python-ingest consumer crashed: {e}")
        finally:
            await consumer.stop()


    async def _safe_py_handle(self, msg) -> bool:
        try:
            event = msg.value if isinstance(msg.value, dict) else json.loads(msg.value)
            await self._handle_python_ingest(event, "")
            self._stats["python_ingest_consumed"] = self._stats.get("python_ingest_consumed", 0) + 1
            self._stats["last_message_at"] = time.time()
            inc_kafka_consumed(getattr(settings, "kafka_topic_ingest_process", ""))
            return True
        except Exception as e:
            self._stats["errors"] = self._stats.get("errors", 0) + 1
            logger.error(f"[Python-ingest] handle error: {e}")
            return False


    async def _handle_python_ingest(self, wrapper: dict, trace_id: str):
        from log_ingestion import log_ingestor
        from models import async_session as db_session
        body = wrapper.get("body")
        if not isinstance(body, dict):
            raise ValueError("python ingest wrapper lacks dict body")
        session_id = str(wrapper.get("session_id") or ("http-" + str(wrapper.get("uuid", ""))))
        async with db_session() as session:
            await log_ingestor.ingest(session, session_id, body)


    async def _consume_enriched(self):
        """消费 security-events-enriched → 全量存储 + 记忆树索引"""
        await self._consume_loop(
            topic=settings.kafka_topic_enriched,
            group_suffix="enriched",
            handler=self._handle_enriched,
            stat_key="enriched_consumed",
        )

    async def _consume_audit_queue(self):
        """消费 security-audit-queue → Audit-LLM 流水线（带背压）"""
        await self._consume_loop(
            topic=settings.kafka_topic_audit_queue,
            group_suffix="audit",
            handler=self._handle_audit_with_backpressure,
            stat_key="audit_consumed",
        )

    async def _consume_alerts(self):
        """消费 security-alerts → 触发响应引擎"""
        await self._consume_loop(
            topic=settings.kafka_topic_alerts,
            group_suffix="alerts",
            handler=self._handle_alert,
            stat_key="alerts_consumed",
        )

    async def _consume_behavior_alerts(self):
        """消费 security-behavior-alerts → L4 行为基线响应"""
        await self._consume_loop(
            topic=settings.kafka_topic_behavior_alerts,
            group_suffix="behavior-alerts",
            handler=self._handle_behavior_alert,
            stat_key="behavior_alerts_consumed",
        )

    async def _consume_rejected(self):
        """消费 security-logs-rejected → 拒绝原因可观测"""
        await self._consume_loop(
            topic=settings.kafka_topic_rejected,
            group_suffix="rejected",
            handler=self._handle_rejected,
            stat_key="rejected_consumed",
        )

    async def _consume_cep_partial(self):
        """消费 security-cep-partial → 攻击链部分匹配可视化"""
        consumer = AIOKafkaConsumer(
            settings.kafka_topic_cep_partial,
            bootstrap_servers=settings.kafka_bootstrap,
            group_id=f"{settings.kafka_consumer_group}-cep-partial",
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            auto_offset_reset="latest",
            enable_auto_commit=True,
            max_poll_records=MAX_POLL_RECORDS,
        )
        try:
            await consumer.start()
            logger.info(f"Consuming {settings.kafka_topic_cep_partial}...")
            async for msg in consumer:
                if not self._running:
                    break
                try:
                    self._cep_partial.append(msg.value)
                    if len(self._cep_partial) > 100:
                        self._cep_partial = self._cep_partial[-100:]
                except Exception as e:
                    logger.debug(f"[CEP-Partial] Error: {e}")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"CEP partial consumer crashed: {e}")
        finally:
            await consumer.stop()

    # ── 业务处理函数 ──

    async def _handle_enriched(self, event: dict, trace_id: str):
        """处理 Flink 富化后的事件：存储 + 索引"""
        from models import async_session as db_session
        from event_store import event_store
        from memory_tree import memory_tree

        session_id = event.get("sourceId", event.get("session_id", "kafka-" + str(event.get("eventId", ""))))
        # Flink AnomalyDetectionJob 把评分写入嵌套的 rawData._anomalyScore,
        # 兼容顶层键以支持其它生产者
        raw = event.get("rawData") or {}
        if not isinstance(raw, dict):
            raw = {}
        anomaly_score = event.get("_anomalyScore", raw.get("_anomalyScore", event.get("anomalyScore", 0.0)))
        anomaly_reasons = event.get("_anomalyReasons", raw.get("_anomalyReasons", []))

        log_data = {
            "eventId": event.get("eventId", ""),
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
                "reasons": anomaly_reasons,
                "sigma": 0,
            },
            "_flink_processed": True,
            "_source_id": event.get("sourceId", ""),
            "_trace_id": trace_id,
        }

        async with db_session() as session:
            stored = await event_store.store(
                session, log_data, session_id,
                anomaly_score=anomaly_score,
            )
            event_text = json.dumps(log_data, ensure_ascii=False)
            await memory_tree.add_leaf(
                session, session_id, log_data, event_text,
                correlation_group="anomaly" if anomaly_score >= 0.6 else "",
            )

        from event_bus import event_bus
        event_bus.publish("security_event", {
            "event_id": stored.id,
            "event_type": log_data["event"],
            "severity": log_data["severity"],
            "src_ip": log_data["src_ip"],
            "anomaly_score": anomaly_score,
            "source": "kafka-flink",
            "trace_id": trace_id,
        })

        # ── P0 修复(审计闭环) ──
        # Flink 只把"中危以下"事件路由进 security-audit-queue；高异常 / critical / high
        # 的事件走 security-alerts 响应路径，导致这些"真正的问题"从未进入 Audit-LLM，
        # 在日志中心永远停留在"待审计/审核中"。此处对命中告警路径的事件同样排队审计，
        # 使高优先级问题进入审计闭环并标记为已分析。
        severity = log_data["severity"]
        if anomaly_score >= 0.6 or severity in ("critical", "high"):
            self._queue_audit(
                log_data=log_data,
                anomaly_score=anomaly_score,
                anomaly_reasons=anomaly_reasons,
                session_id=session_id,
                stored_id=stored.id,
                trace_id=trace_id,
            )

    def _queue_audit(
        self,
        log_data: dict,
        anomaly_score: float,
        anomaly_reasons: list,
        session_id: str,
        stored_id: int,
        trace_id: str,
    ):
        """将事件排入 Audit-LLM 流水线（enriched 告警路径与 audit-queue 共用）。"""
        from log_ingestion import log_ingestor
        from anomaly_detector import AnomalyReport

        report = AnomalyReport(
            event_id=stored_id,
            anomaly_score=anomaly_score,
            is_anomaly=anomaly_score >= 0.6,
            deviation_sigma=anomaly_score * 5,
            reasons=anomaly_reasons,
        )
        asyncio.create_task(
            log_ingestor._audit_pipeline(session_id, stored_id, log_data, report)
        )
        logger.info(
            f"[Kafka-Enriched-Audit] Queued event #{stored_id} for Audit-LLM "
            f"(alert-path closure): {log_data.get('event')} score={anomaly_score:.2f} "
            f"trace={trace_id[:8] if trace_id else 'none'}"
        )

    async def _handle_audit_with_backpressure(self, event: dict, trace_id: str):
        """Audit-LLM 入口 — 通过信号量控制并发（背压）"""
        async with self._audit_semaphore:
            await self._handle_audit(event, trace_id)

    async def _handle_audit(self, event: dict, trace_id: str):
        """将事件送入 Audit-LLM 流水线"""
        from log_ingestion import log_ingestor
        from models import async_session as db_session
        from anomaly_detector import AnomalyReport

        session_id = event.get("sourceId", event.get("session_id", "kafka-audit"))
        # Flink 评分位于嵌套 rawData._anomalyScore（同 _handle_enriched）
        raw = event.get("rawData") or {}
        if not isinstance(raw, dict):
            raw = {}
        anomaly_score = event.get("_anomalyScore", raw.get("_anomalyScore", event.get("anomalyScore", 0.3)))
        anomaly_reasons = event.get("_anomalyReasons", raw.get("_anomalyReasons", []))

        log_data = {
            "eventId": event.get("eventId", ""),
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
                "reasons": anomaly_reasons,
                "sigma": 0,
            },
            "_flink_processed": True,
            "_trace_id": trace_id,
        }

        report = AnomalyReport(
            event_id=0,
            anomaly_score=anomaly_score,
            is_anomaly=anomaly_score >= 0.6,
            deviation_sigma=anomaly_score * 5,
            reasons=anomaly_reasons,
        )

        async with db_session() as session:
            from event_store import event_store
            stored = await event_store.store(
                session, log_data, session_id,
                anomaly_score=anomaly_score,
            )

        asyncio.create_task(
            log_ingestor._audit_pipeline(session_id, stored.id, log_data, report)
        )

        logger.info(
            f"[Kafka-Audit] Queued event #{stored.id} for Audit-LLM: "
            f"{log_data['event']} score={anomaly_score:.2f} trace={trace_id[:8] if trace_id else 'none'}"
        )

    async def _handle_alert(self, alert: dict, trace_id: str):
        """处理 Flink 产生的告警 → 响应引擎"""
        from models import async_session as db_session
        from response_engine import get_orchestrator
        from event_bus import event_bus

        alert_type = alert.get("alertType", "ANOMALY")
        severity = alert.get("severity", "high")
        src_ip = alert.get("srcIp", alert.get("src_ip", ""))

        logger.warning(
            f"[Kafka-Alert] {alert_type}: {alert.get('eventType', '')} "
            f"from {src_ip} score={alert.get('anomalyScore', 0):.2f} "
            f"trace={trace_id[:8] if trace_id else 'none'}"
        )

        event_bus.publish("alert", {
            "alert_type": alert_type,
            "event_type": alert.get("eventType", ""),
            "severity": severity,
            "src_ip": src_ip,
            "anomaly_score": alert.get("anomalyScore", 0),
            "reasons": alert.get("reasons", []),
            "source": "flink-cep",
            "trace_id": trace_id,
        })

        anomaly_score = alert.get("anomalyScore", 0)
        if anomaly_score >= 0.5 or severity in ("critical", "high"):
            try:
                # 资产重要性加成
                from routers.assets import get_asset_weight
                dst_ip = alert.get("dstIp", alert.get("dst_ip", ""))
                asset_weight = get_asset_weight(dst_ip)
                if asset_weight > 1.0:
                    anomaly_score = min(1.0, anomaly_score * asset_weight)
                    logger.info(
                        f"[Kafka-Alert] Asset boost: dst={dst_ip} "
                        f"weight={asset_weight} score→{anomaly_score:.2f}"
                    )

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
                    "trace_id": trace_id,
                    "response_source": "flink_alert",
                    "allow_blocking": True,
                }
                async with db_session() as session:
                    await resp_orch.on_threat_detected(
                        session=session,
                        threat_info=threat_info,
                        event_id=None,
                        session_id="flink-alert",
                        allow_blocking=True,
                    )
            except Exception as e:
                logger.warning(f"[Kafka-Alert] Response trigger failed: {e}")

    async def _handle_behavior_alert(self, alert: dict, trace_id: str):
        """L4: Flink 行为基线告警 → 固定 BEHAVIOR_ANOMALY，强信号可封禁。"""
        from models import async_session as db_session
        from response_engine import get_orchestrator
        from event_bus import event_bus

        src_ip = alert.get("srcIp") or alert.get("src_ip") or ""
        severity = str(alert.get("severity") or "high").lower()
        try:
            anomaly_score = float(alert.get("anomalyScore") or alert.get("confidence") or 0.0)
        except (TypeError, ValueError):
            anomaly_score = 0.0
        reasons = alert.get("reasons") or []
        if isinstance(reasons, str):
            reasons = [reasons]
        category = (
            alert.get("category")
            or ("EXFIL" if any("bytes_out" in str(r) for r in reasons) else "SCAN")
        )

        logger.warning(
            f"[Kafka-Behavior] BEHAVIOR_ANOMALY from {src_ip} "
            f"score={anomaly_score:.2f} cat={category} reasons={reasons} "
            f"trace={trace_id[:8] if trace_id else 'none'}"
        )

        event_bus.publish("alert", {
            "alert_type": "BEHAVIOR_ANOMALY",
            "event_type": "BEHAVIOR_ANOMALY",
            "severity": severity,
            "src_ip": src_ip,
            "anomaly_score": anomaly_score,
            "reasons": reasons,
            "source": "flink_baseline",
            "trace_id": trace_id,
        })

        if not src_ip:
            return
        if anomaly_score < 0.5 and severity not in ("critical", "high"):
            return

        try:
            resp_orch = get_orchestrator()
            threat_info = {
                "threat_type": "BEHAVIOR_ANOMALY",
                "category": category,
                "confidence": min(1.0, max(anomaly_score, 0.6)),
                "severity": severity if severity in (
                    "info", "low", "medium", "high", "critical"
                ) else "high",
                "src_ip": src_ip,
                "dst_ip": alert.get("dstIp") or alert.get("dst_ip") or "",
                "message": alert.get("message") or (
                    "Flink behavior baseline: " + "; ".join(str(r) for r in reasons)
                ),
                "reason": (
                    f"flink_baseline score={anomaly_score:.2f} "
                    f"reasons={','.join(str(r) for r in reasons)}"
                ),
                "session_id": "flink-behavior",
                "event_id": 0,
                "policy_name": "flink_behavior_anomaly",
                "trace_id": trace_id,
                "response_source": "flink_baseline",
                "allow_blocking": True,
                "anomaly_reasons": list(reasons),
            }
            async with db_session() as session:
                await resp_orch.on_threat_detected(
                    session=session,
                    threat_info=threat_info,
                    event_id=None,
                    session_id="flink-behavior",
                    allow_blocking=True,
                )
        except Exception as e:
            logger.warning(f"[Kafka-Behavior] Response trigger failed: {e}")

    async def _handle_rejected(self, record: dict, trace_id: str):
        """处理被拒绝的事件 — 聚合统计 + 环形日志"""
        rejection_type = record.get("rejectionType", "UNKNOWN")
        reason = record.get("rejectionReason", "")
        stage = record.get("stage", "UNKNOWN")

        # 按类型聚合
        self._rejection_by_type[rejection_type] = \
            self._rejection_by_type.get(rejection_type, 0) + 1

        # 环形日志（保留最近 200 条）
        self._rejection_log.append({
            "type": rejection_type,
            "reason": reason[:200],
            "stage": stage,
            "at": record.get("rejectedAt", 0),
            "event_type": record.get("originalEvent", {}).get("eventType", "")
                if isinstance(record.get("originalEvent"), dict) else "",
        })
        if len(self._rejection_log) > 200:
            self._rejection_log = self._rejection_log[-200:]

        logger.debug(f"[Kafka-Rejected] {rejection_type}: {reason[:100]}")

    def rejection_stats(self) -> dict:
        """拒绝原因统计（供 API 暴露）"""
        return {
            "total": self._stats["rejected_consumed"],
            "by_type": dict(self._rejection_by_type),
            "recent": self._rejection_log[-20:],
        }

    def cep_partial_matches(self) -> list[dict]:
        """CEP 部分匹配状态（供 API 暴露）"""
        return self._cep_partial[-50:]

    def stats(self) -> dict:
        return {**self._stats, "running": self._running}


kafka_consumer_manager = KafkaConsumerManager()
