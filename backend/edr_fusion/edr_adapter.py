"""
edr_adapter.py — EDR 数据接入适配器

统一接入层，支持:
  1. Kafka 消费: 从 edr-sysmon / edr-winevent Topic 消费 EDR 日志
  2. HTTP API: 接收 Winlogbeat / NXLog / 自定义 Agent 推送
  3. 插件化: 预留商业 EDR (CrowdStrike / Carbon Black) API 适配器

数据流:
  Kafka (edr-sysmon)  → SysmonParser  → EdrEvent → PostgreSQL
  Kafka (edr-winevent) → WinEventParser → EdrEvent → PostgreSQL
  HTTP POST /api/v1/edr/ingest → 同上
  定时任务 → CrossCorrelator → 关联告警

用法:
    from edr_fusion.edr_adapter import edr_adapter
    await edr_adapter.start()   # 启动 Kafka 消费 + 定时关联
    await edr_adapter.ingest(event_dict)  # HTTP 接入
"""
import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from edr_fusion.sysmon_parser import sysmon_parser
from edr_fusion.winevent_parser import winevent_parser

logger = logging.getLogger(__name__)


class EdrAdapter:
    """
    EDR 数据接入适配器

    职责:
      1. 管理 Kafka 消费者（Sysmon / WinEventLog Topic）
      2. 提供 HTTP 接入接口
      3. 解析后写入 edr_events 表
      4. 触发跨源关联分析
    """

    def __init__(self):
        self.enabled = settings.edr_enabled
        self._running = False
        self._consumer_task: Optional[asyncio.Task] = None
        self._correlation_task: Optional[asyncio.Task] = None
        self._stats = {
            "sysmon_events": 0,
            "winevent_events": 0,
            "correlations": 0,
            "errors": 0,
        }

    @property
    def is_running(self) -> bool:
        return self._running

    async def start(self):
        """启动 EDR 数据接入"""
        if not self.enabled:
            logger.info("EDR 融合未启用 (edr_enabled=false)")
            return

        self._running = True

        # 启动 Kafka 消费
        if settings.kafka_enabled:
            self._consumer_task = asyncio.create_task(self._consume_loop())

        # 启动定时跨源关联
        self._correlation_task = asyncio.create_task(self._correlation_loop())

        logger.info("EDR 适配器启动: kafka=%s", settings.kafka_enabled)

    async def stop(self):
        """停止 EDR 数据接入"""
        self._running = False
        for task in (self._consumer_task, self._correlation_task):
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        logger.info(
            "EDR 适配器停止: sysmon=%d winevent=%d correlations=%d",
            self._stats["sysmon_events"],
            self._stats["winevent_events"],
            self._stats["correlations"],
        )

    async def ingest(self, event_dict: dict, source_type: str = "auto") -> Optional[dict]:
        """
        接入单条 EDR 事件（HTTP API 入口）

        source_type: "sysmon" | "winevent" | "auto"
        """
        try:
            # 自动识别来源
            if source_type == "auto":
                if "EventID" in event_dict or "event_id" in event_dict:
                    eid = event_dict.get("EventID", event_dict.get("event_id", 0))
                    # Sysmon 通常有 Sysmon 特定字段
                    if "EventData" in event_dict:
                        ed = event_dict["EventData"]
                        if "Image" in ed or "ParentImage" in ed:
                            source_type = "sysmon"
                        else:
                            source_type = "winevent"
                    else:
                        source_type = "winevent"
                else:
                    source_type = "winevent"

            # 解析
            if source_type == "sysmon":
                parsed = sysmon_parser.parse_dict(event_dict)
                if parsed:
                    self._stats["sysmon_events"] += 1
                    try:
                        from metrics import inc_edr_event
                        inc_edr_event("sysmon")
                    except Exception:
                        pass
                    return parsed.to_dict()
            else:
                parsed = winevent_parser.parse_dict(event_dict)
                if parsed:
                    self._stats["winevent_events"] += 1
                    try:
                        from metrics import inc_edr_event
                        inc_edr_event("winevent")
                    except Exception:
                        pass
                    return parsed.to_dict()

            return None
        except Exception as e:
            self._stats["errors"] += 1
            logger.warning("EDR 事件接入失败: %s", e)
            return None

    async def ingest_xml(self, xml_string: str, source_type: str = "sysmon") -> Optional[dict]:
        """接入 XML 格式的 EDR 事件"""
        try:
            if source_type == "sysmon":
                parsed = sysmon_parser.parse(xml_string)
                if parsed:
                    self._stats["sysmon_events"] += 1
                    return parsed.to_dict()
            else:
                parsed = winevent_parser.parse(xml_string)
                if parsed:
                    self._stats["winevent_events"] += 1
                    return parsed.to_dict()
            return None
        except Exception as e:
            self._stats["errors"] += 1
            logger.warning("EDR XML 接入失败: %s", e)
            return None

    async def persist(self, session: AsyncSession, event_dict: dict) -> Optional[int]:
        """将解析后的事件写入 edr_events 表"""
        try:
            from models import EdrEvent

            record = EdrEvent(
                source_type=event_dict.get("source_type", "sysmon"),
                event_id=event_dict.get("event_id", 0),
                computer_name=event_dict.get("computer_name", ""),
                user_name=event_dict.get("user_name", ""),
                process_name=event_dict.get("process_name", ""),
                process_id=event_dict.get("process_id", 0),
                parent_process=event_dict.get("parent_process", ""),
                command_line=event_dict.get("command_line", ""),
                image_hash=event_dict.get("image_hash", ""),
                src_ip=event_dict.get("src_ip", ""),
                dst_ip=event_dict.get("dst_ip", ""),
                dst_port=event_dict.get("dst_port", 0),
                file_path=event_dict.get("file_path", ""),
                registry_key=event_dict.get("registry_key", ""),
                event_data=event_dict.get("event_data", {}),
                severity=event_dict.get("severity", "info"),
                mitre_technique=event_dict.get("mitre_technique", ""),
                correlation_key=event_dict.get("correlation_key", ""),
            )
            session.add(record)
            await session.flush()
            return record.id
        except Exception as e:
            logger.error("EDR 事件持久化失败: %s", e)
            return None

    async def _consume_loop(self):
        """Kafka 消费循环"""
        try:
            from aiokafka import AIOKafkaConsumer

            topics = []
            if settings.sysmon_kafka_topic:
                topics.append(settings.sysmon_kafka_topic)
            if settings.winevent_kafka_topic:
                topics.append(settings.winevent_kafka_topic)

            if not topics:
                logger.warning("未配置 EDR Kafka Topic")
                return

            consumer = AIOKafkaConsumer(
                *topics,
                bootstrap_servers=settings.kafka_bootstrap,
                group_id="soc-edr",
                value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                auto_offset_reset="latest",
            )
            await consumer.start()
            logger.info("EDR Kafka 消费者启动: topics=%s", topics)

            try:
                async for msg in consumer:
                    if not self._running:
                        break
                    try:
                        source = "sysmon" if msg.topic == settings.sysmon_kafka_topic else "winevent"
                        parsed = await self.ingest(msg.value, source_type=source)
                        if parsed:
                            from models import async_session
                            async with async_session() as session:
                                await self.persist(session, parsed)
                                await session.commit()
                    except Exception as e:
                        self._stats["errors"] += 1
                        logger.debug("EDR Kafka 消息处理失败: %s", e)
            finally:
                await consumer.stop()

        except ImportError:
            logger.error("aiokafka 未安装，无法消费 EDR Topic")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error("EDR Kafka 消费循环异常: %s", e)

    async def _correlation_loop(self):
        """定时跨源关联分析"""
        try:
            from edr_fusion.cross_correlator import cross_correlator
            from models import async_session

            while self._running:
                await asyncio.sleep(60)  # 每分钟执行一次
                try:
                    async with async_session() as session:
                        results = await cross_correlator.correlate(session)
                        if results:
                            self._stats["correlations"] += len(results)
                            logger.info("跨源关联发现 %d 条结果", len(results))
                            # 高置信度结果推送告警
                            for r in results:
                                if r.confidence >= 0.7:
                                    await self._emit_alert(r)
                except Exception as e:
                    logger.debug("跨源关联执行异常: %s", e)
        except asyncio.CancelledError:
            pass

    async def _emit_alert(self, result):
        """将关联结果推送为告警（写入 event_bus / Kafka）"""
        try:
            from event_bus import event_bus
            # event_bus.publish 是同步方法（返回 None），不能 await
            event_bus.publish("edr_correlation", result.to_dict())
        except Exception as e:
            logger.debug("关联告警推送失败: %s", e)

    def get_stats(self) -> dict:
        return dict(self._stats)


# ── 全局单例 ──
edr_adapter = EdrAdapter()
