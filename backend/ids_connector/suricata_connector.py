"""
suricata_connector.py — Suricata EVE JSON 告警接入

消费 Suricata 的 eve.json 输出（通过 Kafka 或文件 tail），
将 IDS 告警转换为平台 SecurityEvent 并触发审计流水线。

支持:
  - EVE JSON 格式解析 (alert / dns / tls / http / flow 事件类型)
  - Suricata 告警 → Sigma 规则 ID 映射
  - 告警去重（相同 signature_id + src/dst 在窗口内合并）
  - 与现有 sigma_detector / anomaly_detector 联动

用法:
    from ids_connector.suricata_connector import suricata_connector
    await suricata_connector.start()  # 启动 Kafka 消费
    await suricata_connector.process_eve(eve_dict)  # 处理单条 EVE 记录
"""
import asyncio
import json
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)

# Suricata 严重度 → 平台严重度映射
_SEVERITY_MAP = {1: "critical", 2: "high", 3: "medium", 4: "low"}

# 去重窗口 (秒)
_DEDUP_WINDOW = 60


@dataclass
class SuricataAlert:
    """Suricata 告警"""
    signature_id: int = 0
    signature: str = ""
    category: str = ""
    severity: str = "medium"
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""
    action: str = ""           # allowed | blocked
    timestamp: str = ""
    flow_id: int = 0
    metadata: dict = field(default_factory=dict)

    def to_security_event(self) -> dict:
        """转换为平台 SecurityEvent 格式"""
        return {
            "event_type": f"SURICATA:{self.category}" if self.category else "IDS_ALERT",
            "severity": self.severity,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "action": self.action,
            "message": f"[{self.signature_id}] {self.signature}",
            "raw_data": {
                "signature_id": self.signature_id,
                "signature": self.signature,
                "category": self.category,
                "src_port": self.src_port,
                "dst_port": self.dst_port,
                "flow_id": self.flow_id,
                "source": "suricata",
                **self.metadata,
            },
        }


class SuricataConnector:
    """Suricata EVE JSON 连接器"""

    def __init__(self):
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._dedup: dict[str, float] = {}  # key → last_seen
        self._stats = {"alerts": 0, "deduped": 0, "dns": 0, "tls": 0, "http": 0}
        self._alert_callbacks: list = []

    def on_alert(self, callback):
        """注册告警回调: async def cb(alert: SuricataAlert)"""
        self._alert_callbacks.append(callback)

    async def start(self):
        """启动 Suricata EVE 消费"""
        if not settings.kafka_enabled:
            logger.info("Kafka 未启用，Suricata 连接器跳过")
            return

        self._running = True
        self._task = asyncio.create_task(self._consume_loop())
        logger.info("Suricata 连接器启动")

    async def stop(self):
        """停止消费"""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info(
            "Suricata 连接器停止: alerts=%d deduped=%d",
            self._stats["alerts"], self._stats["deduped"],
        )

    async def process_eve(self, eve: dict) -> Optional[SuricataAlert]:
        """
        处理单条 EVE JSON 记录

        支持 event_type: alert / dns / tls / http / flow
        """
        event_type = eve.get("event_type", "")

        if event_type == "alert":
            return await self._process_alert(eve)
        elif event_type == "dns":
            self._stats["dns"] += 1
            # DNS 事件可送入 dns_parser 做进一步分析
        elif event_type == "tls":
            self._stats["tls"] += 1
            # TLS 事件可送入 tls_metadata 做指纹分析
        elif event_type == "http":
            self._stats["http"] += 1
        elif event_type == "flow":
            pass  # 流事件由 flow_aggregator 处理

        return None

    async def _process_alert(self, eve: dict) -> Optional[SuricataAlert]:
        """处理 Suricata alert 事件"""
        alert_data = eve.get("alert", {})

        alert = SuricataAlert(
            signature_id=alert_data.get("signature_id", 0),
            signature=alert_data.get("signature", ""),
            category=alert_data.get("category", ""),
            severity=_SEVERITY_MAP.get(alert_data.get("severity", 3), "medium"),
            src_ip=eve.get("src_ip", ""),
            dst_ip=eve.get("dest_ip", ""),
            src_port=eve.get("src_port", 0),
            dst_port=eve.get("dest_port", 0),
            protocol=eve.get("proto", ""),
            action=alert_data.get("action", "allowed"),
            timestamp=eve.get("timestamp", ""),
            flow_id=eve.get("flow_id", 0),
            metadata={
                "gid": alert_data.get("gid", 0),
                "rev": alert_data.get("rev", 0),
                "metadata": alert_data.get("metadata", {}),
            },
        )

        # 去重
        dedup_key = f"{alert.signature_id}:{alert.src_ip}:{alert.dst_ip}"
        now = time.time()
        last = self._dedup.get(dedup_key, 0)
        if now - last < _DEDUP_WINDOW:
            self._stats["deduped"] += 1
            return None
        self._dedup[dedup_key] = now
        # 定期清理过期去重记录，防止内存泄漏
        if len(self._dedup) % 500 == 0:
            self._cleanup_dedup()

        self._stats["alerts"] += 1
        logger.info(
            "Suricata 告警: [%d] %s %s → %s (%s)",
            alert.signature_id, alert.signature[:50],
            alert.src_ip, alert.dst_ip, alert.severity,
        )

        # 分发回调
        for cb in self._alert_callbacks:
            try:
                await cb(alert)
            except Exception as e:
                logger.warning("Suricata 告警回调异常: %s", e)

        return alert

    async def _consume_loop(self):
        """Kafka 消费循环 — 消费 Suricata EVE Topic"""
        try:
            from aiokafka import AIOKafkaConsumer

            topic = "suricata-eve"  # 可配置
            consumer = AIOKafkaConsumer(
                topic,
                bootstrap_servers=settings.kafka_bootstrap,
                group_id="soc-suricata",
                value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                auto_offset_reset="latest",
            )
            await consumer.start()
            logger.info("Suricata EVE Kafka 消费者启动: topic=%s", topic)

            try:
                async for msg in consumer:
                    if not self._running:
                        break
                    try:
                        await self.process_eve(msg.value)
                    except Exception as e:
                        logger.debug("EVE 消息处理失败: %s", e)
            finally:
                await consumer.stop()

        except ImportError:
            logger.error("aiokafka 未安装")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error("Suricata 消费循环异常: %s", e)

    def _cleanup_dedup(self):
        """清理过期的去重记录"""
        now = time.time()
        expired = [k for k, t in self._dedup.items() if now - t > _DEDUP_WINDOW * 2]
        for k in expired:
            del self._dedup[k]

    def get_stats(self) -> dict:
        return dict(self._stats)


# ── 全局单例 ──
suricata_connector = SuricataConnector()
