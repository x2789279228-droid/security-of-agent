"""
Syslog 转发适配器 — UDP 514 → Kafka / SOC 平台

在 SOC 服务器上运行，接收 Linux 客户端 rsyslog 转发来的日志，
解析并转换为平台 JSON，发送到 Kafka 或 POST 到平台接入接口。

用法:
  HTTP 模式 (旧版):
    python syslog-adapter.py --soc http://192.168.1.50:8001 --port 514

  Kafka 模式 (推荐):
    python syslog-adapter.py --kafka 192.168.1.50:9092 --port 514
    python syslog-adapter.py --kafka 192.168.1.50:9092 --api-key soc-syslog-2024

Linux 客户端配置 (rsyslog):
  echo 'auth.*,authpriv.*,kern.*,user.* @@<SOC_IP>:514' > /etc/rsyslog.d/60-forward.conf
  systemctl restart rsyslog
"""
import argparse
import json
import logging
import re
import socketserver
import time
import urllib.request
import uuid
from datetime import datetime

# Kafka 可选依赖
try:
    from kafka import KafkaProducer as SyncKafkaProducer
    HAS_KAFKA = True
except ImportError:
    HAS_KAFKA = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("syslog-adapter")

SEVERITY_MAP = {0: "critical", 1: "critical", 2: "high", 3: "high",
                4: "medium", 5: "low", 6: "info", 7: "info"}

HEADER_RE = re.compile(
    r"^<(\d{1,3})>\s*(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\S+)\s+(.+)$"
)
RFC5424_RE = re.compile(r"^<(\d{1,3})>1\s+\S+\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+-\s+(.+)$")
IP_RE = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")


def classify(msg: str) -> dict:
    """识别常见安全模式，返回 (event, severity, src_ip, dst_ip, confidence)"""
    if "Failed password" in msg or "authentication failure" in msg:
        m = IP_RE.search(msg)
        return "BRUTE_FORCE", "high", m.group(0) if m else "", "", 85
    if "Invalid user" in msg or "does not exist" in msg:
        m = IP_RE.search(msg)
        return "BRUTE_FORCE", "medium", m.group(0) if m else "", "", 70
    if "Accepted password" in msg or "Accepted publickey" in msg or "session opened for user" in msg:
        return "USER_LOGIN", "info", "", "", 90
    if "sudo:" in msg and "COMMAND=" in msg:
        return "PRIVILEGE_ESCALATION", "medium", "", "", 65
    if "connection refused" in msg:
        return "CONN_REFUSED", "low", "", "", 60
    if "Segmentation fault" in msg or "segfault" in msg:
        return "PROCESS_CRASH", "low", "", "", 60
    if "BLOCKED" in msg or "DROP" in msg.upper():
        m = IP_RE.search(msg)
        return "FIREWALL_BLOCK", "medium", m.group(0) if m else "", "", 75
    return None, None, None, None, None


def make_event(prio: int, hostname: str, msg: str, ts: str) -> dict:
    evt, sev, src, dst, conf = classify(msg)
    if not evt:
        evt, sev, conf = "SYSLOG_EVENT", SEVERITY_MAP.get(prio, "info"), 50
    src = src or (IP_RE.search(msg).group(0) if IP_RE.search(msg) else "")
    return {
        "event": evt,
        "severity": sev,
        "src_ip": src,
        "dst_ip": dst,
        "message": f"[{hostname}] {msg.strip()[:200]}",
        "confidence": conf,
        "protocol": "syslog",
    }


KAFKA_TOPIC_RAW = "security-logs-raw"
DEFAULT_API_KEY = "soc-syslog-2024"


class OutputConfig:
    """输出配置：Kafka 或 HTTP"""
    MODE = "http"            # "kafka" | "http"
    SO_URL = "http://localhost:8001"
    KAFKA_BOOTSTRAP = ""
    API_KEY = DEFAULT_API_KEY
    kafka_producer = None    # SyncKafkaProducer 实例


def send_to_kafka(event: dict, hostname: str):
    """将事件发送到 Kafka（带数据源认证信息）"""
    msg = {
        "eventId": str(uuid.uuid4()),
        "sourceId": f"syslog-{hostname}",
        "apiKey": OutputConfig.API_KEY,
        "eventType": event["event"],
        "severity": event["severity"],
        "srcIp": event.get("src_ip", ""),
        "dstIp": event.get("dst_ip", ""),
        "protocol": event.get("protocol", "syslog"),
        "message": event.get("message", ""),
        "confidence": event.get("confidence", 50),
        "timestamp": int(time.time() * 1000),
        "rawData": event,
    }
    try:
        OutputConfig.kafka_producer.send(
            KAFKA_TOPIC_RAW,
            key=msg["srcIp"].encode("utf-8") if msg["srcIp"] else None,
            value=json.dumps(msg, ensure_ascii=False).encode("utf-8"),
        )
    except Exception as e:
        log.warning(f"Kafka 发送失败: {e}")


def send_to_http(event: dict, hostname: str):
    """将事件 POST 到 SOC 平台（旧版 HTTP 直连）"""
    body = json.dumps({
        "message": event,
        "session_id": "linux-" + hostname,
    }).encode("utf-8")
    try:
        req = urllib.request.Request(
            f"{OutputConfig.SO_URL}/api/logs/ingest",
            data=body, headers={"Content-Type": "application/json"}, method="POST",
        )
        urllib.request.urlopen(req, timeout=10).read()
    except Exception as e:
        log.warning(f"HTTP 上报失败: {e}")


class SyslogHandler(socketserver.BaseRequestHandler):
    def handle(self):
        raw = self.request[0].decode("utf-8", errors="replace").strip()
        if not raw:
            return
        prio, hostname, msg, ts = None, "unknown", raw, datetime.now().isoformat()
        m = RFC5424_RE.match(raw)
        if m:
            prio = int(m.group(1)) & 0x07
            hostname = m.group(2)
            msg = m.group(6)
        else:
            m = HEADER_RE.match(raw)
            if m:
                prio = int(m.group(1)) & 0x07
                hostname = m.group(7)
                msg = m.group(8)
        event = make_event(prio, hostname, msg, ts)
        if event["event"] in ("SYSLOG_EVENT", "USER_LOGIN", "OUTBOUND_CONN"):
            log.debug(f"{hostname}: {msg[:80]}")
        else:
            log.info(f"[{event['severity']}] {event['event']} {hostname}: {msg[:80]}")

        # 根据配置选择输出通道
        if OutputConfig.MODE == "kafka":
            send_to_kafka(event, hostname)
        else:
            send_to_http(event, hostname)


class ThreadedUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Syslog → Kafka / SOC 平台接入适配器")
    parser.add_argument("--soc", default="http://localhost:8001", help="SOC 平台后端地址 (HTTP 模式)")
    parser.add_argument("--kafka", default="", help="Kafka bootstrap 地址 (如 192.168.1.50:9092)")
    parser.add_argument("--api-key", default=DEFAULT_API_KEY, help="数据源 API Key")
    parser.add_argument("--port", type=int, default=514, help="UDP 监听端口")
    parser.add_argument("--host", default="0.0.0.0")
    args = parser.parse_args()

    OutputConfig.API_KEY = args.api_key

    if args.kafka:
        if not HAS_KAFKA:
            log.error("kafka-python 未安装，请运行: pip install kafka-python")
            exit(1)
        OutputConfig.MODE = "kafka"
        OutputConfig.KAFKA_BOOTSTRAP = args.kafka
        OutputConfig.kafka_producer = SyncKafkaProducer(
            bootstrap_servers=args.kafka,
            acks="all",
            retries=3,
        )
        log.info(f"Syslog 适配器启动 (Kafka): udp://{args.host}:{args.port} → kafka:{KAFKA_TOPIC_RAW} @ {args.kafka}")
    else:
        OutputConfig.MODE = "http"
        OutputConfig.SO_URL = args.soc.rstrip("/")
        log.info(f"Syslog 适配器启动 (HTTP): udp://{args.host}:{args.port} → {OutputConfig.SO_URL}/api/logs/ingest")

    server = ThreadedUDPServer((args.host, args.port), SyslogHandler)
    server.serve_forever()
