"""
安全日志源模拟器 — 模拟真实安全设备的持续日志流

用法:
  python log_simulator.py                     # 默认: 持续模式, 每3秒一条 (HTTP)
  python log_simulator.py --mode burst        # 突发模式: 快速注入50条
  python log_simulator.py --mode chain        # 攻击链模式: 模拟完整攻击路径
  python log_simulator.py --interval 1        # 自定义间隔(秒)
  python log_simulator.py --count 100         # 限制总条数
  python log_simulator.py --api http://localhost:8001  # 指定后端地址

  Kafka 模式 (推荐):
  python log_simulator.py --kafka localhost:9092                # 输出到 Kafka
  python log_simulator.py --kafka localhost:9092 --mode chain   # 攻击链 → Kafka
  python log_simulator.py --kafka localhost:9092 --api-key soc-simulator-2024
"""
import argparse
import asyncio
import json
import random
import time
import uuid

import httpx

# Kafka 可选依赖
try:
    from aiokafka import AIOKafkaProducer
    HAS_KAFKA = True
except ImportError:
    HAS_KAFKA = False

KAFKA_TOPIC_RAW = "security-logs-raw"
DEFAULT_API_KEY = "soc-simulator-2024"

# ── 正常事件模板 ──

NORMAL_EVENTS = [
    {"event": "USER_LOGIN", "severity": "info", "protocol": "rdp",
     "message": "管理员登录成功", "confidence": 95},
    {"event": "FILE_ACCESS", "severity": "info", "protocol": "smb",
     "message": "用户访问共享文件夹", "confidence": 90},
    {"event": "DNS_QUERY", "severity": "low", "protocol": "dns",
     "message": "DNS解析请求", "confidence": 85},
    {"event": "EMAIL_SENT", "severity": "info", "protocol": "smtp",
     "message": "邮件发送成功", "confidence": 90},
    {"event": "VPN_CONNECT", "severity": "info", "protocol": "ikev2",
     "message": "VPN隧道建立", "confidence": 92},
    {"event": "SERVICE_START", "severity": "info", "protocol": "local",
     "message": "系统服务启动完成", "confidence": 95},
    {"event": "BACKUP_COMPLETE", "severity": "info", "protocol": "local",
     "message": "定时备份任务完成", "confidence": 98},
    {"event": "CERT_RENEW", "severity": "low", "protocol": "https",
     "message": "SSL证书自动续期", "confidence": 90},
]

# ── 攻击事件模板 ──

ATTACK_EVENTS = [
    {"event": "PORT_SCAN", "severity": "medium", "protocol": "tcp",
     "message": "检测到端口扫描行为", "confidence": 70},
    {"event": "BRUTE_FORCE", "severity": "high", "protocol": "ssh",
     "message": "SSH暴力破解攻击已拦截", "confidence": 85},
    {"event": "SQL_INJECTION", "severity": "high", "protocol": "http",
     "message": "检测到SQL注入攻击尝试", "confidence": 80},
    {"event": "C2_BEACON", "severity": "critical", "protocol": "https",
     "message": "内部主机疑似与C2服务器通信", "confidence": 85},
    {"event": "DATA_EXFIL", "severity": "critical", "protocol": "http",
     "message": "检测到大量数据外传", "confidence": 88},
    {"event": "MALWARE_DETECT", "severity": "critical", "protocol": "local",
     "message": "终端检测到恶意软件", "confidence": 90},
    {"event": "DDoS_TRAFFIC", "severity": "high", "protocol": "tcp",
     "message": "检测到DDoS攻击流量", "confidence": 75},
    {"event": "LATERAL_MOVE", "severity": "high", "protocol": "smb",
     "message": "检测到横向移动行为", "confidence": 78},
    {"event": "PRIVILEGE_ESCALATION", "severity": "critical", "protocol": "local",
     "message": "检测到权限提升尝试", "confidence": 82},
    {"event": "XSS_ATTACK", "severity": "medium", "protocol": "http",
     "message": "检测到跨站脚本攻击", "confidence": 72},
]

# ── 攻击链场景 ──

ATTACK_CHAIN = [
    {"event": "PORT_SCAN", "severity": "medium", "protocol": "tcp",
     "message": "外部IP对内网进行端口扫描", "confidence": 65,
     "src_ip": "45.33.32.156", "dst_ip": "192.168.1.100", "delay": 0},
    {"event": "PORT_SCAN", "severity": "medium", "protocol": "tcp",
     "message": "端口扫描持续，发现开放SSH/RDP服务", "confidence": 70,
     "src_ip": "45.33.32.156", "dst_ip": "192.168.1.100", "delay": 3},
    {"event": "BRUTE_FORCE", "severity": "high", "protocol": "ssh",
     "message": "SSH暴力破解攻击，已尝试200+密码", "confidence": 82,
     "src_ip": "45.33.32.156", "dst_ip": "192.168.1.100", "delay": 5},
    {"event": "BRUTE_FORCE", "severity": "critical", "protocol": "ssh",
     "message": "SSH暴力破解成功，攻击者获得初始访问权限", "confidence": 92,
     "src_ip": "45.33.32.156", "dst_ip": "192.168.1.100", "delay": 8},
    {"event": "PRIVILEGE_ESCALATION", "severity": "critical", "protocol": "local",
     "message": "攻击者尝试提权至SYSTEM", "confidence": 85,
     "src_ip": "192.168.1.100", "dst_ip": "192.168.1.100", "delay": 6},
    {"event": "LATERAL_MOVE", "severity": "high", "protocol": "smb",
     "message": "攻击者通过SMB横向移动至文件服务器", "confidence": 80,
     "src_ip": "192.168.1.100", "dst_ip": "192.168.1.200", "delay": 10},
    {"event": "DATA_EXFIL", "severity": "critical", "protocol": "https",
     "message": "大量敏感数据通过HTTPS外传至境外IP", "confidence": 90,
     "src_ip": "192.168.1.200", "dst_ip": "23.129.64.33", "delay": 15},
    {"event": "C2_BEACON", "severity": "critical", "protocol": "https",
     "message": "文件服务器与C2服务器建立持久化通信", "confidence": 88,
     "src_ip": "192.168.1.200", "dst_ip": "23.129.64.33", "delay": 5},
]

INTERNAL_IPS = [
    "192.168.1.10", "192.168.1.50", "192.168.1.100",
    "192.168.1.150", "192.168.1.200", "10.0.0.5",
]
EXTERNAL_IPS = [
    "45.33.32.156", "103.235.46.22", "119.23.107.2",
    "203.0.113.1", "23.129.64.33", "185.220.101.1",
]


def random_ip(external=False):
    return random.choice(EXTERNAL_IPS if external else INTERNAL_IPS)


def make_event(template: dict, override: dict = None) -> dict:
    evt = dict(template)
    if "src_ip" not in evt:
        is_attack = evt["severity"] in ("high", "critical", "medium") and evt["event"] not in ("DNS_QUERY",)
        evt["src_ip"] = random_ip(external=is_attack)
        evt["dst_ip"] = random_ip(external=False)
    if override:
        evt.update(override)
    return evt


def generate_continuous(attack_ratio: float = 0.25) -> dict:
    if random.random() < attack_ratio:
        return make_event(random.choice(ATTACK_EVENTS))
    return make_event(random.choice(NORMAL_EVENTS))


def to_kafka_message(evt: dict, api_key: str, source_id: str) -> dict:
    """将事件转换为 Kafka 消息格式（与 Flink LogValidationJob 对接）"""
    return {
        "eventId": str(uuid.uuid4()),
        "sourceId": source_id,
        "apiKey": api_key,
        "eventType": evt.get("event", "UNKNOWN"),
        "severity": evt.get("severity", "info"),
        "srcIp": evt.get("src_ip", ""),
        "dstIp": evt.get("dst_ip", ""),
        "protocol": evt.get("protocol", ""),
        "message": evt.get("message", ""),
        "confidence": evt.get("confidence", 50),
        "timestamp": int(time.time() * 1000),
        "rawData": evt,
    }


async def create_kafka_producer(bootstrap: str) -> "AIOKafkaProducer":
    """创建 Kafka 生产者"""
    if not HAS_KAFKA:
        raise RuntimeError("aiokafka 未安装，请运行: pip install aiokafka")
    producer = AIOKafkaProducer(
        bootstrap_servers=bootstrap,
        value_serializer=lambda v: json.dumps(v, ensure_ascii=False).encode("utf-8"),
        key_serializer=lambda k: k.encode("utf-8") if k else None,
        acks="all",
    )
    await producer.start()
    return producer


async def run_continuous_kafka(bootstrap: str, api_key: str, interval: float,
                                count: int, source_id: str):
    """持续模式 (Kafka): 按间隔生成事件流 → Kafka"""
    print(f"[持续模式-Kafka] Bootstrap={bootstrap} 间隔={interval}s 条数={'无限' if count == 0 else count}")
    print(f"[持续模式-Kafka] Source: {source_id} API-Key: {api_key[:8]}...")
    print("-" * 60)

    producer = await create_kafka_producer(bootstrap)
    sent = 0
    try:
        while count == 0 or sent < count:
            evt = generate_continuous()
            msg = to_kafka_message(evt, api_key, source_id)
            await producer.send(KAFKA_TOPIC_RAW, key=msg["srcIp"], value=msg)
            sent += 1
            is_attack = evt["severity"] in ("high", "critical")
            flag = "🔴" if is_attack else "  "
            print(
                f"{flag} #{sent:04d} [{evt['severity']:8s}] {evt['event']:24s} "
                f"{evt.get('src_ip', ''):>15s} → {evt.get('dst_ip', ''):15s} "
                f"→ kafka:{KAFKA_TOPIC_RAW}"
            )
            await asyncio.sleep(interval)
    finally:
        await producer.stop()
    print(f"\n[完成] 共发送 {sent} 条事件到 Kafka")


async def run_burst_kafka(bootstrap: str, api_key: str, count: int, source_id: str):
    """突发模式 (Kafka): 快速批量注入"""
    print(f"[突发模式-Kafka] 快速注入 {count} 条事件 → {bootstrap}")
    print("-" * 60)

    producer = await create_kafka_producer(bootstrap)
    t0 = time.time()
    try:
        for i in range(count):
            evt = generate_continuous(attack_ratio=0.3)
            msg = to_kafka_message(evt, api_key, source_id)
            await producer.send(KAFKA_TOPIC_RAW, key=msg["srcIp"], value=msg)
        await producer.flush()
    finally:
        await producer.stop()
    elapsed = time.time() - t0
    print(f"[完成] {count} 条事件, 耗时 {elapsed:.1f}s → kafka:{KAFKA_TOPIC_RAW}")


async def run_chain_kafka(bootstrap: str, api_key: str, source_id: str):
    """攻击链模式 (Kafka): 模拟完整攻击路径"""
    print("[攻击链模式-Kafka] 端口扫描 → 暴力破解 → 提权 → 横向移动 → 数据外泄 → C2")
    print(f"  → kafka:{KAFKA_TOPIC_RAW} @ {bootstrap}")
    print("-" * 60)

    producer = await create_kafka_producer(bootstrap)
    try:
        for i, step in enumerate(ATTACK_CHAIN):
            delay = step.get("delay", 2)
            if delay > 0 and i > 0:
                print(f"  ⏳ 等待 {delay}s...")
                await asyncio.sleep(delay)

            evt = make_event(step)
            msg = to_kafka_message(evt, api_key, source_id)
            await producer.send(KAFKA_TOPIC_RAW, key=msg["srcIp"], value=msg)
            print(
                f"  🔴 [{i+1}/{len(ATTACK_CHAIN)}] {evt['event']:24s} "
                f"{evt.get('src_ip', '')} → {evt.get('dst_ip', '')} "
                f"→ kafka"
            )
    finally:
        await producer.stop()

    print(f"\n[完成] 攻击链 {len(ATTACK_CHAIN)} 步已注入 Kafka")
    print("  Flink CEP 将自动检测攻击链模式...")


async def run_continuous(api: str, interval: float, count: int, session_id: str):
    """持续模式: 按间隔生成事件流"""
    print(f"[持续模式] API={api} 间隔={interval}s 条数={'无限' if count == 0 else count}")
    print(f"[持续模式] Session: {session_id}")
    print("-" * 60)

    sent = 0
    async with httpx.AsyncClient(timeout=30) as client:
        while count == 0 or sent < count:
            evt = generate_continuous()
            try:
                resp = await client.post(
                    f"{api}/api/logs/ingest",
                    json={"message": evt, "session_id": session_id},
                )
                data = resp.json()
                sent += 1
                anomaly = data.get("anomaly", {})
                score = anomaly.get("score", 0)
                flag = "⚠️ " if anomaly.get("is_anomaly") else "  "
                print(
                    f"{flag}#{sent:04d} [{evt['severity']:8s}] {evt['event']:24s} "
                    f"{evt['src_ip']:>15s} → {evt.get('dst_ip', ''):15s} "
                    f"anomaly={score:.2f} event_id={data.get('event_id', '?')}"
                )
            except Exception as e:
                print(f"  ❌ 发送失败: {e}")

            await asyncio.sleep(interval)

    print(f"\n[完成] 共发送 {sent} 条事件")


async def run_burst(api: str, count: int, session_id: str):
    """突发模式: 快速批量注入"""
    print(f"[突发模式] 快速注入 {count} 条事件")
    print("-" * 60)

    events = [generate_continuous(attack_ratio=0.3) for _ in range(count)]

    async with httpx.AsyncClient(timeout=60) as client:
        t0 = time.time()
        resp = await client.post(
            f"{api}/api/logs/ingest/batch",
            json={"logs": events, "session_id": session_id},
        )
        elapsed = time.time() - t0
        data = resp.json()
        print(f"[完成] {data.get('count', count)} 条事件, 耗时 {elapsed:.1f}s")
        print(f"  Session: {session_id}")

        # 等待分析
        print("\n[等待] Audit-LLM 流水线处理中...")
        for i in range(30):
            await asyncio.sleep(3)
            try:
                status = await client.get(
                    f"{api}/api/logs/status",
                    params={"session_id": session_id},
                )
                s = status.json()
                total = s.get("total_events", 0)
                analyzed = s.get("analyzed", 0)
                pending = s.get("pending", 0)
                print(f"  [{i*3+3:3d}s] 总计={total} 已分析={analyzed} 待处理={pending}")
                if pending == 0 and total > 0:
                    print("[完成] 所有事件分析完毕")
                    break
            except Exception:
                pass


async def run_chain(api: str, session_id: str):
    """攻击链模式: 模拟完整攻击路径"""
    print("[攻击链模式] 模拟: 端口扫描 → 暴力破解 → 提权 → 横向移动 → 数据外泄 → C2")
    print("-" * 60)

    async with httpx.AsyncClient(timeout=30) as client:
        for i, step in enumerate(ATTACK_CHAIN):
            delay = step.pop("delay", 2)
            if delay > 0 and i > 0:
                print(f"  ⏳ 等待 {delay}s...")
                await asyncio.sleep(delay)

            evt = make_event(step)
            try:
                resp = await client.post(
                    f"{api}/api/logs/ingest",
                    json={"message": evt, "session_id": session_id},
                )
                data = resp.json()
                anomaly = data.get("anomaly", {})
                print(
                    f"  🔴 [{i+1}/{len(ATTACK_CHAIN)}] {evt['event']:24s} "
                    f"{evt['src_ip']} → {evt['dst_ip']} "
                    f"anomaly={anomaly.get('score', 0):.2f} "
                    f"event_id={data.get('event_id', '?')}"
                )
            except Exception as e:
                print(f"  ❌ 步骤 {i+1} 失败: {e}")

    print(f"\n[完成] 攻击链 {len(ATTACK_CHAIN)} 步已注入")
    print(f"  Session: {session_id}")
    print("  等待 Audit-LLM 分析 + 响应引擎执行...")

    # 查询攻击链检测结果
    await asyncio.sleep(15)
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.get(
                f"{api}/api/security/chains",
                params={"session_id": session_id},
            )
            chains = resp.json()
            if chains.get("chains"):
                print(f"\n[攻击链检测] 发现 {len(chains['chains'])} 条攻击链:")
                for c in chains["chains"]:
                    print(f"  🔗 {c['pattern_name']} (置信度={c['confidence']})")
                    print(f"     告警: {c['alert']}")
            else:
                print("\n[攻击链检测] 暂未检测到攻击链（可能仍在分析中）")
        except Exception as e:
            print(f"  查询攻击链失败: {e}")

        # 查询响应日志
        try:
            resp = await client.get(
                f"{api}/api/response/logs",
                params={"session_id": session_id, "limit": 10},
            )
            logs = resp.json()
            if logs:
                print(f"\n[响应日志] 共 {len(logs)} 条响应记录:")
                for log in logs:
                    status = "✅" if log.get("action_success") else "❌"
                    print(
                        f"  {status} {log.get('action_name', '?'):16s} "
                        f"IP={log.get('src_ip', '?'):15s} "
                        f"策略={log.get('policy_name', '?')}"
                    )
        except Exception as e:
            print(f"  查询响应日志失败: {e}")


def main():
    parser = argparse.ArgumentParser(description="安全日志源模拟器")
    parser.add_argument("--mode", choices=["continuous", "burst", "chain"],
                        default="continuous", help="运行模式")
    parser.add_argument("--api", default="http://localhost:8001",
                        help="后端 API 地址 (HTTP 模式)")
    parser.add_argument("--kafka", default="",
                        help="Kafka bootstrap 地址 (如 localhost:9092)，启用 Kafka 模式")
    parser.add_argument("--api-key", default=DEFAULT_API_KEY,
                        help="数据源 API Key (Kafka 模式认证)")
    parser.add_argument("--interval", type=float, default=3.0,
                        help="持续模式的事件间隔(秒)")
    parser.add_argument("--count", type=int, default=0,
                        help="事件总数(0=无限)")
    parser.add_argument("--session", default="",
                        help="Session ID / Source ID(默认自动生成)")
    args = parser.parse_args()

    session_id = args.session or f"sim_{uuid.uuid4().hex[:12]}"

    # Kafka 模式
    if args.kafka:
        source_id = args.session or f"simulator-{uuid.uuid4().hex[:8]}"
        if args.mode == "continuous":
            asyncio.run(run_continuous_kafka(
                args.kafka, args.api_key, args.interval, args.count, source_id))
        elif args.mode == "burst":
            asyncio.run(run_burst_kafka(
                args.kafka, args.api_key, args.count or 50, source_id))
        elif args.mode == "chain":
            asyncio.run(run_chain_kafka(args.kafka, args.api_key, source_id))
        return

    # HTTP 直连模式（兼容旧版）
    if args.mode == "continuous":
        asyncio.run(run_continuous(args.api, args.interval, args.count, session_id))
    elif args.mode == "burst":
        asyncio.run(run_burst(args.api, args.count or 50, session_id))
    elif args.mode == "chain":
        asyncio.run(run_chain(args.api, session_id))


if __name__ == "__main__":
    main()
