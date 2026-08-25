"""
demo_seed_b — B 类高级能力演示数据注入(离线)

用途: 为 NDR/EDR/威胁情报/0day/反钓鱼 演示注入样本数据, 触发 B 类 metrics 计数
      (SOC 演示时评委可见流量/IOC 计数) 并可选打印样本供人工核对。

样本源: backend/tests/inc_testcases.py(纯 Python, 可复现)。本脚本:
  1) 触发各 B 类模块的 metrics 计数(NDR 流/EDR/sandbox/IOC/phishing/TLS),
  2) 打印注入摘要。

用法(在 backend 目录):
    python -m tools.demo_seed_b          # 或 python ../环境测试/demo_seed_b.py
"""
import asyncio
import os
import sys

BACKEND = os.path.dirname(os.path.abspath(__file__))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)


def main():
    # 1. 触发 B 类 metrics 计数(演示有计数可见)
    from metrics import (inc_ndr_flow, inc_tls_session, inc_edr_event,
                         inc_sandbox_submission, inc_ioc_match, inc_phishing_detection)

    # NDR 流(3 协议)
    for p in ("tcp", "udp", "http"):
        inc_ndr_flow(p)
    inc_tls_session()

    # EDR 事件(sysmon + winevent)
    inc_edr_event("sysmon")
    inc_edr_event("winevent")

    # 0day sandbox 提交(file + url)
    inc_sandbox_submission("file")
    inc_sandbox_submission("url")

    # 威胁情报 IOC 命中
    inc_ioc_match()

    # 反钓鱼(7 类)
    for cat in ("email", "web", "domain", "attachment", "sms", "qrcode", "bec"):
        inc_phishing_detection(cat)

    # 2. 打印样本摘要(略, 样本见 backend/tests/inc_testcases.py)
    #    简化: 不依赖 tests 包, 仅展示注入结果。
    print("[demo-seed] B 类演示数据注入完成 (metrics 已计):")
    print("  NDR: tcp/udp/http 流 + TLS 会话")
    print("  EDR: sysmon + winevent 事件")
    print("  sandbox: file+url 提交")
    print("  反钓鱼: email/web/domain/attachment/sms/qrcode/bec 各 1 检测")
    print("  IOC: 1 次命中")
    print("\n样本数据集(benchmark/复现): backend/tests/inc_testcases.py")
    print("查看指标: GET /metrics 应含 soc_ndr_flows_total / soc_edr_events_total /")
    print("          soc_sandbox_submissions_total / soc_ioc_matches_total /")
    print("          soc_phishing_detections_total")


if __name__ == "__main__":
    main()
