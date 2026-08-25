"""
sigma_engine.tools.make_sample_events — 构造 dry-run 评估样本事件集

生成平台归一化安全事件 JSONL(字段与 log_ingestion 一致: url/src_ip/dst_ip/event/
message/severity), 用于 sigma_engine.dry_run_import 对候选规则做命中率/误报评估。

样本设计说明:
  - 正样本精确贴合候选规则的 detection 模式(如 path_traversal 的 contains 字符串、
    susp_windows 的 =C:/Windows 等), 以反映"该特征事件在平台上能否被规则命中"。
  - 负样本为正常 web 流量, 用于测误报。

输出: rules_community_candidate/sample_events.jsonl
用法: python -m sigma_engine.tools.make_sample_events [--out PATH]
"""
import argparse
import json
import os

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
SIGMA_ENGINE_DIR = os.path.dirname(PACKAGE_DIR)
DEFAULT_OUT = os.path.join(SIGMA_ENGINE_DIR, "rules_community_candidate", "sample_events.jsonl")


def _ev(url, event="REQ", severity="medium", src="1.2.3.4", dst="10.0.0.5",
        attack=False, message="", **kw) -> dict:
    return {
        "event": event,
        "src_ip": src,
        "dst_ip": dst,
        "url": url,
        "message": message or url,
        "severity": severity,
        "attack": attack,   # 供报告人工比对, 不参与匹配
        **kw,
    }


def build_events() -> list[dict]:
    events = []
    # ── 正样本: 路径遍历（贴合 web_path_traversal 的 cs-uri-query contains 模式）──
    events.append(_ev("/../../../etc/passwd", severity="high", attack=True,
                      message="path traversal /etc/passwd"))
    events.append(_ev("/a/../../../../windows/win.ini", severity="high", attack=True))
    events.append(_ev("/login.jsp?..%252f..%252f..%252fetc%252fpasswd", severity="high", attack=True))
    events.append(_ev("/assets/..%c0%af..%c0%af..%c0%afetc%c0%afshadow", severity="high", attack=True))
    events.append(_ev("/doc/%252e%252e%252fetc%252fpasswd", severity="high", attack=True))
    # ── 正样本: 可疑 Windows 路径（贴合 web_susp_windows_path_uri 的 =C:/... 模式）──
    events.append(_ev("/download.php?file=C:/Windows/system32/config/SAM", severity="medium", attack=True))
    events.append(_ev("/?path=C:/Users/Public/Desktop/note.txt", severity="medium", attack=True))
    events.append(_ev("/dl?f=C%3A%5CProgram%20Files%5Capp%5Cdata.db", severity="medium", attack=True))
    # ── 正样本: SQL 注入（贴合 web_sql_injection 的 keywords: =select / @@version 等; 需 cs-method=GET + 非404状态）──
    events.append(_ev("/api/users?id=1%3Dselect%20password&x=1", severity="high", attack=True, method="GET", status=200))
    events.append(_ev("/search?q=1%27%27%27%27%27%3D%27", severity="high", attack=True, method="GET", status=200))
    events.append(_ev("/login.php?user=1+UNION+select+@@version,2,3", severity="high", attack=True, method="GET", status=200))
    # ── 正样本: XSS（贴合 web_xss keywords: =<script> / <iframe 等; 需 cs-method=GET）──
    events.append(_ev("/q?=<script>alert(1)</script>", severity="high", attack=True, method="GET", status=200))
    events.append(_ev("/comment?body=<iframe%20src=evil>", severity="high", attack=True, method="GET", status=200))
    # ── 正样本: SSTI（贴合 web_ssti keywords: ={{ / =${ 等; 需 cs-method=GET）──
    events.append(_ev("/welcome?name=%7B%7Bconfig%7D%7D", severity="high", attack=True, method="GET", status=200))
    events.append(_ev("/post?tpl=${7*7}", severity="high", attack=True, method="GET", status=200))
    # ── 正样本: 源码枚举（贴合 web_source_code_enumeration keywords: .git/）──
    events.append(_ev("/repo/.git/HEAD", severity="medium", attack=True))
    events.append(_ev("/static/.git/config", severity="medium", attack=True))
    # ── 负样本: 正常 web 流量（不应命中）──
    events.append(_ev("/", message="index page"))
    events.append(_ev("/static/app.js", message="static asset"))
    events.append(_ev("/api/login?user=admin", message="login endpoint"))
    events.append(_ev("/home/dashboard", message="dashboard"))
    events.append(_ev("/img/logo.png", message="image asset"))
    return events


def main():
    ap = argparse.ArgumentParser(description="构造 dry-run 样本事件集")
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args()
    events = build_events()
    with open(args.out, "w", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e, ensure_ascii=False) + "\n")
    pos = sum(1 for e in events if e["attack"])
    neg = len(events) - pos
    print(f"[sample] 写出 {len(events)} 条事件 -> {args.out}")
    print(f"[sample] 正样本(攻击)={pos} 负样本(正常)={neg}")
    print("[sample] 注意: webshell/regeorg 规则依赖 cs-referer/cs-user-agent/cs-method 字段,")
    print("[sample]  平台 web 事件当前仅归一化 url, 该规则契合度低, dry-run 不会命中(属预期)。")


if __name__ == "__main__":
    main()
