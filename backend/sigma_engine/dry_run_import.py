"""
sigma_engine.dry_run_import — 候选 SigmaHQ 规则 dry-run 评估

用法:
    python -m sigma_engine.dry_run_import --rules-dir ./rules_community_active \
        --events sample_events.json --out report.txt

- 不修改任何平台规则/引擎: 在临时目录加载候选规则, 对样本事件(JSON 数组或 JSONL)跑
  pySigma 单事件命中, 输出每规则: 命中数 / 命中率(SIG-00x 级) 供「增量灰度」决策。
- 建议配合 COMMUNITY_RULES_GUIDE.md 的 P0/P1/P2 分档与 apply_mapping, 先小样本后扩容。
- shadow 语义: dry-run 本身只记录不告警, 命中统计即误报/命中评估依据。
"""
import argparse
import json
import os
import sys


def load_events(path: str):
    with open(path, "r", encoding="utf-8") as fh:
        raw = fh.read().strip()
    if raw.startswith("["):
        return json.loads(raw)
    # JSONL / 逐行 JSON
    events = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def main():
    ap = argparse.ArgumentParser(description="SigmaHQ 候选规则 dry-run 评估")
    ap.add_argument("--rules-dir", required=True, help="候选 SigmaHQ 规则目录(*.yml)")
    ap.add_argument("--events", required=True, help="样本事件: JSON 数组或 JSONL 文件")
    ap.add_argument("--out", default="", help="报告输出文件(默认 stdout)")
    ap.add_argument("--mapping", action="store_true",
                    help="先对事件应用 apply_mapping(平台字段→Sigma 标准字段)")
    args = ap.parse_args()

    if not os.path.isdir(args.rules_dir) or not os.listdir(args.rules_dir):
        print(f"[dry-run] rules dir 为空或不存在: {args.rules_dir}")
        return

    from sigma_engine.engine import PySigmaDetector
    from sigma_engine.mapping import apply_mapping

    events = load_events(args.events)
    if not events:
        print("[dry-run] 无样本事件")
        return

    det = PySigmaDetector(args.rules_dir, enforce=False)
    compiled = det._compiled
    total = len(events)
    stats = {r["rule_id"]: {"title": r["name"], "level": r["severity"],
                            "hit": 0, "hit_events": set()} for r in det._rules}

    for ev in events:
        e = apply_mapping(ev) if args.mapping else ev
        for hit in det.detect(e):
            if hit.rule_id in stats:
                stats[hit.rule_id]["hit"] += 1
                try:
                    stats[hit.rule_id]["hit_events"].add(hit.matched_fields.get("src_ip", ""))
                except Exception:
                    pass

    lines = []
    lines.append(f"# SigmaHQ dry-run 报告 (rules={len(compiled)}, events={total})")
    lines.append(f"{'rule_id':<42} {'level':<8} {'hit_count':<10} {'hit_rate':<8}")
    lines.append("-" * 80)
    for rid, s in sorted(stats.items(), key=lambda kv: kv[1]["hit"], reverse=True):
        if s["hit"] == 0:
            continue
        lines.append(f"{rid:<42} {s['level']:<8} {s['hit']:<10} "
                     f"{s['hit']/total:.2%}  ({len(s['hit_events'])} src_ip)")
    lines.append(f"\n未命中规则: {sum(1 for s in stats.values() if s['hit']==0)}/{len(stats)}")

    out = "\n".join(lines)
    print(out)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
        print(f"\n[dry-run] 报告写入 {args.out}")


if __name__ == "__main__":
    main()
