"""
sigma_engine.tools.promote_to_shadow — 把 dry-run 通过的候选 SigmaHQ 规则灰度接入

读取候选规则(dry-run 评估通过)并补 x-soc-* 扩展字段, 以 shadow 灰度写入
backend/sigma_engine/rules_community_active/ 供引擎自动加载(仅记录不告警)。

覆盖逻辑:
  - 自动分配下一个 C-编号(现有最大 C-00X + 1)。
  - 类别→attack_type 映射, confidence/action 默认可取 dry_run_report 或简化映射。
  - 保留候选原装 Sigma YAML(detection/logsource 不动), 追加 x-soc-*。
  - 检测目标是否已灰度(按规则 title 比对已有 rules_community_active/*.yml),
   已存在的跳过, 避免重复。

用法:
    python -m sigma_engine.tools.promote_to_shadow \
        --candidate-dir <候选规则目录> --rules web_path_traversal_exploitation_attempt.yml ...
    # 或 --all-ok 依据 dry_run_report.txt 中命中率>=阈值 的规则批量接入

门槛(缺省): 命中率>=50% 且 误报(负样本未命中) 由 dry_run 报告人工确认, 工具不代判误报。
"""
import argparse
import glob
import os
import re

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
SIGMA_ENGINE_DIR = os.path.dirname(PACKAGE_DIR)
ACTIVE_DIR = os.path.join(SIGMA_ENGINE_DIR, "rules_community_active")
REPORT_PATH = os.path.join(SIGMA_ENGINE_DIR, "rules_community_candidate", "dry_run_report.txt")

# 文件名(去后缀)→ 类别映射 → attack_type / 默认 confidence / action / severity 兜底
CATEGORY = {
    "web_path_traversal_exploitation_attempt": ("path_traversal", "high", "require_confirmation"),
    "web_susp_windows_path_uri":              ("data_exfiltration", "medium", "require_confirmation"),
    "web_webshell_regeorg":                   ("webshell", "high", "block_ip"),
    "web_sql_injection_in_access_logs":       ("sql_injection", "high", "block_ip"),
    "web_xss_in_access_logs":                 ("xss", "medium", "require_confirmation"),
    "web_ssti_in_access_logs":                ("ssti", "high", "block_ip"),
    "web_source_code_enumeration":            ("info_disclosure", "medium", "require_confirmation"),
    "web_java_payload_in_access_logs":        ("malware", "high", "block_ip"),
    "web_jndi_exploit":                       ("exploitation", "critical", "block_ip"),
}


def _next_cid() -> str:
    cids = []
    for fp in glob.glob(os.path.join(ACTIVE_DIR, "*.yml")):
        m = re.search(r"x-soc-id:\s*C-(\d+)", open(fp, "r", encoding="utf-8").read())
        if m:
            cids.append(int(m.group(1)))
    return f"C-{max(cids, default=0) + 1:03d}"


def _already_active(title: str) -> bool:
    for fp in glob.glob(os.path.join(ACTIVE_DIR, "*.yml")):
        if f"title: {title}" in open(fp, "r", encoding="utf-8").read():
            return True
    # 也按 "title 子串" 比对(SOC-C-00X 后缀)
    core = title.split("[SOC-")[0].strip()
    if core:
        for fp in glob.glob(os.path.join(ACTIVE_DIR, "*.yml")):
            txt = open(fp, "r", encoding="utf-8").read()
            if core.split(" [")[0] in txt:
                return True
    return False


def promote_rule(src_path: str, force: bool = False) -> str:
    stem = os.path.basename(src_path)[:-4]
    with open(src_path, "r", encoding="utf-8") as fh:
        text = fh.read().rstrip() + "\n"
    # 解析 title(首行 title: xxx)
    title_m = re.search(r"^title:\s*(.+)$", text, re.M)
    title = title_m.group(1).strip() if title_m else stem
    if _already_active(title) and not force:
        return f"SKIP: 已灰度(规则 {title})"
    cid = _next_cid()
    attack_type, confidence, action = CATEGORY.get(stem, ("custom", "medium", "alert"))
    # 追加 x-soc-* (不覆盖已有)
    for key, val in (("x-soc-id", cid), ("x-soc-attack_type", attack_type),
                     ("x-soc-confidence", confidence), ("x-soc-action", action),
                     ("x-soc-shadow", "true"), ("x-soc-source", "SigmaHQ")):
        if key not in text:
            text += f"{key}: {val}\n"
    dst = os.path.join(ACTIVE_DIR, f"{stem}.yml")
    with open(dst, "w", encoding="utf-8") as fh:
        fh.write(text)
    return f"OK: {stem} -> {cid} (shadow, attack_type={attack_type}, action={action})"


def _parse_report_pass(min_hit_rate: float) -> list[str]:
    """从 dry_run_report.txt 解析命中率>=阈值 的规则文件名(基于出现顺序与候选目录)。"""
    if not os.path.isfile(REPORT_PATH):
        return []
    passed = []
    for line in open(REPORT_PATH, "r", encoding="utf-8"):
        m = re.match(r"^(\S+)\s+\S+\s+\d+\s+([0-9.]+)%", line)
        if not m:
            continue
        rate = float(m.group(2))
        if rate >= min_hit_rate:
            passed.append(m.group(1))
    return passed


def main():
    ap = argparse.ArgumentParser(description="dry-run 通过候选规则灰度接入")
    ap.add_argument("--candidate-dir", required=True, help="候选规则目录(*.yml)")
    ap.add_argument("--rules", nargs="*", help="指定文件(可多个), 缺省用 dry_run_report.txt 通过集")
    ap.add_argument("--min-hit-rate", type=float, default=50.0, help="--all-ok 通过的命中率阈值(%%), 默认50")
    ap.add_argument("--force", action="store_true", help="覆盖已灰度的同 title 规则")
    args = ap.parse_args()

    if args.rules:
        targets = args.rules
    else:
        targets = _parse_report_pass(args.min_hit_rate)
        if not targets:
            print(f"[promote] 无命中率>={args.min_hit_rate}% 的通过规则(或报告不存在: {REPORT_PATH})")
            print("[promote] 可 --rules <file> 显式指定候选规则")
            return

    for name in targets:
        stem = name[:-4] if name.endswith(".yml") else name
        src = os.path.join(args.candidate_dir, f"{stem}.yml")
        if not os.path.isfile(src):
            print(f"[promote] 候选文件不存在, 跳过: {src}")
            continue
        print(f"[promote] {promote_rule(src, args.force)}")
    print("[promote] 灰度接入完成, 引擎 reload 后自动生效(shadow 不告警)。")


if __name__ == "__main__":
    main()
