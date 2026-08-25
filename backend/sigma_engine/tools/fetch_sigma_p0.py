"""
sigma_engine.tools.fetch_sigma_p0 — 拉取 SigmaHQ P0 候选规则到只读候选目录

用途:
    从 SigmaHQ 官方仓库(v2, github.com/SigmaHQ/sigma)挑选"与平台字段直接契合"的
    P0 类别代表规则(当前聚焦 rules/web/webserver_generic 下 cs-uri-query 类 web 攻击),
    复制到 backend/sigma_engine/rules_community_candidate/(只读候选, 不入库), 供 dry-run 评估。

设计:
  - P0 首批聚焦 Web 攻击: 规则用 cs-uri-query / cs-referer, 由 sigma_engine.mapping 的
    url→cs-uri-query 映射, 可直接命中平台归一化 web 事件。SSH/ES/端口等字段契合度更低,
    留待 P1(补 pipelines 字段映射)再扩。
  - 候选规则保留原装 Sigma YAML(detection/logsource 不动), 仅追加 x-soc-source: SigmaHQ
    标注以便溯源。评估通过后由 promote_to_shadow.py 补 x-soc-* 进 rules_community_active/。
  - 不修改任何现有规则/引擎。

用法:
    python -m sigma_engine.tools.fetch_sigma_p0 --source <SigmaHQ 缓目录|git URL> [--force]

    --source: 本地已 clone 的 SigmaHQ 仓库根目录(推荐), 或可直接 clone 的 git URL。
      缺省: 先尝试 ./_sigmahq_cache, 否则从 https://github.com/SigmaHQ/sigma.git 浅克隆。
    --force: 重新拉取(覆盖候选目录)。
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile

# 候选 P0 web 攻击规则(相对 SigmaHQ rules/web/webserver_generic/):
# 与平台 url/cs-uri-query 字段直接契合的类别代表。
_CANDIDATES = [
    "web_path_traversal_exploitation_attempt.yml",
    "web_susp_windows_path_uri.yml",
    "web_sql_injection_in_access_logs.yml",
    "web_xss_in_access_logs.yml",
    "web_ssti_in_access_logs.yml",
    "web_webshell_regeorg.yml",
    "web_source_code_enumeration.yml",
    "web_java_payload_in_access_logs.yml",
    "web_jndi_exploit.yml",
]

# 候选规则写入的相对子目录
CANDIDATE_SUBDIR = "rules_web_webserver_generic"

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))          # sigma_engine/tools
SIGMA_ENGINE_DIR = os.path.dirname(PACKAGE_DIR)                    # sigma_engine
CANDIDATE_DIR = os.path.join(SIGMA_ENGINE_DIR, "rules_community_candidate")

SIGMAHQ_GIT_URL = "https://github.com/SigmaHQ/sigma.git"


def _clone_or_resolve(source: str) -> str:
    """解析 --source: 若是已 clone 的目录则返回; 若是 git URL 则浅克隆到临时目录返回。"""
    if not source:
        raise SystemExit("必须提供 --source (SigmaHQ 仓库目录或 git URL)")
    if os.path.isdir(os.path.join(source, "rules")):
        return source
    # 视为 git URL
    tmp = tempfile.mkdtemp(prefix="sigmahq_")
    subprocess.run(
        ["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse",
         source, tmp],
        check=True, capture_output=True,
    )
    subprocess.run(["git", "sparse-checkout", "set", "rules/web/webserver_generic"],
                   cwd=tmp, check=True, capture_output=True)
    return tmp


def main():
    ap = argparse.ArgumentParser(description="拉取 SigmaHQ P0 候选规则到候选目录")
    ap.add_argument("--source", default="", help="SigmaHQ 仓库目录或 git URL")
    ap.add_argument("--force", action="store_true", help="覆盖候选目录")
    args = ap.parse_args()

    if os.path.isdir(CANDIDATE_DIR) and os.listdir(CANDIDATE_DIR) and not args.force:
        print(f"[fetch] 候选目录已存在且非空(可加 --force 覆盖): {CANDIDATE_DIR}")
        return

    src_root = _clone_or_resolve(args.source)
    web_dir = os.path.join(src_root, "rules", "web", "webserver_generic")
    if not os.path.isdir(web_dir):
        raise SystemExit(f"SigmaHQ 仓库缺少 rules/web/webserver_generic: {web_dir}")

    os.makedirs(CANDIDATE_DIR, exist_ok=True)
    dst_subdir = os.path.join(CANDIDATE_DIR, CANDIDATE_SUBDIR)
    os.makedirs(dst_subdir, exist_ok=True)

    fetched = []
    missing = []
    for fn in _CANDIDATES:
        src = os.path.join(web_dir, fn)
        if not os.path.isfile(src):
            missing.append(fn)
            continue
        with open(src, "r", encoding="utf-8") as fh:
            text = fh.read().rstrip() + "\n"
        # 追加溯源标注(不覆盖已有 x-soc-source)
        if "x-soc-source" not in text:
            text += "x-soc-source: SigmaHQ\n"
        dst = os.path.join(dst_subdir, fn)
        with open(dst, "w", encoding="utf-8") as fh:
            fh.write(text)
        fetched.append(fn)

    print(f"[fetch] 拉取 {len(fetched)}/{len(_CANDIDATES)} 条候选规则 -> {dst_subdir}")
    if missing:
        print(f"[fetch] 缺失(跳过): {missing}")
    print("[fetch] 候选规则保留原装 Sigma YAML, 仅追加 x-soc-source 标注。")
    if fetched:
        print("[fetch] 下一步: python -m sigma_engine.dry_run_import "
              f"--rules-dir {dst_subdir} --events <sample>.jsonl --mapping --out report.txt")


if __name__ == "__main__":
    main()
