"""离线处理比赛 JSON：python cli.py input.json -o result.json"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

try:
    from .prompt_guard import PromptInjectionGuard
except ImportError:  # python cli.py
    from prompt_guard import PromptInjectionGuard


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path, help="JSON 数组文件")
    parser.add_argument("-o", "--output", type=Path, default=Path("guard_results.json"))
    args = parser.parse_args()
    records = json.loads(args.input.read_text(encoding="utf-8"))
    if not isinstance(records, list):
        raise SystemExit("输入 JSON 须为数组")
    guard = PromptInjectionGuard()
    results = [guard.analyze(item).to_dict() for item in records]
    args.output.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"已处理 {len(results)} 条记录，结果写入 {args.output}")


if __name__ == "__main__":
    main()
