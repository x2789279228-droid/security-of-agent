"""命令行跑一局自博弈: python -m self_play --rounds 8"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


async def _main() -> int:
    parser = argparse.ArgumentParser(description="Red vs Blue Self-Play")
    parser.add_argument("--rounds", type=int, default=8)
    parser.add_argument("--level", type=int, default=0)
    parser.add_argument("--inject", action="store_true")
    parser.add_argument("--llm", action="store_true")
    parser.add_argument("--full-attack", action="store_true",
                        help="使用 ATT&CK Enterprise 全量池,不限课程 9 条")
    parser.add_argument("--no-persist", action="store_true")
    parser.add_argument("--decoy", type=float, default=0.2)
    args = parser.parse_args()

    from config import settings
    from models import init_db
    from self_play.orchestrator import orchestrator
    from self_play.types import MatchConfig

    await init_db()
    result = await orchestrator.run_match(MatchConfig(
        rounds=args.rounds,
        start_level=args.level,
        inject=args.inject,
        use_llm=bool(args.llm or settings.self_play_use_llm),
        curriculum=not args.full_attack,
        persist=not args.no_persist,
        decoy_ratio=args.decoy,
    ))
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
