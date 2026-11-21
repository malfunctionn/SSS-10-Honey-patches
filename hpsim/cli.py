"""Command line (spec 10.3). Owner: D.

  python -m hpsim.cli run scenarios/attack.json [--mode all|unpatched|patched|honeypatched]
                                                [--redact on|off|nofreed] [--pool N] [--json]
  python -m hpsim.cli compare results/demo.txt other/demo.txt

`bench` (spec 12) is planned for week 14 (M7).
"""
import argparse
import json
import re
import sys
from pathlib import Path
from typing import List, Optional

from hpsim import report, runner

# A table line (header or row): 8 columns, then the ms column, then the body.
_TABLE_LINE = re.compile(r"^(?:step|\d+) +(?:mode|unpatched|patched|honeypatched) ")
_MS_COLUMN = re.compile(r"^((?:\S+ +){8})\S+ *")


def drop_ms(line: str) -> str:
    """Remove the ms column from a table line; other lines are returned unchanged."""
    line = line.rstrip("\r\n")
    if _TABLE_LINE.match(line):
        return _MS_COLUMN.sub(r"\1", line, count=1).rstrip()
    return line


def compare_files(a: Path, b: Path) -> List[int]:
    """Line numbers (1-based) that differ once the ms column is removed."""
    with open(a, "r", encoding="utf-8") as f:
        la = [drop_ms(x) for x in f.read().splitlines()]
    with open(b, "r", encoding="utf-8") as f:
        lb = [drop_ms(x) for x in f.read().splitlines()]
    diff = [i + 1 for i, (x, y) in enumerate(zip(la, lb)) if x != y]
    if len(la) != len(lb):
        diff.append(min(len(la), len(lb)) + 1)
    return diff


def cmd_compare(args) -> int:
    diff = compare_files(Path(args.a), Path(args.b))
    if not diff:
        print("SAME")
        return 0
    print("DIFF")
    print("differing lines: " + " ".join(str(n) for n in diff[:20]))
    return 1


def cmd_run(args) -> int:
    scenario = runner.load_scenario(args.scenario)
    modes = runner.MODES if args.mode == "all" else (args.mode,)
    result = runner.run_scenario(scenario, modes=modes, redact=args.redact, pool=args.pool)
    if args.json:
        out = {"name": result["name"], "ok": result["ok"], "passed": result["passed"],
               "total": result["total"], "errors": result["errors"],
               "rows": report.json_rows(result)}
        print(json.dumps(out, indent=2, ensure_ascii=True))
    else:
        report.print_lines(report.scenario_lines(result))
    return 0 if result["ok"] else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m hpsim.cli")
    sub = p.add_subparsers(dest="command")
    sub.required = True

    run = sub.add_parser("run", help="run one scenario file")
    run.add_argument("scenario")
    run.add_argument("--mode", default="all", choices=["all"] + list(runner.MODES))
    run.add_argument("--redact", choices=["on", "off", "nofreed"])
    run.add_argument("--pool", type=int)
    run.add_argument("--json", action="store_true")
    run.set_defaults(func=cmd_run)

    cmp_ = sub.add_parser("compare", help="compare two demo.txt files without the ms column")
    cmp_.add_argument("a")
    cmp_.add_argument("b")
    cmp_.set_defaults(func=cmd_compare)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
