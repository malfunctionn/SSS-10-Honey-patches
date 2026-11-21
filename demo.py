"""Run the base cases and the week-12 required cases in all three modes (spec 10.3). Owner: D.

  Windows: py demo.py      macOS: python3 demo.py

Prints one table per scenario, writes results/demo.txt and results/demo.json,
and ends with `ALL PASS` (exit 0) or `FAIL: <names>` (exit 1).
"""
import sys

# Keep this check before any other import so it also works on older Pythons.
if sys.version_info < (3, 9):
    print("Python 3.9 or later is required")
    sys.exit(2)

from pathlib import Path

from hpsim import report, runner

ROOT = Path(__file__).resolve().parent
SCENARIOS = [
    "normal",
    "attack",
    "boundary",
    "freed_session",
    "freed_session_nofreed",
]


def main() -> int:
    lines = []
    data = []
    failed = []
    for name in SCENARIOS:
        scenario = runner.load_scenario(ROOT / "scenarios" / (name + ".json"))
        result = runner.run_scenario(scenario)
        block = report.scenario_lines(result)
        report.print_lines(block)
        print(flush=True)
        lines.extend(block)
        lines.append("")
        data.append({k: v for k, v in result.items()})
        if not result["ok"]:
            failed.append(name)

    final = report.final_line(failed)
    lines.append(final)
    report.write_results(ROOT, lines, {"scenarios": data, "result": final})
    print(final, flush=True)
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
