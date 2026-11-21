"""Table and JSON output (spec 10.3). Owner: D.

Everything written to the console is ASCII only (spec 2.1).
"""
import json
from pathlib import Path
from typing import Iterable, List

# (header, width) for the fixed table columns; the body column follows "ms".
COLUMNS = [
    ("step", 5),
    ("mode", 14),
    ("status", 7),
    ("len", 5),
    ("handled", 8),
    ("forked", 7),
    ("redacted", 9),
    ("leaked", 7),
    ("ms", 6),
]


def show_body(data: bytes) -> str:
    """Printable ASCII as is, newline as \\n, every other byte as \\xNN."""
    out = []
    for b in data:
        if b == 0x0A:
            out.append("\\n")
        elif 0x20 <= b <= 0x7E:
            out.append(chr(b))
        else:
            out.append("\\x%02x" % b)
    return "".join(out)


def ascii_text(value) -> str:
    """Any value as an ASCII-only string (non-ASCII becomes \\uXXXX)."""
    return str(value).encode("ascii", "backslashreplace").decode("ascii")


def _cell(value, width: int) -> str:
    s = ascii_text(value)
    return s.ljust(width) if len(s) < width else s + " "


def _row_line(cells: List[str], body: str) -> str:
    line = "".join(_cell(v, w) for v, (_, w) in zip(cells, COLUMNS))
    return (line + body).rstrip()


def header_line() -> str:
    return _row_line([name for name, _ in COLUMNS], "body")


def row_line(row: dict) -> str:
    forked = row.get("forked")
    cells = [
        row["step"],
        row["mode"],
        "closed" if row.get("closed") else row.get("status", "-"),
        row.get("body_len", "-"),
        row.get("handled_by") or "-",
        "-" if forked is None else ("yes" if forked else "no"),
        "-" if row.get("redacted") is None else row["redacted"],
        row.get("leaked", "-"),
        "-" if row.get("ms") is None else "%.1f" % row["ms"],
    ]
    return _row_line(cells, row.get("body_text", ""))


def result_line(result: dict) -> str:
    verdict = "PASS" if result["ok"] else "FAIL"
    return "RESULT %s: %s (%d/%d)" % (result["name"], verdict, result["passed"], result["total"])


def scenario_lines(result: dict) -> List[str]:
    """Human-readable block for one scenario: title, table, problems, RESULT line."""
    lines = ["== %s ==" % result["name"], header_line()]
    rows = sorted(result["rows"], key=lambda r: (r["step"], r["mode_index"]))
    lines.extend(row_line(r) for r in rows)
    for r in rows:
        for m in r["mismatches"]:
            lines.append("  ! step %d %s: %s" % (r["step"], r["mode"], ascii_text(m)))
    for e in result["errors"]:
        lines.append("  ERROR " + ascii_text(e))
    lines.append(result_line(result))
    return lines


def final_line(failed: Iterable[str]) -> str:
    failed = list(failed)
    return "ALL PASS" if not failed else "FAIL: " + " ".join(failed)


def json_rows(result: dict) -> list:
    """The same rows as the table, as JSON-ready dicts (used by --json)."""
    keep = ("step", "mode", "status", "body_len", "handled_by", "forked", "fork_result",
            "redacted", "leaked", "closed", "ms", "body_text", "pass", "mismatches")
    rows = sorted(result["rows"], key=lambda r: (r["step"], r["mode_index"]))
    return [{k: r.get(k) for k in keep} for r in rows]


def write_text(path: Path, lines: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2, sort_keys=True, ensure_ascii=True)
        f.write("\n")


def write_results(root: Path, lines: List[str], data, stem: str = "demo") -> List[Path]:
    """Overwrite results/<stem>.txt (the table) and results/<stem>.json (raw data)."""
    txt = root / "results" / (stem + ".txt")
    js = root / "results" / (stem + ".json")
    write_text(txt, lines)
    write_json(js, data)
    return [txt, js]


def print_lines(lines: Iterable[str], file=None) -> None:
    for line in lines:
        print(line, file=file, flush=True)
