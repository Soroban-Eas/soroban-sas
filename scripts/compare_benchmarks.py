#!/usr/bin/env python3
"""Compare independent Criterion samples. Fail closed for absent or malformed data."""
import argparse
import json
from pathlib import Path

def load(root: Path, baseline: str):
    measurements = {}
    for path in root.rglob(f"{baseline}/estimates.json"):
        # Criterion stores each benchmark under its own group/function tree.
        key = str(path.parent.parent.relative_to(root))
        data = json.loads(path.read_text())
        value = data["mean"]["point_estimate"]
        if not isinstance(value, (int, float)) or value <= 0:
            raise ValueError(f"invalid Criterion mean: {path}")
        measurements[key] = float(value)
    return measurements

def compare(before, after, threshold):
    keys = sorted(before.keys() & after.keys())
    if not keys:
        raise ValueError("no common Criterion samples found; cannot verify regression")
    lines = ["## Criterion regression report", "",
             "| Benchmark | Base (ns) | PR (ns) | Delta | Result |",
             "|---|---:|---:|---:|---|"]
    regressed = []
    for key in keys:
        diff = 100 * (after[key] - before[key]) / before[key]
        failed = diff > threshold
        if failed:
            regressed.append(key)
        lines.append(f"| `{key}` | {before[key]:,.0f} | {after[key]:,.0f} | {diff:+.1f}% | {'REGRESSION' if failed else 'OK'} |")
    missing = sorted(before.keys() ^ after.keys())
    if missing:
        lines += ["", "Missing benchmark samples (comparison incomplete): " + ", ".join(missing)]
    lines += ["", f"Threshold: **{threshold:g}%**. Mean execution time measured by Criterion.",
              "Memory allocations are **not measured** by these CPU benchmarks.",
              f"Status: **{'FAIL' if regressed or missing else 'PASS'}**."]
    return "\n".join(lines) + "\n", bool(regressed or missing)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("base", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--threshold", type=float, default=10)
    parser.add_argument("--output", type=Path, default=Path("benchmark-report.md"))
    args = parser.parse_args()
    if args.threshold < 0:
        parser.error("threshold must not be negative")
    try:
        base = load(args.base, "base")
        candidate = load(args.candidate, "candidate")
        report, failed = compare(base, candidate, args.threshold)
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as error:
        report = f"## Criterion regression report\n\nStatus: **FAIL** — {error}\n"
        failed = True
    args.output.write_text(report)
    print(report)
    raise SystemExit(1 if failed else 0)

if __name__ == "__main__":
    main()
