#!/usr/bin/env python3
"""Regression harness: validate fixture files are well-formed JSONL."""
import sys, json, glob, os

TESTS_DIR = "detections/tests"
errors = 0

for fixture_path in sorted(glob.glob(f"{TESTS_DIR}/**/*.jsonl", recursive=True)):
    name = os.path.relpath(fixture_path)
    try:
        with open(fixture_path) as f:
            lines = [l.strip() for l in f if l.strip()]
        if not lines:
            print(f"WARN: {name} is empty", file=sys.stderr)
            continue
        for i, line in enumerate(lines, 1):
            json.loads(line)
    except json.JSONDecodeError as e:
        print(f"FAIL: {name}:{i}: {e}", file=sys.stderr)
        errors += 1
    except Exception as e:
        print(f"FAIL: {name}: {e}", file=sys.stderr)
        errors += 1

if errors:
    print(f"\n{errors} fixture error(s)", file=sys.stderr)
    sys.exit(1)

print(f"All fixtures valid.")
