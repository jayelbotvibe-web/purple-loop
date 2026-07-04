#!/usr/bin/env python3
"""Validate Sigma rules: YAML parse, required fields, fixture existence."""
import sys, os, yaml, json, glob

REQUIRED = ["title", "id", "status", "logsource", "detection"]
RULES_DIR = "detections/linux"
TESTS_DIR = "detections/tests"

def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    return 1

errors = 0
rules = glob.glob(f"{RULES_DIR}/*.yml")
if not rules:
    print(f"FAIL: no rules found in {RULES_DIR}", file=sys.stderr)
    sys.exit(1)

print(f"Checking {len(rules)} rules...")

for rule_path in sorted(rules):
    name = os.path.basename(rule_path).replace(".yml", "")
    try:
        with open(rule_path) as f:
            rule = yaml.safe_load(f)
    except yaml.YAMLError as e:
        errors += fail(f"{rule_path}: YAML parse error: {e}")
        continue

    for field in REQUIRED:
        if field not in rule:
            errors += fail(f"{rule_path}: missing required field '{field}'")

    # check fixtures exist
    for fixture in ["positive_events.jsonl", "negative_events.jsonl"]:
        fp = f"{TESTS_DIR}/{name}/{fixture}"
        if not os.path.exists(fp):
            errors += fail(f"{rule_path}: missing fixture {fp}")

if errors:
    print(f"\n{errors} error(s) found", file=sys.stderr)
    sys.exit(1)

print(f"All {len(rules)} rules valid.")
