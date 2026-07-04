#!/usr/bin/env bash
set -euo pipefail
R="jayelbotvibe-web/purple-loop"
gh label create "telemetry" -c "#45B9F0" -f 2>/dev/null || true
gh api repos/$R/milestones -f title="v1.2" -f description="Honest non-zero coverage" >/dev/null 2>&1 || true
iss(){ gh issue create -R "$R" -t "$1" -b "$2" -m v1.2 -l "$3"; }

iss "Sysmon process-creation telemetry (Linux + Windows)" "Ensure Sysmon-for-Linux runs on the Linux victim and Windows Sysmon on the Windows VM, both logging ProcessCreate, and Wazuh collects them. AC: a captured Wazuh event on EACH platform contains populated Image, ParentImage, CommandLine." "telemetry,fix"
iss "Re-derive normalizer from REAL Sysmon events" "Using captured Sysmon events, map actual Wazuh field paths to canonical Image/ParentImage/CommandLine/User for both platforms. Commit captured events as testdata fixtures. AC: captured Windows+Linux events normalize to non-empty Image AND CommandLine; unit tests pass." "telemetry,fix"
iss "Re-baseline coverage honestly" "Re-run discovery.yml with real telemetry. Record real numbers (expect >0 DETECTED, <100%, with genuine MISSED). Update README, reports/samples/, CHANGELOG. AC: committed report shows >0 DETECTED and >=1 genuine MISSED." "telemetry,docs"
iss "Land & verify v1.2.0" "PR → green CI → merge → tag v1.2.0 → Landing Verification against origin per AGENT_SYNC_AND_VERIFY.md. AC: all PASS, hashes match." "telemetry"

echo "v1.2 backlog created."
