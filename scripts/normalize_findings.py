#!/usr/bin/env python3
"""Normalize tfsec and Checkov JSON into a single findings document for OPA.

Both scanners describe the same conditions with different schemas and
different rule ID namespaces. Normalizing here keeps the Rego policy free
of tool-specific parsing.
"""
import json
import os
import sys
from pathlib import Path

ENV = os.environ.get('SCAN_ENV', 'vulnerable')

findings = []

tfsec_path = Path(f'scans/tfsec/output/{ENV}.json')
if tfsec_path.exists():
    for r in json.loads(tfsec_path.read_text()).get('results') or []:
        findings.append({
            "tool": "tfsec",
            "rule_id": r.get('long_id') or r.get('rule_id'),
            "message": r.get('rule_description', ''),
            "resource": r.get('resource', ''),
            "severity": r.get('severity', ''),
        })

ck_path = Path('scans/checkov/output/results_json.json')
if ck_path.exists():
    for c in json.loads(ck_path.read_text())['results'].get('failed_checks') or []:
        findings.append({
            "tool": "checkov",
            "rule_id": c['check_id'],
            "message": c.get('check_name', ''),
            "resource": c.get('resource', ''),
            "severity": c.get('severity') or '',
        })

prowler_path = Path(f'scans/prowler/output/{ENV}-scan.ocsf.json')
if prowler_path.exists():
    for f in json.loads(prowler_path.read_text()):
        if f.get('status_code') != 'FAIL':
            continue
        findings.append({
            "tool": "prowler",
            "rule_id": f['metadata']['event_code'],
            "message": f.get('status_detail') or f.get('finding_info', {}).get('desc', ''),
            "resource": (f.get('resources') or [{}])[0].get('uid', ''),
            "severity": f.get('severity', ''),
        })

out = {"findings": findings}
json.dump(out, sys.stdout, indent=2)
print(f"\n{len(findings)} findings normalized", file=sys.stderr)
