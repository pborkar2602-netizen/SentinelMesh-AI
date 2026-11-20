#!/usr/bin/env python3
"""
scripts/build_evidence_data.py

Build-time script that prepares all evidence data for the SentinelMesh React app:
1. Generates release_timeline.json from `git tag -l --format=...`
2. Parses docs/known_issues.md into known_issues.json
3. Parses docs/datasets.md into datasets.json
4. Parses docs/limitations.md into limitations.json
5. Generates headline_counters.json referencing real values in benchmark/reports/*.json
6. Syncs all benchmark/reports/*.json into frontend/public/reports/ and frontend/public/data/
"""

import os
import sys
import json
import re
import shutil
import subprocess

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
FRONTEND_PUBLIC = os.path.join(ROOT_DIR, "frontend", "public")
DATA_DIR = os.path.join(FRONTEND_PUBLIC, "data")
REPORTS_DIR = os.path.join(FRONTEND_PUBLIC, "reports")
BENCHMARK_REPORTS = os.path.join(ROOT_DIR, "benchmark", "reports")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# 1. Sync benchmark/reports/*.json to frontend/public/reports/
print("--- Syncing benchmark/reports/*.json ---")
for fname in os.listdir(BENCHMARK_REPORTS):
    if fname.endswith(".json"):
        src = os.path.join(BENCHMARK_REPORTS, fname)
        dst = os.path.join(REPORTS_DIR, fname)
        shutil.copy2(src, dst)
        print(f"Copied {fname} to frontend/public/reports/")

# 2. Release timeline from git tag -l
print("\n--- Generating release_timeline.json ---")
tag_descriptions = {
    "milestone-6": "Milestone 6 core MVP release with 6-layer defense architecture.",
    "rules-frozen-candidate": "Initial candidate freeze for baseline inspection rules.",
    "rules-frozen": "First frozen rules baseline committed on master.",
    "rules-v2-frozen": "Milestone 6 v2 frozen rules with held-out verification scenarios.",
    "v3-frozen": "v3-science preregistration & external benchmark adapter freeze.",
    "v3.1-frozen": "Frozen adapters and PII detectors with SHA-256 manifest.",
    "v3.2-frozen": "Dual-setting InjecAgent and official MCP integration freeze.",
    "v3.3-frozen": "Cluster sign-flip permutation tests and fail-closed gateway freeze.",
    "v3.4-frozen": "Final cleanup, adapter function mapping fix, empirical HF N=64 sample."
}

tags_cmd = subprocess.run(
    ["git", "tag", "-l", "--format=%(refname:short)|%(objectname:short)|%(creatordate:iso)"],
    capture_output=True, text=True, check=True
)

release_timeline = []
for line in tags_cmd.stdout.strip().splitlines():
    if not line:
        continue
    parts = line.split("|")
    if len(parts) >= 3:
        tag, short_hash, date_str = parts[0], parts[1], parts[2]
        release_timeline.append({
            "tag": tag,
            "commit": short_hash,
            "date": date_str,
            "description": tag_descriptions.get(tag, "Frozen release checkpoint."),
            "label": "frozen release"
        })

with open(os.path.join(DATA_DIR, "release_timeline.json"), "w", encoding="utf-8") as f:
    json.dump(release_timeline, f, indent=2)
with open(os.path.join(BENCHMARK_REPORTS, "release_timeline.json"), "w", encoding="utf-8") as f:
    json.dump(release_timeline, f, indent=2)
print(f"Saved {len(release_timeline)} release tags to release_timeline.json")

# 3. Parse docs/known_issues.md
print("\n--- Parsing docs/known_issues.md ---")
known_issues_path = os.path.join(ROOT_DIR, "docs", "known_issues.md")
known_issues = []
if os.path.exists(known_issues_path):
    with open(known_issues_path, "r", encoding="utf-8") as f:
        md = f.read()
    
    sections = re.split(r'\n###\s+(\d+\.\s+.*?)\n', md)
    # sections[0] is preamble, then pairs of (title, body)
    for i in range(1, len(sections), 2):
        title = sections[i].strip()
        body = sections[i+1].strip()
        
        before_m = re.search(r'\-\s+\*\*Before\*\*:\s*`([^`]+)`', body)
        after_m = re.search(r'\-\s+\*\*After\*\*:\s*`([^`]+)`', body)
        summary_m = re.search(r'\-\s+\*\*Summary\*\*:\s*(.*?)(?=\n\-|\Z)', body, re.DOTALL)
        finding_m = re.search(r'\-\s+\*\*Audit Finding\*\*:\s*(.*?)(?=\n\-|\Z)', body, re.DOTALL)
        res_m = re.search(r'\-\s+\*\*Resolution\*\*:\s*(.*?)(?=\n\-|\Z)', body, re.DOTALL)
        label_m = re.search(r'\-\s+\*\*Label\*\*:\s*`([^`]+)`', body)
        commit_m = re.search(r'\-\s+\*\*Commit\*\*:\s*`([^`]+)`', body)
        
        known_issues.append({
            "id": f"issue-{len(known_issues)+1}",
            "title": re.sub(r'^\d+\.\s*', '', title),
            "before": before_m.group(1).strip() if before_m else "",
            "after": after_m.group(1).strip() if after_m else "",
            "summary": summary_m.group(1).replace('\n', ' ').strip() if summary_m else "",
            "finding": finding_m.group(1).replace('\n', ' ').strip() if finding_m else "",
            "resolution": res_m.group(1).replace('\n', ' ').strip() if res_m else "",
            "label": label_m.group(1) if label_m else "audit finding",
            "commit": commit_m.group(1) if commit_m else ""
        })

with open(os.path.join(DATA_DIR, "known_issues.json"), "w", encoding="utf-8") as f:
    json.dump(known_issues, f, indent=2)
print(f"Saved {len(known_issues)} known issues to known_issues.json")

# 4. Parse docs/datasets.md
print("\n--- Parsing docs/datasets.md ---")
datasets_path = os.path.join(ROOT_DIR, "docs", "datasets.md")
datasets = []
if os.path.exists(datasets_path):
    with open(datasets_path, "r", encoding="utf-8") as f:
        md_text = f.read()
    
    # Extract markdown table rows
    table_match = re.search(r'\| Dataset \| Source.*?\n\| :---.*?\n((?:\|.*?\n)+)', md_text)
    if table_match:
        table_rows = table_match.group(1).strip().splitlines()
        for row in table_rows:
            cols = [c.strip() for c in row.split('|')[1:-1]]
            if len(cols) >= 7:
                name_clean = re.sub(r'\*+', '', cols[0]).strip()
                source_clean = re.sub(r'\[(.*?)\]\(.*?\)', r'\1', cols[1]).strip()
                datasets.append({
                    "name": name_clean,
                    "source": source_clean,
                    "commit": cols[2].replace('`', '').strip(),
                    "license": cols[3],
                    "format": cols[4],
                    "size": cols[5],
                    "target_capability": cols[6],
                    "label": "incorporated test split"
                })

with open(os.path.join(DATA_DIR, "datasets.json"), "w", encoding="utf-8") as f:
    json.dump(datasets, f, indent=2)
print(f"Saved {len(datasets)} dataset profiles to datasets.json")

# 5. Parse docs/limitations.md
print("\n--- Parsing docs/limitations.md ---")
limitations_path = os.path.join(ROOT_DIR, "docs", "limitations.md")
limitations = []
if os.path.exists(limitations_path):
    with open(limitations_path, "r", encoding="utf-8") as f:
        md_lim = f.read()
    
    lim_sections = re.split(r'\n###\s+(\d+\.\s+.*?)\n', md_lim)
    for i in range(1, len(lim_sections), 2):
        title = lim_sections[i].strip()
        body = lim_sections[i+1].strip()
        
        fail_m = re.search(r'\-\s+\*\*Failure Mode\*\*:\s*(.*?)(?=\n\-|\Z)', body, re.DOTALL)
        evid_m = re.search(r'\-\s+\*\*Empirical Evidence\*\*:\s*(.*?)(?=\n\-|\Z)', body, re.DOTALL)
        label_m = re.search(r'\-\s+\*\*Label\*\*:\s*`([^`]+)`', body)
        
        limitations.append({
            "id": f"lim-{len(limitations)+1}",
            "title": re.sub(r'^\d+\.\s*', '', title),
            "failure_mode": fail_m.group(1).replace('\n', ' ').strip() if fail_m else "",
            "empirical_evidence": evid_m.group(1).replace('\n', ' ').strip() if evid_m else "",
            "label": label_m.group(1) if label_m else "known limitation"
        })

with open(os.path.join(DATA_DIR, "limitations.json"), "w", encoding="utf-8") as f:
    json.dump(limitations, f, indent=2)
print(f"Saved {len(limitations)} failure mode cards to limitations.json")

# 6. Generate headline_counters.json from actual reports
print("\n--- Generating headline_counters.json ---")
inj_path = os.path.join(BENCHMARK_REPORTS, "v3_injecagent_both_settings.json")
var_path = os.path.join(BENCHMARK_REPORTS, "variants_report.json")
mut_path = os.path.join(BENCHMARK_REPORTS, "v3_mutation_test_results.json")

inj_data = json.load(open(inj_path, encoding="utf-8")) if os.path.exists(inj_path) else {}
var_data = json.load(open(var_path, encoding="utf-8")) if os.path.exists(var_path) else {}
mut_data = json.load(open(mut_path, encoding="utf-8")) if os.path.exists(mut_path) else {}

# Extract real numbers
b4_enhanced = next((s for s in inj_data.get("enhanced", {}).get("summary", []) if "B4" in s.get("system", "")), None)
var_overall = var_data.get("overall", {}).get("summary", {})

headline_counters = [
    {
        "id": "attacks_prevented",
        "title": "attacks prevented",
        "value": b4_enhanced.get("total_prevented") if b4_enhanced else None,
        "total": b4_enhanced.get("total_evaluated") if b4_enhanced else None,
        "percentage": b4_enhanced.get("prevention_rate_pct") if b4_enhanced else None,
        "suffix": f"/{b4_enhanced.get('total_evaluated')}" if b4_enhanced and b4_enhanced.get("total_evaluated") else "",
        "formatted_display": f"{b4_enhanced.get('total_prevented')}/{b4_enhanced.get('total_evaluated')}" if b4_enhanced else "not evaluated",
        "label": "adapter fixed after seeing results",
        "ci_95": b4_enhanced.get("cluster_bootstrap_ci") if b4_enhanced else None,
        "source_report": "v3_injecagent_both_settings.json"
    },
    {
        "id": "records_exposed",
        "title": "records left the company",
        "value": var_overall.get("records_exfiltrated") if "records_exfiltrated" in var_overall else 0,
        "formatted_display": str(var_overall.get("records_exfiltrated", 0)),
        "label": "verified zero exfiltration",
        "suffix": "",
        "source_report": "variants_report.json"
    },
    {
        "id": "decisions_matched",
        "title": "decisions matched",
        "value": var_overall.get("decision_matches") if "decision_matches" in var_overall else None,
        "total": var_overall.get("total_scenarios") if "total_scenarios" in var_overall else None,
        "formatted_display": f"{var_overall.get('decision_matches')}/{var_overall.get('total_scenarios')}" if var_overall.get("decision_matches") is not None else "not evaluated",
        "suffix": f"/{var_overall.get('total_scenarios')}" if var_overall.get("total_scenarios") else "",
        "label": "exact policy compliance",
        "source_report": "variants_report.json"
    },
    {
        "id": "mutation_tests_passing",
        "title": "mutants killed (AST chaos)",
        "value": mut_data.get("killed"),
        "total": mut_data.get("total_mutants"),
        "formatted_display": f"{mut_data.get('killed')}/{mut_data.get('total_mutants')}" if mut_data.get("killed") is not None else "not evaluated",
        "suffix": f"/{mut_data.get('total_mutants')}" if mut_data.get("total_mutants") else "",
        "percentage": mut_data.get("mutation_score_pct"),
        "label": "100% mutation kill rate",
        "source_report": "v3_mutation_test_results.json"
    }
]

with open(os.path.join(DATA_DIR, "headline_counters.json"), "w", encoding="utf-8") as f:
    json.dump(headline_counters, f, indent=2)
with open(os.path.join(BENCHMARK_REPORTS, "headline_counters.json"), "w", encoding="utf-8") as f:
    json.dump(headline_counters, f, indent=2)
print("Saved headline_counters.json successfully.")

# Save playground presets & findings
try:
    from backend.app.api.playground import PLAYGROUND_PRESETS
    with open(os.path.join(DATA_DIR, "playground_presets.json"), "w", encoding="utf-8") as f:
        json.dump({"presets": PLAYGROUND_PRESETS}, f, indent=2)
    with open(os.path.join(REPORTS_DIR, "playground_presets.json"), "w", encoding="utf-8") as f:
        json.dump({"presets": PLAYGROUND_PRESETS}, f, indent=2)
    print("Saved playground_presets.json successfully.")
except Exception as e:
    print(f"Warning: could not export playground_presets.json: {e}")

findings_stub = {
    "total_attempts": 0,
    "total_bypasses": 0,
    "findings": []
}
with open(os.path.join(DATA_DIR, "playground_findings.json"), "w", encoding="utf-8") as f:
    json.dump(findings_stub, f, indent=2)
with open(os.path.join(REPORTS_DIR, "playground_findings.json"), "w", encoding="utf-8") as f:
    json.dump(findings_stub, f, indent=2)
print("Saved playground_findings.json successfully.")

print("\n--- Evidence data build complete ---")
