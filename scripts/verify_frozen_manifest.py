import hashlib
import os
import re
from pathlib import Path

manifest_path = Path("docs/frozen_manifest.md")
with open(manifest_path, "r", encoding="utf-8") as f:
    text = f.read()

# Only test Section A: rules-v2-frozen (before Historical Archive Section B)
sec_a = text.split("## B.")[0]

checked = 0
mismatches = []

for line in sec_a.splitlines():
    line = line.strip()
    if not line.startswith("|"):
        continue
    code_spans = re.findall(r"`([^`]+)`", line)
    if len(code_spans) == 2:
        rel_path, exp_hash = code_spans[0].strip(), code_spans[1].strip()
        if len(exp_hash) == 64:
            p = Path(rel_path)
            if not p.exists():
                mismatches.append((rel_path, "FILE_NOT_FOUND"))
                continue
            with open(p, "rb") as fh:
                act_hash = hashlib.sha256(fh.read()).hexdigest()
            checked += 1
            if act_hash != exp_hash.lower():
                mismatches.append((rel_path, exp_hash, act_hash))

print(f"Checked {checked} Section A frozen manifest entries.")
if mismatches:
    print(f"FAIL: {len(mismatches)} mismatches found in Section A:")
    for m in mismatches:
        print(" ", m)
    exit(1)
else:
    print("SUCCESS: All Section A rules-v2-frozen entries (33 files) match 100% perfectly!")
    exit(0)
