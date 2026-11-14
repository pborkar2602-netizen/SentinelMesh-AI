#!/usr/bin/env python3
"""
scripts/audit_pii_phone_fps.py

Analyzes False Positive Phone detections on ai4privacy test split.
Identifies recurring patterns (timestamps, order numbers, IP fragments, national IDs).
"""

import os
import sys
import json
import re
from collections import Counter

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from backend.app.privacy.detectors import CompositePiiDetector


def analyze_phone_fps():
    detector = CompositePiiDetector()
    with open(os.path.join(ROOT_DIR, "benchmark", "data_splits", "test", "ai4privacy_test.json"), "r", encoding="utf-8") as f:
        records = json.load(f)

    fp_samples = []
    pattern_categories = Counter()

    for r in records:
        text = r.get("source_text", "")
        masks = r.get("privacy_mask", [])
        gt_phones = [m.get("value", "") for m in masks if m.get("label") == "TEL"]
        gt_clean = [re.sub(r"[\s\-\(\)\.]", "", p) for p in gt_phones if p]

        findings = detector.detect(text)
        for f in findings:
            if f.pii_type == "PHONE":
                val_clean = re.sub(r"[\s\-\(\)\.]", "", f.value)
                if not any(val_clean in g or g in val_clean for g in gt_clean):
                    v = f.value.strip()
                    # Classify pattern
                    if re.match(r"^\d{4}[-/]\d{2}[-/]\d{2}", v) or re.match(r"^\d{2}[-/]\d{2}[-/]\d{4}", v):
                        cat = "Date / Timestamp String"
                    elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}", v):
                        cat = "IPv4 Address Fragment"
                    elif len(re.sub(r"\D", "", v)) in [9, 10] and any(x in text.lower() for x in ["social", "passport", "license", "card", "tax", "iban"]):
                        cat = "National ID / Driver License / Tax ID Number"
                    elif re.search(r"\b(id|ref|order|invoice|code|zip|account)\b", text.lower()):
                        cat = "Account / Reference / Tracking ID"
                    else:
                        cat = "Generic Numeric Sequence (7-12 digits)"

                    pattern_categories[cat] += 1
                    fp_samples.append((v, cat))

    print(f"Total Phone FPs on ai4privacy test: {len(fp_samples)}")
    print("\nRecurring False Positive Phone Patterns:")
    for cat, cnt in pattern_categories.most_common():
        pct = (cnt / len(fp_samples)) * 100
        print(f"  - {cat:<42}: {cnt:>4} occurrences ({pct:.1f}%)")

    print("\nRepresentative Phone FP Samples:")
    for v, cat in fp_samples[:10]:
        print(f"  - \"{v}\" [{cat}]")


if __name__ == "__main__":
    analyze_phone_fps()
