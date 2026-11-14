#!/usr/bin/env python3
"""
scripts/evaluate_pii_comparison.py

Implements:
1. Side-by-side comparison of Old Regex Phone Detector vs New Phonenumbers Phone Detector.
2. Type-agnostic masking precision, recall, and F1 (a span counts as TP if ANY PII span of ANY type overlaps it).
3. Evaluated on both:
   - Original test split (ai4privacy_pii_test.json)
   - Fresh disjoint test split (ai4privacy_fresh_test.json)
4. Empirical decision on whether to revert or keep phonenumbers.
"""

import os
import sys
import json
import re
from typing import Dict, Any, List, Tuple

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from backend.app.privacy.detectors import (
    IPiiDetector,
    PiiFinding,
    EmailDetector,
    NationalIdDetector,
    CreditCardDetector,
    CompositePiiDetector,
)

try:
    import phonenumbers
    HAS_PHONENUMBERS = True
except ImportError:
    HAS_PHONENUMBERS = False

class OldPhoneDetector(IPiiDetector):
    REGEX = re.compile(r"(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{3,4}\b")
    IPV4_REGEX = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

    def detect(self, text: str) -> List[PiiFinding]:
        findings = []
        for match in self.REGEX.finditer(text):
            val = match.group(0)
            if self.IPV4_REGEX.search(val):
                continue
            digits = re.sub(r"\D", "", val)
            if 10 <= len(digits) <= 15:
                findings.append(PiiFinding(
                    pii_type="PHONE",
                    start=match.start(),
                    end=match.end(),
                    value=val,
                    confidence=0.88
                ))
        return findings

class NewPhoneDetector(IPiiDetector):
    IPV4_REGEX = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

    def detect(self, text: str) -> List[PiiFinding]:
        findings = []
        if HAS_PHONENUMBERS:
            for match in phonenumbers.PhoneNumberMatcher(text, "US", leniency=phonenumbers.Leniency.POSSIBLE):
                val = match.raw_string
                if self.IPV4_REGEX.search(val):
                    continue
                digits = re.sub(r"\D", "", val)
                if 7 <= len(digits) <= 15:
                    if phonenumbers.is_possible_number(match.number):
                        findings.append(PiiFinding(
                            pii_type="PHONE",
                            start=match.start,
                            end=match.end,
                            value=val,
                            confidence=0.92
                        ))
        else:
            return OldPhoneDetector().detect(text)
        return findings

ENTITY_MAP = {
    "EMAIL": "EMAIL",
    "TEL": "PHONE",
    "SOCIALNUMBER": "NATIONAL_ID",
    "CREDITCARD": "CREDIT_CARD",
}

def normalize_str(s: str) -> str:
    return re.sub(r"[\s\-\(\)\.]", "", s).lower()

def spans_overlap(s1: int, e1: int, s2: int, e2: int) -> bool:
    return max(s1, s2) < min(e1, e2)

def evaluate_detector_on_records(phone_detector_cls, records: List[Dict[str, Any]]) -> Dict[str, Any]:
    detectors = [
        EmailDetector(),
        phone_detector_cls(),
        NationalIdDetector(),
        CreditCardDetector(),
    ]

    typed_metrics = {t: {"TP": 0, "FP": 0, "FN": 0} for t in ENTITY_MAP.values()}
    type_agnostic = {"TP": 0, "FP": 0, "FN": 0}

    for record in records:
        text = record.get("source_text", "")
        ground_truth_masks = record.get("privacy_mask", [])

        # Ground truth spans: (start, end, label, value)
        all_gt_spans = []
        gt_by_type = {t: [] for t in ENTITY_MAP.values()}

        for mask in ground_truth_masks:
            if not isinstance(mask, dict):
                continue
            lbl = mask.get("label", "")
            if lbl in ENTITY_MAP:
                mapped_type = ENTITY_MAP[lbl]
                val = mask.get("value", "")
                # Find span coordinates in text
                for m in re.finditer(re.escape(val), text):
                    span_info = (m.start(), m.end(), mapped_type, normalize_str(val))
                    all_gt_spans.append(span_info)
                    gt_by_type[mapped_type].append(span_info)
                    break

        # Predicted spans
        all_pred_spans = []
        pred_by_type = {t: [] for t in ENTITY_MAP.values()}
        for d in detectors:
            findings = d.detect(text)
            for f in findings:
                if f.pii_type in pred_by_type:
                    span_info = (f.start, f.end, f.pii_type, normalize_str(f.value))
                    all_pred_spans.append(span_info)
                    pred_by_type[f.pii_type].append(span_info)

        # 1. Typed matching
        for t in ENTITY_MAP.values():
            gts = gt_by_type[t]
            preds = pred_by_type[t]
            matched_gts = set()
            matched_preds = set()
            for p_idx, p in enumerate(preds):
                for g_idx, g in enumerate(gts):
                    if g_idx in matched_gts:
                        continue
                    if spans_overlap(p[0], p[1], g[0], g[1]) or p[3] == g[3] or p[3] in g[3] or g[3] in p[3]:
                        matched_preds.add(p_idx)
                        matched_gts.add(g_idx)
                        break
            tp = len(matched_preds)
            fp = len(preds) - tp
            fn = len(gts) - len(matched_gts)
            typed_metrics[t]["TP"] += tp
            typed_metrics[t]["FP"] += fp
            typed_metrics[t]["FN"] += fn

        # 2. Type-agnostic matching: ANY predicted span overlapping ANY ground-truth span
        matched_gt_agnostic = set()
        matched_pred_agnostic = set()
        for p_idx, p in enumerate(all_pred_spans):
            for g_idx, g in enumerate(all_gt_spans):
                if g_idx in matched_gt_agnostic:
                    continue
                if spans_overlap(p[0], p[1], g[0], g[1]) or p[3] == g[3] or p[3] in g[3] or g[3] in p[3]:
                    matched_pred_agnostic.add(p_idx)
                    matched_gt_agnostic.add(g_idx)
                    break
        ag_tp = len(matched_pred_agnostic)
        ag_fp = len(all_pred_spans) - ag_tp
        ag_fn = len(all_gt_spans) - len(matched_gt_agnostic)
        type_agnostic["TP"] += ag_tp
        type_agnostic["FP"] += ag_fp
        type_agnostic["FN"] += ag_fn

    # Compute prec, rec, f1
    def calc_prf(counts):
        tp, fp, fn = counts["TP"], counts["FP"], counts["FN"]
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        return round(prec * 100, 2), round(rec * 100, 2), round(f1 * 100, 2), tp, fp, fn

    out = {"entities": {}, "type_agnostic": {}}
    for t, cnt in typed_metrics.items():
        p, r, f1, tp, fp, fn = calc_prf(cnt)
        out["entities"][t] = {"precision": p, "recall": r, "f1": f1, "TP": tp, "FP": fp, "FN": fn}
    ag_p, ag_r, ag_f1, ag_tp, ag_fp, ag_fn = calc_prf(type_agnostic)
    out["type_agnostic"] = {"precision": ag_p, "recall": ag_r, "f1": ag_f1, "TP": ag_tp, "FP": ag_fp, "FN": ag_fn}
    return out

def main():
    orig_path = os.path.join(ROOT_DIR, "benchmark", "data_splits", "test", "ai4privacy_test.json")
    fresh_path = os.path.join(ROOT_DIR, "benchmark", "data_splits", "test", "ai4privacy_fresh_test.json")

    with open(orig_path, "r", encoding="utf-8") as f:
        orig_records = json.load(f)
    with open(fresh_path, "r", encoding="utf-8") as f:
        fresh_records = json.load(f)

    print("=" * 95)
    print("PII DETECTOR EVALUATION: OLD REGEX vs NEW PHONENUMBERS (WITH TYPE-AGNOSTIC METRICS)")
    print("=" * 95)

    datasets = [
        ("Original Test Partition", orig_records),
        ("Fresh Disjoint Test Partition", fresh_records),
    ]

    results_all = {}

    for d_name, records in datasets:
        print(f"\nEvaluating dataset: {d_name} (N={len(records)} records)...")
        old_res = evaluate_detector_on_records(OldPhoneDetector, records)
        new_res = evaluate_detector_on_records(NewPhoneDetector, records)

        results_all[d_name] = {"old_regex": old_res, "new_phonenumbers": new_res}

        print(f"\n--- {d_name} Results ---")
        print(f"{'Detector / Metric':<30} | {'Old Regex (P/R/F1)':<24} | {'New Phonenumbers (P/R/F1)':<24}")
        print("-" * 85)

        # Phone entity comparison
        old_ph = old_res["entities"]["PHONE"]
        new_ph = new_res["entities"]["PHONE"]
        print(f"{'PHONE (Typed)':<30} | {old_ph['precision']}% / {old_ph['recall']}% / {old_ph['f1']}%  | {new_ph['precision']}% / {new_ph['recall']}% / {new_ph['f1']}%")
        print(f"{'  Counts (TP/FP/FN)':<30} | {old_ph['TP']}/{old_ph['FP']}/{old_ph['FN']:<18} | {new_ph['TP']}/{new_ph['FP']}/{new_ph['FN']}")

        # National ID
        old_nid = old_res["entities"]["NATIONAL_ID"]
        new_nid = new_res["entities"]["NATIONAL_ID"]
        print(f"{'NATIONAL_ID (Typed)':<30} | {old_nid['precision']}% / {old_nid['recall']}% / {old_nid['f1']}%  | {new_nid['precision']}% / {new_nid['recall']}% / {new_nid['f1']}%")

        # Type-agnostic masking metrics
        old_ag = old_res["type_agnostic"]
        new_ag = new_res["type_agnostic"]
        print(f"{'TYPE-AGNOSTIC MASKING':<30} | {old_ag['precision']}% / {old_ag['recall']}% / {old_ag['f1']}%  | {new_ag['precision']}% / {new_ag['recall']}% / {new_ag['f1']}%")
        print(f"{'  Counts (TP/FP/FN)':<30} | {old_ag['TP']}/{old_ag['FP']}/{old_ag['FN']:<18} | {new_ag['TP']}/{new_ag['FP']}/{new_ag['FN']}")

    out_file = os.path.join(ROOT_DIR, "benchmark", "reports", "v3_pii_detector_comparison.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results_all, f, indent=2)
    print(f"\nDetailed metrics saved to {out_file}")

if __name__ == "__main__":
    main()
