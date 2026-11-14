#!/usr/bin/env python3
"""
scripts/evaluate_pii_side_by_side.py

Evaluates SentinelMesh's CompositePiiDetector on both the original test split
and the fresh disjoint test split, producing side-by-side comparative metrics.
"""

import os
import sys
import json
import re
from typing import Dict, Any, List

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from backend.app.privacy.detectors import CompositePiiDetector
from benchmark.harness.statistics import wilson_score_interval

ENTITY_MAP = {
    "EMAIL": "EMAIL",
    "TEL": "PHONE",
    "SOCIALNUMBER": "NATIONAL_ID",
    "CREDITCARD": "CREDIT_CARD",
}

def normalize_match(s: str) -> str:
    return re.sub(r"[\s\-\(\)\.]", "", s).lower()

def run_eval_on_file(file_path: str, label: str) -> Dict[str, Any]:
    with open(file_path, "r", encoding="utf-8") as f:
        records = json.load(f)

    detector = CompositePiiDetector()
    metrics_by_entity = {
        mapped_type: {"TP": 0, "FP": 0, "FN": 0}
        for mapped_type in set(ENTITY_MAP.values())
    }

    for record in records:
        text = record.get("source_text", "")
        ground_truth_masks = record.get("privacy_mask", [])

        gt_by_type: Dict[str, List[str]] = {m_type: [] for m_type in metrics_by_entity}
        for mask in ground_truth_masks:
            if not isinstance(mask, dict):
                continue
            lbl = mask.get("label", "")
            if lbl in ENTITY_MAP:
                mapped = ENTITY_MAP[lbl]
                gt_val = mask.get("value", "")
                if gt_val:
                    gt_by_type[mapped].append(normalize_match(gt_val))

        findings = detector.detect(text)
        pred_by_type: Dict[str, List[str]] = {m_type: [] for m_type in metrics_by_entity}
        for f in findings:
            if f.pii_type in pred_by_type:
                pred_by_type[f.pii_type].append(normalize_match(f.value))

        for entity_type in metrics_by_entity:
            gts = list(gt_by_type[entity_type])
            preds = list(pred_by_type[entity_type])

            matched_preds = set()
            matched_gts = set()

            for p_idx, p_val in enumerate(preds):
                matched = False
                for g_idx, g_val in enumerate(gts):
                    if g_idx in matched_gts:
                        continue
                    if p_val == g_val or p_val in g_val or g_val in p_val:
                        matched = True
                        matched_preds.add(p_idx)
                        matched_gts.add(g_idx)
                        break

            tp = len(matched_preds)
            fp = len(preds) - tp
            fn = len(gts) - len(matched_gts)

            metrics_by_entity[entity_type]["TP"] += tp
            metrics_by_entity[entity_type]["FP"] += fp
            metrics_by_entity[entity_type]["FN"] += fn

    res = {
        "dataset_split_label": label,
        "sample_count": len(records),
        "entities": {}
    }
    overall_tp = overall_fp = overall_fn = 0
    for entity, counts in metrics_by_entity.items():
        tp, fp, fn = counts["TP"], counts["FP"], counts["FN"]
        overall_tp += tp
        overall_fp += fp
        overall_fn += fn

        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0

        _, prec_l, prec_u = wilson_score_interval(tp, tp + fp)
        _, rec_l, rec_u = wilson_score_interval(tp, tp + fn)

        res["entities"][entity] = {
            "TP": tp,
            "FP": fp,
            "FN": fn,
            "precision": round(prec, 4),
            "precision_ci_95": [prec_l, prec_u],
            "recall": round(rec, 4),
            "recall_ci_95": [rec_l, rec_u],
            "f1_score": round(f1, 4),
        }

    macro_f1 = sum(e["f1_score"] for e in res["entities"].values()) / len(res["entities"])
    res["macro_f1"] = round(macro_f1, 4)
    res["micro_precision"] = round(overall_tp / (overall_tp + overall_fp), 4) if (overall_tp + overall_fp) > 0 else 0.0
    res["micro_recall"] = round(overall_tp / (overall_tp + overall_fn), 4) if (overall_tp + overall_fn) > 0 else 0.0
    return res

if __name__ == "__main__":
    old_test_path = os.path.join(ROOT_DIR, "benchmark", "data_splits", "test", "ai4privacy_test.json")
    fresh_test_path = os.path.join(ROOT_DIR, "benchmark", "data_splits", "test", "ai4privacy_fresh_test.json")

    print("Evaluating original test slice with enhanced detector...")
    eval_original = run_eval_on_file(old_test_path, "Original Test Split (N=1028, enhanced detector)")

    print("Evaluating fresh disjoint test slice with enhanced detector...")
    eval_fresh = run_eval_on_file(fresh_test_path, "Fresh Disjoint Test Split (N=1043, enhanced detector)")

    # Load baseline original result for comparison
    orig_baseline_path = os.path.join(ROOT_DIR, "benchmark", "reports", "v3_pii_evaluation_test.json")
    with open(orig_baseline_path, "r", encoding="utf-8") as f:
        orig_baseline = json.load(f)

    comparison_report = {
        "benchmark": "ai4privacy English Validation PII Masking",
        "description": "Side-by-side evaluation of initial v3 regex baseline vs. preregistered v3.1 phonenumbers & expanded national ID detectors across original and fresh test slices.",
        "runs": {
            "initial_v3_baseline_old_test": {
                "label": "v3 Initial Regex (Old Test Slice, N=1028)",
                "macro_f1": orig_baseline.get("macro_f1"),
                "micro_precision": orig_baseline.get("micro_precision"),
                "micro_recall": orig_baseline.get("micro_recall"),
                "entities": orig_baseline.get("entities")
            },
            "enhanced_v3_1_old_test": {
                "label": "v3.1 Enhanced (Old Test Slice, N=1028)",
                "macro_f1": eval_original["macro_f1"],
                "micro_precision": eval_original["micro_precision"],
                "micro_recall": eval_original["micro_recall"],
                "entities": eval_original["entities"]
            },
            "enhanced_v3_1_fresh_test": {
                "label": "v3.1 Enhanced (Fresh Disjoint Test Slice, N=1043, Seed 99)",
                "macro_f1": eval_fresh["macro_f1"],
                "micro_precision": eval_fresh["micro_precision"],
                "micro_recall": eval_fresh["micro_recall"],
                "entities": eval_fresh["entities"]
            }
        }
    }

    out_file = os.path.join(ROOT_DIR, "benchmark", "reports", "v3_pii_evaluation_test.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(comparison_report, f, indent=2)

    print("\n=== PII SIDE-BY-SIDE EVALUATION COMPLETE ===")
    print(f"Old baseline Phone Prec: {orig_baseline['entities']['PHONE']['precision']:.4f}, FP: {orig_baseline['entities']['PHONE']['FP']}")
    print(f"Enhanced v3.1 (Old test) Phone Prec: {eval_original['entities']['PHONE']['precision']:.4f}, FP: {eval_original['entities']['PHONE']['FP']}")
    print(f"Enhanced v3.1 (Fresh test) Phone Prec: {eval_fresh['entities']['PHONE']['precision']:.4f}, FP: {eval_fresh['entities']['PHONE']['FP']}")
    print(f"Old baseline NationalID Recall: {orig_baseline['entities']['NATIONAL_ID']['recall']:.4f}, TP: {orig_baseline['entities']['NATIONAL_ID']['TP']}")
    print(f"Enhanced v3.1 (Old test) NationalID Recall: {eval_original['entities']['NATIONAL_ID']['recall']:.4f}, TP: {eval_original['entities']['NATIONAL_ID']['TP']}")
    print(f"Enhanced v3.1 (Fresh test) NationalID Recall: {eval_fresh['entities']['NATIONAL_ID']['recall']:.4f}, TP: {eval_fresh['entities']['NATIONAL_ID']['TP']}")
