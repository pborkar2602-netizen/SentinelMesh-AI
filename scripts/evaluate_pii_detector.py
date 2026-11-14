#!/usr/bin/env python3
"""
scripts/evaluate_pii_detector.py

Evaluates SentinelMesh's CompositePiiDetector on the ai4privacy English validation dataset.
Reports per-entity:
- True Positives, False Positives, False Negatives
- Precision, Recall, F1 score
- Wilson score 95% Confidence Intervals
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

# Mapping between ai4privacy entity labels and SentinelMesh PIITypes
ENTITY_MAP = {
    "EMAIL": "EMAIL",
    "TEL": "PHONE",
    "SOCIALNUMBER": "NATIONAL_ID",
    "CREDITCARD": "CREDIT_CARD",
}


def normalize_match(s: str) -> str:
    return re.sub(r"[\s\-\(\)\.]", "", s).lower()


def evaluate_pii(split: str = "dev") -> Dict[str, Any]:
    file_path = os.path.join(ROOT_DIR, "benchmark", "data_splits", split, f"ai4privacy_{split}.json")
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

        # Extract ground truth entities for mapped types
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

        # Run SentinelMesh detector
        findings = detector.detect(text)
        pred_by_type: Dict[str, List[str]] = {m_type: [] for m_type in metrics_by_entity}
        for f in findings:
            if f.pii_type in pred_by_type:
                pred_by_type[f.pii_type].append(normalize_match(f.value))

        # Evaluate matches for each entity
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

    # Format per-entity report with Wilson score CIs
    results = {
        "dataset": "ai4privacy English PII Masking",
        "split": split,
        "sample_count": len(records),
        "entities": {},
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

        results["entities"][entity] = {
            "TP": tp,
            "FP": fp,
            "FN": fn,
            "precision": round(prec, 4),
            "precision_ci_95": [prec_l, prec_u],
            "recall": round(rec, 4),
            "recall_ci_95": [rec_l, rec_u],
            "f1_score": round(f1, 4),
        }

    macro_f1 = sum(e["f1_score"] for e in results["entities"].values()) / len(results["entities"])
    results["macro_f1"] = round(macro_f1, 4)
    results["micro_precision"] = round(overall_tp / (overall_tp + overall_fp), 4) if (overall_tp + overall_fp) > 0 else 0.0
    results["micro_recall"] = round(overall_tp / (overall_tp + overall_fn), 4) if (overall_tp + overall_fn) > 0 else 0.0

    return results


if __name__ == "__main__":
    split = sys.argv[1] if len(sys.argv) > 1 else "dev"
    rep = evaluate_pii(split)
    print(json.dumps(rep, indent=2))
