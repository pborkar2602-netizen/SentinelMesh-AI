#!/usr/bin/env python3
"""
scripts/evaluate_text_baseline.py

Evaluates the static prompt injection phrase detection rule on:
1. deepset/prompt-injections (binary classification: benign vs injection)
2. Tensor Trust (adversarial prompt hijacking strings)

Strict scientific compliance:
- Does NOT tune or modify prompt injection phrases.
- Evaluates split (dev or test) deterministically.
- Outputs exact precision, recall, F1, and Wilson score 95% confidence intervals.
"""

import os
import sys
import json
from typing import Dict, Any

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from backend.app.detection.rules import check_prompt_injection
from benchmark.harness.statistics import wilson_score_interval


def evaluate_deepset(split: str = "dev") -> Dict[str, Any]:
    file_path = os.path.join(ROOT_DIR, "benchmark", "data_splits", split, f"deepset_{split}.json")
    with open(file_path, "r", encoding="utf-8") as f:
        items = json.load(f)

    tp = fp = tn = fn = 0
    for item in items:
        text = item["text"]
        label = item["label"]  # 0: benign, 1: injection
        findings = check_prompt_injection([], {"input": text})
        pred = 1 if len(findings) > 0 else 0

        if pred == 1 and label == 1:
            tp += 1
        elif pred == 1 and label == 0:
            fp += 1
        elif pred == 0 and label == 0:
            tn += 1
        else:
            fn += 1

    total = len(items)
    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    _, rec_l, rec_u = wilson_score_interval(tp, tp + fn)
    _, acc_l, acc_u = wilson_score_interval(tp + tn, total)

    return {
        "dataset": "deepset/prompt-injections",
        "split": split,
        "total_samples": total,
        "contingency_matrix": {"TP": tp, "FP": fp, "TN": tn, "FN": fn},
        "accuracy": round(accuracy, 4),
        "accuracy_ci_95": [acc_l, acc_u],
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "recall_ci_95": [rec_l, rec_u],
        "f1_score": round(f1, 4),
    }


def evaluate_tensor_trust(split: str = "dev") -> Dict[str, Any]:
    file_path = os.path.join(ROOT_DIR, "benchmark", "data_splits", split, f"tensor_trust_{split}.json")
    with open(file_path, "r", encoding="utf-8") as f:
        items = json.load(f)

    hits = 0
    total = len(items)
    for item in items:
        text = item.get("attacker_input", "")
        findings = check_prompt_injection([], {"input": text})
        if findings:
            hits += 1

    recall = hits / total if total > 0 else 0.0
    _, rec_l, rec_u = wilson_score_interval(hits, total)

    return {
        "dataset": "Tensor Trust (Hijacking Robustness)",
        "split": split,
        "total_samples": total,
        "adversarial_detections": hits,
        "recall": round(recall, 4),
        "recall_ci_95": [rec_l, rec_u],
        "limitations_note": "Evaluates raw static phrase regex against adversarial human attacks without stateful taint tracking.",
    }


def run_all(split: str = "dev") -> Dict[str, Any]:
    deepset_res = evaluate_deepset(split)
    tt_res = evaluate_tensor_trust(split)
    report = {
        "evaluation": "Text-Level Prompt Injection Rule Baseline",
        "claim": "a six-phrase list has low recall on natural-language injections",
        "open_ml_classifier": "not evaluated (offline environment; deep learning framework weights not bundled)",
        "split": split,
        "deepset": deepset_res,
        "tensor_trust": tt_res,
    }
    return report


if __name__ == "__main__":
    split = sys.argv[1] if len(sys.argv) > 1 else "dev"
    rep = run_all(split)
    print(json.dumps(rep, indent=2))
