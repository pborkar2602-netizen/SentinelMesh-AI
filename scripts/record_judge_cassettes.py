#!/usr/bin/env python3
"""
SentinelMesh AI — Real LLM Intent Judge Verdict Recording Utility
Records empirical live LLM verdicts and real round-trip latencies into cassettes
when SENTINEL_JUDGE_API_KEY is set.
If no key is present, prints "judge not evaluated" and exits without writing stub verdicts.
"""

import os
import sys
import json
import time
from pathlib import Path
from datetime import datetime, timezone

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

CASSETTE_FILE = PROJECT_ROOT / "backend" / "app" / "judge" / "cassettes" / "judge_cassettes.json"


def _collect_sensitive_calls_from_scenarios() -> list[dict]:
    """
    Scans scenario JSON files in benchmark/scenarios/dev and benchmark/scenarios/dev_v1_heldout
    to collect sensitive tool calls for real LLM verdict recording.
    """
    from backend.app.judge.intent_judge import IntentJudge
    from backend.app.privacy.masker import PrivacyEngine
    from backend.app.privacy.detectors import CompositePiiDetector

    detector = CompositePiiDetector()
    calls = []
    for split_name in ("dev", "dev_v1_heldout"):
        split_dir = PROJECT_ROOT / "benchmark" / "scenarios" / split_name
        if not split_dir.exists():
            continue
        for fpath in sorted(split_dir.glob("*.json")):
            try:
                data = json.loads(fpath.read_text(encoding="utf-8"))
            except Exception:
                continue
            sc_id = data.get("id", fpath.stem)
            task = data.get("agent_task", "Autonomous session task")
            input_ctx = data.get("input_context", [])
            is_tainted = any(bool(c.get("is_untrusted")) for c in input_ctx)
            tainted_sources = [c.get("source_id", "untrusted") for c in input_ctx if c.get("is_untrusted")]

            for step in data.get("scripted_steps", []):
                if step.get("event_type", "tool_call") != "tool_call":
                    continue
                t_name = step.get("tool_name")
                args = step.get("arguments", {})
                if not t_name:
                    continue
                if t_name == "read_doc":
                    is_tainted = True
                    fp = str(args.get("file_path") or "")
                    if fp and fp not in tainted_sources:
                        tainted_sources.append(fp)

                masked_args, _ = PrivacyEngine.mask_payload(f"rec-{sc_id}", args)
                if not IntentJudge.is_sensitive_action(t_name, masked_args):
                    continue

                dest_domain = None
                if t_name == "send_email":
                    to_val = str(args.get("to") or args.get("recipient") or "")
                    if "@" in to_val:
                        dest_domain = to_val.split("@")[-1].strip().lower()
                elif t_name == "external_api":
                    import urllib.parse
                    url_val = str(args.get("url") or args.get("endpoint") or "")
                    dest_domain = urllib.parse.urlparse(url_val).hostname

                data_counts = {}
                for v in args.values():
                    if isinstance(v, str):
                        for f in detector.detect(v):
                            data_counts[f.pii_type] = data_counts.get(f.pii_type, 0) + 1

                calls.append(
                    {
                        "id": f"{sc_id}_step_{step.get('step_index', 0)}",
                        "task_description": task,
                        "tool_name": t_name,
                        "destination_domain": dest_domain,
                        "is_tainted": is_tainted,
                        "tainted_sources": list(tainted_sources),
                        "data_class_counts": data_counts,
                        "masked_arguments": masked_args,
                    }
                )
    return calls


def record_live_verdicts() -> int:
    api_key = (os.getenv("SENTINEL_JUDGE_API_KEY") or "").strip()
    api_url = os.getenv("SENTINEL_JUDGE_API_URL", "https://api.openai.com/v1/chat/completions")
    model = os.getenv("SENTINEL_JUDGE_MODEL", "gpt-4o-mini")

    if not api_key:
        print("judge not evaluated")
        print("Note: SENTINEL_JUDGE_API_KEY is not set. Stub verdicts are refused for headline numbers and excluded from all results.")
        return 0

    import httpx
    from backend.app.judge.intent_judge import IntentJudge

    print("=" * 80)
    print(f"[*] Recording real LLM Judge verdicts via {api_url} (model: {model})")
    print("=" * 80)

    cassette_data = {}
    if CASSETTE_FILE.exists():
        with open(CASSETTE_FILE, "r", encoding="utf-8") as f:
            cassette_data = json.load(f)

    recorded_runs = cassette_data.setdefault("recorded_runs", {})
    calls = _collect_sensitive_calls_from_scenarios()
    results = []

    for sc in calls:
        prompt = IntentJudge.build_judge_prompt(
            task_description=sc["task_description"],
            tool_name=sc["tool_name"],
            destination_domain=sc["destination_domain"],
            is_tainted=sc["is_tainted"],
            tainted_sources=sc["tainted_sources"],
            data_class_counts=sc["data_class_counts"],
            masked_arguments=sc["masked_arguments"],
        )
        p_hash = IntentJudge.compute_prompt_hash(prompt)
        print(f"[*] Recording '{sc['id']}' (Prompt Hash: {p_hash})...")

        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        body = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.0,
            "response_format": {"type": "json_object"},
        }

        start = time.perf_counter()
        try:
            with httpx.Client(timeout=15.0) as client:
                resp = client.post(api_url, json=body, headers=headers)
                resp.raise_for_status()
                latency_ms = round((time.perf_counter() - start) * 1000, 2)
                raw_json = resp.json()["choices"][0]["message"]["content"]

                verdict = IntentJudge.parse_and_validate_json(raw_json, latency_ms=latency_ms)

                record_entry = {
                    "source": "recorded_llm",
                    "provider": "openai-compatible",
                    "model": model,
                    "recorded_at": datetime.now(timezone.utc).isoformat(),
                    "prompt_hash": p_hash,
                    "is_aligned": verdict.is_aligned,
                    "mismatch_score": verdict.mismatch_score,
                    "reasoning": verdict.reasoning,
                    "risk_level": verdict.risk_level,
                    "latency_ms": latency_ms,
                }
                recorded_runs[f"rec_{p_hash}"] = record_entry
                results.append((sc["id"], verdict.is_aligned, verdict.mismatch_score, latency_ms))
                print(
                    f"    [OK] aligned={verdict.is_aligned}, mismatch={verdict.mismatch_score}/100, latency={latency_ms}ms"
                )
        except Exception as e:
            print(f"    [ERROR] Live call failed for '{sc['id']}': {e}")

    with open(CASSETTE_FILE, "w", encoding="utf-8") as f:
        json.dump(cassette_data, f, indent=2)
    IntentJudge.invalidate_cassette_cache()

    print("\n" + "=" * 80)
    print(f"[+] Recorded {len(results)} real LLM verdicts into {CASSETTE_FILE}")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    sys.exit(record_live_verdicts())
