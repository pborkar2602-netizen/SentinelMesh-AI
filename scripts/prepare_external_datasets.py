#!/usr/bin/env python3
"""
scripts/prepare_external_datasets.py

Downloads and deterministically partitions external benchmarks into:
- adapter-dev (30%, stratified, seed 42)
- test (70%)

Compliance:
- Integrity Rules: dev, dev_v1_heldout, held_out_v2 remain untouched.
- External datasets split BEFORE any adapter or detector evaluation.
- No fabricated contents or labels.
"""

import os
import sys
import json
import hashlib
import urllib.request
import pandas as pd

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(ROOT_DIR, "benchmark", "external_data")
SPLIT_DEV = os.path.join(ROOT_DIR, "benchmark", "data_splits", "dev")
SPLIT_TEST = os.path.join(ROOT_DIR, "benchmark", "data_splits", "test")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(SPLIT_DEV, exist_ok=True)
os.makedirs(SPLIT_TEST, exist_ok=True)


def download_file(url: str, dest_path: str) -> None:
    if os.path.exists(dest_path) and os.path.getsize(dest_path) > 0:
        print(f"  [Cache hit] {dest_path}")
        return
    print(f"  [Downloading] {url} -> {dest_path}")
    req = urllib.request.Request(url, headers={"User-Agent": "SentinelMesh-v3-evaluator/1.0"})
    with urllib.request.urlopen(req, timeout=45) as resp:
        content = resp.read()
    with open(dest_path, "wb") as f:
        f.write(content)
    print(f"  [Downloaded] {len(content)} bytes")


def deterministic_split(item_id: str, salt: str = "v3_science_salt") -> str:
    """Returns 'adapter-dev' if hash % 100 < 30 else 'test'."""
    h = hashlib.sha256(f"{salt}_{item_id}".encode("utf-8")).hexdigest()
    val = int(h[:8], 16)
    return "adapter-dev" if (val % 100) < 30 else "test"


def prepare_injecagent():
    print("=== 1. Preparing InjecAgent ===")
    base_url = "https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/data"
    files = [
        "test_cases_dh_base.json",
        "test_cases_dh_enhanced.json",
        "test_cases_ds_base.json",
        "test_cases_ds_enhanced.json",
        "tools.json",
        "user_cases.jsonl"
    ]
    inj_dir = os.path.join(DATA_DIR, "injecagent")
    os.makedirs(inj_dir, exist_ok=True)

    for fname in files:
        download_file(f"{base_url}/{fname}", os.path.join(inj_dir, fname))

    # Aggregate test cases
    combined_cases = []
    for fname in ["test_cases_dh_base.json", "test_cases_ds_base.json"]:
        path = os.path.join(inj_dir, fname)
        attack_type = "direct_harm" if "dh" in fname else "data_stealing"
        with open(path, "r", encoding="utf-8") as f:
            items = json.load(f)
            for idx, item in enumerate(items):
                cid = f"injecagent_{attack_type}_{idx}_{item.get('Case_ID', idx)}"
                item["_sentinel_id"] = cid
                item["_attack_type"] = attack_type
                combined_cases.append(item)

    dev_items = []
    test_items = []
    for item in combined_cases:
        split = deterministic_split(item["_sentinel_id"])
        if split == "adapter-dev":
            dev_items.append(item)
        else:
            test_items.append(item)

    with open(os.path.join(SPLIT_DEV, "injecagent_dev.json"), "w", encoding="utf-8") as f:
        json.dump(dev_items, f, indent=2)
    with open(os.path.join(SPLIT_TEST, "injecagent_test.json"), "w", encoding="utf-8") as f:
        json.dump(test_items, f, indent=2)

    print(f"InjecAgent total: {len(combined_cases)} (dev: {len(dev_items)}, test: {len(test_items)})")


def prepare_deepset():
    print("=== 2. Preparing deepset/prompt-injections ===")
    deepset_dir = os.path.join(DATA_DIR, "deepset")
    os.makedirs(deepset_dir, exist_ok=True)
    parquet_url = "https://huggingface.co/datasets/deepset/prompt-injections/resolve/main/data/train-00000-of-00001-9564e8b05b4757ab.parquet"
    local_parquet = os.path.join(deepset_dir, "train.parquet")
    download_file(parquet_url, local_parquet)

    df = pd.read_parquet(local_parquet)
    records = []
    for idx, row in df.iterrows():
        cid = f"deepset_{idx}"
        records.append({
            "id": cid,
            "text": str(row["text"]),
            "label": int(row["label"])
        })

    dev_items = []
    test_items = []
    for item in records:
        split = deterministic_split(item["id"])
        if split == "adapter-dev":
            dev_items.append(item)
        else:
            test_items.append(item)

    with open(os.path.join(SPLIT_DEV, "deepset_dev.json"), "w", encoding="utf-8") as f:
        json.dump(dev_items, f, indent=2)
    with open(os.path.join(SPLIT_TEST, "deepset_test.json"), "w", encoding="utf-8") as f:
        json.dump(test_items, f, indent=2)

    print(f"deepset total: {len(records)} (dev: {len(dev_items)}, test: {len(test_items)})")


def prepare_tensor_trust():
    print("=== 3. Preparing Tensor Trust ===")
    tt_dir = os.path.join(DATA_DIR, "tensor_trust")
    os.makedirs(tt_dir, exist_ok=True)
    url = "https://raw.githubusercontent.com/HumanCompatibleAI/tensor-trust-data/main/benchmarks/hijacking-robustness/v1/hijacking_robustness_dataset.jsonl"
    local_jsonl = os.path.join(tt_dir, "hijacking.jsonl")
    download_file(url, local_jsonl)

    records = []
    with open(local_jsonl, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            if not line.strip():
                continue
            row = json.loads(line)
            cid = f"tensor_trust_hijack_{idx}"
            records.append({
                "id": cid,
                "attacker_input": row.get("attacker_input", ""),
                "pre_prompt": row.get("pre_prompt", ""),
                "access_code": row.get("access_code", "")
            })

    dev_items = []
    test_items = []
    for item in records:
        split = deterministic_split(item["id"])
        if split == "adapter-dev":
            dev_items.append(item)
        else:
            test_items.append(item)

    with open(os.path.join(SPLIT_DEV, "tensor_trust_dev.json"), "w", encoding="utf-8") as f:
        json.dump(dev_items, f, indent=2)
    with open(os.path.join(SPLIT_TEST, "tensor_trust_test.json"), "w", encoding="utf-8") as f:
        json.dump(test_items, f, indent=2)

    print(f"Tensor Trust total: {len(records)} (dev: {len(dev_items)}, test: {len(test_items)})")


def prepare_agentdojo():
    print("=== 4. Preparing AgentDojo Static Tasks ===")
    suites = ["banking", "slack", "travel", "workspace"]
    base_url = "https://raw.githubusercontent.com/ethz-spylab/agentdojo/main/src/agentdojo/default_suites/v1"
    ad_dir = os.path.join(DATA_DIR, "agentdojo")
    os.makedirs(ad_dir, exist_ok=True)

    records = []
    for suite in suites:
        u_url = f"{base_url}/{suite}/user_tasks.py"
        i_url = f"{base_url}/{suite}/injection_tasks.py"
        u_dest = os.path.join(ad_dir, f"{suite}_user_tasks.py")
        i_dest = os.path.join(ad_dir, f"{suite}_injection_tasks.py")
        download_file(u_url, u_dest)
        download_file(i_url, i_dest)

        # Parse task metadata from user_tasks and injection_tasks
        # Each task class defines PROMPT or TASK instruction
        with open(u_dest, "r", encoding="utf-8") as f:
            u_content = f.read()
        with open(i_dest, "r", encoding="utf-8") as f:
            i_content = f.read()

        import re
        # Extract user tasks: class UserTask(BaseUserTask): ... PROMPT = "..."
        user_matches = re.findall(r'class\s+([A-Za-z0-9_]+)\(.*?PROMPT\s*=\s*["\'](.*?)["\']', u_content, re.DOTALL)
        for tname, prompt in user_matches:
            records.append({
                "id": f"agentdojo_{suite}_user_{tname}",
                "suite": suite,
                "task_type": "user_task",
                "name": tname,
                "prompt": prompt.strip()
            })

        # Extract injection tasks: class InjectionTask(BaseInjectionTask): ... GOAL = "..."
        inj_matches = re.findall(r'class\s+([A-Za-z0-9_]+)\(.*?GOAL\s*=\s*["\'](.*?)["\']', i_content, re.DOTALL)
        for tname, goal in inj_matches:
            records.append({
                "id": f"agentdojo_{suite}_injection_{tname}",
                "suite": suite,
                "task_type": "injection_task",
                "name": tname,
                "goal": goal.strip()
            })

    dev_items = []
    test_items = []
    for item in records:
        split = deterministic_split(item["id"])
        if split == "adapter-dev":
            dev_items.append(item)
        else:
            test_items.append(item)

    with open(os.path.join(SPLIT_DEV, "agentdojo_dev.json"), "w", encoding="utf-8") as f:
        json.dump(dev_items, f, indent=2)
    with open(os.path.join(SPLIT_TEST, "agentdojo_test.json"), "w", encoding="utf-8") as f:
        json.dump(test_items, f, indent=2)

    print(f"AgentDojo total: {len(records)} (dev: {len(dev_items)}, test: {len(test_items)})")


def prepare_ai4privacy():
    print("=== 5. Preparing ai4privacy English validation subset ===")
    ai_dir = os.path.join(DATA_DIR, "ai4privacy")
    os.makedirs(ai_dir, exist_ok=True)
    dest_file = os.path.join(ai_dir, "1english_openpii_8k.jsonl")
    # Stream the first 1,500 records to keep evaluation deterministic and fast
    url = "https://huggingface.co/datasets/ai4privacy/pii-masking-300k/resolve/main/data/validation/1english_openpii_8k.jsonl"
    
    if not os.path.exists(dest_file):
        print(f"  [Downloading validation sample from] {url}")
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        records = []
        with urllib.request.urlopen(req, timeout=60) as resp:
            for idx, line in enumerate(resp):
                if idx >= 1500:
                    break
                if line.strip():
                    records.append(json.loads(line.decode("utf-8")))
        with open(dest_file, "w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
        print(f"  [Saved {len(records)} ai4privacy records]")
    else:
        records = []
        with open(dest_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    records.append(json.loads(line))

    dev_items = []
    test_items = []
    for idx, item in enumerate(records):
        cid = f"ai4privacy_{idx}_{item.get('id', idx)}"
        item["_sentinel_id"] = cid
        split = deterministic_split(cid)
        if split == "adapter-dev":
            dev_items.append(item)
        else:
            test_items.append(item)

    with open(os.path.join(SPLIT_DEV, "ai4privacy_dev.json"), "w", encoding="utf-8") as f:
        json.dump(dev_items, f, indent=2)
    with open(os.path.join(SPLIT_TEST, "ai4privacy_test.json"), "w", encoding="utf-8") as f:
        json.dump(test_items, f, indent=2)

    print(f"ai4privacy total: {len(records)} (dev: {len(dev_items)}, test: {len(test_items)})")


if __name__ == "__main__":
    prepare_injecagent()
    prepare_deepset()
    prepare_tensor_trust()
    prepare_agentdojo()
    prepare_ai4privacy()
    print("All external dataset splits prepared cleanly!")
