import json
import hashlib
import os

INPUT_PATH = "benchmark/external_data/ai4privacy/fresh_validation_slice.jsonl"
DEV_PATH = "benchmark/data_splits/dev/ai4privacy_fresh_dev.json"
TEST_PATH = "benchmark/data_splits/test/ai4privacy_fresh_test.json"

records = []
with open(INPUT_PATH, "r", encoding="utf-8") as f:
    for line in f:
        if line.strip():
            records.append(json.loads(line))

print(f"Total fresh records loaded: {len(records)}")

dev_records = []
test_records = []

for idx, rec in enumerate(records):
    # Deterministic hash split using seed 99 and index/id
    h = hashlib.sha256(f"seed_99_pii_{rec.get('id', idx)}".encode("utf-8")).hexdigest()
    val = int(h, 16) % 100
    if val < 30:
        dev_records.append(rec)
    else:
        test_records.append(rec)

print(f"Fresh Dev: {len(dev_records)}, Fresh Test: {len(test_records)}")

os.makedirs(os.path.dirname(DEV_PATH), exist_ok=True)
os.makedirs(os.path.dirname(TEST_PATH), exist_ok=True)

with open(DEV_PATH, "w", encoding="utf-8") as f:
    json.dump(dev_records, f, indent=2)

with open(TEST_PATH, "w", encoding="utf-8") as f:
    json.dump(test_records, f, indent=2)

print(f"Saved: {DEV_PATH} and {TEST_PATH}")
