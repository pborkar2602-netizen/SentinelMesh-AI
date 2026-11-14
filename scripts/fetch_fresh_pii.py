import urllib.request
import os

url = "https://huggingface.co/datasets/ai4privacy/pii-masking-300k/resolve/main/data/validation/1english_openpii_8k.jsonl"
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
target_path = "benchmark/external_data/ai4privacy/fresh_validation_slice.jsonl"

try:
    with urllib.request.urlopen(req, timeout=30) as resp:
        with open(target_path, "w", encoding="utf-8") as out_f:
            count = 0
            saved = 0
            for raw_line in resp:
                count += 1
                if count <= 1500:
                    continue
                out_f.write(raw_line.decode("utf-8"))
                saved += 1
                if saved >= 1500:
                    break
    print(f"SUCCESS: Fetched {saved} records into {target_path}")
except Exception as e:
    print(f"ERROR: {e}")
