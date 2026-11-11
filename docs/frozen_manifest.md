# SentinelMesh AI — Rules & Detection Frozen Manifest

**Freeze Tag**: `rules-frozen`  
**Timestamp**: 2026-11-12T01:03:00Z  
**Commit**: `f3200f0`

This manifest records the immutable cryptographic SHA-256 hashes of the baseline training distribution and all detection and core gateway policy modules at the benchmark freeze step. No detector, policy, baseline, or scenario modifications are permitted beyond this freeze boundary.

## 1. Behavioral Baseline Training Distribution

| File Path | SHA-256 Digest |
|---|---|
| `backend/app/baseline/baseline_data.json` | `6cd5a34b241cc1e98114718f02e9a91dc5aeca43d7cdf2956d4b612b3180ca08` |

## 2. Detection Engine

| File Path | SHA-256 Digest |
|---|---|
| `backend/app/detection/rules.py` | `439d2d65a5bc9a013697218a6c10115dfd27556b1b8929dee33af19de9cbb2c0` |

## 3. Core Gateway Pipeline

| File Path | SHA-256 Digest |
|---|---|
| `backend/app/core/gateway.py` | `81fb970b41db12c25ed3d59225a864cfc94106fe07dcb9cfcaed72fcdd98d1b8` |
| `backend/app/core/incident_builder.py` | `cd83dbb31db6f018a526887e2db3dd9262513bf8d6f43182ce7ff76b43287c98` |
| `backend/app/core/policy_engine.py` | `11aeb0c730406cd3527fe54fa43cf6038ac6f64fdb49d7a29cf9a3fce205debd` |
| `backend/app/core/risk_scorer.py` | `531b69700bae6a3331f9171c6bf107fd4c976ecbdd91f50d95c91c6ff6a1fbe0` |
| `backend/app/core/taint_tracker.py` | `a4f2288b4892c570612fd1c31c00caf515ac1afde537d9d416589bdb14b09e64` |
| `backend/app/core/trust_labeler.py` | `14ef4e44dc1ac1b134610e136c12775359728a0e8537d641dad4dc54a94a770d` |

## 4. Verification Command

To verify that the working tree matches these frozen digests exactly:
```bash
python -c "
import hashlib
from pathlib import Path
manifest = {
    'backend/app/baseline/baseline_data.json': '6cd5a34b241cc1e98114718f02e9a91dc5aeca43d7cdf2956d4b612b3180ca08',
    'backend/app/detection/rules.py': '439d2d65a5bc9a013697218a6c10115dfd27556b1b8929dee33af19de9cbb2c0',
    'backend/app/core/gateway.py': '81fb970b41db12c25ed3d59225a864cfc94106fe07dcb9cfcaed72fcdd98d1b8',
    'backend/app/core/incident_builder.py': 'cd83dbb31db6f018a526887e2db3dd9262513bf8d6f43182ce7ff76b43287c98',
    'backend/app/core/policy_engine.py': '11aeb0c730406cd3527fe54fa43cf6038ac6f64fdb49d7a29cf9a3fce205debd',
    'backend/app/core/risk_scorer.py': '531b69700bae6a3331f9171c6bf107fd4c976ecbdd91f50d95c91c6ff6a1fbe0',
    'backend/app/core/taint_tracker.py': 'a4f2288b4892c570612fd1c31c00caf515ac1afde537d9d416589bdb14b09e64',
    'backend/app/core/trust_labeler.py': '14ef4e44dc1ac1b134610e136c12775359728a0e8537d641dad4dc54a94a770d'
}
for path, expected in manifest.items():
    actual = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    assert actual == expected, f'MISMATCH for {path}: expected {expected}, got {actual}'
print('ALL FROZEN HASHES VERIFIED INTACT.')
"
```
