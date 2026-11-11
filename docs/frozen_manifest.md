# SentinelMesh AI — Rules & Detection Frozen Manifest

**Current Freeze Tag**: `rules-v2-frozen`  
**Branch**: `v2-fixes`  
**Timestamp**: 2026-11-11T21:50:00Z  

This manifest records the immutable cryptographic SHA-256 hashes of the baseline training distribution, anomaly detector, detection engine, core gateway policy modules, tool execution proxy, intent judge, privacy subsystem, and human approval subsystem at the `rules-v2-frozen` benchmark freeze step. No detector, policy, baseline, or scenario modifications are permitted beyond this freeze boundary before evaluating fresh held-out scenarios.

---

## A. `rules-v2-frozen` Manifest (`v2-fixes` Branch)

### 1. Behavioral Baseline Training Distribution & Anomaly Detector

| File Path | SHA-256 Digest |
|---|---|
| `backend/app/baseline/baseline_data.json` | `6cd5a34b241cc1e98114718f02e9a91dc5aeca43d7cdf2956d4b612b3180ca08` |
| `backend/app/baseline/anomaly_detector.py` | `77c7f622c16a4857474d62894d65a3d0e56e2c01923fcc08aa58d8f21f758003` |
| `backend/app/baseline/baseline_dev_sessions.json` | `37317a7636f1ac9fd6d3b1ab0a71bf4eff7882340bc2020685be8fbdb50a87c7` |
| `backend/app/baseline/profiler.py` | `0ea5270a6e3f6bfdc5aee228cac2aa0f2cf8396322c017833685731c54b43620` |

### 2. Detection Engine

| File Path | SHA-256 Digest |
|---|---|
| `backend/app/detection/rules.py` | `91f3d6451447075b91d94bfb8d933c66e66018a58a1ea102162be3b881eec925` |

### 3. Core Gateway Pipeline & Tool Proxy

| File Path | SHA-256 Digest |
|---|---|
| `backend/app/core/gateway.py` | `5447c4bb88d22bc7cde758f3150042a56fe8aec060f79a44e8f5640ededa53b3` |
| `backend/app/core/incident_builder.py` | `bbad70b82e39793bea45d7b8b710401d59defb5852556f39e6094370a408023a` |
| `backend/app/core/policy_engine.py` | `9c30d74661bab13f4ef2083e76067dcac11aa49693950334e312cf279c715b8f` |
| `backend/app/core/risk_scorer.py` | `531b69700bae6a3331f9171c6bf107fd4c976ecbdd91f50d95c91c6ff6a1fbe0` |
| `backend/app/core/taint_tracker.py` | `8f58398dfe8a57e46f5686416b609d36737b1418e3a73daf596b10eb07d7badd` |
| `backend/app/core/tool_proxy.py` | `9eb9083f1dfca827bac1c5d0a98c79440dd88072d693cebd0158c5c71aff6056` |
| `backend/app/core/trust_labeler.py` | `14ef4e44dc1ac1b134610e136c12775359728a0e8537d641dad4dc54a94a770d` |

### 4. Privacy & Masking Subsystem

| File Path | SHA-256 Digest |
|---|---|
| `backend/app/privacy/__init__.py` | `ac5ac4809458d69d58f0769069681d4eb4e8e5c2608c33a01b99b0379c53df3e` |
| `backend/app/privacy/detectors.py` | `6e898e888feedfa314a1a95e15523507a028ef0ddd7b20b5af2fe540c8ec6c81` |
| `backend/app/privacy/masker.py` | `fa0b850e4461dadf48498eed9c8267eaae494336b9fb62e3db06f4f3c35cb9e5` |
| `backend/app/privacy/vault.py` | `5d3c24ef4096d08b3bb1340a310dd7d3f0d854ba6e8cfe5b7533437d55edde74` |

### 5. Human Approvals & Cryptographic Tokens

| File Path | SHA-256 Digest |
|---|---|
| `backend/app/approvals/reviewer.py` | `e9e247fe33e0168997b3a85e3cc825c3d0dde5c4748bb29899d672c4f3fbcb53` |
| `backend/app/approvals/service.py` | `99ec90ca7af44e77e08b668ee9c65245ac166e1fbfe986a14df6468d1fa63c3d` |
| `backend/app/approvals/tokens.py` | `1941b59defa5eef91b6084368070dd71ab396184b81f4bdf652e4b27ece2516e` |

### 6. Intent Judge Module

| File Path | SHA-256 Digest |
|---|---|
| `backend/app/judge/intent_judge.py` | `8273281d11cd54a7d8b39cb0e35df1df1fd006327b4b58bfaf0cf44a359454fe` |
| `backend/app/judge/schema.py` | `66b95113664f258af31698cd31080913f94ce9801f394488693e6cbfe598a663` |

### 7. Verification Command (`rules-v2-frozen`)

```bash
python -c "
import hashlib
from pathlib import Path
manifest = {
    'backend/app/baseline/baseline_data.json': '6cd5a34b241cc1e98114718f02e9a91dc5aeca43d7cdf2956d4b612b3180ca08',
    'backend/app/baseline/anomaly_detector.py': '77c7f622c16a4857474d62894d65a3d0e56e2c01923fcc08aa58d8f21f758003',
    'backend/app/baseline/baseline_dev_sessions.json': '37317a7636f1ac9fd6d3b1ab0a71bf4eff7882340bc2020685be8fbdb50a87c7',
    'backend/app/baseline/profiler.py': '0ea5270a6e3f6bfdc5aee228cac2aa0f2cf8396322c017833685731c54b43620',
    'backend/app/detection/rules.py': '91f3d6451447075b91d94bfb8d933c66e66018a58a1ea102162be3b881eec925',
    'backend/app/core/gateway.py': '5447c4bb88d22bc7cde758f3150042a56fe8aec060f79a44e8f5640ededa53b3',
    'backend/app/core/incident_builder.py': 'bbad70b82e39793bea45d7b8b710401d59defb5852556f39e6094370a408023a',
    'backend/app/core/policy_engine.py': '9c30d74661bab13f4ef2083e76067dcac11aa49693950334e312cf279c715b8f',
    'backend/app/core/risk_scorer.py': '531b69700bae6a3331f9171c6bf107fd4c976ecbdd91f50d95c91c6ff6a1fbe0',
    'backend/app/core/taint_tracker.py': '8f58398dfe8a57e46f5686416b609d36737b1418e3a73daf596b10eb07d7badd',
    'backend/app/core/tool_proxy.py': '9eb9083f1dfca827bac1c5d0a98c79440dd88072d693cebd0158c5c71aff6056',
    'backend/app/core/trust_labeler.py': '14ef4e44dc1ac1b134610e136c12775359728a0e8537d641dad4dc54a94a770d',
    'backend/app/privacy/__init__.py': 'ac5ac4809458d69d58f0769069681d4eb4e8e5c2608c33a01b99b0379c53df3e',
    'backend/app/privacy/detectors.py': '6e898e888feedfa314a1a95e15523507a028ef0ddd7b20b5af2fe540c8ec6c81',
    'backend/app/privacy/masker.py': 'fa0b850e4461dadf48498eed9c8267eaae494336b9fb62e3db06f4f3c35cb9e5',
    'backend/app/privacy/vault.py': '5d3c24ef4096d08b3bb1340a310dd7d3f0d854ba6e8cfe5b7533437d55edde74',
    'backend/app/approvals/reviewer.py': 'e9e247fe33e0168997b3a85e3cc825c3d0dde5c4748bb29899d672c4f3fbcb53',
    'backend/app/approvals/service.py': '99ec90ca7af44e77e08b668ee9c65245ac166e1fbfe986a14df6468d1fa63c3d',
    'backend/app/approvals/tokens.py': '1941b59defa5eef91b6084368070dd71ab396184b81f4bdf652e4b27ece2516e',
    'backend/app/judge/intent_judge.py': '8273281d11cd54a7d8b39cb0e35df1df1fd006327b4b58bfaf0cf44a359454fe',
    'backend/app/judge/schema.py': '66b95113664f258af31698cd31080913f94ce9801f394488693e6cbfe598a663'
}
for path, expected in manifest.items():
    actual = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    assert actual == expected, f'MISMATCH for {path}: expected {expected}, got {actual}'
print('ALL 21 FROZEN V2 HASHES VERIFIED INTACT.')
"
```

---

## B. Historical `rules-frozen` Manifest (`d05932e` on `master`)

| File Path | SHA-256 Digest (`rules-frozen`) |
|---|---|
| `backend/app/baseline/baseline_data.json` | `6cd5a34b241cc1e98114718f02e9a91dc5aeca43d7cdf2956d4b612b3180ca08` |
| `backend/app/baseline/anomaly_detector.py` | `5b982c933303ea3c20e6daff9aa9cea24eac846d47050c09e4fc1ccb4995e6db` |
| `backend/app/detection/rules.py` | `439d2d65a5bc9a013697218a6c10115dfd27556b1b8929dee33af19de9cbb2c0` |
| `backend/app/core/gateway.py` | `81fb970b41db12c25ed3d59225a864cfc94106fe07dcb9cfcaed72fcdd98d1b8` |
| `backend/app/core/incident_builder.py` | `cd83dbb31db6f018a526887e2db3dd9262513bf8d6f43182ce7ff76b43287c98` |
| `backend/app/core/policy_engine.py` | `11aeb0c730406cd3527fe54fa43cf6038ac6f64fdb49d7a29cf9a3fce205debd` |
| `backend/app/core/risk_scorer.py` | `531b69700bae6a3331f9171c6bf107fd4c976ecbdd91f50d95c91c6ff6a1fbe0` |
| `backend/app/core/taint_tracker.py` | `a4f2288b4892c570612fd1c31c00caf515ac1afde537d9d416589bdb14b09e64` |
| `backend/app/core/trust_labeler.py` | `14ef4e44dc1ac1b134610e136c12775359728a0e8537d641dad4dc54a94a770d` |
| `backend/app/privacy/__init__.py` | `ac5ac4809458d69d58f0769069681d4eb4e8e5c2608c33a01b99b0379c53df3e` |
| `backend/app/privacy/detectors.py` | `6e898e888feedfa314a1a95e15523507a028ef0ddd7b20b5af2fe540c8ec6c81` |
| `backend/app/privacy/masker.py` | `fa0b850e4461dadf48498eed9c8267eaae494336b9fb62e3db06f4f3c35cb9e5` |
| `backend/app/privacy/vault.py` | `5d3c24ef4096d08b3bb1340a310dd7d3f0d854ba6e8cfe5b7533437d55edde74` |
| `backend/app/approvals/reviewer.py` | `e9e247fe33e0168997b3a85e3cc825c3d0dde5c4748bb29899d672c4f3fbcb53` |
| `backend/app/approvals/service.py` | `99ec90ca7af44e77e08b668ee9c65245ac166e1fbfe986a14df6468d1fa63c3d` |
| `backend/app/approvals/tokens.py` | `1941b59defa5eef91b6084368070dd71ab396184b81f4bdf652e4b27ece2516e` |
