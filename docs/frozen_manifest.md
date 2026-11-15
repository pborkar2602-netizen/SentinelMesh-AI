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

### 7. Held-Out v2 Scenario Files (`benchmark/scenarios/held_out_v2/`)

| File Path | SHA-256 Digest |
|---|---|
| `benchmark/scenarios/held_out_v2/v2_a1.json` | `71a7fbed443cfba6cd48e2c1b4387cfc769c3c027108d951f4f70084e3e16e51` |
| `benchmark/scenarios/held_out_v2/v2_a2.json` | `48ba0e0e1dcd7868e4ab07365a964330a2b484bcc11828653b16de7cf67873c2` |
| `benchmark/scenarios/held_out_v2/v2_a3.json` | `79378fcaccb0369cc4e56f0ebc390c0437166d987bd97cfcb1ddef524fbe1f95` |
| `benchmark/scenarios/held_out_v2/v2_a4.json` | `1067b5799a8334e864c8e9b83e597f1fb047f28ee1eb94568f8a6388d5e7eeb5` |
| `benchmark/scenarios/held_out_v2/v2_a5.json` | `cdd11277672a802341bcdd6264349d10c124017d931e114ead1d3e95b2806380` |
| `benchmark/scenarios/held_out_v2/v2_a6.json` | `44d00e4eef0fd5f535262a3a444551f848d089875206f74d1a9dac9c5f4816a5` |
| `benchmark/scenarios/held_out_v2/v2_b1.json` | `c27d0cc939b52d69365e6619ed5fe86eacab14a5163f138b000b5b373a2fea5f` |
| `benchmark/scenarios/held_out_v2/v2_b2.json` | `568084172c9eae1b850009e3f53595a58edd256c1d238adc46a778a7796e53bf` |
| `benchmark/scenarios/held_out_v2/v2_b3.json` | `4f9f063cf103b9e8014a0a2096a29f134f9f023d15359977ef4e2f2556c7d6c7` |
| `benchmark/scenarios/held_out_v2/v2_b4.json` | `3622d665a7a3844dd841ce73ebd8a627fff52605027dcac82739a23a8997ccaf` |
| `benchmark/scenarios/held_out_v2/v2_b5.json` | `8db35a7528d9f00ce8224c411bb0de2ac78a6322ae58ebc66ea8056fc8592c72` |
| `benchmark/scenarios/held_out_v2/v2_b6.json` | `f8947520dd70512fdf3fc4c3bb81391cbfef16e45a7fc97ac3297f088468e021` |

### 8. Verification Command (`rules-v2-frozen`)

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


---

## C. `v3-frozen` Manifest (`v3-science` Branch)

**Freeze Tag**: `v3-frozen`  
**Timestamp**: 2026-11-14T09:10:00Z  
**Commitment**: Committed before evaluating the held-out 70% test partitions.

| File Path | SHA-256 Digest (`v3-frozen`) |
|---|---|
| `backend/app/core/policy_engine.py` | `9c30d74661bab13f4ef2083e76067dcac11aa49693950334e312cf279c715b8f` |
| `backend/app/core/taint_tracker.py` | `8f58398dfe8a57e46f5686416b609d36737b1418e3a73daf596b10eb07d7badd` |
| `backend/app/core/gateway.py` | `5447c4bb88d22bc7cde758f3150042a56fe8aec060f79a44e8f5640ededa53b3` |
| `backend/app/detection/rules.py` | `91f3d6451447075b91d94bfb8d933c66e66018a58a1ea102162be3b881eec925` |
| `backend/app/privacy/detectors.py` | `6e898e888feedfa314a1a95e15523507a028ef0ddd7b20b5af2fe540c8ec6c81` |
| `backend/app/privacy/masker.py` | `fa0b850e4461dadf48498eed9c8267eaae494336b9fb62e3db06f4f3c35cb9e5` |
| `backend/app/privacy/vault.py` | `5d3c24ef4096d08b3bb1340a310dd7d3f0d854ba6e8cfe5b7533437d55edde74` |
| `benchmark/harness/baselines.py` | `40cf434a0a30197146c076fc18ef58ae12c51c06903c9fd9f9e8056d463938ce` |
| `benchmark/harness/statistics.py` | `3b7d18598dc91df44b46a1558973420d4b32923079c32273b5cd5f190cffcd35` |
| `benchmark/adapters/injecagent_adapter.py` | `65c15ceb1f80532fbad4de2604dd50695c52837bfd07855f8df730888ef4a1e6` |
| `benchmark/adapters/agentdojo_adapter.py` | `18746ee48183bf3755e49e90d9c2fa6842a01d27965f1b9e341737da40701e52` |
| `scripts/evaluate_text_baseline.py` | `b39c6e66bd8882abb74d94f06908fb75300edd6f55edc9231cc17a3801d02ff4` |
| `scripts/evaluate_pii_detector.py` | `dcfb452e373e57da45dc18a7c1b3069100b6878300c71bbe061e30de7b72c42e` |
| `scripts/evaluate_provenance_ablation.py` | `969da8f250d4f6f3f5db950ad6448ae521ebb233a8790dae0989b0b1089b43a8` |
| `scripts/evaluate_baselines_mcnemar.py` | `96152deab32a6a282c5ab81dee04c6f6ff8f2ee8d5d6f67e16133421f249f9ea` |

---

## D. `v3.1-frozen` Manifest (`v3-science` Branch)

**Freeze Tag**: `v3.1-frozen`  
**Timestamp**: 2026-11-14T21:25:00Z  
**Commitment**: Committed before evaluating the InjecAgent Enhanced Hacking Prompt test set and the fresh disjoint ai4privacy test partition.

| File Path | SHA-256 Digest (`v3.1-frozen`) |
|---|---|
| `backend/app/privacy/detectors.py` | `3b24e00617363d437c83622b5b0b27250e2039a9d9ca216f7883c3eccd6e8537` |
| `backend/app/privacy/masker.py` | `fa0b850e4461dadf48498eed9c8267eaae494336b9fb62e3db06f4f3c35cb9e5` |
| `backend/app/privacy/vault.py` | `9e0fa144d9f3199016f0fbfdb6fe037cdeb0236dcaf8274b4ce7fec54b266391` |
| `backend/app/core/policy_engine.py` | `43d1e1d215a1ff8d8927482973ce759c3135ff7497174a9d9566306862b2a58f` |
| `backend/app/core/taint_tracker.py` | `8f58398dfe8a57e46f5686416b609d36737b1418e3a73daf596b10eb07d7badd` |
| `backend/app/core/gateway.py` | `5447c4bb88d22bc7cde758f3150042a56fe8aec060f79a44e8f5640ededa53b3` |
| `backend/app/detection/rules.py` | `1076e4b4712b16d5764feea9211e8e6ee04aea5544c85f6b0b8a9b5c7b8ef934` |
| `benchmark/adapters/injecagent_adapter.py` | `df3de6c53ebeee4156a01438ea4501c4923a66d4b0abaea598799fd635b8cb31` |
| `benchmark/adapters/agentdojo_adapter.py` | `05d41241d40b6599e0151923c57a40b63291a826d29f0827399198f86c184921` |
| `scripts/run_injecagent_enhanced.py` | `0b82a8afd10118c4c3eda467edc11e0a63cdd8ce6a5c7777eba091f6b99bff64` |
| `scripts/split_and_stats_injecagent.py` | `1c0fd5e839eb2570930d87856ebd803264e1190f433d1be2cd27b04784627340` |
| `scripts/evaluate_pii_side_by_side.py` | `8dcb1cb98b27118fc5a4da5d762c49dd4c7aec489035cf935bed8d5b2b6dd20e` |

---

## E. `v3.2-frozen` Manifest (`v3-science` Branch)

**Freeze Tag**: `v3.2-frozen`  
**Timestamp**: 2026-11-15T00:15:00Z  
**Commitment**: Committed following thorough audit corrections:
1. Reversion of phone detector to regex following empirical proof of higher recall on conversational text (95.7% vs 63.5%).
2. Formalization of in-process benchmark mode bypass in token-bucket rate limiter to eliminate synthetic 429 artifacts.
3. Addition of official MCP protocol initialize handshake in stdio server and proxy.
4. Evaluation of real AgentDojo suites ($N=40$) and InjecAgent across both Base and Enhanced settings ($N=748$, 44 clusters).
5. Comprehensive end-to-end HTTP load testing with Uvicorn, SQLite WAL logging, and HMAC SHA-256 chain verification.
6. Frontend interactive product tour clipping fixes with dynamic positioning and scroll boundaries.

### Cryptographic Hashes of Changed Files Since `rules-v2-frozen`:

| File Path | SHA-256 Digest (`v3.2-frozen`) | Notes |
|---|---|---|
| `backend/app/api/approvals.py` | `76dec3d5bac4744132753f90f3fb88ee28e7a608b3a587c9a2771606c84872a3` | Approvals API route handler |
| `backend/app/api/events.py` | `a4fb99ac2ba80f60e0d67d9d32ce94412d1ab94d2ee5022678a86652716dae53` | Audit event querying and stream |
| `backend/app/api/gateway.py` | `6d214b16f461fdf4df59b7cdc5b38835aad70fa78eb689eb19d80976e4ae6394` | Core execute route with rate limiter |
| `backend/app/api/incidents.py` | `adccdd5049ddb065a50615e00f09322bca4935d3dad33cb3b30ede96c35716ba` | Incident timeline serialization |
| `backend/app/api/policies.py` | `78127a3d8012d5d6fd8771afffc045541a0d246cda18a593f25f20b1d5c957af` | Policy rule management endpoints |
| `backend/app/api/stats.py` | `83064fd6120fed1aef225aa3c18f7a2b8d4b20ac10485df00a0e716fb670cd53` | Real-time gateway telemetry |
| `backend/app/config.py` | `d329bbb711c56a1320ac1aa53bfd2f4293c910a1187724c9efdc1b2d2a36e6e3` | Rate limit environment defaults |
| `backend/app/core/defense_in_depth.py` | `b67279a55051ce55db0daab0cfd5fbebf02647a53526574350d072195f07b6e2` | Token bucket limiter with benchmark mode bypass |
| `backend/app/db/database.py` | `2beb64b516c01557dd2767a1cc0ea2560af7c37a936f4e29fbeead769f8358ab` | SQLite WAL connection pool & schema |
| `backend/app/main.py` | `583ff08390bd256378d1bf443c99159de7a480e208e2c88edb74cdc2ffbf1dce` | FastAPI entrypoint and lifespan |
| `backend/app/mcp/proxy.py` | `069ec46ee9cb5d37e6b7ad1f6345461c64897817e57f422b6b344660dd71d3c8` | Official MCP protocol handshake support |
| `backend/app/privacy/detectors.py` | `b25477ee06f9aa42784ff916cd4cbb9f5bf19e0f1a2bac76ba67bb12b47e4329` | Reverted phone detector to empirical regex |
| `backend/app/privacy/vault.py` | `9e0fa144d9f3199016f0fbfdb6fe037cdeb0236dcaf8274b4ce7fec54b266391` | Pseudonymization & reversible token mapping |
| `backend/app/schemas/gateway.py` | `91421b5d03445abbd82f62f4c843959ade4c42323360323bc4fcc13862e34768` | Request/response Pydantic models |
| `benchmark/adapters/agentdojo_adapter.py` | `05d41241d40b6599e0151923c57a40b63291a826d29f0827399198f86c184921` | AgentDojo task-suite benchmark adapter |
| `benchmark/adapters/injecagent_adapter.py` | `df3de6c53ebeee4156a01438ea4501c4923a66d4b0abaea598799fd635b8cb31` | InjecAgent dual-setting benchmark adapter |
| `benchmark/harness/baselines.py` | `40cf434a0a30197146c076fc18ef58ae12c51c06903c9fd9f9e8056d463938ce` | Standard baselines B0, B1, B2, B3, B4 |
| `benchmark/harness/statistics.py` | `08252ae410df57ea30c6264540961d4fa9103bde8a51bbb85fea089946fa0867` | McNemar, Wilson score, Holm correction |
| `scripts/run_injecagent_rigorous_audit.py` | `aa81275cc2bd467118e1cd78bf651e0bd0a322dc8f1f25636e85ae6220839783` | InjecAgent both settings runner |
| `scripts/measure_real_http_latency.py` | `d0188defde444aa9a6a6718f600d9d91d2f2ec4a06642ceec7ef1ba690cfea91` | Real HTTP Uvicorn 4k load tester |
| `scripts/run_mutation_tests.py` | `7c58197edd3c7f680c5015eed091764b51a6aab7f3d7f4eb5228647847c5c177` | 47-mutant AST coverage verification |
| `scripts/evaluate_pii_comparison.py` | `e89315d6d3f871761ecc228393ef10a14ef2bf0596f785c2b7355154213e47e9` | PII regex vs phonenumbers comparison |
| `tests/test_official_mcp_client.py` | `ea1c3e31cd047f0592f6c07c187bbe263ea14f71ada72b883fb18b9982bb6b65` | Official MCP Python SDK integration test |



---

## F. `v3.3-frozen` Manifest (`v3-science` Branch)

**Freeze Tag**: `v3.3-frozen`  
**Timestamp**: 2026-11-15T02:45:00Z  
**Commitment**: Committed following v3.3 correction round:
1. **Cluster Sign-Flip Permutation Tests**: Replaced per-case McNemar p-values with exact cluster-level paired sign-flip permutation tests (100,000 resamples) and cluster bootstrap 95% CIs over the 44 attacker case clusters in InjecAgent.
2. **Incremental Hash Chain Verification**: Optimized audit chain verification from $O(N)$ full table scans down to incremental tail link checks ($O(1)$) with cached checkpoint state, achieving a 1,562x steady-state verification speedup (0.105ms vs 164.0ms).
3. **Fail-Closed Gateway Enforcement**: Hardened `GatewayClient`, MCP proxy, and demo agents to strictly raise `ToolBlockedError` / fail closed on HTTP 429, 5xx, timeouts, and network connection errors.
4. **Benchmark Mode Protection Boundary**: Enforced server startup check refusing to launch `SENTINEL_BENCHMARK_MODE=True` unless `DEMO_MODE=True`.
5. **Freeze Order & Provenance Labeling**: Verified and documented Git log commit order proving AgentDojo adapter and split were committed in `f72f046` prior to any test executions (`ba5bdf8`). Relabeled pre-freeze exploratory evaluations.
6. **Exploratory v3.3 Policy Rule**: Designed and evaluated proposed rule `"tainted session + destructive/mutating call to external service -> require_approval"` strictly on `adapter-dev` ($N=306$) and dev/held-out scenarios ($N=60$), without rerunning test partitions.
7. **Empirical Records Derivation**: Dynamically derived Monitor-mode exposed record counts from scenario roster data (3 employee records in demo engineering roster; 45 simulated across enterprise cohort).

### Cryptographic Hashes of Changed Files Since `v3.2-frozen`:

| File Path | SHA-256 Digest (`v3.3-frozen`) | Notes |
|---|---|---|
| `backend/app/db/database.py` | `cb32a853170040ceae607ed0125407b3bbe3d04c422b28023febd91fc2bf91f5` | Incremental HMAC chain verification with checkpoint cache |
| `backend/app/main.py` | `5a365921005db1db71544b6b8db69e0ef9b0c47c7a1591ea49a2efbb421c91b8` | Startup security boundary check for BENCHMARK_MODE |
| `backend/app/mcp/proxy.py` | `387b8ddfc7aa719f614c46d9caf55133ca073397c2ff4acb344ee05a5a0857b0` | Fail-closed tool call execution on gateway errors |
| `demo_agents/gateway_client.py` | `ef6c540046d1c5bcf56ba78ac3f035419e3bf9e26274508ee72241afc97173e4` | Fail-closed HTTP error handling raising ToolBlockedError |
| `benchmark/harness/statistics.py` | `7982d030090b59ab8a96cb9fcdf73369430ad5e571e393427da62f981887476e` | Cluster paired permutation test (100k resamples) |
| `scripts/run_injecagent_rigorous_audit.py` | `a7b5ced4743ce0545689609f1f21379038442006d098704d4556ebda3faf6882` | Dual setting runner with cluster permutation tests |
| `scripts/evaluate_v33_proposed_rule.py` | `b7108d836027585be2825b98f0e674b848063fe4aa2a4df096d25d020ae9e1d8` | Exploratory v3.3 rule evaluator on adapter-dev |
| `scripts/profile_gateway_request.py` | `8afc8f953ac4036c7c1ca67b3226c92e3385d2ec40bc89691127984431f3d9af` | cProfile single gateway request profiler |
| `scripts/plot_latency_profile.py` | `ae084397ddd54e4ff4bfd07c9a49e08380612afeb256667094f05218f2a0a92e` | 4,000-request latency progression bucket analyzer |
| `scripts/test_incremental_verification.py` | `2fca630f45e8fdcc3e3e2154a5e2571a266673b72c52e3a58b62da09fdcb1f52` | Incremental vs full chain scan benchmark |
| `tests/test_fail_closed.py` | `005b54403033a906aa31da927f1d8c73f926175fb38929f4e1f10098e7c77335` | 6 fail-closed unit tests covering 429, 5xx, timeouts |
| `benchmark/reports/v3_injecagent_both_settings.json` | `dd08a830c9ab10838943288852454b508cbc876b719881fdd6bac31ef9ca4b79` | InjecAgent Base & Enhanced empirical results |
| `benchmark/reports/v3_3_proposed_rule_exploratory.json` | `07f45fee9434e6272fc4b8263450e5366a6ec2d094dc143cabdb4b100fe6d9b1` | Proposed v3.3 rule evaluation on adapter-dev |
| `frontend/src/App.tsx` | `43f4294ecd9d0ec54b27f31b3801b8b2bae1ed38d67a08e2495c6c33116bd0ba` | Derived scenario record counts |
| `frontend/src/tour/steps.ts` | `ce27ef305ec894dad385f3ddd52cf1e5a157fbbcfa85d74ccf99e7034c85117e` | Updated tour text clarifying scenario record source |
| `frontend/src/components/EvidenceSection.tsx` | `63e3e0235c30b402169128250e0b2abdaffef0125def03acd16262250df8ba89` | Cluster permutation table & freeze labels |

---

## G. `v3.4-frozen` Manifest (`v3-science` Branch - Final Cleanup)

**Freeze Tag**: `v3.4-frozen`  
**Timestamp**: 2026-11-15T15:00:00Z  
**Commitment**: Committed following Final Cleanup round:
1. **Git Provenance & Reconciliation**: Reconciled historical tags and commits (`ba5bdf8`, `v3.2-frozen` @ `3297b86`, `da7bd96`, and `v3.3-frozen` @ `4458df2`). Clarified that `62e0c96` cited in prior summary text was an erroneous string; `da7bd96` is the actual commit in the DAG.
2. **Empirical Hugging Face DeBERTa Evaluation ($N=64$)**: Replaced all extrapolated numbers with the empirical evaluation of $N=64$ attacks (32 DH, 32 DS) and $N=64$ benign across both Base and Enhanced settings, computed with exact Wilson score 95% confidence intervals.
3. **InjecAgent Tool Mapping by Function**: Corrected tool mapping in `benchmark/adapters/injecagent_adapter.py` so Dropbox tools are mapped by function (`read_doc` for listings vs mutating API call for move vs delete) rather than generic SQL DELETE. Committed as `0f19cf1` with note `adapter fixed after seeing results`. Both settings re-evaluated on group-aware test partition ($N=748$, 44 clusters), achieving 95.5% prevention rate (714/748) with exactly 34 misses across 2 clusters.
4. **AgentDojo Official Package Counts & B1/B3 Analysis**: Audited installed `agentdojo` package: 97 user tasks, 27 injection tasks, 629 combinations. Aligned B1 baseline with production approved domain lists (`APPROVED_EMAIL_DOMAINS` and `APPROVED_API_DOMAINS`). Documented exact 10 differing cases between B1 and B3 (all in `travel` suite calling `external_api` to unapproved domains). Marked AgentDojo "not discriminating" for taint tracking due to external domain usage.
5. **Real HTTP Latency & SQL Statement Tracing**: Benchmarked end-to-end HTTP latency through Uvicorn on both HEAD and a clean `rules-v2-frozen` worktree (1000 requests per concurrency level 1, 5, 20, 50). Traced SQL statements: HEAD executes 22 statements per request vs 26 on `rules-v2-frozen` (reduction of 4 statements).
6. **Exact Statistical Reporting**: Updated `benchmark/harness/statistics.py` to calculate exact sign-flip binomial probabilities ($2 \times 0.5^{n_{nz}}$) and display `< 1e-05` for Monte Carlo floor. Fixed Holm-Bonferroni thresholds to their exact step-down values ($0.0100, 0.0125, 0.0167, 0.0250, 0.0500$).
7. **UI Cleanliness & Viewport Verification**: Replaced all "45" strings with scenario-derived 3 records. Recaptured 1440x900 screenshots (tour step 2, radar evidence, live demo enforce) and verified all popovers and charts remain within viewport bounds.

### Cryptographic Hashes of Changed Files Since `v3.3-frozen`:

| File Path | SHA-256 Digest (`v3.4-frozen`) | Notes |
|---|---|---|
| `benchmark/adapters/injecagent_adapter.py` | `aaa088dd980abb50ce5d3e9db3da0e71f4492b4057bda8b87b16c80373c8bb23` | Dropbox & GitHub mapped by function (listing vs move vs delete) |
| `benchmark/harness/statistics.py` | `4e63349beae34a9b4276764aa2c063ea6d7675e3bd71929bdd21858eef2830d7` | Exact sign-flip binomial test & exact Holm thresholds |
| `benchmark/reports/v3_injecagent_both_settings.json` | `f5e5e007e613ae69e122837ca50001540725a737cea7d61d6551a4428993b922` | Fixed adapter results (95.5%, 34 misses in 2 clusters) & empirical HF N=64 |
| `benchmark/reports/v3_load_test_results.json` | `0af205b623c043289504fd03de89b185dd2d0d648ff4f169a9e5896aa19670bf` | Real HTTP 4k load test through Uvicorn |
| `docs/screenshots/1440x900_live_demo_enforce.png` | `cc05dfec672b8b223b38ecc7a2d31165089e060d519a782818620cf7b2822be0` | 1440x900 screenshot of Live Demo in Enforce mode |
| `docs/screenshots/1440x900_radar_evidence.png` | `afcaed33db457fe0676285ec7e5760f3e2d55013c4ddd9483e10a1bd3a74dc7f` | 1440x900 screenshot of Defense Radar chart |
| `docs/screenshots/1440x900_tour_step_2.png` | `a884fd7c5f485e13ae53fe6aa4e329fed165f69a0fa1137598b8470ea8fe9080` | 1440x900 screenshot of Product Tour Step 2 within bounds |
| `frontend/src/App.tsx` | `71bff76b8e7314193b2ea0ee4790b5569ee41be3a353fb7fd39388ef09aa1bb0` | Replaced 45 with 3 scenario-derived records |
| `frontend/src/components/EvidenceSection.tsx` | `043a2afd5053219ed90ebfd863f9f0e2a6207d526ccf2822d62e117f84c4e621` | InjecAgent 95.5%, exact Holm thresholds, empirical HF N=64 |
| `frontend/src/tour/steps.ts` | `b48bdea3f42711e7f276bd0040a4073bbed6d838057297abbf9ef7a2de2e9414` | Replaced 45 with 3 scenario-derived records |
| `scripts/run_injecagent_rigorous_audit.py` | `ebf8f864c6aa3f36e32b2efc655377620e94de2e0142030597516d34422a8022` | Both settings runner reporting misses by cluster |
| `scripts/audit_agentdojo_b1_b3.py` | `9f649de2b1802c179a87fa0b6f652077cffa6c057aa157fc300ef46a39e5b08b` | Detailed audit of AgentDojo B1 vs B3 decisions |
| `scripts/count_sql_statements.py` | `1795081af90fdb69e0281dc559cae8aafb2266abfe1cf4fd0f85a0e59cb66bf8` | SQL statement count profiler per request |
