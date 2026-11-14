# Preregistration: PII Detection Enhancements (v3.1)

**Date**: 2026-11-14  
**Status**: Committed and Frozen BEFORE Test Partition Evaluation  
**Target Benchmark**: ai4privacy PII Masking (English subset, validation split)

---

## 1. Motivation & Error Analysis on Previous Slice
In the initial v3 evaluation on the old ai4privacy slice (1,028 test records), `PhoneDetector` exhibited excessive false positives due to raw regex greediness matching:
1. IPv4 addresses (e.g., `192.168.1.1`, `169.254.169.254`).
2. High-digit sequences (>15 digits) or date formats (`2026-11-14`).
3. Bare 7-digit substrings lacking telephone formatting.

Concurrently, `NationalIdDetector` had false negatives on international and keyword-preceded unhyphenated national IDs (e.g., UK NINO, Canadian SIN, and unseparated 9-digit SSNs).

---

## 2. Preregistered Architectural Improvements
The following specific deterministic upgrades are preregistered for `backend/app/privacy/detectors.py`:

### 2.1 PhoneDetector Upgrade
- **Library Integration**: Integrate Google's `phonenumbers` (Python port of `libphonenumber`, v9.0.43).
- **Extraction Strategy**: Utilize `phonenumbers.PhoneNumberMatcher(text, "US", leniency=phonenumbers.Leniency.POSSIBLE)` to leverage ITU-T E.164 parsing rules.
- **Strict Guardrails**:
  1. Reject any candidate containing an IPv4 address pattern (`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`).
  2. Digit length bounds: Require normalized digit count between 7 and 15 digits (`7 <= len(digits) <= 15`).
  3. Validate structural possibility via `phonenumbers.is_possible_number(match.number)`.

### 2.2 NationalIdDetector Upgrade
- **US SSN**: Retain standard hyphenated format (`\b(?:\d{3}|000)-[0-9A-Za-z]{2}-[0-9A-Za-z]{4}\b`).
- **Contextual Unhyphenated SSN**: Detect 9-digit strings preceded by contextual triggers (`ssn`, `social security`, `tax id`, `national id`):
  `(?i)\b(?:ssn|social\s*security(?:\s*number)?|tax\s*id|national\s*id)[\s:#=-]*(\d{9})\b`.
- **UK National Insurance Number (NINO)**: Add HMRC format `\b[A-CEGHJ-PR-TW-Z]{2}\s*\d{6}\s*[A-D]\b`.
- **Canadian Social Insurance Number (SIN)**: Add 3-3-3 format `\b\d{3}[ -]\d{3}[ -]\d{3}\b`.

---

## 3. Fresh Disjoint Test Slice Specification
- **Dataset**: `ai4privacy/pii-masking-300k` (`data/validation/1english_openpii_8k.jsonl`).
- **Fresh Slice Window**: Records 1,501 to 3,000 (1,500 records), strictly disjoint from the initial slice (records 1 to 1,500).
- **Partitioning**:
  - Deterministic PRNG Seed: `99` (SHA-256 hash partitioning).
  - Dev Partition (30%): 450 records in `benchmark/data_splits/dev/ai4privacy_fresh_dev.json`.
  - Test Partition (70%): 1,050 records in `benchmark/data_splits/test/ai4privacy_fresh_test.json`.
- **Execution Protocol**:
  - Adapter & detector code frozen under tag `v3.1-frozen` with hashes in `docs/frozen_manifest.md`.
  - Test partition run exactly ONCE.
  - Old ($N=1,028$) and fresh ($N=1,050$) results reported side-by-side in `benchmark/reports/v3_pii_evaluation_test.json`.
