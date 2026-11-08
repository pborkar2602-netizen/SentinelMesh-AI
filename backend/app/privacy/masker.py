import copy
from typing import Any, Dict, List, Tuple

from backend.app.privacy.detectors import CompositePiiDetector, PiiFinding
from backend.app.privacy.vault import PrivacyVault

class PrivacyEngine:
    """
    Central Privacy & Masking Engine for SentinelMesh AI.
    Scans payloads, performs session-consistent tokenization, masks data before logging,
    and computes structured privacy risk metrics.
    """
    _detector = CompositePiiDetector()

    @classmethod
    def mask_text(cls, session_id: str, text: str) -> Tuple[str, List[PiiFinding]]:
        """
        Detects PII in a string and replaces values with session-consistent tokens.
        Replaces backwards from string end to preserve character offsets.
        """
        if not text or not isinstance(text, str):
            return text, []

        findings = cls._detector.detect(text)
        if not findings:
            return text, []

        # Sort findings by start descending so replacement doesn't invalidate earlier spans
        sorted_findings = sorted(findings, key=lambda f: f.start, reverse=True)
        masked = text

        for f in sorted_findings:
            token = PrivacyVault.get_or_create_token(session_id, f.pii_type, f.value)
            masked = masked[:f.start] + token + masked[f.end:]

        return masked, findings

    @classmethod
    def mask_payload(cls, session_id: str, obj: Any) -> Tuple[Any, List[PiiFinding]]:
        """
        Recursively traverses dicts, lists, or primitive values,
        masking all sensitive PII strings and aggregating all findings.
        """
        all_findings: List[PiiFinding] = []

        def _traverse(item: Any) -> Any:
            if isinstance(item, str):
                masked_str, findings = cls.mask_text(session_id, item)
                all_findings.extend(findings)
                return masked_str
            elif isinstance(item, dict):
                return {k: _traverse(v) for k, v in item.items()}
            elif isinstance(item, list):
                return [_traverse(elem) for elem in item]
            elif isinstance(item, tuple):
                return tuple(_traverse(elem) for elem in item)
            else:
                return item

        masked_obj = _traverse(obj)
        return masked_obj, all_findings

    @classmethod
    def calculate_privacy_risk(
        cls,
        findings: List[PiiFinding],
        is_external: bool = False,
        is_tainted: bool = False
    ) -> Tuple[int, Dict[str, Any]]:
        """
        Calculates a standardized 0-100 privacy risk score with structured breakdown.
        Generates readable data-class summaries (e.g., '3 emails, 2 salary amounts exposed or attempted').
        """
        if not findings:
            return 0, {
                "score": 0,
                "classes_present": [],
                "counts": {},
                "summary": "No PII detected",
                "is_external": is_external,
                "is_tainted": is_tainted
            }

        # Severity weights per data class
        weights = {
            "CREDIT_CARD": 35,
            "NATIONAL_ID": 35,
            "API_KEY": 30,
            "IBAN": 25,
            "SALARY": 20,
            "EMAIL": 10,
            "PHONE": 10,
            "PERSON_NAME": 5
        }

        counts: Dict[str, int] = {}
        base_score = 0
        for f in findings:
            ptype = f.pii_type
            counts[ptype] = counts.get(ptype, 0) + 1
            w = weights.get(ptype, 10)
            # Diminishing returns for repeated occurrences of the same type
            factor = 1.0 if counts[ptype] == 1 else (0.5 if counts[ptype] == 2 else 0.25)
            base_score += w * factor

        # Context multipliers
        multiplier = 1.0
        if is_external:
            multiplier *= 1.4
        if is_tainted:
            multiplier *= 1.3

        final_score = int(min(100, max(0, round(base_score * multiplier))))

        # Human-readable summary string
        summary_labels = {
            "CREDIT_CARD": ("card number", "card numbers"),
            "NATIONAL_ID": ("national ID", "national IDs"),
            "API_KEY": ("API key / secret", "API keys / secrets"),
            "IBAN": ("bank IBAN", "bank IBANs"),
            "SALARY": ("salary amount", "salary amounts"),
            "EMAIL": ("email", "emails"),
            "PHONE": ("phone number", "phone numbers"),
            "PERSON_NAME": ("person name", "person names")
        }

        summary_parts = []
        for ptype, count in counts.items():
            sing, plur = summary_labels.get(ptype, (ptype.lower(), f"{ptype.lower()}s"))
            summary_parts.append(f"{count} {sing if count == 1 else plur}")

        summary_text = f"{', '.join(summary_parts)} exposed or attempted"

        breakdown = {
            "score": final_score,
            "classes_present": sorted(list(counts.keys())),
            "counts": counts,
            "summary": summary_text,
            "is_external": is_external,
            "is_tainted": is_tainted
        }

        return final_score, breakdown
