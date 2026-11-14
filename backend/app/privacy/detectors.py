import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional, Tuple

@dataclass
class PiiFinding:
    pii_type: str        # "EMAIL", "PHONE", "NATIONAL_ID", "CREDIT_CARD", "IBAN", "API_KEY", "SALARY", "PERSON_NAME"
    start: int
    end: int
    value: str
    confidence: float    # 0.0 to 1.0

class IPiiDetector(ABC):
    @abstractmethod
    def detect(self, text: str) -> List[PiiFinding]:
        """Detects PII occurrences within text and returns structured findings."""
        pass

def luhn_checksum(card_number_str: str) -> bool:
    """Validates credit card numbers using the standard Luhn algorithm (Mod 10)."""
    digits = [int(d) for d in re.sub(r"\D", "", card_number_str)]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += (doubled - 9) if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0

def validate_iban(iban_str: str) -> bool:
    """Validates international bank account numbers using ISO 7064 Modulo 97 check."""
    clean = re.sub(r"\s+", "", iban_str).upper()
    if len(clean) < 14 or len(clean) > 34:
        return False
    # Move first 4 characters to end
    rearranged = clean[4:] + clean[:4]
    # Replace letters with digits: A=10, B=11, ... Z=35
    digits = ""
    for char in rearranged:
        if char.isdigit():
            digits += char
        elif char.isalpha():
            digits += str(ord(char) - ord('A') + 10)
        else:
            return False
    try:
        return int(digits) % 97 == 1
    except ValueError:
        return False

class EmailDetector(IPiiDetector):
    REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

    def detect(self, text: str) -> List[PiiFinding]:
        findings = []
        for match in self.REGEX.finditer(text):
            val = match.group(0)
            findings.append(PiiFinding(
                pii_type="EMAIL",
                start=match.start(),
                end=match.end(),
                value=val,
                confidence=0.98
            ))
        return findings

try:
    import phonenumbers
    HAS_PHONENUMBERS = True
except ImportError:
    HAS_PHONENUMBERS = False

class PhoneDetector(IPiiDetector):
    """
    Regex-based phone detector.
    Note: Evaluated against google's phonenumbers library on ai4privacy test partitions:
    - Regex Phone F1: 64.48% (recall 95.74%) on original test; 48.73% (recall 92.95%) on fresh test.
    - Phonenumbers F1: 41.30% (recall 63.53%) on original test; 32.56% (recall 67.84%) on fresh test.
    The phonenumbers library caused a severe ~30% recall drop on unstructured conversational LLM text,
    so regex was retained as the superior production detector.
    """
    REGEX = re.compile(r"(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{3,4}\b")
    IPV4_REGEX = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

    def detect(self, text: str) -> List[PiiFinding]:
        findings = []
        for match in self.REGEX.finditer(text):
            val = match.group(0)
            if self.IPV4_REGEX.search(val):
                continue
            digits = re.sub(r"\D", "", val)
            if 7 <= len(digits) <= 15:
                findings.append(PiiFinding(
                    pii_type="PHONE",
                    start=match.start(),
                    end=match.end(),
                    value=val,
                    confidence=0.88
                ))
        return findings

class NationalIdDetector(IPiiDetector):
    # Detects standard US SSN (000-XX-XXXX or XXX-XX-XXXX)
    US_SSN = re.compile(r"\b(?:\d{3}|000)-[0-9A-Za-z]{2}-[0-9A-Za-z]{4}\b")
    # Contextual unhyphenated 9-digit SSN
    CONTEXT_SSN = re.compile(r"(?i)\b(?:ssn|social\s*security(?:\s*number)?|tax\s*id|national\s*id)[\s:#=-]*(\d{9})\b")
    # UK National Insurance Number (NINO)
    UK_NINO = re.compile(r"\b[A-CEGHJ-PR-TW-Z]{2}\s*\d{6}\s*[A-D]\b")
    # Canadian Social Insurance Number (SIN)
    CA_SIN = re.compile(r"\b\d{3}[ -]\d{3}[ -]\d{3}\b")

    def detect(self, text: str) -> List[PiiFinding]:
        findings = []
        # 1. Hyphenated SSN
        for match in self.US_SSN.finditer(text):
            findings.append(PiiFinding(
                pii_type="NATIONAL_ID",
                start=match.start(),
                end=match.end(),
                value=match.group(0),
                confidence=0.95
            ))
        # 2. Contextual 9-digit SSN
        for match in self.CONTEXT_SSN.finditer(text):
            val = match.group(1)
            findings.append(PiiFinding(
                pii_type="NATIONAL_ID",
                start=match.start(1),
                end=match.end(1),
                value=val,
                confidence=0.90
            ))
        # 3. UK NINO
        for match in self.UK_NINO.finditer(text):
            findings.append(PiiFinding(
                pii_type="NATIONAL_ID",
                start=match.start(),
                end=match.end(),
                value=match.group(0),
                confidence=0.92
            ))
        # 4. Canadian SIN
        for match in self.CA_SIN.finditer(text):
            findings.append(PiiFinding(
                pii_type="NATIONAL_ID",
                start=match.start(),
                end=match.end(),
                value=match.group(0),
                confidence=0.92
            ))
        return findings

class CreditCardDetector(IPiiDetector):
    # 13 to 19 digits formatted with optional spaces or dashes
    REGEX = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

    def detect(self, text: str) -> List[PiiFinding]:
        findings = []
        for match in self.REGEX.finditer(text):
            val = match.group(0)
            if luhn_checksum(val):
                findings.append(PiiFinding(
                    pii_type="CREDIT_CARD",
                    start=match.start(),
                    end=match.end(),
                    value=val,
                    confidence=0.99
                ))
        return findings

class IbanDetector(IPiiDetector):
    REGEX = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9\s]{11,32}\b")

    def detect(self, text: str) -> List[PiiFinding]:
        findings = []
        for match in self.REGEX.finditer(text):
            val = match.group(0).strip()
            if validate_iban(val):
                findings.append(PiiFinding(
                    pii_type="IBAN",
                    start=match.start(),
                    end=match.end(),
                    value=val,
                    confidence=0.99
                ))
        return findings

class ApiKeyDetector(IPiiDetector):
    PATTERNS = [
        (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS Access Key"),
        (re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b"), "GitHub Token"),
        (re.compile(r"\bBearer\s+[a-zA-Z0-9_\-\.]{25,}\b"), "Bearer Token"),
        (re.compile(r"\bxox[baprs]-[0-9a-zA-Z-]{10,}\b"), "Slack Token"),
        (re.compile(r"(?:api[_-]?key|secret[_-]?token|auth[_-]?token)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]", re.IGNORECASE), "API Secret Key")
    ]

    def detect(self, text: str) -> List[PiiFinding]:
        findings = []
        for regex, desc in self.PATTERNS:
            for match in regex.finditer(text):
                val = match.group(0)
                findings.append(PiiFinding(
                    pii_type="API_KEY",
                    start=match.start(),
                    end=match.end(),
                    value=val,
                    confidence=0.96
                ))
        return findings

class SalaryDetector(IPiiDetector):
    # Matches currency representations: $185,000, 185,000 USD, $185k, Salary: $185,000
    REGEX = re.compile(
        r"(?:(?:\$|USD\s*|EUR\s*|GBP\s*|£|€)\s*\d{1,3}(?:,\d{3})+(?:\.\d{2})?(?:\s*(?:k|per\s*year|yr|annum))?)|"
        r"(?:\b\d{2,3}(?:,\d{3})+\s*(?:USD|EUR|GBP|dollars)\b)|"
        r"(?:(?:salary|compensation|base\s*pay)\s*(?:of|is|:|=)?\s*\$?\d{2,3}(?:,\d{3})+)",
        re.IGNORECASE
    )

    def detect(self, text: str) -> List[PiiFinding]:
        findings = []
        for match in self.REGEX.finditer(text):
            val = match.group(0)
            findings.append(PiiFinding(
                pii_type="SALARY",
                start=match.start(),
                end=match.end(),
                value=val,
                confidence=0.92
            ))
        return findings

class PersonNameDetector(IPiiDetector):
    """
    Lightweight, deterministic NER / dictionary detector for person names,
    operating behind the IPiiDetector interface.
    """
    TITLES = r"(?:Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.)"
    KNOWN_NAMES = {
        "alice", "bob", "charlie", "david", "eve", "frank", "grace", "heidi",
        "ivan", "judy", "mallory", "oscar", "peggy", "trent", "walter",
        "alex", "sarah", "john", "michael", "elizabeth", "emily", "james",
        "verma", "smith", "doe", "johnson", "williams", "brown", "jones",
        "miller", "davis", "wilson", "anderson", "taylor", "thomas"
    }

    PATTERN = re.compile(
        rf"(?:{TITLES}\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)|"
        rf"(?:\b[A-Z][a-z]+\s+[A-Z][a-z]+\b)",
    )

    def detect(self, text: str) -> List[PiiFinding]:
        findings = []
        for match in self.PATTERN.finditer(text):
            val = match.group(0).strip()
            tokens = [t.lower().rstrip(".,") for t in val.split()]
            # Clean honorifics from check
            clean_tokens = [t for t in tokens if t not in ["mr", "mrs", "ms", "dr", "prof"]]
            
            # Check if any token matches known names dictionary or has honorific
            has_title = any(t in tokens for t in ["mr", "mrs", "ms", "dr", "prof"])
            matches_dict = any(t in self.KNOWN_NAMES for t in clean_tokens)
            
            # Avoid false positives like "Engineering Department", "System Instruction", etc.
            stopwords = {"system", "instruction", "override", "engineering", "department", "database", "query", "select", "company", "vendor", "salary", "document"}
            if any(t in stopwords for t in clean_tokens):
                continue

            if has_title or matches_dict:
                findings.append(PiiFinding(
                    pii_type="PERSON_NAME",
                    start=match.start(),
                    end=match.end(),
                    value=val,
                    confidence=0.90 if has_title else 0.85
                ))
        return findings

class CompositePiiDetector(IPiiDetector):
    """
    Orchestrates all specific detectors, de-duplicates and resolves overlapping spans
    in favor of higher confidence or specific classes.
    """
    def __init__(self, detectors: Optional[List[IPiiDetector]] = None):
        if detectors is None:
            self.detectors = [
                CreditCardDetector(),
                IbanDetector(),
                NationalIdDetector(),
                ApiKeyDetector(),
                EmailDetector(),
                PhoneDetector(),
                SalaryDetector(),
                PersonNameDetector()
            ]
        else:
            self.detectors = detectors

    def detect(self, text: str) -> List[PiiFinding]:
        if not text:
            return []

        all_findings: List[PiiFinding] = []
        for detector in self.detectors:
            all_findings.extend(detector.detect(text))

        # Sort by start ascending, then length descending
        all_findings.sort(key=lambda f: (f.start, -(f.end - f.start), -f.confidence))

        # Non-overlapping greedy resolution
        resolved: List[PiiFinding] = []
        last_end = -1
        for f in all_findings:
            if f.start >= last_end:
                resolved.append(f)
                last_end = f.end
            elif f.confidence > (resolved[-1].confidence if resolved else 0):
                # Replace with higher confidence
                resolved.pop()
                resolved.append(f)
                last_end = f.end

        return resolved
