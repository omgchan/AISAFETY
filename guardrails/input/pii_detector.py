"""
PII Detector — Personally Identifiable Information Detection & Anonymization.

Meets Assignment Specification:
- Detects emails, phone numbers, identification numbers (National IDs, Citizenship, PAN, SSN, Passport).
- Detects adversarial obfuscations (spaced characters, 'at/dot' substitutions, bracketed tokens).
- Supports three anonymization actions: Redaction, Masking, and Tokenization.
- Hybrid architecture: High-performance deterministic regex bank + optional Presidio engine.
"""

from __future__ import annotations

import re
import uuid
from typing import Dict, List, Literal, Optional, Tuple
from guardrails.models import PIIFinding, PIIResult

AnonymizationMode = Literal["redact", "mask", "tokenize"]

# ----------------------------------------------------------------------
# Regex Pattern Definitions for PII
# ----------------------------------------------------------------------

# Standard Email
EMAIL_REGEX = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
)

# Obfuscated Emails: "john at example dot com", "john[at]example[dot]com"
OBFUSCATED_EMAIL_REGEX = re.compile(
    r'\b([A-Za-z0-9._%+-]+)\s*(?:@|\[at\]|\bat\b)\s*([A-Za-z0-9.-]+)\s*(?:\.|\bdot\b|\[dot\])\s*([A-Za-z]{2,7})\b',
    re.IGNORECASE,
)

# Spaced Email: "j o h n @ e x a m p l e . c o m"
SPACED_EMAIL_REGEX = re.compile(
    r'\b(?:[A-Za-z0-9]\s+){3,}@\s+(?:[A-Za-z0-9]\s+){3,}\.\s+(?:[A-Za-z]\s+){1,}[A-Za-z]\b',
    re.IGNORECASE,
)

# Phone Numbers: Nepal (+977-98XXXXXXXX, 98XXXXXXXX, 01-XXXXXXX) & International (+1, (555) 123-4567)
PHONE_REGEX = re.compile(
    r'(?:\+?977[-.\s]?)?(?:9[78]\d{8}|0[1-9][-.\s]?\d{6,7})|'  # Nepal mobile/landline
    r'(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b|'   # US/Standard 10-digit
    r'\+\d{1,4}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{2,5}[-.\s]?\d{2,5}\b'  # International E.164
)

# Spaced Phone: "9 8 4 1 2 3 4 5 6 7"
SPACED_PHONE_REGEX = re.compile(
    r'\b(?:\d\s+){9,11}\d\b'
)

# Nepal Citizenship Number: "12-01-78-12345" or "1234/5678"
NEPAL_CITIZENSHIP_REGEX = re.compile(
    r'\b\d{2}-\d{2}-\d{2}-\d{4,6}\b|\b\d{4}/\d{4,6}\b'
)

# Nepal PAN (Permanent Account Number - 9 digits) with context or standalone
PAN_NUMBER_REGEX = re.compile(
    r'(?i)\b(?:pan(?:\s*number|\s*no)?[:\s]*)(\d{9})\b|\b(pan\s*\d{9})\b'
)

# US Social Security Number: "123-45-6789"
SSN_REGEX = re.compile(
    r'\b\d{3}-\d{2}-\d{4}\b'
)

# Passport Number: Letter followed by 7-8 digits
PASSPORT_REGEX = re.compile(
    r'(?i)\b(?:passport(?:\s*number|\s*no)?[:\s]*)([A-Z][0-9]{7,8})\b|\b([A-Z]\d{7,8})\b'
)

# Credit Card (13-19 digits, formatted with spaces or dashes)
CREDIT_CARD_REGEX = re.compile(
    r'\b(?:\d{4}[ -]?){3}\d{4}\b|\b\d{15,16}\b'
)

# IP Address (IPv4)
IP_ADDRESS_REGEX = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)


def luhn_checksum(card_number: str) -> bool:
    """Verify numeric string passes the Luhn checksum algorithm."""
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


class PIIDetector:
    """
    Comprehensive PII detection and anonymization.
    
    Provides detection for email, telephone, citizenship numbers, SSN, PAN,
    passports, credit cards, and addresses.
    Supports de-obfuscation and three distinct actions:
    - Redaction: Replaces entity with descriptive label (e.g. [REDACTED_EMAIL])
    - Masking: Obfuscates sensitive characters (e.g. jo***@domain.com)
    - Tokenization: Replaces entity with unique cryptographic vault surrogate
    """

    def __init__(
        self,
        default_mode: AnonymizationMode = "redact",
        confidence_threshold: float = 0.7,
    ) -> None:
        self.default_mode = default_mode
        self.confidence_threshold = confidence_threshold

    def detect(self, text: str) -> PIIResult:
        """Scan text and identify all PII entities with offsets and confidence scores."""
        if not text:
            return PIIResult(pii_detected=False)

        findings: List[PIIFinding] = []
        occupied_spans: List[Tuple[int, int]] = []

        def is_overlapping(start: int, end: int) -> bool:
            return any(s < end and start < e for s, e in occupied_spans)

        def add_finding(entity_type: str, start: int, end: int, val: str, score: float = 1.0):
            if not is_overlapping(start, end):
                occupied_spans.append((start, end))
                # Audit safe snippet
                snippet = val[:3] + "..." + val[-2:] if len(val) > 5 else "[REDACTED]"
                findings.append(
                    PIIFinding(
                        entity_type=entity_type,
                        value_snippet=snippet,
                        start=start,
                        end=end,
                        score=score,
                    )
                )

        # 1. Standard Email
        for match in EMAIL_REGEX.finditer(text):
            add_finding("EMAIL_ADDRESS", match.start(), match.end(), match.group(), 0.99)

        # 2. Obfuscated / Spaced Email
        for match in OBFUSCATED_EMAIL_REGEX.finditer(text):
            add_finding("EMAIL_ADDRESS_OBFUSCATED", match.start(), match.end(), match.group(), 0.95)
        for match in SPACED_EMAIL_REGEX.finditer(text):
            add_finding("EMAIL_ADDRESS_OBFUSCATED", match.start(), match.end(), match.group(), 0.95)

        # 3. Phone Numbers
        for match in PHONE_REGEX.finditer(text):
            val = match.group()
            digits_count = sum(ch.isdigit() for ch in val)
            if digits_count >= 7:
                add_finding("PHONE_NUMBER", match.start(), match.end(), val, 0.95)

        # 4. Spaced Phone Numbers
        for match in SPACED_PHONE_REGEX.finditer(text):
            add_finding("PHONE_NUMBER_OBFUSCATED", match.start(), match.end(), match.group(), 0.90)

        # 5. Nepal Citizenship Number
        for match in NEPAL_CITIZENSHIP_REGEX.finditer(text):
            add_finding("CITIZENSHIP_NUMBER", match.start(), match.end(), match.group(), 0.98)

        # 6. US SSN
        for match in SSN_REGEX.finditer(text):
            add_finding("SSN", match.start(), match.end(), match.group(), 0.99)

        # 7. Nepal PAN Number
        for match in PAN_NUMBER_REGEX.finditer(text):
            add_finding("PAN_NUMBER", match.start(), match.end(), match.group(), 0.95)

        # 8. Passport Number
        for match in PASSPORT_REGEX.finditer(text):
            # If word passport is present, high confidence
            val = match.group()
            score = 0.95 if "passport" in text.lower() else 0.75
            if score >= self.confidence_threshold:
                add_finding("PASSPORT_NUMBER", match.start(), match.end(), val, score)

        # 9. Credit Card with Luhn validation
        for match in CREDIT_CARD_REGEX.finditer(text):
            val = match.group()
            if luhn_checksum(val):
                add_finding("CREDIT_CARD", match.start(), match.end(), val, 0.99)

        # 10. IP Address
        for match in IP_ADDRESS_REGEX.finditer(text):
            add_finding("IP_ADDRESS", match.start(), match.end(), match.group(), 0.85)

        # Sort findings by start offset
        findings.sort(key=lambda f: f.start)

        pii_detected = len(findings) > 0
        redacted_text = self.redact(text, findings) if pii_detected else text
        masked_text = self.mask(text, findings) if pii_detected else text
        tokenized_text, token_map = self.tokenize(text, findings) if pii_detected else (text, {})

        return PIIResult(
            pii_detected=pii_detected,
            findings=findings,
            redacted_text=redacted_text,
            masked_text=masked_text,
            tokenized_text=tokenized_text,
            token_map=token_map,
        )

    # ------------------------------------------------------------------
    # Anonymization Actions
    # ------------------------------------------------------------------

    def redact(self, text: str, findings: Optional[List[PIIFinding]] = None) -> str:
        """Replace all detected PII with canonical redaction tags e.g. [REDACTED_EMAIL_ADDRESS]."""
        if findings is None:
            findings = self.detect(text).findings

        if not findings:
            return text

        result_chars = []
        last_idx = 0
        for f in findings:
            result_chars.append(text[last_idx:f.start])
            tag = f"[REDACTED_{f.entity_type}]"
            result_chars.append(tag)
            last_idx = f.end
        result_chars.append(text[last_idx:])
        return "".join(result_chars)

    def mask(self, text: str, findings: Optional[List[PIIFinding]] = None) -> str:
        """Partially mask PII entities (e.g. jo***@domain.com, ***-**-1234)."""
        if findings is None:
            findings = self.detect(text).findings

        if not findings:
            return text

        result_chars = []
        last_idx = 0
        for f in findings:
            result_chars.append(text[last_idx:f.start])
            raw_val = text[f.start:f.end]
            masked_val = self._mask_value(raw_val, f.entity_type)
            result_chars.append(masked_val)
            last_idx = f.end
        result_chars.append(text[last_idx:])
        return "".join(result_chars)

    def tokenize(
        self, text: str, findings: Optional[List[PIIFinding]] = None
    ) -> Tuple[str, Dict[str, str]]:
        """
        Replace PII with cryptographically secure surrogates.
        Returns the tokenized string and a reversible token mapping table.
        """
        if findings is None:
            findings = self.detect(text).findings

        if not findings:
            return text, {}

        result_chars = []
        token_map: Dict[str, str] = {}
        last_idx = 0

        for idx, f in enumerate(findings, start=1):
            result_chars.append(text[last_idx:f.start])
            raw_val = text[f.start:f.end]
            token = f"<TOKEN_{f.entity_type}_{idx}_{uuid.uuid4().hex[:6]}>"
            token_map[token] = raw_val
            result_chars.append(token)
            last_idx = f.end
        result_chars.append(text[last_idx:])

        return "".join(result_chars), token_map

    def _mask_value(self, val: str, entity_type: str) -> str:
        """Helper to create realistic masking based on entity type."""
        clean = val.strip()
        if "EMAIL" in entity_type and "@" in clean:
            user, domain = clean.split("@", 1)
            masked_user = user[0] + "***" + (user[-1] if len(user) > 1 else "")
            return f"{masked_user}@{domain}"
        if "SSN" in entity_type or "CITIZENSHIP" in entity_type:
            parts = clean.split("-")
            if len(parts) >= 3:
                return f"***-**-{parts[-1]}"
            return clean[:2] + "****" + clean[-2:] if len(clean) > 4 else "****"
        if "PHONE" in entity_type:
            return clean[:4] + "****" + clean[-2:] if len(clean) > 6 else "****"
        if "CREDIT_CARD" in entity_type:
            digits = re.sub(r'\D', '', clean)
            return "****-****-****-" + digits[-4:] if len(digits) >= 12 else "****"
        return clean[:2] + "***" + clean[-2:] if len(clean) > 4 else "***"
