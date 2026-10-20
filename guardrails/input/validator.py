"""
Input Validator — Normalization, Homoglyphs, and Structural Integrity.

Performs Stage 1 of the Input Guardrail Pipeline:
- Strips invisible / zero-width characters used for evasion
- Normalizes Unicode to NFKC
- Detects mixed-script homoglyph obfuscation (e.g. Cyrillic lookalikes)
- Enforces min/max length constraints and blocks control characters
"""

from __future__ import annotations

import re
import unicodedata
from guardrails.models import ValidationResult

# Zero-width / invisible characters commonly used in evasion attacks
ZERO_WIDTH_CHARS = {
    '\u200b',  # Zero width space
    '\u200c',  # Zero width non-joiner
    '\u200d',  # Zero width joiner
    '\u200e',  # Left-to-right mark
    '\u200f',  # Right-to-left mark
    '\ufeff',  # Byte order mark / zero width no-break space
    '\u00ad',  # Soft hyphen
}

# Cyrillic & Greek homoglyphs frequently substituted into Latin attack words
HOMOGLYPH_MAP = {
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
    '\u0458': 'j', '\u0410': 'A', '\u0412': 'B', '\u0415': 'E',
    '\u041a': 'K', '\u041c': 'M', '\u041d': 'H', '\u041e': 'O',
    '\u0420': 'P', '\u0421': 'C', '\u0422': 'T', '\u0423': 'Y',
    '\u0425': 'X',
}


class InputValidator:
    """Pre-processes and sanitizes user input before specialized detector stages."""

    def __init__(self, max_length: int = 16_000, min_length: int = 1) -> None:
        self.max_length = max_length
        self.min_length = min_length

    def validate(self, text: str) -> ValidationResult:
        """Validate, normalize, and detect obfuscation in user text."""
        warnings: list[str] = []

        if not text or len(text.strip()) < self.min_length:
            return ValidationResult(
                valid=False,
                normalized_text="",
                error="Input is empty or whitespace only.",
            )

        if len(text) > self.max_length:
            return ValidationResult(
                valid=False,
                normalized_text=text[:self.max_length],
                error=f"Input length ({len(text)}) exceeds maximum allowed ({self.max_length}).",
            )

        # 1. Check for null bytes
        if '\x00' in text:
            return ValidationResult(
                valid=False,
                normalized_text="",
                error="Null byte detected in input.",
            )

        # 2. Strip zero-width evasion characters
        cleaned = "".join(ch for ch in text if ch not in ZERO_WIDTH_CHARS)
        if len(cleaned) < len(text):
            warnings.append("Invisible/zero-width evasion characters stripped.")

        # 3. Unicode NFKC normalization
        normalized = unicodedata.normalize("NFKC", cleaned)

        # 4. Homoglyph substitution & detection
        homoglyph_detected = False
        homoglyph_fixed = []
        for ch in normalized:
            if ch in HOMOGLYPH_MAP:
                homoglyph_detected = True
                homoglyph_fixed.append(HOMOGLYPH_MAP[ch])
            else:
                homoglyph_fixed.append(ch)

        if homoglyph_detected:
            warnings.append("Homoglyph character substitution normalized.")
            normalized = "".join(homoglyph_fixed)

        # 5. Excessive control characters check
        control_chars = sum(1 for ch in normalized if unicodedata.category(ch).startswith('C') and ch not in ('\n', '\r', '\t'))
        if control_chars > 5:
            return ValidationResult(
                valid=False,
                normalized_text="",
                error="Excessive non-printable control characters detected.",
            )

        return ValidationResult(
            valid=True,
            normalized_text=normalized,
            error=None,
            warnings=warnings,
        )
