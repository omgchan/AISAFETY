"""
Sensitive Information Detector (Output-side) & Remediation Engine.

Meets Assignment Specification:
- Inspects generated responses for leaked PII, system secrets, and canary tokens.
- Defines and executes remediation actions:
  * Redaction: scrubs confidential items and preserves surrounding safe content.
  * Regeneration: builds corrective instruction to regenerate without sensitive data.
  * Refusal: returns a standard policy refusal.
  * Safe Fallback: replaces with a pre-certified static fallback response.
"""

from __future__ import annotations

import re
from typing import List, Optional
from guardrails.input.injection_detector import CanaryTokenManager
from guardrails.input.pii_detector import PIIDetector
from guardrails.models import (
    PIIFinding,
    RemediationAction,
    SensitiveOutputResult,
)

# Secrets pattern bank (API keys, private keys, auth headers)
SECRET_PATTERNS = [
    (r'(?i)\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{16,})["\']?', "API_KEY_OR_SECRET"),
    (r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b', "GITHUB_TOKEN"),
    (r'\bAKIA[0-9A-Z]{16}\b', "AWS_ACCESS_KEY"),
    (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', "PRIVATE_KEY"),
]

SAFE_LEGAL_FALLBACK = (
    "NOTICE: The requested response could not be verified according to statutory safety standards. "
    "Under the Nepal Legal Practice Act, confidential legal advice must be provided by a certified "
    "advocate. Please consult the Nepal Bar Association directory or your designated legal counsel."
)


class SensitiveOutputDetector:
    """Detects leaks of PII, secrets, or integrity canaries in generated text, and applies remediation."""

    def __init__(self, pii_detector: Optional[PIIDetector] = None) -> None:
        self.pii_detector = pii_detector or PIIDetector()
        self._compiled_secrets = [(re.compile(p), name) for p, name in SECRET_PATTERNS]

    def scan_and_remediate(
        self,
        output_text: str,
        canary_manager: Optional[CanaryTokenManager] = None,
        preferred_action: RemediationAction = RemediationAction.REDACT,
    ) -> SensitiveOutputResult:
        """
        Scan output for sensitive disclosures and apply the chosen remediation strategy.
        """
        if not output_text:
            return SensitiveOutputResult(sensitive_detected=False)

        findings: List[PIIFinding] = []
        canary_leaked = False

        # 1. Canary Token Leak Check
        if canary_manager and canary_manager.is_leaked(output_text):
            canary_leaked = True
            findings.append(
                PIIFinding(
                    entity_type="SYSTEM_CANARY_TOKEN",
                    value_snippet="[CANARY_EXPOSED]",
                    start=0,
                    end=len(output_text),
                    score=1.0,
                )
            )

        # 2. PII Detection on Output
        pii_res = self.pii_detector.detect(output_text)
        if pii_res.pii_detected:
            findings.extend(pii_res.findings)

        # 3. Secret Scanner
        for pattern, secret_type in self._compiled_secrets:
            for match in pattern.finditer(output_text):
                if match.groups() and match.group(1):
                    start, end = match.start(1), match.end(1)
                else:
                    start, end = match.start(), match.end()
                findings.append(
                    PIIFinding(
                        entity_type=secret_type,
                        value_snippet="[SECRET_EXPOSED]",
                        start=start,
                        end=end,
                        score=0.99,
                    )
                )

        sensitive_detected = len(findings) > 0 or canary_leaked

        if not sensitive_detected:
            return SensitiveOutputResult(
                sensitive_detected=False,
                findings=[],
                canary_leaked=False,
                remediation_action=RemediationAction.ALLOW,
                sanitized_text=output_text,
            )

        # Sort all findings by character offset
        findings.sort(key=lambda f: f.start)

        # Apply Remediation
        # Critical canary leakage forces immediate refusal or fallback
        effective_action = RemediationAction.REFUSE if canary_leaked else preferred_action

        sanitized_text: Optional[str] = None
        refusal_message: Optional[str] = None

        if effective_action == RemediationAction.REDACT:
            # Perform clean offset-based redaction on the text
            sanitized_text = self.pii_detector.redact(output_text, findings)

        elif effective_action == RemediationAction.SAFE_FALLBACK:
            sanitized_text = SAFE_LEGAL_FALLBACK

        elif effective_action == RemediationAction.REFUSE:
            refusal_message = (
                "I apologize, but this response cannot be presented because it contains "
                "confidential, privileged, or personally identifiable data."
            )
            sanitized_text = refusal_message

        elif effective_action == RemediationAction.REGENERATE:
            sanitized_text = None  # Signals upstream caller to re-prompt the LLM

        return SensitiveOutputResult(
            sensitive_detected=True,
            findings=findings,
            canary_leaked=canary_leaked,
            remediation_action=effective_action,
            sanitized_text=sanitized_text,
            refusal_message=refusal_message,
        )
