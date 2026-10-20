"""
Input Guardrail Pipeline — Orchestrates and executes all input guardrails.

Execution Sequence:
1. InputValidator: Unicode normalization, homoglyph normalization, length & control characters.
2. InjectionDetector: Multi-layer pattern matching and heuristic threat analysis.
3. PIIDetector: Entity recognition, de-obfuscation, and anonymization (redact/mask/tokenize).
4. SensitiveTopicClassifier: Multi-class risk categorization and strict action routing.

Design Principles:
- Fail-fast / Fail-closed: Critical security or safety violations stop execution immediately.
- Comprehensive Auditability: Returns complete reports with timestamps, latencies, and findings.
"""

from __future__ import annotations

import time
from typing import Optional
from guardrails.input.validator import InputValidator
from guardrails.input.injection_detector import CanaryTokenManager, InjectionDetector
from guardrails.input.pii_detector import AnonymizationMode, PIIDetector
from guardrails.input.sensitive_classifier import SensitiveTopicClassifier
from guardrails.models import (
    InputGuardrailReport,
    RouteAction,
)


class InputGuardrailPipeline:
    """
    Coordinates all input-side safety, security, and privacy checks.
    """

    def __init__(
        self,
        injection_strictness: float = 0.5,
        default_anonymization: AnonymizationMode = "redact",
        max_length: int = 16_000,
    ) -> None:
        self.validator = InputValidator(max_length=max_length)
        self.injection_detector = InjectionDetector(strictness=injection_strictness)
        self.pii_detector = PIIDetector(default_mode=default_anonymization)
        self.sensitive_classifier = SensitiveTopicClassifier()
        self.canary_manager = CanaryTokenManager()
        self.default_anonymization = default_anonymization

    def run(
        self,
        text: str,
        anonymization_mode: Optional[AnonymizationMode] = None,
    ) -> InputGuardrailReport:
        """
        Execute the input guardrails in strict sequence against the given text.
        
        Returns an InputGuardrailReport detailing decisions, findings, and sanitized text.
        """
        start_time = time.monotonic()
        detectors_run: list[str] = []
        mode = anonymization_mode or self.default_anonymization
        report = InputGuardrailReport()

        # -------------------------------------------------------------
        # Stage 1: Structural Validation & Normalization
        # -------------------------------------------------------------
        detectors_run.append("input_validator")
        validation = self.validator.validate(text)
        report.validation = validation

        if not validation.valid:
            report.allowed = False
            report.block_reason = f"Input validation rejected: {validation.error}"
            report.action_taken = "block_malformed"
            report.detectors_run = detectors_run
            report.total_latency_ms = round((time.monotonic() - start_time) * 1000, 3)
            return report

        safe_text = validation.normalized_text

        # -------------------------------------------------------------
        # Stage 2: Prompt Injection & Adversarial Attack Detection
        # -------------------------------------------------------------
        detectors_run.append("injection_detector")
        injection = self.injection_detector.scan(safe_text)
        report.injection = injection

        if injection.is_injection:
            report.allowed = False
            report.block_reason = (
                f"Prompt injection detected ({injection.category.value}): "
                f"risk_score={injection.risk_score:.2f}, "
                f"matched {len(injection.matched_patterns)} pattern(s)"
            )
            report.action_taken = "block_injection"
            report.detectors_run = detectors_run
            report.total_latency_ms = round((time.monotonic() - start_time) * 1000, 3)
            return report

        # -------------------------------------------------------------
        # Stage 3: PII Detection & Anonymization
        # -------------------------------------------------------------
        detectors_run.append("pii_detector")
        pii = self.pii_detector.detect(safe_text)
        report.pii = pii

        if pii.pii_detected:
            if mode == "redact":
                safe_text = pii.redacted_text or safe_text
            elif mode == "mask":
                safe_text = pii.masked_text or safe_text
            elif mode == "tokenize":
                safe_text = pii.tokenized_text or safe_text

        # -------------------------------------------------------------
        # Stage 4: Sensitive Topic Classification & Policy Routing
        # -------------------------------------------------------------
        detectors_run.append("sensitive_classifier")
        sensitive = self.sensitive_classifier.classify(safe_text)
        report.sensitive_topics = sensitive

        if sensitive.topics_detected:
            if sensitive.strictest_action == RouteAction.HARD_BLOCK:
                categories = [f.category.value for f in sensitive.findings]
                report.allowed = False
                report.block_reason = f"Prohibited sensitive topics detected (hard block): {', '.join(categories)}"
                report.action_taken = "block_sensitive_topic"
                report.detectors_run = detectors_run
                report.total_latency_ms = round((time.monotonic() - start_time) * 1000, 3)
                return report

            elif sensitive.strictest_action == RouteAction.SAFE_RESPONSE:
                report.allowed = False
                report.block_reason = "Crisis content detected — routing to certified safe crisis response."
                report.action_taken = "safe_crisis_response"
                report.detectors_run = detectors_run
                report.processed_text = safe_text
                report.total_latency_ms = round((time.monotonic() - start_time) * 1000, 3)
                return report

        # -------------------------------------------------------------
        # Pipeline Approved
        # -------------------------------------------------------------
        report.allowed = True
        report.action_taken = "allow"
        report.processed_text = safe_text
        report.detectors_run = detectors_run
        report.total_latency_ms = round((time.monotonic() - start_time) * 1000, 3)
        return report
