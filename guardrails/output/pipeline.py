"""
Output Guardrail Pipeline — Orchestrator for Generated AI Responses.

Execution Stages:
1. Schema Validation: Checks structural conformance, field types, and value constraints.
2. Groundedness Evaluation: Tests factual faithfulness against source context.
3. Sensitive Information & Secret Detection: Scans for leaked PII, credentials, or canary tokens.
4. Remediation: Applies redaction, regeneration instructions, refusal, or safe fallbacks.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional
from guardrails.input.injection_detector import CanaryTokenManager
from guardrails.models import (
    DomainType,
    OutputGuardrailReport,
    RemediationAction,
)
from guardrails.output.groundedness_checker import GroundednessChecker
from guardrails.output.schema_validator import OutputSchemaValidator
from guardrails.output.sensitive_detector import SAFE_LEGAL_FALLBACK, SensitiveOutputDetector


class OutputGuardrailPipeline:
    """
    Executes and coordinates all output safety, structural, and privacy guardrails.
    """

    def __init__(self, default_domain: DomainType = DomainType.LEGAL) -> None:
        self.default_domain = default_domain
        self.schema_validator = OutputSchemaValidator()
        self.groundedness_checker = GroundednessChecker()
        self.sensitive_detector = SensitiveOutputDetector()

    def run(
        self,
        output_text: str,
        source_context: Optional[str] = None,
        expected_schema: Optional[Dict[str, Any]] = None,
        domain: Optional[DomainType] = None,
        canary_manager: Optional[CanaryTokenManager] = None,
        preferred_remediation: RemediationAction = RemediationAction.REDACT,
    ) -> OutputGuardrailReport:
        """
        Execute output guardrails sequentially against the LLM's generated response.
        """
        start_time = time.monotonic()
        effective_domain = domain or self.default_domain
        detectors_run: list[str] = []
        report = OutputGuardrailReport()
        current_text = output_text

        # -------------------------------------------------------------
        # Stage 1: Schema Validation (Structural Check)
        # -------------------------------------------------------------
        if expected_schema:
            detectors_run.append("schema_validator")
            schema_res = self.schema_validator.validate(current_text, expected_schema)
            report.schema_validation = schema_res

            if not schema_res.passed:
                report.allowed = False
                report.remediation_action = RemediationAction.REGENERATE
                report.block_reason = f"Schema validation failed: {'; '.join(schema_res.errors[:3])}"
                report.final_output = (
                    f"[SCHEMA_ERROR]: Generated response does not conform to expected schema. "
                    f"Retry required with prompt:\n{schema_res.retry_prompt}"
                )
                report.detectors_run = detectors_run
                report.total_latency_ms = round((time.monotonic() - start_time) * 1000, 3)
                return report

        # -------------------------------------------------------------
        # Stage 2: Sensitive Information, PII, and Canary Detection
        # -------------------------------------------------------------
        detectors_run.append("sensitive_detector")
        sensitive_res = self.sensitive_detector.scan_and_remediate(
            output_text=current_text,
            canary_manager=canary_manager,
            preferred_action=preferred_remediation,
        )
        report.sensitive_output = sensitive_res

        if sensitive_res.sensitive_detected:
            report.remediation_action = sensitive_res.remediation_action
            if sensitive_res.remediation_action == RemediationAction.REDACT:
                current_text = sensitive_res.sanitized_text or current_text
                report.allowed = True
                report.block_reason = "PII or confidential tokens were detected and redacted."
            elif sensitive_res.remediation_action == RemediationAction.REFUSE:
                report.allowed = False
                report.block_reason = "Critical confidential disclosure prevented (refusal enforced)."
                report.final_output = sensitive_res.refusal_message or current_text
                report.detectors_run = detectors_run
                report.total_latency_ms = round((time.monotonic() - start_time) * 1000, 3)
                return report
            elif sensitive_res.remediation_action == RemediationAction.SAFE_FALLBACK:
                report.allowed = False
                report.block_reason = "Confidential data disclosure prevented (fallback invoked)."
                report.final_output = SAFE_LEGAL_FALLBACK
                report.detectors_run = detectors_run
                report.total_latency_ms = round((time.monotonic() - start_time) * 1000, 3)
                return report
            elif sensitive_res.remediation_action == RemediationAction.REGENERATE:
                report.allowed = False
                report.block_reason = "Output contained sensitive entities; regeneration required."
                report.final_output = "[RETRY]: Please regenerate output without confidential client or system data."
                report.detectors_run = detectors_run
                report.total_latency_ms = round((time.monotonic() - start_time) * 1000, 3)
                return report

        # -------------------------------------------------------------
        # Stage 3: Groundedness & Hallucination Check
        # -------------------------------------------------------------
        detectors_run.append("groundedness_checker")
        groundedness_res = self.groundedness_checker.check(
            output_text=current_text,
            source_context=source_context,
            domain=effective_domain,
        )
        report.groundedness = groundedness_res

        if not groundedness_res.passed and effective_domain != DomainType.CREATIVE:
            report.allowed = False
            report.remediation_action = RemediationAction.SAFE_FALLBACK
            report.block_reason = (
                f"Groundedness check failed: score={groundedness_res.score:.2f} "
                f"< threshold={groundedness_res.domain_threshold:.2f} "
                f"({len(groundedness_res.unsupported_claims)} unsupported claims)"
            )
            report.final_output = SAFE_LEGAL_FALLBACK
            report.detectors_run = detectors_run
            report.total_latency_ms = round((time.monotonic() - start_time) * 1000, 3)
            return report

        # -------------------------------------------------------------
        # Output Approved & Finalized
        # -------------------------------------------------------------
        if not report.block_reason:
            report.allowed = True
            report.remediation_action = RemediationAction.ALLOW

        report.final_output = current_text
        report.detectors_run = detectors_run
        report.total_latency_ms = round((time.monotonic() - start_time) * 1000, 3)
        return report
