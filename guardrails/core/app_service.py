"""
Legal AI Assistant Service — End-to-End Orchestrator with Guardrails.

Provides an application-level workflow for legal queries:
1. System prompt canary injection.
2. Input guardrail inspection (validation, injection detection, PII sanitization, sensitive routing).
3. Contextual LLM generation simulation with strict legal schema enforcement.
4. Output guardrail inspection (schema conformance, groundedness scoring, sensitive output scrub).
5. Tamper-evident audit logging.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional
from guardrails.core.audit_logger import AuditLogger
from guardrails.input.pipeline import InputGuardrailPipeline
from guardrails.models import (
    DomainType,
    EndToEndPipelineResponse,
    GuardrailStatus,
    LegalAIResponseStructure,
    LegalQueryRequest,
    OutputGuardrailReport,
    RemediationAction,
)
from guardrails.output.pipeline import OutputGuardrailPipeline

# Pre-defined JSON Schema for the Legal AI Assistant
LEGAL_RESPONSE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required": [
        "summary",
        "applicable_laws",
        "risk_level",
        "confidence_score",
        "legal_advice",
        "disclaimer",
        "citations",
    ],
    "properties": {
        "summary": {"type": "string"},
        "applicable_laws": {"type": "array", "items": {"type": "string"}},
        "risk_level": {
            "type": "string",
            "enum": ["low", "medium", "high", "critical"],
        },
        "confidence_score": {
            "type": "number",
            "minimum": 0.0,
            "maximum": 1.0,
        },
        "legal_advice": {"type": "string"},
        "disclaimer": {"type": "string"},
        "citations": {"type": "array", "items": {"type": "string"}},
    },
}


class LegalAIAssistantService:
    """End-to-end service coordinating LLM interaction with trustworthy AI guardrails."""

    def __init__(
        self,
        audit_log_path: Optional[str] = None,
        default_domain: DomainType = DomainType.LEGAL,
    ) -> None:
        self.audit_logger = AuditLogger(log_path=audit_log_path)
        self.input_pipeline = InputGuardrailPipeline()
        self.output_pipeline = OutputGuardrailPipeline(default_domain=default_domain)

    def process_query(
        self,
        request: LegalQueryRequest,
        mock_raw_generation: Optional[str] = None,
    ) -> EndToEndPipelineResponse:
        """
        Process a user query through the complete input and output guardrail lifecycle.
        
        If mock_raw_generation is provided, it simulates the model output for testing/eval.
        """
        start_time = time.monotonic()

        # -------------------------------------------------------------
        # 1. Input Guardrail Stage
        # -------------------------------------------------------------
        input_report = self.input_pipeline.run(request.query)

        if not input_report.allowed:
            # Blocked at input gate
            if input_report.action_taken == "safe_crisis_response":
                final_text = (
                    "CRISIS INTERVENTION ASSISTANCE:\n"
                    "We care about your safety and well-being. "
                    "If you are experiencing distress, thoughts of self-harm, or need urgent support, "
                    "please contact the following resources immediately:\n"
                    "- Nepal Mental Health & Suicide Helpline: 1166 (Toll-Free, 24/7)\n"
                    "- Nepal Emergency Police: 100\n"
                    "- US/International Suicide & Crisis Lifeline: 988\n"
                    "Help is available, confidential, and free."
                )
                status = GuardrailStatus.BLOCKED
            else:
                final_text = f"Request Rejected by Safety Guardrail: {input_report.block_reason}"
                status = GuardrailStatus.BLOCKED

            total_ms = round((time.monotonic() - start_time) * 1000, 3)

            # Audit log entry
            self.audit_logger.log(
                event_type="input_guardrail",
                action_taken=input_report.action_taken,
                allowed=False,
                user_id=request.user_id,
                risk_score=input_report.injection.risk_score if input_report.injection else 0.0,
                latency_ms=total_ms,
                metadata={
                    "query": request.query[:100],
                    "block_reason": input_report.block_reason,
                    "detectors_run": input_report.detectors_run,
                },
            )

            return EndToEndPipelineResponse(
                query=request.query,
                status=status,
                final_text=final_text,
                input_report=input_report,
                output_report=None,
                total_execution_ms=total_ms,
            )

        # -------------------------------------------------------------
        # 2. Model Generation Stage
        # -------------------------------------------------------------
        # If mock_raw_generation is supplied (e.g. during test suite), use it;
        # otherwise generate a compliant structured legal response.
        raw_output = mock_raw_generation or self._simulate_legal_generation(
            processed_query=input_report.processed_text,
            reference_context=request.reference_context,
        )

        # -------------------------------------------------------------
        # 3. Output Guardrail Stage
        # -------------------------------------------------------------
        expected_schema = LEGAL_RESPONSE_SCHEMA if request.require_schema else None

        output_report = self.output_pipeline.run(
            output_text=raw_output,
            source_context=request.reference_context,
            expected_schema=expected_schema,
            domain=request.domain,
            canary_manager=self.input_pipeline.canary_manager,
            preferred_remediation=RemediationAction.REDACT,
        )

        if not output_report.allowed:
            status = GuardrailStatus.REFUSED if output_report.remediation_action == RemediationAction.REFUSE else GuardrailStatus.BLOCKED
            final_text = output_report.final_output
        elif output_report.remediation_action == RemediationAction.REDACT:
            status = GuardrailStatus.REMEDIATED
            final_text = output_report.final_output
        else:
            status = GuardrailStatus.ALLOWED
            final_text = output_report.final_output

        total_ms = round((time.monotonic() - start_time) * 1000, 3)

        # Audit log entry
        self.audit_logger.log(
            event_type="output_guardrail",
            action_taken=output_report.remediation_action.value,
            allowed=output_report.allowed,
            user_id=request.user_id,
            risk_score=1.0 - output_report.groundedness.score if output_report.groundedness else 0.0,
            latency_ms=total_ms,
            metadata={
                "block_reason": output_report.block_reason,
                "detectors_run": output_report.detectors_run,
                "groundedness_score": output_report.groundedness.score if output_report.groundedness else None,
            },
        )

        return EndToEndPipelineResponse(
            query=request.query,
            status=status,
            final_text=final_text,
            input_report=input_report,
            output_report=output_report,
            total_execution_ms=total_ms,
        )

    def _simulate_legal_generation(
        self,
        processed_query: str,
        reference_context: Optional[str] = None,
    ) -> str:
        """Simulate a compliant, grounded response conforming to the Nepal Legal Schema."""
        context = reference_context.strip() if reference_context and reference_context.strip() else "General legal principles under statutory law."
        import re
        laws = re.findall(r'(?i)\b(?:[A-Z][A-Za-z\s]+(?:Act|Code|Rules?|Regulations?)(?:\s+\d{4})?)\b', context)
        applicable_laws = list(dict.fromkeys(laws)) if laws else ["Statutory Rules"]

        response_dict = {
            "summary": context,
            "applicable_laws": applicable_laws,
            "risk_level": "low",
            "confidence_score": 0.95,
            "legal_advice": context,
            "disclaimer": (
                "Statutory Disclaimer: This analysis is an informational summary under the laws of Nepal "
                "and does not constitute formal advocate-client representation."
            ),
            "citations": applicable_laws,
        }
        return json.dumps(response_dict, indent=2)
