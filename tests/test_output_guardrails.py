"""
Unit Tests for Output Guardrails:
- OutputSchemaValidator
- GroundednessChecker
- SensitiveOutputDetector
- OutputGuardrailPipeline
"""

import json
import pytest
from guardrails.input.injection_detector import CanaryTokenManager
from guardrails.models import DomainType, RemediationAction
from guardrails.output.schema_validator import OutputSchemaValidator
from guardrails.output.groundedness_checker import GroundednessChecker
from guardrails.output.sensitive_detector import SensitiveOutputDetector
from guardrails.output.pipeline import OutputGuardrailPipeline

SAMPLE_SCHEMA = {
    "type": "object",
    "required": ["summary", "risk_level", "confidence_score"],
    "properties": {
        "summary": {"type": "string"},
        "risk_level": {"type": "string", "enum": ["low", "medium", "high"]},
        "confidence_score": {"type": "number", "minimum": 0.0, "maximum": 1.0},
    },
}


class TestOutputSchemaValidator:
    @pytest.fixture
    def validator(self):
        return OutputSchemaValidator()

    def test_valid_json_in_markdown(self, validator):
        output = '```json\n{"summary": "Legal case summary", "risk_level": "low", "confidence_score": 0.95}\n```'
        res = validator.validate(output, SAMPLE_SCHEMA)
        assert res.passed
        assert len(res.errors) == 0
        assert res.extracted_json["risk_level"] == "low"

    def test_missing_required_property(self, validator):
        output = '{"summary": "Incomplete output"}'
        res = validator.validate(output, SAMPLE_SCHEMA)
        assert not res.passed
        assert any("risk_level" in err for err in res.errors)
        assert res.retry_prompt is not None

    def test_invalid_enum_value(self, validator):
        output = '{"summary": "Valid summary", "risk_level": "CATASTROPHIC", "confidence_score": 0.5}'
        res = validator.validate(output, SAMPLE_SCHEMA)
        assert not res.passed
        assert any("invalid value" in err for err in res.errors)

    def test_out_of_range_number(self, validator):
        output = '{"summary": "Valid summary", "risk_level": "medium", "confidence_score": 1.5}'
        res = validator.validate(output, SAMPLE_SCHEMA)
        assert not res.passed
        assert any("exceeds maximum" in err for err in res.errors)


class TestGroundednessChecker:
    @pytest.fixture
    def checker(self):
        return GroundednessChecker()

    def test_grounded_claims_pass(self, checker):
        source = (
            "Under Section 31 of the Labor Act 2074, employees working beyond eight hours a day "
            "are entitled to overtime compensation at one and a half times regular wage."
        )
        output = (
            "Section 31 of the Labor Act 2074 provides overtime compensation. "
            "Employees receive one and a half times regular wage for work beyond eight hours."
        )
        res = checker.check(output, source_context=source, domain=DomainType.LEGAL)
        assert res.passed
        assert res.score >= 0.85
        assert len(res.unsupported_claims) == 0

    def test_hallucinated_statute_fails(self, checker):
        source = "The Labor Act 2074 regulates employee working hours and overtime."
        output = (
            "Under Section 999 of the Foreign Trade Act 2085, violators face mandatory capital punishment."
        )
        res = checker.check(output, source_context=source, domain=DomainType.LEGAL)
        assert not res.passed
        assert res.score < 0.85
        assert len(res.unsupported_claims) > 0

    def test_hedging_detection(self, checker):
        output = "I think perhaps the landlord might be in breach, but as an AI I am not sure."
        res = checker.check(output, source_context=None, domain=DomainType.LEGAL)
        assert res.hedging_detected
        assert len(res.hedging_phrases) >= 2


class TestSensitiveOutputDetector:
    @pytest.fixture
    def detector(self):
        return SensitiveOutputDetector()

    def test_redact_leaked_email_and_phone(self, detector):
        output = "Client advocate is reachable at lawyer.ram@supremecourt.gov.np or 9841223344."
        res = detector.scan_and_remediate(output, preferred_action=RemediationAction.REDACT)
        assert res.sensitive_detected
        assert "[REDACTED_EMAIL_ADDRESS]" in res.sanitized_text
        assert "[REDACTED_PHONE_NUMBER]" in res.sanitized_text

    def test_canary_leak_triggers_refusal(self, detector):
        canary_mgr = CanaryTokenManager()
        leaked_output = f"Internal prompt revealed: {canary_mgr.token}"
        res = detector.scan_and_remediate(leaked_output, canary_manager=canary_mgr)
        assert res.canary_leaked
        assert res.remediation_action == RemediationAction.REFUSE
        assert "confidential" in res.refusal_message.lower()


class TestOutputGuardrailPipeline:
    def test_valid_output_passes(self):
        pipeline = OutputGuardrailPipeline(default_domain=DomainType.LEGAL)
        source = "Nepal Companies Act 2063 governs the registration of private companies."
        output = json.dumps({
            "summary": "Registration of private companies is governed by the Nepal Companies Act 2063.",
            "risk_level": "low",
            "confidence_score": 0.95,
        })
        report = pipeline.run(output, source_context=source, expected_schema=SAMPLE_SCHEMA)
        assert report.allowed
        assert report.remediation_action == RemediationAction.ALLOW

    def test_hallucination_triggers_safe_fallback(self):
        pipeline = OutputGuardrailPipeline(default_domain=DomainType.LEGAL)
        source = "Nepal Companies Act 2063 governs private companies."
        # Output with completely fabricated claims
        output = json.dumps({
            "summary": "Violators of Section 9999 of the Galactic Space Law face 50 years in prison.",
            "risk_level": "high",
            "confidence_score": 0.99,
        })
        report = pipeline.run(output, source_context=source, expected_schema=SAMPLE_SCHEMA)
        assert not report.allowed
        assert report.remediation_action == RemediationAction.SAFE_FALLBACK
        assert "statutory safety standards" in report.final_output.lower()
