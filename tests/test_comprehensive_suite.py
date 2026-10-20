"""
Comprehensive 25-Case Benchmark Evaluation Test Suite.

Evaluates:
- Normal benign inputs
- Malicious prompt injections
- Sensitive personal information (PII)
- Sensitive policy categories & crisis intervention
- Invalid output schemas
- Unsupported / hallucinated claims
- Output PII leaks
"""

import pytest
from guardrails.core.app_service import LegalAIAssistantService
from guardrails.models import DomainType, LegalQueryRequest
from tests.test_cases_data import BENCHMARK_TEST_CASES


@pytest.fixture
def service():
    return LegalAIAssistantService(audit_log_path="logs/test_audit.jsonl")


class TestComprehensiveGuardrailSuite:
    @pytest.mark.parametrize("case", BENCHMARK_TEST_CASES, ids=lambda c: f"{c['id']}_{c['category']}")
    def test_benchmark_case(self, service, case):
        req = LegalQueryRequest(
            query=case["input"],
            reference_context=case["reference_context"],
            require_schema=True,
            domain=DomainType.LEGAL,
        )

        mock_output = case.get("mock_model_output")
        resp = service.process_query(req, mock_raw_generation=mock_output)

        # 1. Verify Allow / Block outcome
        expected_allowed = case["expected_allowed"]

        if case["category"] == "normal_input":
            assert resp.input_report.allowed, f"TC {case['id']}: Benign input was incorrectly blocked: {resp.input_report.block_reason}"
            assert resp.output_report.allowed, f"TC {case['id']}: Benign output was blocked: {resp.output_report.block_reason}"

        elif case["category"] == "malicious_injection":
            assert not resp.input_report.allowed, f"TC {case['id']}: Injection was not blocked!"
            assert resp.input_report.injection.is_injection

        elif case["category"] == "sensitive_pii":
            assert resp.input_report.allowed, f"TC {case['id']}: PII input should be allowed after sanitization"
            assert resp.input_report.pii.pii_detected, f"TC {case['id']}: PII was not detected!"
            assert "[REDACTED_" in resp.input_report.processed_text

        elif case["category"] == "sensitive_topic":
            assert not resp.input_report.allowed, f"TC {case['id']}: Sensitive topic was not flagged/blocked!"
            assert resp.input_report.sensitive_topics.topics_detected

        elif case["category"] == "invalid_schema":
            assert resp.input_report.allowed
            assert not resp.output_report.allowed, f"TC {case['id']}: Invalid schema should have been rejected!"
            assert not resp.output_report.schema_validation.passed

        elif case["category"] == "unsupported_claim":
            assert resp.input_report.allowed
            assert not resp.output_report.allowed, f"TC {case['id']}: Hallucinated claim should have failed groundedness!"
            assert not resp.output_report.groundedness.passed

        elif case["category"] == "output_pii_leak":
            assert resp.input_report.allowed
            assert resp.output_report.sensitive_output.sensitive_detected, f"TC {case['id']}: Output PII leak was not detected!"
            assert "[REDACTED_" in resp.final_text
