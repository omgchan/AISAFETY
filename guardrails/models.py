"""
Data models for the Trustworthy AI Guardrails System.
All input and output detections, findings, reports, and configurations
are structured using robust Pydantic schemas.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


# =====================================================================
# Common & Enums
# =====================================================================

class GuardrailStatus(str, Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    MODIFIED = "modified"
    REMEDIATED = "remediated"
    REFUSED = "refused"


class DomainType(str, Enum):
    LEGAL = "legal"
    MEDICAL = "medical"
    FINANCIAL = "financial"
    GENERAL = "general"
    CREATIVE = "creative"


class RemediationAction(str, Enum):
    ALLOW = "allow"
    REDACT = "redact"
    REGENERATE = "regenerate"
    REFUSE = "refuse"
    SAFE_FALLBACK = "safe_fallback"


# =====================================================================
# Stage 1: Input Guardrails Models
# =====================================================================

class ValidationResult(BaseModel):
    """Result of basic input validation (length, unicode, homoglyphs)."""
    valid: bool = True
    normalized_text: str = ""
    error: Optional[str] = None
    warnings: List[str] = Field(default_factory=list)


class InjectionCategory(str, Enum):
    DIRECT_INJECTION = "direct_injection"
    JAILBREAK = "jailbreak"
    EXTRACTION = "extraction"
    IMPERSONATION = "impersonation"
    CONTEXT_MANIPULATION = "context_manipulation"
    ENCODING_TRICK = "encoding_trick"
    NONE = "none"


class InjectionResult(BaseModel):
    """Result of prompt injection detection."""
    is_injection: bool = False
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    category: InjectionCategory = InjectionCategory.NONE
    matched_patterns: List[str] = Field(default_factory=list)
    heuristic_flags: List[str] = Field(default_factory=list)
    canary_triggered: bool = False


class PIIFinding(BaseModel):
    """A detected Personally Identifiable Information entity."""
    entity_type: str
    value_snippet: str
    start: int
    end: int
    score: float = 1.0


class PIIResult(BaseModel):
    """Aggregate result of PII detection & anonymization."""
    pii_detected: bool = False
    findings: List[PIIFinding] = Field(default_factory=list)
    redacted_text: Optional[str] = None
    masked_text: Optional[str] = None
    tokenized_text: Optional[str] = None
    token_map: Dict[str, str] = Field(default_factory=dict)


class SensitiveCategory(str, Enum):
    WEAPONS_CBRN = "weapons_cbrn"
    CYBERWEAPONS_MALWARE = "cyberweapons_malware"
    SELF_HARM_CRISIS = "self_harm_crisis"
    EXTREMISM = "extremism"
    CSAE = "csae"
    FRAUD = "fraud"
    LEGAL_ETHICS_VIOLATION = "legal_ethics_violation"
    NONE = "none"


class RouteAction(str, Enum):
    HARD_BLOCK = "hard_block"
    SAFE_RESPONSE = "safe_response"
    WARN_AND_FLAG = "warn_and_flag"
    ALLOW = "allow"


class SensitiveTopicFinding(BaseModel):
    """A detected sensitive topic occurrence."""
    category: SensitiveCategory
    route: RouteAction
    matched_terms: List[str] = Field(default_factory=list)
    confidence: float = 1.0


class SensitiveTopicResult(BaseModel):
    """Aggregate result of sensitive topic classification."""
    topics_detected: bool = False
    findings: List[SensitiveTopicFinding] = Field(default_factory=list)
    strictest_action: RouteAction = RouteAction.ALLOW
    crisis_resources: Optional[Dict[str, str]] = None


class InputGuardrailReport(BaseModel):
    """Comprehensive report produced by the Input Guardrail Pipeline."""
    report_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    allowed: bool = True
    block_reason: Optional[str] = None
    action_taken: str = "allow"
    detectors_run: List[str] = Field(default_factory=list)
    total_latency_ms: float = 0.0
    processed_text: str = ""
    validation: Optional[ValidationResult] = None
    injection: Optional[InjectionResult] = None
    pii: Optional[PIIResult] = None
    sensitive_topics: Optional[SensitiveTopicResult] = None


# =====================================================================
# Stage 2: Output Guardrails Models
# =====================================================================

class SchemaValidationResult(BaseModel):
    """Result of validating generated text against structured JSON schema."""
    passed: bool = True
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    retry_prompt: Optional[str] = None
    extracted_json: Optional[Any] = None


class GroundednessResult(BaseModel):
    """Result of factual groundedness and hallucination evaluation."""
    passed: bool = True
    score: float = Field(default=1.0, ge=0.0, le=1.0)
    domain_threshold: float = 0.85
    total_claims: int = 0
    supported_claims: int = 0
    unsupported_claims: List[str] = Field(default_factory=list)
    citation_density: float = Field(default=0.0, ge=0.0, le=1.0)
    hedging_detected: bool = False
    hedging_phrases: List[str] = Field(default_factory=list)


class SensitiveOutputResult(BaseModel):
    """Result of output-side sensitive information and secret detection."""
    sensitive_detected: bool = False
    findings: List[PIIFinding] = Field(default_factory=list)
    canary_leaked: bool = False
    remediation_action: RemediationAction = RemediationAction.ALLOW
    sanitized_text: Optional[str] = None
    refusal_message: Optional[str] = None


class OutputGuardrailReport(BaseModel):
    """Comprehensive report produced by the Output Guardrail Pipeline."""
    report_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    allowed: bool = True
    block_reason: Optional[str] = None
    remediation_action: RemediationAction = RemediationAction.ALLOW
    final_output: str = ""
    detectors_run: List[str] = Field(default_factory=list)
    total_latency_ms: float = 0.0
    schema_validation: Optional[SchemaValidationResult] = None
    groundedness: Optional[GroundednessResult] = None
    sensitive_output: Optional[SensitiveOutputResult] = None


# =====================================================================
# End-to-End Application & Service Models
# =====================================================================

class LegalQueryRequest(BaseModel):
    """User request to the Legal AI Assistant."""
    query: str
    reference_context: Optional[str] = None
    require_schema: bool = True
    domain: DomainType = DomainType.LEGAL
    user_id: Optional[str] = "anon_user"


class LegalAIResponseStructure(BaseModel):
    """Target output schema for Nepal Legal & Compliance queries."""
    summary: str = Field(description="High-level legal executive summary.")
    applicable_laws: List[str] = Field(description="Statutory references, act names, or sections.")
    risk_level: Literal["low", "medium", "high", "critical"] = Field(description="Assessed legal risk.")
    confidence_score: float = Field(ge=0.0, le=1.0, description="Confidence in legal statutory applicability.")
    legal_advice: str = Field(description="Actionable legal guidance and compliance steps.")
    disclaimer: str = Field(description="Mandatory statutory legal disclaimer.")
    citations: List[str] = Field(description="List of verified citations from the reference text.")


class EndToEndPipelineResponse(BaseModel):
    """End-to-end execution summary combining input and output evaluation."""
    request_id: str = Field(default_factory=lambda: str(uuid4()))
    query: str
    status: GuardrailStatus
    final_text: str
    input_report: InputGuardrailReport
    output_report: Optional[OutputGuardrailReport] = None
    total_execution_ms: float = 0.0
