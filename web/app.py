"""
FastAPI Server for Trustworthy AI Guardrails Interactive Web Dashboard.
Provides REST APIs for live testing, benchmark evaluation, and audit inspection.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from evaluate import run_benchmark
from guardrails.core.app_service import LegalAIAssistantService
from guardrails.models import (
    DomainType,
    EndToEndPipelineResponse,
    InputGuardrailReport,
    LegalQueryRequest,
    OutputGuardrailReport,
    RemediationAction,
)
from tests.test_cases_data import BENCHMARK_TEST_CASES

app = FastAPI(
    title="Nyaya-Guard: Trustworthy AI Guardrails",
    description="Input & Output Guardrail Layer for AI Applications",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

service = LegalAIAssistantService()


# ----------------------------------------------------------------------
# Request / Response Schemas
# ----------------------------------------------------------------------

class InputTestRequest(BaseModel):
    text: str
    anonymization_mode: Optional[str] = "redact"


class OutputTestRequest(BaseModel):
    output_text: str
    source_context: Optional[str] = None
    domain: Optional[str] = "legal"
    remediation_action: Optional[str] = "redact"


class FullPipelineRequest(BaseModel):
    query: str
    reference_context: Optional[str] = None
    mock_model_output: Optional[str] = None
    require_schema: bool = True
    domain: Optional[str] = "legal"


# ----------------------------------------------------------------------
# REST Endpoints
# ----------------------------------------------------------------------

@app.get("/api/health")
def health_check():
    return {"status": "healthy", "service": "Nyaya-Guard Guardrails", "version": "1.0.0"}


@app.post("/api/guardrails/input", response_model=InputGuardrailReport)
def test_input_guardrail(payload: InputTestRequest):
    """Test input text against validation, prompt injection, PII, and sensitive topic classifiers."""
    return service.input_pipeline.run(
        text=payload.text,
        anonymization_mode=payload.anonymization_mode,  # type: ignore
    )


@app.post("/api/guardrails/output", response_model=OutputGuardrailReport)
def test_output_guardrail(payload: OutputTestRequest):
    """Test generated output against schema, groundedness, and output-side sensitive data."""
    domain_enum = DomainType(payload.domain) if payload.domain in DomainType._value2member_map_ else DomainType.LEGAL
    remed_enum = RemediationAction(payload.remediation_action) if payload.remediation_action in RemediationAction._value2member_map_ else RemediationAction.REDACT

    from guardrails.core.app_service import LEGAL_RESPONSE_SCHEMA
    return service.output_pipeline.run(
        output_text=payload.output_text,
        source_context=payload.source_context,
        expected_schema=LEGAL_RESPONSE_SCHEMA,
        domain=domain_enum,
        canary_manager=service.input_pipeline.canary_manager,
        preferred_remediation=remed_enum,
    )


@app.post("/api/guardrails/full-pipeline", response_model=EndToEndPipelineResponse)
def run_full_pipeline(payload: FullPipelineRequest):
    """Execute end-to-end legal query with input guardrails, generation simulation, and output guardrails."""
    domain_enum = DomainType(payload.domain) if payload.domain in DomainType._value2member_map_ else DomainType.LEGAL
    req = LegalQueryRequest(
        query=payload.query,
        reference_context=payload.reference_context,
        require_schema=payload.require_schema,
        domain=domain_enum,
    )
    return service.process_query(req, mock_raw_generation=payload.mock_model_output)


@app.get("/api/test-cases")
def get_benchmark_cases():
    """Retrieve all 25 benchmark test cases."""
    return BENCHMARK_TEST_CASES


@app.post("/api/evaluate")
def execute_benchmark():
    """Run the 25-case benchmark evaluation and return detailed metrics."""
    return run_benchmark(verbose=False)


@app.get("/api/audit-log")
def get_audit_log(limit: int = 50):
    """Fetch recent audit log entries and verify cryptographic integrity."""
    integrity = service.audit_logger.verify_integrity()
    records = []
    if service.audit_logger.log_path.exists():
        import json
        with open(service.audit_logger.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except Exception:
                        pass
    return {
        "integrity": integrity,
        "total_records": len(records),
        "recent_records": records[-limit:],
    }


# ----------------------------------------------------------------------
# Mount Static Frontend
# ----------------------------------------------------------------------

static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/")
    def serve_frontend():
        return FileResponse(str(static_dir / "index.html"))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("web.app:app", host="127.0.0.1", port=8000, reload=True)
