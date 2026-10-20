"""
Audit Logger — Cryptographically Hashed, Tamper-Evident Guardrail Audit Trail.

Implements an append-only JSONL log with SHA-256 hash chaining to ensure that
all safety decisions, latencies, PII redactions, and injection detections
are permanently and reliably recorded.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AuditRecord(BaseModel):
    """An individual tamper-evident audit record."""
    record_id: str
    timestamp: str
    event_type: str
    user_id: Optional[str] = None
    action_taken: str
    allowed: bool
    risk_score: float = 0.0
    latency_ms: float = 0.0
    metadata: Dict[str, Any] = Field(default_factory=dict)
    prev_hash: str = "GENESIS"
    hash: str = ""


class AuditLogger:
    """Manages append-only, SHA-256 chained audit logs."""

    def __init__(self, log_path: Optional[str] = None) -> None:
        self.log_path = Path(log_path or "logs/guardrails_audit.jsonl")
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash = self._get_latest_hash()

    def log(
        self,
        event_type: str,
        action_taken: str,
        allowed: bool,
        user_id: Optional[str] = None,
        risk_score: float = 0.0,
        latency_ms: float = 0.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditRecord:
        """Create and write an audit record with hash chaining."""
        record_id = hashlib.sha256(f"{datetime.now(timezone.utc).isoformat()}_{action_taken}".encode()).hexdigest()[:16]
        timestamp = datetime.now(timezone.utc).isoformat()

        record = AuditRecord(
            record_id=record_id,
            timestamp=timestamp,
            event_type=event_type,
            user_id=user_id,
            action_taken=action_taken,
            allowed=allowed,
            risk_score=risk_score,
            latency_ms=latency_ms,
            metadata=metadata or {},
            prev_hash=self._last_hash,
            hash="",
        )

        # Compute SHA-256 hash of this record
        record_bytes = json.dumps(record.model_dump(exclude={"hash"}), sort_keys=True).encode()
        record.hash = hashlib.sha256(record_bytes).hexdigest()
        self._last_hash = record.hash

        # Append to log file
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(record.model_dump_json() + "\n")

        return record

    def verify_integrity(self) -> Dict[str, Any]:
        """Verify the cryptographic hash chain of the audit log."""
        if not self.log_path.exists():
            return {"valid": True, "records_checked": 0, "errors": []}

        records_checked = 0
        errors: List[str] = []
        expected_prev = "GENESIS"

        with open(self.log_path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    stored_hash = data.get("hash")
                    prev_hash = data.get("prev_hash")

                    if prev_hash != expected_prev:
                        errors.append(f"Line {line_no}: Broken hash link (expected {expected_prev}, got {prev_hash})")

                    calc_bytes = json.dumps({k: v for k, v in data.items() if k != "hash"}, sort_keys=True).encode()
                    calc_hash = hashlib.sha256(calc_bytes).hexdigest()
                    if calc_hash != stored_hash:
                        errors.append(f"Line {line_no}: Tampered record hash (expected {calc_hash}, got {stored_hash})")

                    expected_prev = stored_hash
                    records_checked += 1
                except Exception as exc:
                    errors.append(f"Line {line_no}: Malformed JSON entry ({exc})")

        return {
            "valid": len(errors) == 0,
            "records_checked": records_checked,
            "errors": errors,
        }

    def _get_latest_hash(self) -> str:
        """Find the last hash in the log file or return GENESIS."""
        if not self.log_path.exists():
            return "GENESIS"
        last_hash = "GENESIS"
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        data = json.loads(line)
                        if "hash" in data:
                            last_hash = data["hash"]
                    except Exception:
                        pass
        return last_hash
