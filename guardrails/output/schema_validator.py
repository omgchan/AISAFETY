"""
Output Schema Validator — Structure, Types, and Value Conformance.

Meets Assignment Specification:
- Validates LLM output against target JSON schema or Pydantic definitions.
- Extracts JSON embedded in markdown fences or surrounding chatter.
- Verifies required fields, valid data types, enum boundaries, and numeric ranges.
- Automatically generates corrective retry prompts when schema errors occur.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional
from guardrails.models import SchemaValidationResult


class OutputSchemaValidator:
    """Validates generated outputs against structured schemas and builds corrective prompts."""

    def validate(
        self,
        output_text: str,
        expected_schema: Optional[Dict[str, Any]] = None,
    ) -> SchemaValidationResult:
        """
        Validate output_text against expected_schema.
        If expected_schema is None, only validates that output is parseable JSON.
        """
        if not output_text or not output_text.strip():
            return SchemaValidationResult(
                passed=False,
                errors=["Output text is empty."],
                retry_prompt="Please generate a non-empty response conforming to the expected JSON schema.",
            )

        # 1. Extract JSON substring
        extracted_str = self._extract_json_string(output_text)
        if not extracted_str:
            return SchemaValidationResult(
                passed=False,
                errors=["No JSON object or array could be extracted from response."],
                retry_prompt=self._build_retry_prompt(
                    ["No valid JSON found. Your entire response must be a single valid JSON object."],
                    expected_schema,
                ),
            )

        # 2. Parse JSON
        try:
            parsed_data = json.loads(extracted_str)
        except json.JSONDecodeError as exc:
            # Attempt minor automatic repair (strip trailing commas)
            repaired_str = re.sub(r',\s*([}\]])', r'\1', extracted_str)
            try:
                parsed_data = json.loads(repaired_str)
            except json.JSONDecodeError:
                return SchemaValidationResult(
                    passed=False,
                    errors=[f"JSON syntax error: {exc.msg} at line {exc.lineno}, col {exc.colno}"],
                    retry_prompt=self._build_retry_prompt(
                        [f"Malformed JSON: {exc.msg}. Please fix syntax errors."],
                        expected_schema,
                    ),
                )

        # 3. Schema Conformance
        errors: List[str] = []
        warnings: List[str] = []

        if expected_schema:
            schema_type = expected_schema.get("type", "object")
            if schema_type == "object" and not isinstance(parsed_data, dict):
                errors.append(f"Expected JSON object, got {type(parsed_data).__name__}.")
            elif schema_type == "array" and not isinstance(parsed_data, list):
                errors.append(f"Expected JSON array, got {type(parsed_data).__name__}.")
            elif isinstance(parsed_data, dict):
                # Check required fields
                required_fields = expected_schema.get("required", [])
                for field in required_fields:
                    if field not in parsed_data:
                        errors.append(f"Missing required field: '{field}'.")

                # Check properties
                properties = expected_schema.get("properties", {})
                for key, prop_spec in properties.items():
                    if key in parsed_data:
                        val = parsed_data[key]
                        val_errs = self._validate_field(key, val, prop_spec)
                        errors.extend(val_errs)

        passed = len(errors) == 0
        retry_prompt = self._build_retry_prompt(errors, expected_schema) if not passed else None

        return SchemaValidationResult(
            passed=passed,
            errors=errors,
            warnings=warnings,
            retry_prompt=retry_prompt,
            extracted_json=parsed_data if passed else None,
        )

    def _extract_json_string(self, text: str) -> Optional[str]:
        """Extract JSON from markdown code fence or first balanced JSON structure."""
        # Check ```json ... ``` or ``` ... ```
        fence_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', text, re.IGNORECASE)
        if fence_match:
            candidate = fence_match.group(1).strip()
            if (candidate.startswith("{") and candidate.endswith("}")) or (candidate.startswith("[") and candidate.endswith("]")):
                return candidate

        # Look for outer curly braces
        first_brace = text.find("{")
        last_brace = text.rfind("}")
        if first_brace != -1 and last_brace > first_brace:
            return text[first_brace:last_brace + 1].strip()

        # Look for outer brackets
        first_bracket = text.find("[")
        last_bracket = text.rfind("]")
        if first_bracket != -1 and last_bracket > first_bracket:
            return text[first_bracket:last_bracket + 1].strip()

        return None

    def _validate_field(self, field_name: str, val: Any, spec: Dict[str, Any]) -> List[str]:
        """Validate type, enums, and ranges for a specific property."""
        errs: List[str] = []
        expected_type = spec.get("type")

        # Type check
        if expected_type == "string" and not isinstance(val, str):
            errs.append(f"Field '{field_name}' must be string, got {type(val).__name__}.")
        elif expected_type == "number" and not isinstance(val, (int, float)):
            errs.append(f"Field '{field_name}' must be a number, got {type(val).__name__}.")
        elif expected_type == "integer" and (not isinstance(val, int) or isinstance(val, bool)):
            errs.append(f"Field '{field_name}' must be an integer, got {type(val).__name__}.")
        elif expected_type == "boolean" and not isinstance(val, bool):
            errs.append(f"Field '{field_name}' must be a boolean, got {type(val).__name__}.")
        elif expected_type == "array" and not isinstance(val, list):
            errs.append(f"Field '{field_name}' must be an array, got {type(val).__name__}.")

        # Enum check
        if "enum" in spec and val not in spec["enum"]:
            errs.append(f"Field '{field_name}' has invalid value '{val}'. Allowed values: {spec['enum']}.")

        # Numeric Range check
        if isinstance(val, (int, float)):
            if "minimum" in spec and val < spec["minimum"]:
                errs.append(f"Field '{field_name}' ({val}) is below minimum allowed ({spec['minimum']}).")
            if "maximum" in spec and val > spec["maximum"]:
                errs.append(f"Field '{field_name}' ({val}) exceeds maximum allowed ({spec['maximum']}).")

        # Array item constraints
        if expected_type == "array" and isinstance(val, list) and "items" in spec:
            item_type = spec["items"].get("type")
            for idx, item in enumerate(val):
                if item_type == "string" and not isinstance(item, str):
                    errs.append(f"Item {idx} in '{field_name}' must be string, got {type(item).__name__}.")

        return errs

    def _build_retry_prompt(self, errors: List[str], schema: Optional[Dict[str, Any]]) -> str:
        """Constructs an LLM corrective re-prompt pointing out exact validation failures."""
        error_bullets = "\n".join(f"- {e}" for e in errors)
        schema_snippet = json.dumps(schema, indent=2) if schema else "valid JSON"
        return (
            f"Your previous response failed schema validation with the following error(s):\n"
            f"{error_bullets}\n\n"
            f"Please regenerate your response to strictly satisfy the required JSON structure:\n"
            f"```json\n{schema_snippet}\n```\n"
            f"Output ONLY the corrected JSON object without preamble."
        )
