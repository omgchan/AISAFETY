"""
Groundedness & Hallucination Checker — Factual Verification Against Source Reference.

Meets Assignment Specification:
- Evaluates whether generated claims are grounded in provided reference context.
- Extracts propositional factual assertions and tests entity/statute/lexical overlap.
- Detects uncertainty and hedging phrases.
- Enforces strict domain thresholds (Legal: 0.85, Medical: 0.85, Financial: 0.80, General: 0.70).
- Specifically identifies unsupported claims to enable remediation and failure analysis.
"""

from __future__ import annotations

import json
import re
from typing import List, Optional, Set
from guardrails.models import DomainType, GroundednessResult

DOMAIN_THRESHOLDS: dict[DomainType, float] = {
    DomainType.LEGAL: 0.85,
    DomainType.MEDICAL: 0.85,
    DomainType.FINANCIAL: 0.80,
    DomainType.GENERAL: 0.70,
    DomainType.CREATIVE: 0.0,
}

HEDGING_PATTERNS = [
    r'(?i)\b(i\s+think|i\s+believe|probably|maybe|perhaps|possibly)\b',
    r'(?i)\b(i\'?m\s+not\s+(certain|sure)|i\s+cannot\s+(guarantee|confirm))\b',
    r'(?i)\b(might\s+be|could\s+be|may\s+be|seems?\s+(like|to\s+be))\b',
    r'(?i)\b(as\s+an\s+ai|as\s+a\s+language\s+model)\b',
    r'(?i)\b(to\s+the\s+best\s+of\s+my\s+knowledge)\b',
]

STOPWORDS = {
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and", "any", "are",
    "aren't", "as", "at", "be", "because", "been", "before", "being", "below", "between", "both",
    "but", "by", "can", "can't", "cannot", "could", "did", "do", "does", "doing", "don't", "down",
    "during", "each", "few", "for", "from", "further", "had", "has", "have", "having", "he", "her",
    "here", "hers", "herself", "him", "himself", "his", "how", "i", "if", "in", "into", "is",
    "isn't", "it", "it's", "its", "itself", "let's", "me", "more", "most", "my", "myself", "no",
    "nor", "not", "of", "off", "on", "once", "only", "or", "other", "ought", "our", "ours",
    "ourselves", "out", "over", "own", "same", "she", "should", "so", "some", "such", "than",
    "that", "the", "their", "theirs", "them", "themselves", "then", "there", "these", "they",
    "this", "those", "through", "to", "too", "under", "until", "up", "very", "was", "wasn't",
    "we", "were", "weren't", "what", "when", "where", "which", "while", "who", "whom", "why",
    "with", "won't", "would", "you", "your", "yours", "yourself", "yourselves"
}


class GroundednessChecker:
    """Evaluates factual grounding and citation support of LLM outputs against source context."""

    def __init__(self, claim_overlap_threshold: float = 0.55) -> None:
        self.claim_overlap_threshold = claim_overlap_threshold
        self._compiled_hedging = [re.compile(p) for p in HEDGING_PATTERNS]

    def check(
        self,
        output_text: str,
        source_context: Optional[str] = None,
        domain: DomainType = DomainType.LEGAL,
    ) -> GroundednessResult:
        """
        Evaluate output claims against source reference text.
        
        Returns GroundednessResult with scores, supported/unsupported claims, and hedging status.
        """
        threshold = DOMAIN_THRESHOLDS.get(domain, 0.70)

        # 1. Hedging detection
        hedging_phrases: List[str] = []
        for p in self._compiled_hedging:
            matches = p.findall(output_text)
            if matches:
                hedging_phrases.extend(matches if isinstance(matches[0], str) else [m[0] for m in matches])
        hedging_detected = len(hedging_phrases) > 0

        # If domain is creative, groundedness check is bypassed
        if domain == DomainType.CREATIVE:
            return GroundednessResult(
                passed=True,
                score=1.0,
                domain_threshold=0.0,
                total_claims=0,
                supported_claims=0,
                unsupported_claims=[],
                citation_density=1.0,
                hedging_detected=hedging_detected,
                hedging_phrases=hedging_phrases,
            )

        # 2. Extract atomic claims
        claims = self._extract_claims(output_text)
        if not claims:
            return GroundednessResult(
                passed=True,
                score=1.0,
                domain_threshold=threshold,
                total_claims=0,
                supported_claims=0,
                unsupported_claims=[],
                citation_density=1.0,
                hedging_detected=hedging_detected,
                hedging_phrases=hedging_phrases,
            )

        # If source_context is missing or empty, factual claims cannot be verified
        if not source_context or not source_context.strip():
            return GroundednessResult(
                passed=False,
                score=0.0,
                domain_threshold=threshold,
                total_claims=len(claims),
                supported_claims=0,
                unsupported_claims=claims,
                citation_density=0.0,
                hedging_detected=hedging_detected,
                hedging_phrases=hedging_phrases,
            )

        # 3. Verify each claim against source context
        normalized_source = source_context.lower()
        source_tokens = self._tokenize(normalized_source)

        supported_count = 0
        unsupported_claims: List[str] = []
        cited_count = 0

        for claim in claims:
            claim_tokens = self._tokenize(claim.lower())
            salient_tokens = [t for t in claim_tokens if t not in STOPWORDS and len(t) > 2]

            if not salient_tokens:
                # Trivial statement
                supported_count += 1
                continue

            # Check overlap ratio
            matched_tokens = sum(1 for t in salient_tokens if t in source_tokens)
            overlap_ratio = matched_tokens / len(salient_tokens)

            # Check for specific statutory or numeric entities
            statute_match = re.search(r'(?i)\b(section\s+\d+|act\s+\d{4}|code\s+\d{4}|article\s+\d+)\b', claim)
            if statute_match:
                entity = statute_match.group().lower()
                if entity not in normalized_source:
                    # Fabricated legal section or statute
                    overlap_ratio = 0.0

            # Check citation markers e.g. [1], [Act 2074]
            if re.search(r'\[(?:citation|\d+|ref|section)\]', claim, re.IGNORECASE):
                cited_count += 1

            if overlap_ratio >= self.claim_overlap_threshold:
                supported_count += 1
            else:
                unsupported_claims.append(claim)

        score = round(supported_count / len(claims), 3) if claims else 1.0
        citation_density = round(cited_count / len(claims), 3) if claims else 0.0
        passed = score >= threshold

        return GroundednessResult(
            passed=passed,
            score=score,
            domain_threshold=threshold,
            total_claims=len(claims),
            supported_claims=supported_count,
            unsupported_claims=unsupported_claims,
            citation_density=citation_density,
            hedging_detected=hedging_detected,
            hedging_phrases=hedging_phrases,
        )

    def _extract_claims(self, text: str) -> List[str]:
        """Split text into individual propositional sentences or bullet points."""
        parsed_dict = None
        try:
            fence = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', text)
            raw = fence.group(1).strip() if fence else text.strip()
            if raw.startswith("{") and raw.endswith("}"):
                parsed_dict = json.loads(raw)
        except Exception:
            parsed_dict = None

        if isinstance(parsed_dict, dict):
            # Extract narrative text only from substantive fields
            narrative_parts = []
            for field in ["summary", "legal_advice", "analysis", "content", "answer", "text"]:
                val = parsed_dict.get(field)
                if isinstance(val, str) and len(val.strip()) > 5:
                    narrative_parts.append(val.strip())
            cleaned = " ".join(narrative_parts) if narrative_parts else ""
        else:
            # Clean markdown formatting
            cleaned = re.sub(r'```[\s\S]*?```', '', text)
            cleaned = re.sub(r'[{}\[\]"]', ' ', cleaned)
            cleaned = re.sub(r'(?:summary|legal_advice|applicable_laws|disclaimer):', '', cleaned, flags=re.IGNORECASE)

        # Split on sentence boundaries, colons, or newlines
        raw_sentences = re.split(r'(?<=[.!?])\s+|\n+|(?:;\s*)', cleaned)
        claims = []
        for s in raw_sentences:
            s_clean = s.strip().lstrip("-*•0123456789. ")
            if len(s_clean) > 15 and any(ch.isalpha() for ch in s_clean):
                # Filter out contact boilerplate, disclaimers, and redaction placeholders
                if re.search(r'(?i)\b(contact|reach\s+out|call\s+us|email\s+us|disclaimer|inquiries|api[_-]?key)\b', s_clean):
                    continue
                if "[REDACTED_" in s_clean:
                    continue
                claims.append(s_clean)
        return claims

    def _tokenize(self, text: str) -> Set[str]:
        """Tokenize text into lowercase alphanumeric words."""
        return set(re.findall(r'\b[a-z0-9_-]+\b', text.lower()))
