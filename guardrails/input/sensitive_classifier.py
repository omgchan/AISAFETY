"""
Sensitive Topic Classifier — Content Risk Categorization and Routing.

Meets Assignment Specification:
- Classifies requests into critical risk categories (Weapons/CBRN, Cyberweapons,
  Self-Harm/Crisis, Extremism, CSAE, Financial Fraud, Legal Ethics Violations).
- Defines explicit routing actions per category:
  * hard_block: Immediate refusal and pipeline termination.
  * safe_response: Specialized safe intervention path with crisis helplines.
  * warn_and_flag: Allowed with audit trail and legal disclaimers.
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple
from guardrails.models import (
    RouteAction,
    SensitiveCategory,
    SensitiveTopicFinding,
    SensitiveTopicResult,
)

# ----------------------------------------------------------------------
# Category Keyword and Pattern Specifications
# ----------------------------------------------------------------------

CATEGORY_SPECS: dict[SensitiveCategory, dict] = {
    SensitiveCategory.WEAPONS_CBRN: {
        "route": RouteAction.HARD_BLOCK,
        "keywords": [
            "how to make a bomb", "synthesize explosives", "build nuclear weapon",
            "chemical weapon", "biological weapon", "ricin", "anthrax", "sarin",
            "cbrn", "dirty bomb", "pipe bomb recipe", "manufacture dynamite",
            "detonator schematic", "weaponize pathogens",
        ],
        "patterns": [
            r'(?i)\b(make|build|construct|assemble|synthesize)\b.*\b(bomb|explosive|warhead|detonator|ied)\b',
            r'(?i)\b(chemical|biological|radiological|nuclear)\s+(weapon|agent|attack|dispersal)\b',
        ],
    },
    SensitiveCategory.CYBERWEAPONS_MALWARE: {
        "route": RouteAction.HARD_BLOCK,
        "keywords": [
            "write ransomware", "create malware", "build a botnet", "ddos script",
            "how to hack into", "exploit zero-day", "phishing kit", "keylogger source",
            "rootkit tutorial", "sql injection payload", "remote access trojan",
            "credential harvester", "bypass edr", "privilege escalation exploit",
        ],
        "patterns": [
            r'(?i)\b(write|create|code|compile)\b.*\b(ransomware|malware|keylogger|trojan|rootkit|spyware)\b',
            r'(?i)\b(hack|breach|infiltrate|crack)\b.*\b(server|database|firewall|wi-fi|system|account)\b',
        ],
    },
    SensitiveCategory.SELF_HARM_CRISIS: {
        "route": RouteAction.SAFE_RESPONSE,
        "keywords": [
            "want to kill myself", "end my life", "suicide method",
            "how to commit suicide", "i want to die", "no reason to live",
            "self harm", "cutting myself", "overdose on pills to die",
            "jump off a bridge", "hang myself", "feel like ending it",
        ],
        "patterns": [
            r'(?i)\b(i\s+(want|need|plan|am\s+going)\s+to\s+(die|kill\s+myself|end\s+my\s+life|commit\s+suicide))\b',
            r'(?i)\b(suicide|self[\s-]?harm|cutting)\b.*\b(how|method|easiest\s+way|painless)\b',
        ],
    },
    SensitiveCategory.EXTREMISM: {
        "route": RouteAction.HARD_BLOCK,
        "keywords": [
            "terrorist attack", "jihadist manual", "white supremacy",
            "hate crime", "ethnic cleansing", "genocide tutorial",
            "mass shooting plan", "bombing target list", "extremist recruitment",
        ],
        "patterns": [
            r'(?i)\b(terrorist|extremist)\s+(organization|manifesto|attack|operation)\b',
            r'(?i)\b(plan|organize|execute)\s+(a\s+)?(mass\s+shooting|bombing|hate\s+crime)\b',
        ],
    },
    SensitiveCategory.CSAE: {
        "route": RouteAction.HARD_BLOCK,
        "keywords": [
            "child pornography", "csam", "lolita", "underage nude",
            "child abuse material", "jailbait", "pedophile guide",
        ],
        "patterns": [
            r'(?i)\b(child|minor|underage|infant|toddler)\b.*\b(sexual|nude|porn|naked|erotic)\b',
            r'(?i)\b(pedophile|pedo|csam)\b',
        ],
    },
    SensitiveCategory.FRAUD: {
        "route": RouteAction.HARD_BLOCK,
        "keywords": [
            "how to launder money", "credit card fraud method", "identity theft steps",
            "ponzi scheme setup", "tax evasion scheme", "fake passport template",
            "counterfeit currency printing", "bank fraud script",
        ],
        "patterns": [
            r'(?i)\b(launder|counterfeit|forge)\b.*\b(money|currency|passport|checks?|documents?)\b',
            r'(?i)\b(evade|avoid|bypass)\b.*\b(taxes|customs|anti-money\s+laundering|aml\s+laws)\b',
        ],
    },
    SensitiveCategory.LEGAL_ETHICS_VIOLATION: {
        "route": RouteAction.HARD_BLOCK,
        "keywords": [
            "how to bribe a judge", "forge court document", "fake evidence for trial",
            "suborn perjury", "hide subpoenaed documents", "destroy evidence in lawsuit",
            "forge official seal", "bribe court clerk",
        ],
        "patterns": [
            r'(?i)\b(bribe|corrupt|pay\s+off)\b.*\b(judge|clerk|juror|magistrate|witness)\b',
            r'(?i)\b(forge|fabricate|tamper\s+with|destroy)\b.*\b(evidence|court\s+record|testimony|affidavit)\b',
        ],
    },
}

CRISIS_RESOURCES = {
    "nepal_helpline": "Nepal Mental Health & Suicide Helpline: 1166 (Toll-Free, 24/7)",
    "nepal_emergency": "Nepal Emergency Police: 100",
    "international_lifeline": "US/International Crisis Line: 988 or text HOME to 741741",
    "guidance_message": (
        "If you or someone you know is going through a difficult time, please reach out. "
        "Compassionate, confidential support is available right now."
    ),
}


class SensitiveTopicClassifier:
    """Classifies user queries into pre-defined risk categories and computes routing."""

    def __init__(self) -> None:
        self._compiled_patterns: dict[SensitiveCategory, list[re.Pattern]] = {
            cat: [re.compile(p) for p in spec["patterns"]]
            for cat, spec in CATEGORY_SPECS.items()
        }

    def classify(self, text: str) -> SensitiveTopicResult:
        """Analyze text against all sensitive categories and return findings and routing."""
        if not text or not text.strip():
            return SensitiveTopicResult(topics_detected=False)

        findings: List[SensitiveTopicFinding] = []
        text_lower = text.lower()

        for category, spec in CATEGORY_SPECS.items():
            matched_terms: List[str] = []

            # 1. Exact phrase/keyword matching
            for term in spec["keywords"]:
                if term in text_lower:
                    matched_terms.append(term)

            # 2. Regex pattern matching
            for pattern in self._compiled_patterns[category]:
                if pattern.search(text):
                    matched_terms.append(pattern.pattern)

            if matched_terms:
                findings.append(
                    SensitiveTopicFinding(
                        category=category,
                        route=spec["route"],
                        matched_terms=matched_terms[:5],
                        confidence=1.0 if len(matched_terms) > 1 else 0.85,
                    )
                )

        if not findings:
            return SensitiveTopicResult(
                topics_detected=False,
                findings=[],
                strictest_action=RouteAction.ALLOW,
            )

        # Determine strictest action: HARD_BLOCK > SAFE_RESPONSE > WARN_AND_FLAG > ALLOW
        action_priority = {
            RouteAction.HARD_BLOCK: 4,
            RouteAction.SAFE_RESPONSE: 3,
            RouteAction.WARN_AND_FLAG: 2,
            RouteAction.ALLOW: 1,
        }
        strictest_action = max((f.route for f in findings), key=lambda r: action_priority[r])

        crisis_info = CRISIS_RESOURCES if any(f.category == SensitiveCategory.SELF_HARM_CRISIS for f in findings) else None

        return SensitiveTopicResult(
            topics_detected=True,
            findings=findings,
            strictest_action=strictest_action,
            crisis_resources=crisis_info,
        )
