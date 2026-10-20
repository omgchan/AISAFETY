# Nyaya-Guard: Trustworthy AI Input & Output Guardrails System

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.14-blue.svg)](https://python.org)
[![Tests Passing](https://img.shields.io/badge/pytest-59%20passed-success.svg)]()
[![Benchmark Pass Rate](https://img.shields.io/badge/benchmark-100%25%20(25%2F25)-brightgreen.svg)]()
[![Latency](https://img.shields.io/badge/latency-1.26ms-cyan.svg)]()
[![License](https://img.shields.io/badge/license-MIT-purple.svg)]()

> A robust, dual-stage defense-in-depth guardrail system engineered for high-assurance AI applications, demonstrated on the **Nepal Legal & Compliance AI Assistant** domain.

---

## Table of Contents
- [Project Overview](#project-overview)
- [Key Features](#key-features)
- [Architecture & Guardrail Stages](#architecture--guardrail-stages)
- [Setup & Installation](#setup--installation)
- [Running the Test Suites](#running-the-test-suites)
- [Running the Benchmark Evaluation](#running-the-benchmark-evaluation)
- [Interactive CLI Usage](#interactive-cli-usage)
- [Interactive Web Dashboard](#interactive-web-dashboard)
- [Benchmark Results & Metrics](#benchmark-results--metrics)
- [Design Decisions & Trade-offs](#design-decisions--trade-offs)
- [Repository Structure](#repository-structure)

---

## Project Overview

When deploying Large Language Models (LLMs) in sensitive legal, regulatory, and public service environments, systems must guarantee:
1. **Privacy:** User and client Personally Identifiable Information (PII) must not leak to third-party models or third-party context logs.
2. **Security:** Malicious actors must not hijack instructions via prompt injection, jailbreaks, or extract internal system prompts.
3. **Safety:** Queries regarding dangerous weapons, malware, or self-harm must be blocked or redirected to certified crisis resources.
4. **Reliability:** Generated outputs must conform to strict JSON schemas and must be factually grounded in provided reference statutes to prevent legal hallucinations.

**Nyaya-Guard** provides a production-grade, zero-native-build-dependency guardrail implementation that executes in **under 2 milliseconds**.

---

## Key Features

### 1. Stage 1: Input Guardrails (Pre-Ingestion Gate)
- **Input Normalizer & Validator:** Strips zero-width evasion characters (`\u200b`, `\ufeff`), executes Unicode NFKC normalization, and neutralizes cross-script Cyrillic/Greek homoglyphs.
- **Prompt Injection Detector:** 35+ compiled pattern bank detecting direct instruction overrides, DAN persona jailbreaks, system prompt extractions, authority impersonation, and delimiter manipulation, supplemented with Shannon entropy analysis.
- **PII Detection & Anonymization Engine:** Identifies Emails, Nepal phone numbers (`+977-98xxxxxxxx`), Nepal Citizenship numbers (`12-01-78-xxxxx`), PAN tax numbers, US SSNs, and Passports. Supports three actions:
  - `redact`: Replaces with `[REDACTED_<TYPE>]`
  - `mask`: Obfuscates partially (e.g. `jo***@law.org.np`, `***-**-04321`)
  - `tokenize`: Swaps entities with cryptographic surrogates (`<TOKEN_PII_1>`) stored in a reversible vault.
- **Sensitive Topic Classifier & Crisis Router:** Maps queries across 6 policy risk categories. Blocks weapons, malware, and fraud (`hard_block`); routes mental health crisis queries to certified emergency helplines (`safe_response` providing Nepal 1166 Helpline).

### 2. Stage 2: Output Guardrails (Post-Generation Gate)
- **Schema Validator:** Extracts JSON from markdown fences, repairs minor syntax errors, and validates required keys, types, enums, and numerical ranges against `LegalAIResponseStructure`. Builds automated corrective re-prompts on failure.
- **Sensitive Output Detector:** Scans generated text for unredacted user PII, API tokens, cryptographic private keys, and canary tokens. Applies automatic in-place redaction or enforcement refusal.
- **Groundedness & Hallucination Checker:** Extracts atomic propositional claims from narrative fields, measures lexical and n-gram overlap against source reference context, checks statutory citation integrity, and flags uncertainty hedging markers. Intercepts ungrounded outputs and substitutes certified Safe Fallbacks.

### 3. Cryptographic Audit Trail
- Maintains an append-only log in `logs/guardrails_audit.jsonl` where every decision, risk score, and latency is cryptographically chained using **SHA-256 hashing**, making log tampering immediately detectable.

---

## Architecture & Guardrail Stages

```
                  ┌──────────────────────────────────────────────┐
                  │                 USER QUERY                   │
                  └──────────────────────┬───────────────────────┘
                                         │
                    STAGE 1: INPUT GUARDRAILS PIPELINE
         ┌───────────────────────────────┴───────────────────────────────┐
         │ 1. InputValidator (Unicode NFKC, Zero-width, Homoglyphs)     │
         │ 2. InjectionDetector (35+ Patterns, Heuristics, Canary)      │
         │ 3. PIIDetector (Email, Phone, Citizenship, PAN, SSN)         │
         │ 4. SensitiveTopicClassifier (CBRN, Malware, Crisis 1166)     │
         └───────────────────────────────┬───────────────────────────────┘
                     Blocked? ─── YES ───┴───► Refusal / Crisis Helpline
                                 NO
                                 ▼
                  ┌──────────────────────────────────────────────┐
                  │       MODEL REASONING & GENERATION CORE      │
                  └──────────────────────┬───────────────────────┘
                                         │
                   STAGE 2: OUTPUT GUARDRAILS PIPELINE
         ┌───────────────────────────────┴───────────────────────────────┐
         │ 1. SchemaValidator (JSON Conformance, Re-prompting)          │
         │ 2. SensitiveOutputDetector (Canary & PII Scrubbing)          │
         │ 3. GroundednessChecker (Citation & Factual Claim Overlap)    │
         └───────────────────────────────┬───────────────────────────────┘
                    Failed? ──── YES ────┴───► Safe Legal Fallback
                                 NO
                                 ▼
                  ┌──────────────────────────────────────────────┐
                  │          VERIFIED RESPONSE TO USER           │
                  └──────────────────────────────────────────────┘
```

For full sequence diagrams and detailed component specifications, see [ARCHITECTURE.md](file:///d:/fusefinal/ARCHITECTURE.md).

---

## Setup & Installation

### Prerequisites
- Python 3.10, 3.11, 3.12, or 3.14
- Operating System: Windows, macOS, or Linux

### Installation
Clone the repository and install the lightweight dependencies:
```bash
git clone https://github.com/omgchan/Nepal-Legal-AI-Assistant.git
cd Nepal-Legal-AI-Assistant
pip install -r requirements.txt
```

---

## Running the Test Suites

Run the full suite of **59 unit and benchmark tests** via `pytest`:
```bash
python -m pytest tests/ -v
```
All 59 unit and integration tests run and pass in ~0.9 seconds.

---

## Running the Benchmark Evaluation

Execute the automated 25-case evaluation benchmark:
```bash
python evaluate.py
```

This runs all 25 benchmark test cases, computes the confusion matrix, outputs the evaluation metrics, and exports `benchmark_results.json`.

---

## Interactive CLI Usage

Launch the interactive CLI tool:
```bash
python demo_cli.py
```
From the interactive menu:
- Select **[1-6]** to test pre-configured scenarios (Benign, Injection, PII, Crisis, Schema Error, Hallucination)
- Select **[C]** to enter a custom query and reference context
- Select **[A]** to verify the cryptographic SHA-256 hash chain of the audit log

Or test a single query directly from the command line:
```bash
python demo_cli.py --query "What is the limitation period for filing contract disputes?"
```

---

## Interactive Web Dashboard

Launch the FastAPI web server:
```bash
python web/app.py
```
Open your browser and navigate to: **`http://localhost:8000`**

### Dashboard Features:
1. **Live Playground:** Interactive prompt testing with instant telemetry, PII mode toggling (Redact / Mask / Tokenize), and one-click scenario presets.
2. **Benchmark Suite:** One-click execution of the 25 benchmark cases with live progress, Confusion Matrix cards, and filterable test table.
3. **Architecture & Specs:** Interactive component breakdown and parameter specifications.
4. **Audit Log Chain:** Live inspection of the SHA-256 hash chain with instant tamper-verification.

---

## Benchmark Results & Metrics

Evaluated across the 25 comprehensive test cases specified in the assignment:

| Metric | Score | Performance Details |
| :--- | :--- | :--- |
| **Test Pass Rate** | **100.0% (25/25)** | All benchmark cases behaved exactly as expected |
| **Precision** | **1.0000 (100.0%)** | Zero False Positives (legitimate legal queries never blocked) |
| **Recall (Sensitivity)**| **1.0000 (100.0%)** | Zero False Negatives (all attacks and PII caught) |
| **Specificity** | **1.0000 (100.0%)** | 100% true negative identification rate |
| **F1-Score** | **1.0000** | Perfect harmonic balance between precision and recall |
| **Mean Latency** | **1.26 ms** | Negligible overhead added to user queries |

### Confusion Matrix

| | Predicted Positive (Flagged / Threat) | Predicted Negative (Allowed / Benign) |
| :--- | :---: | :---: |
| **Actual Positive (Threat / PII)** | **TP = 20** | **FN = 0** |
| **Actual Negative (Benign)** | **FP = 0** | **TN = 5** |

For the full academic report, failure case analysis, and deployment risk assessment, read [REPORT.md](file:///d:/fusefinal/REPORT.md).

---

## Design Decisions & Trade-offs

1. **Deterministic Pattern Banks vs. Heavy Native NLP:** Presidio / LLM-Guard often require C++ compilation or fail on Windows Python 3.14. Nyaya-Guard uses compiled regexes, mathematical Shannon entropy, and lightweight Unicode algorithms to run everywhere with sub-2ms latency.
2. **Context-Aware Claim Extraction:** When validating structured JSON output, GroundednessChecker isolates substantive narrative fields (`summary`, `legal_advice`) and filters out contact boilerplate, preventing false hallucination flags on JSON schema metadata.
3. **Multi-Action Output Remediation:** Invalid responses are not merely dropped; they are handled according to severity: PII is redacted in-place, malformed schemas generate corrective re-prompts, and hallucinations are replaced with verified statutory fallback notices.

---

## Repository Structure

```
d:\fusefinal\
├── guardrails/                      # Core Guardrails Package
│   ├── __init__.py
│   ├── models.py                    # Unified Pydantic models & schemas
│   ├── input/                       # Stage 1: Input Guardrails
│   │   ├── __init__.py
│   │   ├── validator.py             # Unicode NFKC, zero-width, homoglyph normalization
│   │   ├── pii_detector.py          # Email, phone, Nepal citizenship, PAN, SSN, passport
│   │   ├── injection_detector.py    # 35+ Injection patterns, heuristics, canary tokens
│   │   ├── sensitive_classifier.py  # CBRN, malware, self-harm crisis, fraud router
│   │   └── pipeline.py              # Input pipeline orchestrator (fail-fast)
│   ├── output/                      # Stage 2: Output Guardrails
│   │   ├── __init__.py
│   │   ├── schema_validator.py      # JSON structure, type & range conformance
│   │   ├── groundedness_checker.py  # Propositional claims, lexical overlap, hedging
│   │   ├── sensitive_detector.py    # Output PII scrub, secret scanner, canary leak detector
│   │   └── pipeline.py              # Output pipeline orchestrator (remediation)
│   └── core/                        # Core Application Engine
│       ├── __init__.py
│       ├── audit_logger.py          # Append-only JSONL with SHA-256 hash chaining
│       └── app_service.py           # End-to-end Legal AI Assistant service
├── tests/                           # Test Suites (59 Tests Total)
│   ├── __init__.py
│   ├── test_cases_data.py           # Central 25-case benchmark dataset
│   ├── test_input_guardrails.py     # Unit tests for input guardrail modules
│   ├── test_output_guardrails.py    # Unit tests for output guardrail modules
│   └── test_comprehensive_suite.py  # Comprehensive parameterized benchmark suite
├── web/                             # Interactive Web Dashboard
│   ├── app.py                       # FastAPI REST API server
│   └── static/
│       ├── index.html               # Modern dark-mode HTML5 dashboard
│       ├── style.css                # Glassmorphism design system
│       └── app.js                   # Reactive UI logic & benchmark runner
├── evaluate.py                      # Standalone evaluation & metrics benchmark runner
├── demo_cli.py                      # Interactive Command-Line Interface
├── ARCHITECTURE.md                  # Comprehensive Mermaid architectural diagrams
├── REPORT.md                        # Formal assignment report & failure analysis
├── README.md                        # Documentation & setup guide
└── requirements.txt                 # Clean minimal dependencies
```
