# System Architecture: Nyaya-Guard

## Overview
**Nyaya-Guard** is a dual-stage, defense-in-depth trustworthy AI guardrail architecture engineered specifically for high-assurance AI applications (demonstrated on the **Nepal Legal & Compliance AI Assistant** domain).

The architecture enforces strict safety, security, and privacy boundaries across two distinct checkpoints:
1. **Input Guardrail Pipeline (Pre-Ingestion Gate)**: Sanitizes and evaluates user prompts *before* they can reach the underlying model or reasoning engine.
2. **Output Guardrail Pipeline (Post-Generation Gate)**: Evaluates and remediates model responses *before* they are delivered to the user.

---

## 1. End-to-End Architectural Flow Diagram

```mermaid
flowchart TD
    User([User / Client Application]) -->|Raw Query Text| S1_Norm[1. Input Normalizer & Validator]
    
    subgraph STAGE_1 ["Stage 1: Input Guardrails Pipeline"]
        S1_Norm -->|Check Zero-width, NFKC, Homoglyphs| S1_NormCheck{Valid & Clean?}
        S1_NormCheck -->|No / Malformed| BlockMalformed[Block: Malformed Input]
        S1_NormCheck -->|Yes: Safe Normalized Text| S1_Inj[2. Prompt Injection Detector]
        
        S1_Inj -->|Pattern Bank + Heuristics| S1_InjCheck{Injection Threat?}
        S1_InjCheck -->|Yes: Score >= Threshold| BlockInj[Block: Prompt Injection]
        S1_InjCheck -->|No: Clean| S1_PII[3. PII Detector & De-obfuscator]
        
        S1_PII -->|Scan Email, Phone, Citizen ID, PAN| S1_PIIAction[Sanitize: Redact / Mask / Tokenize]
        S1_PIIAction --> S1_Sens[4. Sensitive Topic Classifier]
        
        S1_Sens -->|CBRN, Cyberweapons, Extremism, Fraud| S1_SensCheck{Route Action?}
        S1_SensCheck -->|Hard Block| BlockSens[Block: Prohibited Policy Topic]
        S1_SensCheck -->|Safe Response / Crisis| RouteCrisis[Safe Crisis Intervention: Hotlines 1166 / 100]
        S1_SensCheck -->|Allow / Benign| S1_Pass[Pass Sanitized Input]
    end

    BlockMalformed --> AuditLog[(Cryptographic Audit Log)]
    BlockInj --> AuditLog
    BlockSens --> AuditLog
    RouteCrisis --> User
    
    S1_Pass -->|Sanitized Input + RAG Context| ModelCore[AI Reasoning & LLM Core\n+ Secret Canary Token Directive]
    ModelCore -->|Raw Generated Response| STAGE_2

    subgraph STAGE_2 ["Stage 2: Output Guardrails Pipeline"]
        S2_Schema[1. Output Schema Validator]
        S2_Schema -->|JSON Extraction & Conformance| S2_SchemaCheck{Schema Valid?}
        S2_SchemaCheck -->|No| S2_Retry[Generate Corrective Re-prompt / Retry]
        
        S2_SchemaCheck -->|Yes| S2_Sens[2. Sensitive Output Detector]
        S2_Sens -->|Check Canary Leak, PII, Secrets| S2_SensCheck{Confidential Leak?}
        S2_SensCheck -->|Canary Leaked| S2_Refuse[Refusal: Confidential Security Breach]
        S2_SensCheck -->|PII / Secret Leaked| S2_Redact[Auto-Redact Leaked Tokens]
        S2_SensCheck -->|Clean| S2_Ground[3. Groundedness Checker]
        
        S2_Redact --> S2_Ground
        S2_Ground -->|Claim Extraction vs Source Reference| S2_GroundCheck{Score >= 0.85 Threshold?}
        S2_GroundCheck -->|No: Hallucination| S2_Fallback[Intercept: Return Safe Legal Fallback]
        S2_GroundCheck -->|Yes: Grounded| S2_Pass[Pass Verified Response]
    end

    S2_Retry --> AuditLog
    S2_Refuse --> AuditLog
    S2_Fallback --> AuditLog
    S2_Pass --> AuditLog
    AuditLog --> FinalResp([Deliver Final Protected Response to User])
```

---

## 2. Component Interaction & Lifecycle Sequence

```mermaid
sequenceDiagram
    autonumber
    actor User as Client / User
    participant IP as Input Pipeline
    participant AL as Audit Logger (SHA-256)
    participant LLM as Model / Generation Core
    participant OP as Output Pipeline

    User->>IP: Submit Query (e.g., Legal Dispute Question + PII)
    IP->>IP: Step 1: InputValidator (Strip zero-width, NFKC, homoglyphs)
    IP->>IP: Step 2: InjectionDetector (Scan 35+ patterns, commands, heuristics)
    IP->>IP: Step 3: PIIDetector (Identify & Redact Citizen ID / Email / Phone)
    IP->>IP: Step 4: SensitiveTopicClassifier (Classify weapons, crisis, fraud)
    
    alt Input Threat Detected (Injection / Prohibited Category)
        IP->>AL: Log Security Event (Blocked, Risk Score, Latency)
        IP-->>User: Refusal / Safe Crisis Hotline
    else Input Sanitized & Approved
        IP->>AL: Log Input Approved (Sanitized Text, Latency)
        IP->>LLM: Pass Sanitized Prompt + Reference Context + System Canary
        LLM-->>OP: Raw Generated Response
        
        OP->>OP: Step 1: OutputSchemaValidator (JSON syntax, types, ranges)
        alt Schema Invalid
            OP->>AL: Log Schema Violation
            OP-->>User: Re-prompt / Formatting Error
        else Schema Valid
            OP->>OP: Step 2: SensitiveOutputDetector (Scan unredacted PII / Canary)
            opt PII / Secrets Found
                OP->>OP: Auto-redact leaked tokens
            end
            OP->>OP: Step 3: GroundednessChecker (Extract claims, compare with context)
            alt Groundedness Score < 0.85 (Hallucination Detected)
                OP->>AL: Log Hallucination Failure
                OP-->>User: Safe Certified Legal Fallback Notice
            else Groundedness Verified
                OP->>AL: Log Output Approved (Score, Latency)
                OP-->>User: Structured, Verified Legal Advice JSON
            end
        end
    end
```

---

## 3. Defense Stages & Control Points

### Stage 1: Input Guardrail Controls
| Control Point | Detection Mechanism | Action on Flag | Architectural Rationale |
| :--- | :--- | :--- | :--- |
| **Input Validator** | Unicode NFKC, zero-width stripping, Cyrillic/Greek homoglyph map | Rejects malformed / null bytes; normalizes clean text | Prevents encoding-based bypasses from evading subsequent regex and NLP detectors |
| **Prompt Injection Detector** | 35+ compiled patterns (Direct override, DAN mode, Prompt extraction, Impersonation, Context delimiters) + Shannon entropy | Immediate hard block (`block_injection`) | Prevents malicious user control over system instructions, tool execution, or confidential leaks |
| **PII Detector & Vault** | Multi-entity regex for emails, phone numbers (+977 / US / Intl), citizenship numbers, PAN, SSN, passports | In-place Redaction, Masking, or Tokenization | Protects user privacy before data leaves the trust boundary; complies with Privacy Acts |
| **Sensitive Topic Classifier** | Keyword and pattern matching across 6 critical safety categories | `hard_block` for prohibited harms; `safe_response` for self-harm/crisis | Enforces strict public safety; routes individuals in distress to certified emergency helplines (1166) |

### Stage 2: Output Guardrail Controls
| Control Point | Detection Mechanism | Action on Flag | Architectural Rationale |
| :--- | :--- | :--- | :--- |
| **Schema Validator** | Markdown fence stripping, JSON parsing, field type & range checking | Corrective re-prompt generation / Regeneration | Protects downstream UI and API consumers from crash bugs caused by malformed or non-JSON output |
| **Sensitive Output Detector** | Secondary PII scan, secret/API key scanner, system canary token monitor | In-place redaction for PII; Immediate refusal if canary leaks | Defense-in-depth: prevents model memorization leakage and verifies system prompt confidentiality |
| **Groundedness Checker** | Atomic claim extraction, n-gram overlap, entity preservation against source context | Substitution with verified Safe Fallback response | Prevents dangerous legal hallucinations, fabricated case citations, or non-existent statutory sections |

---

## 4. Cryptographic Audit Log Architecture

The system maintains a tamper-evident audit record in `logs/guardrails_audit.jsonl` using **SHA-256 hash chaining**:

```mermaid
graph LR
    subgraph Record_1 ["Record N-1"]
        H1["Hash: e3b0c442..."]
    end
    subgraph Record_2 ["Record N"]
        P2["prev_hash: e3b0c442..."] --> Data2["Metadata + Decision + Latency"] --> H2["Hash: 7a8f102c..."]
    end
    subgraph Record_3 ["Record N+1"]
        P3["prev_hash: 7a8f102c..."] --> Data3["Metadata + Decision + Latency"] --> H3["Hash: 9b2e55d1..."]
    end
    H1 --> P2
    H2 --> P3
```

- Any post-hoc modification or record deletion breaks the cryptographic chain immediately.
- The `AuditLogger.verify_integrity()` utility traverses the log and guarantees audit validity.
