# Automated Security Testing & Risk Assessment of an Exam Verification System

[![Python 3.11](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com)
[![Security Testing](https://img.shields.io/badge/Security-STRIDE%20%7C%20SAST%20%7C%20DAST%20%7C%20Fuzzing-red.svg)]()
[![Risk Scoring](https://img.shields.io/badge/Risk%20Framework-CVSS%20v3.1-orange.svg)]()
[![CI Pipeline](https://img.shields.io/badge/DevSecOps-GitHub%20Actions-green.svg)]()

> **Master's Thesis Portfolio Project (Focus: Software Quality, Security Testing & Risk Assessment)**  
> This repository presents a systematic, end-to-end security testing and quantitative risk assessment methodology executed against a realistic, cloud-ready **Exam Verification & Integrity Backend**. Rather than relying on simple scanner reports, this research evaluates design-time threat modeling, comparative detection efficacy across testing paradigms, empirical load/DoS degradation, and CVSS v3.1 risk prioritization.

---

## Table of Contents
1. [System Architecture & Scope](#1-system-architecture--scope)
2. [Testing & Assessment Methodology](#2-testing--assessment-methodology)
3. [Design-Time Threat Model (STRIDE)](#3-design-time-threat-model-stride)
4. [Static Analysis (SAST & SCA)](#4-static-analysis-sast--sca)
5. [Dynamic Testing, Fuzzing & Manual DAST](#5-dynamic-testing-fuzzing--manual-dast)
6. [Comparative Detection Matrix (Key Empirical Data)](#6-comparative-detection-matrix-key-empirical-data)
7. [Load Testing & Denial-of-Service (DoS) Analysis](#7-load-testing--denial-of-service-dos-analysis)
8. [Central Risk Register & CVSS v3.1 Prioritization](#8-central-risk-register--cvss-v31-prioritization)
9. [Remediation & Automated Regression Testing](#9-remediation--automated-regression-testing)
10. [DevSecOps "Shift-Left" CI Pipeline](#10-devsecops-shift-left-ci-pipeline)
11. [Threats to Validity & Limitations](#11-threats-to-validity--limitations)
12. [Reproducibility & Execution Guide](#12-reproducibility--execution-guide)

---

## 1. System Architecture & Scope

The target application is a high-assurance **Exam Verification & Submission Platform** built with **FastAPI** and **SQLAlchemy**:
- **Authentication & RBAC:** Role-based access control (`student`, `invigilator`, `admin`) utilizing JWT tokens and bcrypt password hashing.
- **Biometric Identity Pre-Check:** Candidate identity verification simulation prior to exam room entry.
- **Integrity-Validated Submission:** Multipart file upload enforcing SHA-256 cryptographic checksum matching.
- **Confidential Result Distribution:** Exam grading and result retrieval with row-level ownership protections.

```mermaid
flowchart TD
    subgraph Client Tier [Untrusted Network Boundary]
        Student["Candidate / Student Client"]
        Invigilator["Invigilator / Examiner Client"]
    end

    subgraph API Tier [FastAPI Core Services]
        Auth["Auth & JWT Issuer (/api/auth)"]
        Verify["Identity Verifier (/api/sessions)"]
        Submit["Submission & Hash Validator (/api/submissions)"]
        Results["Result Engine & Search (/api/results)"]
    end

    subgraph Data Tier [Storage & File System Boundaries]
        DB[("Relational Database\nUsers, Sessions, Results")]
        FS[("Secure File Storage\n/uploads (UUID Protected)")]
        BioMock["Mock Biometric Verification Engine"]
    end

    Student -->|JWT Auth, Biometric Scan, Exam Upload| API Tier
    Invigilator -->|Session Controls, Grading, Queries| API Tier
    Auth <--> DB
    Verify <--> BioMock
    Verify <--> DB
    Submit <--> DB
    Submit --> FS
    Results <--> DB
```

---

## 2. Testing & Assessment Methodology

The security evaluation follows a rigorous 8-stage engineering pipeline:

```
┌─────────────────┐     ┌──────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│ 1. STRIDE Model │ ──► │ 2. Static (SAST) │ ──► │ 3. Dynamic/Fuzz  │ ──► │ 4. Load Testing │
│  (Design-Time)  │     │ (Bandit/Semgrep) │     │ (Schemathesis)   │     │ (Locust DoS)    │
└─────────────────┘     └──────────────────┘     └──────────────────┘     └─────────────────┘
                                                                                   │
┌─────────────────┐     ┌──────────────────┐     ┌──────────────────┐              ▼
│  8. DevSecOps   │ ◄── │ 7. Regression    │ ◄── │ 6. Remediation   │ ◄── ┌─────────────────┐
│   (CI Pipeline) │     │  Verification    │     │   (P0/P1 Fixes)  │     │ 5. CVSS Risk    │
└─────────────────┘     └──────────────────┘     └──────────────────┘     │    Register     │
                                                                          └─────────────────┘
```

---

## 3. Design-Time Threat Model (STRIDE)

Before executing automated scanners, a formal **STRIDE threat analysis** was performed across all Data Flow Diagram (DFD) elements:
- Full Document: [`THREAT_MODEL_STRIDE.md`](THREAT_MODEL_STRIDE.md)
- Identified 8 core architectural threats: **IDOR** in result retrieval, **SQL Injection** in search filters, **Path Traversal** during submission, **Weak JWT Secrets**, and **Authentication Brute-Forcing/User Enumeration**.

---

## 4. Static Analysis (SAST & SCA)

- Full Document: [`STATIC_ANALYSIS_REPORT.md`](STATIC_ANALYSIS_REPORT.md)
- **Tools Executed:**
  - **Bandit v1.8.6:** AST python security scanner (detected SQL string formatting `B608` and interface bind `B104`).
  - **Semgrep v1.136.0:** Semantic rule engine with `p/owasp-top-ten` (detected SQL injection via `text()` and Permissive Wildcard CORS).
  - **pip-audit v2.9.0:** Supply chain vulnerability scanner (detected 38 transitive package advisories).

---

## 5. Dynamic Testing, Fuzzing & Manual DAST

- Full Document: [`DYNAMIC_AND_FUZZ_TESTING_REPORT.md`](DYNAMIC_AND_FUZZ_TESTING_REPORT.md)
- **Schemathesis OpenAPI Fuzzing:** Uncovered unhandled `OSError [Errno 63]` worker crashes on excessively long filenames (DoS vector).
- **OWASP Testing Guide Manual Verification:** Successfully exploited and verified IDOR (cross-student data leak), SQLi boolean injection (`' OR '1'='1`), Path Traversal (`../../`), and JWT signature forgery.

---

## 6. Comparative Detection Matrix (Key Empirical Data)

A primary academic finding is analyzing **what each security testing paradigm catches versus where it exhibits blindspots**:

| Vulnerability / Security Finding | STRIDE Category | OWASP Category | Static (SAST) | Fuzzing (Schemathesis) | Manual DAST | Primary Detection Paradigm |
|---|---|---|:---:|:---:|:---:|---|
| **SEC-01: Weak JWT Fallback Secret** | Spoofing / Privilege Escalation | A02: Cryptographic Failures | Missed | Missed | **Caught** | **Manual DAST Only** |
| **SEC-02: SQL Injection in Search** | Injection / Info Disclosure | A03: Injection | **Caught** | **Caught** (500 Fault) | **Caught** | **Multiple Methods** |
| **SEC-03: Path Traversal & Unvalidated File** | Tampering / Privilege Escalation | A04: Insecure Design | Missed | **Caught** (Crash) | **Caught** | **Fuzzing + Manual DAST** |
| **SEC-04: IDOR on Result Endpoint** | Elevation of Privilege / Info Leak | A01: Broken Access Control | Missed | Missed | **Caught** | **Manual DAST Only** |
| **SEC-05: User Enumeration on Login** | Info Disclosure / Denial of Service | A07: Auth & ID Failures | Missed | Missed | **Caught** | **Manual DAST Only** |
| **SEC-06: Wildcard CORS Policy** | Security Misconfiguration | A05: Misconfiguration | **Caught** | Missed | **Caught** | **SAST + DAST** |
| **SEC-07: Unhandled Filename Length (DoS)** | Denial of Service | A04: Insecure Design | Missed | **Caught** (OSError 63) | Missed | **API Schema Fuzzing Only** |
| **SCA-01: Dependency Vulnerabilities** | Outdated Components | A06: Vulnerable Components | **Caught** (pip-audit) | Missed | Missed | **SCA Only** |

### Critical Research Insight:
> **The Authorization Blindspot of SAST:** Static linters analyze syntax patterns, making them **100% blind to IDOR and business logic flaws** (SEC-04 and SEC-05). Fuzzing discovers unhandled boundary crashes, while SAST detects syntactic anti-patterns. **Only a combined STRIDE-guided multi-tier testing strategy achieves full coverage.**

---

## 7. Load Testing & Denial-of-Service (DoS) Analysis

- Full Document: [`LOAD_TESTING_REPORT.md`](LOAD_TESTING_REPORT.md)
- **Tool:** Locust v2.34.0
- **Test Scenarios:**
  - **Scenario A (50 Concurrent Students):** 2,832 total requests at 149.6 RPS. Read endpoints responded with **2ms median latency**; security controls (biometric pre-check) remained **100% intact with zero bypasses**.
  - **Scenario B (200 Concurrent Students - Stress Burst):** Asymmetric resource exhaustion identified. Unthrottled login requests saturated single-worker CPU cores on synchronous bcrypt hashing, driving read latency from 2ms to **890ms (445x degradation)**.

---

## 8. Central Risk Register & CVSS v3.1 Prioritization

- Full Document: [`RISK_REGISTER.md`](RISK_REGISTER.md)

| Rank | Finding ID | Vulnerability Title | CVSS v3.1 Vector String | Score | Severity | Priority | Remediation Effort |
|:---:|---|---|---|:---:|:---:|:---:|:---:|
| **1** | **SEC-01** | **Static / Hardcoded JWT Secret Key** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8** | **CRITICAL** | **P0** | **S** (< 1 hr) |
| **2** | **SEC-02** | **SQL Injection in Result Search Query** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | **8.8** | **HIGH** | **P0** | **S** (< 2 hrs) |
| **3** | **SEC-03** | **Path Traversal & Unvalidated File Upload** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H` | **8.1** | **HIGH** | **P0** | **M** (2-4 hrs) |
| **4** | **SEC-04** | **Insecure Direct Object Reference (IDOR)** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | **6.5** | **MEDIUM** | **P1** | **S** (< 1 hr) |
| **5** | **SEC-05** | **Missing Rate Limiting & User Enumeration** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L` | **6.5** | **MEDIUM** | **P2** | **M** (2-3 hrs) |
| **6** | **SEC-06** | **Permissive CORS Wildcard Policy (`*`)** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` | **5.4** | **MEDIUM** | **P2** | **S** (< 1 hr) |
| **7** | **SEC-07** | **Unhandled Filename Length OS Error** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L` | **4.3** | **LOW** | **P3** | **S** (< 1 hr) |

---

## 9. Remediation & Automated Regression Testing

- Full Document: [`REMEDIATION_AND_VERIFICATION_REPORT.md`](REMEDIATION_AND_VERIFICATION_REPORT.md)
- **Remediations Implemented:**
  - Parameterized ORM queries (`User.username.ilike`) eliminating SQLi.
  - Row-level owner validation checks eliminating IDOR.
  - Extension whitelisting (`.pdf`, `.zip`, `.txt`, `.docx`), basename traversal stripping, and random UUID storage.
  - Cryptographically secure dynamic random JWT secret generation.
  - Generic authentication error messages (`"Invalid username or password"`).
  - Explicit CORS whitelist (`settings.ALLOWED_ORIGINS`).
- **Post-Fix Verification:** **14/14 automated regression and functional tests passed**, and Semgrep reported **0 blocking findings**.

---

## 10. DevSecOps "Shift-Left" CI Pipeline

- Full Document: [`DEVSECOPS_CI_PIPELINE.md`](DEVSECOPS_CI_PIPELINE.md)
- Configuration: [`.github/workflows/security-ci.yml`](.github/workflows/security-ci.yml)
- **Automated CI Gates:**
  1. Unit, Fuzzing & Security Regression Tests (`pytest`)
  2. AST Security Linting (`bandit -r app/ -ll`)
  3. Semantic OWASP Top 10 Audit (`semgrep scan --error`)
  4. Software Supply Chain Audit (`pip-audit`)

---

## 11. Threats to Validity & Limitations

To maintain academic rigor and transparency, the following experimental limitations are documented:
1. **Construct Validity (Planted Vulnerability Scope):** While the planted vulnerabilities model standard OWASP Top 10 flaws (IDOR, SQLi, Traversal, Weak Crypto, Auth Enumeration), real-world legacy codebases may feature nuanced multi-tier race conditions and zero-day dependency exploits not fully captured in isolated micro-benchmarks.
2. **Internal Validity (Reviewer Bias Mitigation):** The author designed both the target application and the test suite. To mitigate observer bias, the design-time threat model (Phase 2) was frozen prior to running static or dynamic tools, and automated fuzzing (Schemathesis) was driven autonomously by the OpenAPI schema.
3. **External Validity (Local Test Environment vs Production Scale):** Load testing was conducted on a local macOS environment using simulated worker loops. Production environments behind multi-node Kubernetes clusters, ingress load balancers, and external managed PostgreSQL databases will experience distinct network queue dynamics and distributed connection pool bottlenecks.

---

## 12. Reproducibility & Execution Guide

### Local Environment Setup
```bash
# 1. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt
pip install bandit semgrep pip-audit schemathesis locust pytest

# 3. Run complete functional, fuzzing & regression test suite (14 tests)
pytest -v

# 4. Run SAST scanners
bandit -r app/
semgrep scan --config auto --config p/owasp-top-ten app/
pip-audit

# 5. Start Application Server
uvicorn app.main:app --reload --port 8000
```

### Docker Execution
```bash
docker compose up --build
```
The interactive Swagger API documentation will be available at `http://localhost:8000/docs`.
