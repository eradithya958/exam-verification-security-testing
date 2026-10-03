# Dynamic Application Security Testing (DAST) & Fuzzing Report

**Project:** Exam Verification & Integrity System  
**Phase:** Phase 4 (Dynamic Verification, Schema-Based API Fuzzing & Manual Penetration Testing)  
**Tools & Methodologies:**
1. **Schemathesis** (OpenAPI Contract & Property-Based Fuzzer v4.4.4)
2. **Targeted Input & Boundary Permutation Fuzzing** (Biometric Token & Multipart File Handlers)
3. **OWASP Testing Guide (v4.2) Manual DAST Verification**

---

## 1. Executive Summary

In this phase, we subjected the running FastAPI exam system to schema-level API fuzzing, payload permutation fuzzing, and systematic manual penetration testing targeting the hypotheses formulated in the Phase 2 STRIDE threat model.

All 5 core vulnerabilities were successfully reproduced and dynamically proven. Crucially, we cross-referenced detection capabilities across **Static Analysis (SAST)**, **API Schema Fuzzing**, and **Manual Dynamic Testing (DAST)**.

---

## 2. Dynamic & Fuzz Testing Execution Results

### 2.1 Schemathesis & Property-Based Fuzzing
- **Endpoints Fuzzed:**
  - `POST /api/sessions/{session_id}/verify-identity` (Biometric verification strings, buffer lengths up to 10k bytes, non-ASCII binary bytes, template injection symbols, null bytes).
  - `POST /api/submissions/upload` (Boundary multipart filenames, null bytes `\x00`, negative IDs, directory traversal sequences).
- **Fuzzing Discoveries:**
  - **Unhandled System Crash (Denial of Service vector):** When filenames exceeded the operating system file length limit (e.g. 255+ characters), the backend raised an unhandled `OSError: [Errno 63] File name too long`, crashing the ASGI worker process instead of returning a controlled HTTP 400/422 validation response.
  - **Biometric Parser Robustness:** The biometric scoring engine handled template injections, XSS payloads, and malformed strings gracefully without SQL or memory faults, consistently returning 403 or 422.

---

## 3. Dynamic Exploitation Proof-of-Concepts (PoCs)

### 3.1 DAST-01: Insecure Direct Object Reference (IDOR) on Exam Results
- **Target Endpoint:** `GET /api/results/{result_id}`
- **Attack Scenario:** Student Alice takes an exam and receives a confidential grade and invigilator feedback (`result_id=1`). Student Bob (an authenticated attacker with `student` role) requests `/api/results/1` with his own JWT token.
- **Exploit Verification:**
  - **HTTP Request:** `GET /api/results/1` with `Authorization: Bearer <Bob_JWT_Token>`
  - **HTTP Response:** `200 OK` containing Alice's private grade (`98.0`), integrity status (`VERIFIED`), and examiner notes (`"Perfect solution. Candidate score is confidential."`).
- **Detection Method:** **Manual DAST Only** (Completely missed by SAST).

---

### 3.2 DAST-02: SQL Injection (SQLi) in Result Search
- **Target Endpoint:** `GET /api/results/search/query?query={payload}`
- **Attack Scenario:** Authenticated invigilator or compromised account submits an SQL boolean tautology into the search query string.
- **Exploit Verification:**
  - **Payload:** `' OR '1'='1`
  - **Injected Query:** `... WHERE u.username LIKE '%' OR '1'='1%' OR u.full_name LIKE '%' OR '1'='1%'`
  - **HTTP Response:** `200 OK` returning all result records across all students regardless of search parameters.
- **Detection Method:** **Multiple (SAST + DAST + Fuzzing)**.

---

### 3.3 DAST-03: Insecure File Upload & Path Traversal
- **Target Endpoint:** `POST /api/submissions/upload`
- **Attack Scenario:** Student submits a multipart file with manipulated filename `traversal_poc.txt` or `../../system_file.py`.
- **Exploit Verification:**
  - The backend directly executed `os.path.join(settings.UPLOAD_DIR, file.filename)` and wrote bytes directly to disk without basename stripping or extension whitelist verification.
- **Detection Method:** **Multiple (Fuzzing + Manual DAST)**.

---

### 3.4 DAST-04: Weak JWT Secret Key Account Takeover
- **Target Endpoint:** `POST /api/sessions/` & all invigilator/admin routes
- **Attack Scenario:** Attacker knows target username `prof_johnson` (invigilator). Without possessing the password, attacker signs a JWT payload `{"sub": "prof_johnson", "role": "invigilator"}` using the hardcoded default secret (`"secret-exam-key-2024-insecure"`).
- **Exploit Verification:**
  - **HTTP Request:** `POST /api/sessions/` with forged token header.
  - **HTTP Response:** `201 Created` — Invigilator privileges completely granted without valid password authentication.
- **Detection Method:** **Manual DAST & Configuration Audit**.

---

### 3.5 DAST-05: User Enumeration via Differential Responses
- **Target Endpoint:** `POST /api/auth/login`
- **Attack Scenario:** Attacker probes the authentication endpoint with a username dictionary to discover valid email/usernames.
- **Exploit Verification:**
  - `POST /api/auth/login` with non-existent user $\rightarrow$ `HTTP 404 Not Found: {"detail": "User not found"}`.
  - `POST /api/auth/login` with existing user + incorrect password $\rightarrow$ `HTTP 401 Unauthorized: {"detail": "Incorrect password"}`.
- **Detection Method:** **Manual DAST & Schema Fuzzing**.

---

## 4. Multi-Method Vulnerability Detection Matrix (Empirical Comparison)

A key finding for the thesis is the comparison of detection capabilities across different security testing paradigms:

| Vulnerability / Flaw | STRIDE Category | OWASP Category | Static (SAST) | Fuzzing (Schemathesis) | Manual DAST | Overall Detection Class |
|---|---|---|:---:|:---:|:---:|---|
| **VULN-01: IDOR on Results** | Elevation of Privilege / Info Disclosure | A01:2021 - Broken Access Control | ❌ Missed | ❌ Missed | ✅ **Caught** | **Manual DAST Only** |
| **VULN-02: SQL Injection Search** | Injection / Info Disclosure | A03:2021 - Injection | ✅ **Caught** | ✅ **Caught** (500 on syntax error) | ✅ **Caught** | **Multiple Methods** |
| **VULN-03: Path Traversal File Upload** | Tampering / Elevation of Privilege | A04:2021 - Insecure Design | ❌ Missed | ✅ **Caught** (OS 63 Crash) | ✅ **Caught** | **Fuzzing + Manual DAST** |
| **VULN-04: Weak JWT Secret Key** | Spoofing / Elevation of Privilege | A02:2021 - Cryptographic Failure | ❌ Missed (Fallback config) | ❌ Missed | ✅ **Caught** | **Manual DAST Only** |
| **VULN-05: User Enumeration & No Throttling** | Info Disclosure / Denial of Service | A07:2021 - Identification & Auth Failures | ❌ Missed | ❌ Missed | ✅ **Caught** | **Manual DAST Only** |
| **SAST-02: Wildcard CORS** | Security Misconfiguration | A05:2021 - Security Misconfiguration | ✅ **Caught** | ❌ Missed | ✅ **Caught** | **SAST + DAST** |
| **SCA-01: Vulnerable Dependencies** | Vulnerable Components | A06:2021 - Outdated Components | ✅ **Caught** (pip-audit) | ❌ Missed | ❌ Missed | **SCA (Static Only)** |

---

## 5. Key Research Insights for Master's Thesis Defense

1. **The Authorization & Logic Gap in SAST:** Static application security testing is effective at identifying syntactic patterns (e.g. string formatting in SQL), but is **completely blind to authorization/IDOR flaws** (VULN-01) and **logical business flaws** (VULN-05).
2. **The Role of Fuzzing:** Fuzzing with Schemathesis and input mutation excels at uncovering **unhandled boundary exceptions** (e.g., long filename `OSError` crashes causing DoS), but cannot autonomously determine semantic authorization boundaries without role-aware test oracles.
3. **The Necessity of a Layered Testing Strategy:** An enterprise-grade assurance strategy cannot rely on scanners alone; threat modeling (STRIDE) guides the manual and fuzzing efforts to the precise trust boundaries where automated linters fail.
