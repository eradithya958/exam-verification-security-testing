# Risk Assessment Framework & Central Risk Register

**Target System:** Exam Verification & Integrity System  
**Phase:** Phase 6 (Quantitative Risk Modeling & Prioritization Framework)  
**Standard Utilized:** First.org Common Vulnerability Scoring System (CVSS v3.1) & OWASP Risk Rating Methodology

---

## 1. Risk Scoring Methodology Justification

To provide a defensible, repeatable risk prioritization strategy tailored for enterprise evaluation (e.g. Ericsson testing and product quality standards), we adopt the **CVSS v3.1 Quantitative Framework** augmented with **Business Context Weighting**:

$$\text{Final Risk Priority} = f(\text{CVSS Base Score}, \text{Asset Sensitivity / Impact}, \text{Exploitation Complexity}, \text{Remediation Dependencies})$$

### Why CVSS v3.1 over DREAD or Qualitative Gut Feel:
1. **Industry Standard Alignment:** CVSS v3.1 provides standardized metric vectors (`AV`, `AC`, `PR`, `UI`, `S`, `C`, `I`, `A`) that remove subjective bias.
2. **Defensible Granularity:** Vector strings allow stakeholders to audit the exact assumptions made regarding attacker prerequisites (e.g. `PR:N` vs `PR:L`).
3. **Multi-Dimensional Impact Analysis:** Disaggregates impact into Confidentiality ($C$), Integrity ($I$), and Availability ($A$), which is crucial for academic exam systems where Integrity and Confidentiality carry catastrophic reputational liability.

---

## 2. Quantitative CVSS v3.1 Scoring & Metric Breakdown

| Finding ID | Finding Title | CVSS v3.1 Vector String | Base Score | Severity Rating |
|---|---|---|:---:|:---:|
| **SEC-01** | Static / Hardcoded JWT Fallback Secret Key | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8** | **CRITICAL** |
| **SEC-02** | SQL Injection in Result Search Query | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | **8.8** | **HIGH** |
| **SEC-03** | Path Traversal & Unvalidated File Upload | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H` | **8.1** | **HIGH** |
| **SEC-04** | Insecure Direct Object Reference (IDOR) on Results | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | **6.5** | **MEDIUM** *(High Business Impact)* |
| **SEC-05** | Missing Rate Limiting & User Enumeration on Login | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L` | **6.5** | **MEDIUM** |
| **SEC-06** | Permissive Wildcard CORS Configuration (`*`) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` | **5.4** | **MEDIUM** |
| **SEC-07** | Unhandled Long Filename OS Exception (Fuzzing DoS) | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L` | **4.3** | **LOW** |

---

## 3. Central Risk Register & Prioritized Remediation Action Plan

This table is the centerpiece risk artifact combining threat modeling, multi-method detection, quantitative risk scoring, and engineering remediation estimates.

| Rank | Finding ID | Vulnerability Title | STRIDE Category | OWASP Top 10 | Detection Method | CVSS 3.1 Vector | Score / Severity | Priority | Recommended Remediation | Fix Effort (S/M/L) |
|:---:|---|---|---|---|---|---|:---:|:---:|---|:---:|
| **1** | **SEC-01** | **Hardcoded Weak JWT Secret Key** | Spoofing / Elevation of Privilege | A02: Cryptographic Failures | Manual DAST / Audit | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8 (Critical)** | **P0 (Immediate)** | Enforce runtime validation: require high-entropy `SECRET_KEY` from environment; refuse startup in production if default key is present. | **S** (< 1 hr) |
| **2** | **SEC-02** | **SQL Injection in Result Search** | Injection / Info Disclosure | A03: Injection | Static (Semgrep/Bandit) + DAST | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | **8.8 (High)** | **P0 (Immediate)** | Eliminate raw `text(f"...")` SQL queries. Migrate to parameterized SQLAlchemy ORM filters (`User.username.ilike(...)`). | **S** (< 2 hrs) |
| **3** | **SEC-03** | **Path Traversal & Unrestricted File Upload** | Tampering / Elevation of Privilege | A04: Insecure Design | Fuzzing + Manual DAST | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H` | **8.1 (High)** | **P0 (Immediate)** | Sanitize filenames via `os.path.basename`, enforce strict MIME-type / `.pdf` whitelist, and store files under random UUID filenames. | **M** (2-4 hrs) |
| **4** | **SEC-04** | **Insecure Direct Object Reference (IDOR)** | Elevation of Privilege / Info Disclosure | A01: Broken Access Control | Manual DAST Only | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | **6.5 (Medium)** | **P1 (High)** | Implement strict row-level authorization check: verify `result.student_id == current_user.id` or user is an authorized session invigilator. | **S** (< 1 hr) |
| **5** | **SEC-05** | **Missing Rate Limiting & User Enumeration** | Denial of Service / Info Disclosure | A07: Identification & Auth Failures | Load Testing + Manual DAST | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L` | **6.5 (Medium)** | **P2 (Medium)** | Unify login error message to `"Invalid username or password"`. Add rate-limiting middleware (e.g. `slowapi`) to throttle auth attempts. | **M** (2-3 hrs) |
| **6** | **SEC-06** | **Permissive CORS Wildcard (`*`)** | Security Misconfiguration | A05: Security Misconfiguration | Static (Semgrep) + DAST | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` | **5.4 (Medium)** | **P2 (Medium)** | Restrict `allow_origins` to explicit university frontend domains; reject wildcard origin reflection when credentials are used. | **S** (< 1 hr) |
| **7** | **SEC-07** | **Unhandled Filename Length Exception** | Denial of Service | A04: Insecure Design | Schemathesis Fuzzing | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L` | **4.3 (Low)** | **P3 (Low)** | Validate `file.filename` length in Pydantic schema or upload handler and return structured HTTP 422/400. | **S** (< 1 hr) |

---

## 4. Prioritization Matrix (Risk vs. Effort / Complexity)

```
        High Impact / Risk ▲
                           │
                           │  [SEC-01: JWT Secret]      [SEC-03: Path Traversal]
                           │  [SEC-02: SQL Injection]   
                           │  [SEC-04: IDOR Results]    [SEC-05: Rate Limiting]
                           │
                           │  [SEC-06: CORS Policy]     
                           │  [SEC-07: Filename Length] 
                           │
                           └────────────────────────────────────────► Fix Effort / Complexity
                             Small (S: < 2 hrs)         Medium / Large (M/L)
```

### Strategic Remediation Decision:
- **Phase 7 Target Selection:** We will immediately remediate the top 4 highest-priority findings:
  1. **SEC-01 (JWT Secret Key Validation & Hardening)**
  2. **SEC-02 (SQL Injection Parameterization)**
  3. **SEC-03 (Path Traversal Sanitization & UUID Storage)**
  4. **SEC-04 (IDOR Authorization Enforcement)**
  5. **SEC-05 (Generic Auth Messaging & Error Handling)**
- For each remediation, we will add automated regression tests to prevent regressions in continuous integration.
