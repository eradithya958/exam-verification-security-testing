# Planted Vulnerabilities (Confidential Assessment Key)

> **NOTICE**: This document is intended for evaluation and ground-truth comparison after Phase 4 / Phase 6. 
> Do not review during threat modeling or initial black-box test design to preserve test validity.

---

### Summary Table of Planted Flaws

| ID | Vulnerability Title | Affected Component / Endpoint | OWASP Top 10 | STRIDE Category | Mechanism / Root Cause |
|---|---|---|---|---|---|
| **VULN-01** | Insecure Direct Object Reference (IDOR) | `GET /api/results/{result_id}` | A01:2021 - Broken Access Control | Information Disclosure / Elevation of Privilege | No authorization check matching `current_user.id` or invigilator role against `result.student_id`. Any student can read any other student's exam score and feedback by guessing/incrementing ID. |
| **VULN-02** | SQL Injection via Dynamic Search Query | `GET /api/results/search/query` | A03:2021 - Injection | Information Disclosure / Tampering | Raw string concatenation (`f"... LIKE '%{query}%'"`) passed directly to SQLAlchemy `db.execute(text(...))` instead of bind parameters. Allows arbitrary SQL query injection (`' UNION SELECT ...`). |
| **VULN-03** | Insecure File Upload & Path Traversal | `POST /api/submissions/upload` | A04:2021 - Insecure Design / A08: Software and Data Integrity Failures | Tampering / Elevation of Privilege | Backend uses raw `file.filename` directly in `os.path.join(UPLOAD_DIR, file.filename)` without extension allowlisting or `os.path.basename` path sanitization. Allows arbitrary file overwrite via `../../`. |
| **VULN-04** | Hardcoded / Weak JWT Secret Key | `app/config.py` & `app/security.py` | A02:2021 - Cryptographic Failures / A07: Identification and Authentication Failures | Spoofing / Elevation of Privilege | Default fallback secret is static and low-entropy (`"secret-exam-key-2024-insecure"`). Vulnerable to dictionary brute-forcing via tools like hashcat/jwt-cracker to forge administrative JWT tokens. |
| **VULN-05** | Missing Rate Limiting & User Enumeration | `POST /api/auth/login` | A07:2021 - Identification and Authentication Failures | Denial of Service / Information Disclosure | Login endpoint returns differential error responses (`404 User not found` vs `401 Incorrect password`) and implements no request throttling or rate limiting, enabling brute-force and credential stuffing. |

---

### Technical Details & Code Snippets

#### 1. IDOR in Result Retrieval (`app/routers/results.py`)
```python
@router.get("/{result_id}", response_model=ResultResponse)
def get_result_by_id(result_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = db.query(ExamResult).filter(ExamResult.id == result_id).first()
    # Missing: if current_user.role == "student" and result.student_id != current_user.id: raise 403
    return result
```

#### 2. SQL Injection in Search (`app/routers/results.py`)
```python
raw_query = f"""
    SELECT r.id, r.score, r.grade, r.integrity_status, u.username, u.full_name, s.course_code
    FROM exam_results r
    JOIN users u ON r.student_id = u.id
    JOIN exam_sessions s ON r.session_id = s.id
    WHERE u.username LIKE '%{query}%' OR u.full_name LIKE '%{query}%'
"""
cursor = db.execute(text(raw_query))
```

#### 3. Path Traversal & Unrestricted File Upload (`app/routers/submissions.py`)
```python
os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
saved_path = os.path.join(settings.UPLOAD_DIR, file.filename)
with open(saved_path, "wb") as f:
    f.write(content)
```

#### 4. Hardcoded Weak Secret (`app/config.py`)
```python
SECRET_KEY: str = os.getenv("SECRET_KEY", "secret-exam-key-2024-insecure")
```

#### 5. User Enumeration in Login (`app/routers/auth.py`)
```python
user = db.query(User).filter(User.username == login_data.username).first()
if not user:
    raise HTTPException(status_code=404, detail="User not found")
if not verify_password(login_data.password, user.hashed_password):
    raise HTTPException(status_code=401, detail="Incorrect password")
```
