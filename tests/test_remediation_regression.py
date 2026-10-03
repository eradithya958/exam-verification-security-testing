import io
import os
import hashlib
from datetime import datetime, timedelta

def test_regression_idor_is_blocked(client, invigilator_auth_header, student_auth_header, student_bob_auth_header):
    """
    REGRESSION TEST: SEC-04 (IDOR Fix Verification)
    Asserts that Student Bob cannot access Student Alice's result and receives 403 Forbidden.
    """
    # 1. Create Session
    session_res = client.post(
        "/api/sessions/",
        json={"title": "Regression Test Exam", "course_code": "REG-101", "start_time": "2026-10-01T10:00:00", "end_time": "2026-10-01T12:00:00"},
        headers=invigilator_auth_header
    )
    session_id = session_res.json()["id"]

    # 2. Alice verifies & submits
    client.post(
        f"/api/sessions/{session_id}/verify-identity",
        json={"session_id": session_id, "biometric_data": "alice_biometric_sample"},
        headers=student_auth_header
    )
    content = b"Alice private exam response"
    sub_res = client.post(
        "/api/submissions/upload",
        data={"session_id": session_id, "provided_hash": hashlib.sha256(content).hexdigest()},
        files={"file": ("alice_exam.pdf", io.BytesIO(content), "application/pdf")},
        headers=student_auth_header
    )
    alice_sub_id = sub_res.json()["id"]
    alice_student_id = sub_res.json()["student_id"]

    # 3. Invigilator grades Alice
    grade_res = client.post(
        "/api/results/",
        json={
            "submission_id": alice_sub_id,
            "session_id": session_id,
            "student_id": alice_student_id,
            "score": 96.0,
            "grade": "A",
            "integrity_status": "VERIFIED",
            "feedback": "Strictly confidential."
        },
        headers=invigilator_auth_header
    )
    alice_result_id = grade_res.json()["id"]

    # 4. Bob tries to access Alice's result -> Must be blocked with 403 Forbidden
    bob_attempt = client.get(
        f"/api/results/{alice_result_id}",
        headers=student_bob_auth_header
    )
    assert bob_attempt.status_code == 403
    assert "not authorized" in bob_attempt.json()["detail"].lower()

    # 5. Alice CAN access her own result -> 200 OK
    alice_access = client.get(
        f"/api/results/{alice_result_id}",
        headers=student_auth_header
    )
    assert alice_access.status_code == 200
    assert alice_access.json()["score"] == 96.0

    # 6. Invigilator CAN access Alice's result -> 200 OK
    invigilator_access = client.get(
        f"/api/results/{alice_result_id}",
        headers=invigilator_auth_header
    )
    assert invigilator_access.status_code == 200


def test_regression_sql_injection_is_neutralized(client, invigilator_auth_header, student_auth_header):
    """
    REGRESSION TEST: SEC-02 (SQL Injection Neutralization Verification)
    Asserts that SQL injection tautology payload (' OR '1'='1) is treated as literal search string.
    """
    # Create Session & submission
    session_res = client.post(
        "/api/sessions/",
        json={"title": "DB Security Exam", "course_code": "SEC-SQL", "start_time": "2026-10-01T10:00:00", "end_time": "2026-10-01T12:00:00"},
        headers=invigilator_auth_header
    )
    session_id = session_res.json()["id"]

    client.post(
        f"/api/sessions/{session_id}/verify-identity",
        json={"session_id": session_id, "biometric_data": "alice_valid_sample"},
        headers=student_auth_header
    )
    content = b"SQL exam submission"
    sub_res = client.post(
        "/api/submissions/upload",
        data={"session_id": session_id, "provided_hash": hashlib.sha256(content).hexdigest()},
        files={"file": ("sql_test.pdf", io.BytesIO(content), "application/pdf")},
        headers=student_auth_header
    )
    client.post(
        "/api/results/",
        json={
            "submission_id": sub_res.json()["id"],
            "session_id": session_id,
            "student_id": sub_res.json()["student_id"],
            "score": 90.0,
            "grade": "A",
            "integrity_status": "VERIFIED"
        },
        headers=invigilator_auth_header
    )

    # Injected query should NOT match standard student "student_alice"
    sqli_attempt = client.get(
        "/api/results/search/query?query=' OR '1'='1",
        headers=invigilator_auth_header
    )
    assert sqli_attempt.status_code == 200
    assert len(sqli_attempt.json()) == 0  # No user is literally named "' OR '1'='1"

    # Legitimate search by partial name works accurately
    legit_search = client.get(
        "/api/results/search/query?query=alice",
        headers=invigilator_auth_header
    )
    assert legit_search.status_code == 200
    assert len(legit_search.json()) >= 1


def test_regression_path_traversal_and_file_whitelist(client, invigilator_auth_header, student_auth_header):
    """
    REGRESSION TEST: SEC-03 (Path Traversal & Extension Whitelisting Verification)
    """
    session_res = client.post(
        "/api/sessions/",
        json={"title": "OS Exam", "course_code": "OS-101", "start_time": "2026-10-01T10:00:00", "end_time": "2026-10-01T12:00:00"},
        headers=invigilator_auth_header
    )
    session_id = session_res.json()["id"]
    client.post(
        f"/api/sessions/{session_id}/verify-identity",
        json={"session_id": session_id, "biometric_data": "alice_valid_sample"},
        headers=student_auth_header
    )

    # 1. Traversal filename is sanitized
    traversal_name = "../../../escaped_name.pdf"
    content = b"PDF exam content"
    res1 = client.post(
        "/api/submissions/upload",
        data={"session_id": session_id, "provided_hash": hashlib.sha256(content).hexdigest()},
        files={"file": (traversal_name, io.BytesIO(content), "application/pdf")},
        headers=student_auth_header
    )
    assert res1.status_code == 201
    assert res1.json()["filename"] == "escaped_name.pdf"

    # 2. Dangerous file extensions (.sh, .exe) are rejected with HTTP 400
    res2 = client.post(
        "/api/submissions/upload",
        data={"session_id": session_id, "provided_hash": hashlib.sha256(content).hexdigest()},
        files={"file": ("exploit.exe", io.BytesIO(b"MZ..."), "application/x-dosexec")},
        headers=student_auth_header
    )
    assert res2.status_code == 400
    assert "Unsupported file type" in res2.json()["detail"]


def test_regression_user_enumeration_is_mitigated(client):
    """
    REGRESSION TEST: SEC-05 (User Enumeration Defense Verification)
    Both invalid user and wrong password must return 401 with identical message.
    """
    # 1. Non-existent user
    res1 = client.post(
        "/api/auth/login",
        json={"username": "ghost_user_999", "password": "AnyPassword!"}
    )
    assert res1.status_code == 401
    assert res1.json()["detail"] == "Invalid username or password"

    # 2. Existing user with wrong password
    client.post(
        "/api/auth/register",
        json={"username": "valid_student", "email": "valid@uni.edu", "password": "Password123!", "full_name": "Valid Student", "role": "student"}
    )
    res2 = client.post(
        "/api/auth/login",
        json={"username": "valid_student", "password": "WrongPassword!"}
    )
    assert res2.status_code == 401
    assert res2.json()["detail"] == "Invalid username or password"
