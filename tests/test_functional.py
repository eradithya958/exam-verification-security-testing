import hashlib
import io
from datetime import datetime, timedelta

def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_user_registration_and_login(client):
    # Register student
    reg_response = client.post(
        "/api/auth/register",
        json={
            "username": "charlie_student",
            "email": "charlie@university.edu",
            "password": "SecurePassword123!",
            "full_name": "Charlie Davis",
            "role": "student",
            "student_id": "STU1003"
        }
    )
    assert reg_response.status_code == 201
    data = reg_response.json()
    assert data["username"] == "charlie_student"
    assert data["role"] == "student"

    # Login
    login_response = client.post(
        "/api/auth/login",
        json={"username": "charlie_student", "password": "SecurePassword123!"}
    )
    assert login_response.status_code == 200
    token_data = login_response.json()
    assert "access_token" in token_data
    assert token_data["role"] == "student"

def test_duplicate_registration_fails(client):
    user_payload = {
        "username": "duplicate_user",
        "email": "dup@university.edu",
        "password": "Password123!",
        "full_name": "Duplicate User",
        "role": "student"
    }
    res1 = client.post("/api/auth/register", json=user_payload)
    assert res1.status_code == 201

    res2 = client.post("/api/auth/register", json=user_payload)
    assert res2.status_code == 400
    assert "already registered" in res2.json()["detail"]

def test_exam_session_lifecycle(client, invigilator_auth_header, student_auth_header):
    # Invigilator creates session
    start_time = datetime.utcnow().isoformat()
    end_time = (datetime.utcnow() + timedelta(hours=3)).isoformat()
    
    session_payload = {
        "title": "Software Security Exam Final",
        "course_code": "CS-801",
        "start_time": start_time,
        "end_time": end_time
    }
    create_res = client.post(
        "/api/sessions/",
        json=session_payload,
        headers=invigilator_auth_header
    )
    assert create_res.status_code == 201
    session_id = create_res.json()["id"]

    # Student cannot create session (Forbidden)
    stu_create_res = client.post(
        "/api/sessions/",
        json=session_payload,
        headers=student_auth_header
    )
    assert stu_create_res.status_code == 403

    # List active sessions
    list_res = client.get("/api/sessions/", headers=student_auth_header)
    assert list_res.status_code == 200
    assert any(s["id"] == session_id for s in list_res.json())

def test_identity_verification_and_submission_flow(client, invigilator_auth_header, student_auth_header):
    # 1. Create Session
    start_time = datetime.utcnow().isoformat()
    end_time = (datetime.utcnow() + timedelta(hours=2)).isoformat()
    session_res = client.post(
        "/api/sessions/",
        json={
            "title": "Distributed Systems Exam",
            "course_code": "CS-601",
            "start_time": start_time,
            "end_time": end_time
        },
        headers=invigilator_auth_header
    )
    session_id = session_res.json()["id"]

    # 2. Attempt submission BEFORE identity verification -> should fail
    test_file_content = b"Answer 1: Distributed consensus via Raft algorithm..."
    file_hash = hashlib.sha256(test_file_content).hexdigest()
    
    premature_upload = client.post(
        "/api/submissions/upload",
        data={"session_id": session_id, "provided_hash": file_hash},
        files={"file": ("exam_solution.pdf", io.BytesIO(test_file_content), "application/pdf")},
        headers=student_auth_header
    )
    assert premature_upload.status_code == 403
    assert "biometric verification" in premature_upload.json()["detail"]

    # 3. Perform Biometric Verification
    verify_res = client.post(
        f"/api/sessions/{session_id}/verify-identity",
        json={"session_id": session_id, "biometric_data": "valid_biometric_face_scan_token_data"},
        headers=student_auth_header
    )
    assert verify_res.status_code == 200
    assert verify_res.json()["verification_status"] == "VERIFIED"

    # 4. Attempt submission with wrong hash -> should fail
    bad_hash_upload = client.post(
        "/api/submissions/upload",
        data={"session_id": session_id, "provided_hash": "badhash1234567890abcdef"},
        files={"file": ("exam_solution.pdf", io.BytesIO(test_file_content), "application/pdf")},
        headers=student_auth_header
    )
    assert bad_hash_upload.status_code == 400
    assert "Integrity check failed" in bad_hash_upload.json()["detail"]

    # 5. Successful submission with valid hash
    upload_res = client.post(
        "/api/submissions/upload",
        data={"session_id": session_id, "provided_hash": file_hash},
        files={"file": ("exam_solution.pdf", io.BytesIO(test_file_content), "application/pdf")},
        headers=student_auth_header
    )
    assert upload_res.status_code == 201
    submission_id = upload_res.json()["id"]
    assert upload_res.json()["file_hash"] == file_hash

    # 6. Invigilator grades the submission
    student_id = upload_res.json()["student_id"]
    grade_res = client.post(
        "/api/results/",
        json={
            "submission_id": submission_id,
            "session_id": session_id,
            "student_id": student_id,
            "score": 92.5,
            "grade": "A",
            "integrity_status": "VERIFIED",
            "feedback": "Excellent reasoning on consensus failure modes."
        },
        headers=invigilator_auth_header
    )
    assert grade_res.status_code == 201
    result_id = grade_res.json()["id"]

    # 7. Student checks their results via authorized endpoint
    my_results_res = client.get("/api/results/student/me", headers=student_auth_header)
    assert my_results_res.status_code == 200
    assert len(my_results_res.json()) >= 1
    assert my_results_res.json()[0]["score"] == 92.5

def test_biometric_rejection_on_spoofed_data(client, invigilator_auth_header, student_auth_header):
    # Create Session
    start_time = datetime.utcnow().isoformat()
    end_time = (datetime.utcnow() + timedelta(hours=2)).isoformat()
    session_res = client.post(
        "/api/sessions/",
        json={
            "title": "Network Security Exam",
            "course_code": "CS-701",
            "start_time": start_time,
            "end_time": end_time
        },
        headers=invigilator_auth_header
    )
    session_id = session_res.json()["id"]

    # Attempt verification with spoofed biometric signature
    reject_res = client.post(
        f"/api/sessions/{session_id}/verify-identity",
        json={"session_id": session_id, "biometric_data": "spoofed_biometric_attack_frame"},
        headers=student_auth_header
    )
    assert reject_res.status_code == 403
    assert "verification failed" in reject_res.json()["detail"]

def test_invigilator_session_oversight_and_search(client, invigilator_auth_header, student_auth_header):
    # 1. Create Session
    start_time = datetime.utcnow().isoformat()
    end_time = (datetime.utcnow() + timedelta(hours=2)).isoformat()
    session_res = client.post(
        "/api/sessions/",
        json={
            "title": "Cloud Architecture Exam",
            "course_code": "CS-901",
            "start_time": start_time,
            "end_time": end_time
        },
        headers=invigilator_auth_header
    )
    session_id = session_res.json()["id"]

    # 2. Verify identity
    client.post(
        f"/api/sessions/{session_id}/verify-identity",
        json={"session_id": session_id, "biometric_data": "student_valid_token_303"},
        headers=student_auth_header
    )

    # 3. Invigilator checks verification list
    verifs = client.get(f"/api/sessions/{session_id}/verifications", headers=invigilator_auth_header)
    assert verifs.status_code == 200
    assert len(verifs.json()) == 1

    # 4. Student uploads submission
    content = b"Cloud security exam submission content"
    fhash = hashlib.sha256(content).hexdigest()
    sub_res = client.post(
        "/api/submissions/upload",
        data={"session_id": session_id, "provided_hash": fhash},
        files={"file": ("cloud_submission.pdf", io.BytesIO(content), "application/pdf")},
        headers=student_auth_header
    )
    submission_id = sub_res.json()["id"]
    student_id = sub_res.json()["student_id"]

    # 5. Invigilator views session submissions
    session_subs = client.get(f"/api/submissions/session/{session_id}", headers=invigilator_auth_header)
    assert session_subs.status_code == 200
    assert len(session_subs.json()) == 1

    # 6. Invigilator publishes grade
    client.post(
        "/api/results/",
        json={
            "submission_id": submission_id,
            "session_id": session_id,
            "student_id": student_id,
            "score": 95.0,
            "grade": "A+",
            "integrity_status": "VERIFIED",
            "feedback": "Outstanding work."
        },
        headers=invigilator_auth_header
    )

    # 7. Search results by student username
    search_res = client.get("/api/results/search/query?query=student_alice", headers=invigilator_auth_header)
    assert search_res.status_code == 200
    assert len(search_res.json()) >= 1
    assert search_res.json()[0]["username"] == "student_alice"
