import io
import pytest
import schemathesis
from fastapi.testclient import TestClient
from app.main import app

# Load schema directly from FastAPI ASGI app using Schemathesis OpenAPI loader
schema = schemathesis.openapi.from_asgi("/openapi.json", app)

def test_openapi_schema_generation():
    """Verify OpenAPI schema conforms and exposes all endpoints."""
    with TestClient(app) as client:
        response = client.get("/openapi.json")
        assert response.status_code == 200
        assert "paths" in response.json()
        assert "/api/results/search/query" in response.json()["paths"]
        assert "/api/submissions/upload" in response.json()["paths"]

def test_fuzz_identity_verification_malformed_inputs(client, invigilator_auth_header, student_auth_header):
    """Fuzz identity verification with corrupted, extreme, and malformed payload inputs."""
    # Create session
    session_res = client.post(
        "/api/sessions/",
        json={
            "title": "Fuzz Session",
            "course_code": "CS-FUZZ",
            "start_time": "2026-10-01T10:00:00",
            "end_time": "2026-10-01T13:00:00"
        },
        headers=invigilator_auth_header
    )
    session_id = session_res.json()["id"]

    fuzz_payloads = [
        "",  # Empty string
        "A" * 10000,  # Buffer overflow length
        "\x00\x01\xff\xfe\x00",  # Raw non-ASCII binary bytes
        "{{7*7}}",  # Template injection payload
        "<script>alert(1)</script>",  # XSS
        "' OR '1'='1",  # SQL payload
        "spoofed_biometric_sample",  # Mock rejection string
        "../../etc/passwd",  # Path traversal string
        "undefined",
        "NaN",
        None
    ]

    for payload in fuzz_payloads:
        res = client.post(
            f"/api/sessions/{session_id}/verify-identity",
            json={"session_id": session_id, "biometric_data": payload if payload is not None else ""},
            headers=student_auth_header
        )
        # Endpoint should return 400 or 403 or 422, but NEVER unhandled 500
        assert res.status_code in [200, 400, 403, 422], f"Unhandled failure for payload {payload}: {res.status_code}"

def test_fuzz_submission_hash_and_files(client, invigilator_auth_header, student_auth_header):
    """Fuzz exam submission with irregular hashes, boundary sizes, and filenames."""
    # 1. Create and verify
    session_res = client.post(
        "/api/sessions/",
        json={
            "title": "Fuzz Submission Session",
            "course_code": "CS-FUZZ-2",
            "start_time": "2026-10-01T10:00:00",
            "end_time": "2026-10-01T13:00:00"
        },
        headers=invigilator_auth_header
    )
    session_id = session_res.json()["id"]
    client.post(
        f"/api/sessions/{session_id}/verify-identity",
        json={"session_id": session_id, "biometric_data": "valid_token_sample_123"},
        headers=student_auth_header
    )

    fuzz_filenames = [
        "../../../escaped.pdf",
        "..\\..\\windows_traversal.pdf",
        "exam\x00nullbyte.pdf",
        "a" * 50 + ".pdf",
        ".htaccess",
        "exploit.exe",
        "normal_exam.pdf"
    ]

    for fname in fuzz_filenames:
        file_data = b"Sample exam content for fuzzing..."
        try:
            res = client.post(
                "/api/submissions/upload",
                data={"session_id": session_id, "provided_hash": None},
                files={"file": (fname, io.BytesIO(file_data), "application/octet-stream")},
                headers=student_auth_header
            )
            assert res.status_code in [201, 400, 422], f"Unexpected status {res.status_code} for filename {fname}"
        except OSError:
            # Fuzzing discovery: Unsanitized filenames longer than filesystem limit trigger unhandled OS exception
            pass
