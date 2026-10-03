import hashlib
import random
import string
from locust import HttpUser, task, between

class ExamSystemUser(HttpUser):
    wait_time = between(0.1, 0.5)

    def on_start(self):
        """Simulate student registration and authentication before taking the exam."""
        rand_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        self.username = f"load_student_{rand_suffix}"
        self.password = "LoadTestPass123!"
        self.student_id = f"STU_{rand_suffix}"
        
        # 1. Register student
        reg_res = self.client.post("/api/auth/register", json={
            "username": self.username,
            "email": f"{self.username}@university.edu",
            "password": self.password,
            "full_name": f"Student {rand_suffix}",
            "role": "student",
            "student_id": self.student_id
        }, name="/api/auth/register")

        # 2. Login student
        login_res = self.client.post("/api/auth/login", json={
            "username": self.username,
            "password": self.password
        }, name="/api/auth/login")

        if login_res.status_code == 200:
            token = login_res.json()["access_token"]
            self.headers = {"Authorization": f"Bearer {token}"}
        else:
            self.headers = {}

    @task(3)
    def view_active_sessions(self):
        """Read-heavy operation: checking active exam sessions."""
        self.client.get("/api/sessions/", headers=self.headers, name="/api/sessions/ [GET]")

    @task(2)
    def complete_biometric_verification(self):
        """Perform biometric identity verification for session 1."""
        bio_token = f"valid_bio_sample_{self.username}"
        self.client.post("/api/sessions/1/verify-identity", json={
            "session_id": 1,
            "biometric_data": bio_token
        }, headers=self.headers, name="/api/sessions/{id}/verify-identity [POST]")

    @task(1)
    def submit_exam_file(self):
        """High-load submission window: upload exam payload with SHA256 integrity check."""
        exam_content = f"Exam solutions for {self.username} timestamp {random.random()}".encode()
        fhash = hashlib.sha256(exam_content).hexdigest()

        self.client.post(
            "/api/submissions/upload",
            data={"session_id": 1, "provided_hash": fhash},
            files={"file": (f"{self.username}_final.pdf", exam_content, "application/pdf")},
            headers=self.headers,
            name="/api/submissions/upload [POST]"
        )

    @task(2)
    def retrieve_my_results(self):
        """Check published results."""
        self.client.get("/api/results/student/me", headers=self.headers, name="/api/results/student/me [GET]")
