import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.config import settings

# In-memory SQLite for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="session", autouse=True)
def setup_upload_dir():
    test_upload_dir = "./test_uploads"
    settings.UPLOAD_DIR = test_upload_dir
    os.makedirs(test_upload_dir, exist_ok=True)
    yield
    # Cleanup test uploads
    if os.path.exists(test_upload_dir):
        for f in os.listdir(test_upload_dir):
            try:
                os.remove(os.path.join(test_upload_dir, f))
            except Exception:
                pass
        try:
            os.rmdir(test_upload_dir)
        except Exception:
            pass

@pytest.fixture(scope="function")
def db_session():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass
            
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()

@pytest.fixture
def student_auth_header(client):
    # Register student
    client.post(
        "/api/auth/register",
        json={
            "username": "student_alice",
            "email": "alice@university.edu",
            "password": "Password123!",
            "full_name": "Alice Smith",
            "role": "student",
            "student_id": "STU1001"
        }
    )
    # Login student
    res = client.post(
        "/api/auth/login",
        json={"username": "student_alice", "password": "Password123!"}
    )
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def student_bob_auth_header(client):
    # Register second student
    client.post(
        "/api/auth/register",
        json={
            "username": "student_bob",
            "email": "bob@university.edu",
            "password": "Password123!",
            "full_name": "Bob Jones",
            "role": "student",
            "student_id": "STU1002"
        }
    )
    # Login Bob
    res = client.post(
        "/api/auth/login",
        json={"username": "student_bob", "password": "Password123!"}
    )
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def invigilator_auth_header(client):
    # Register invigilator
    client.post(
        "/api/auth/register",
        json={
            "username": "prof_johnson",
            "email": "johnson@university.edu",
            "password": "ProfessorPass123!",
            "full_name": "Dr. Alan Johnson",
            "role": "invigilator"
        }
    )
    # Login invigilator
    res = client.post(
        "/api/auth/login",
        json={"username": "prof_johnson", "password": "ProfessorPass123!"}
    )
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
