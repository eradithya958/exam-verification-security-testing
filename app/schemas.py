from pydantic import BaseModel, EmailStr, Field, ConfigDict
from typing import Optional, List
from datetime import datetime

# --- Auth Schemas ---
class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=6)
    full_name: str = Field(..., min_length=1, max_length=100)
    role: str = Field(default="student", pattern="^(student|invigilator|admin)$")
    student_id: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    role: str
    full_name: str
    student_id: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

# --- Exam Session Schemas ---
class ExamSessionCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=150)
    course_code: str = Field(..., min_length=2, max_length=20)
    start_time: datetime
    end_time: datetime

class ExamSessionResponse(BaseModel):
    id: int
    title: str
    course_code: str
    start_time: datetime
    end_time: datetime
    invigilator_id: int
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

# --- Verification Schemas ---
class BiometricVerifyRequest(BaseModel):
    session_id: int
    biometric_data: str  # Simulated base64 biometric string or token
    device_fingerprint: Optional[str] = None

class BiometricVerifyResponse(BaseModel):
    id: int
    session_id: int
    student_id: int
    verification_status: str
    confidence_score: float
    verified_at: datetime

    model_config = ConfigDict(from_attributes=True)

# --- Submission Schemas ---
class SubmissionResponse(BaseModel):
    id: int
    session_id: int
    student_id: int
    filename: str
    file_hash: str
    status: str
    submitted_at: datetime

    model_config = ConfigDict(from_attributes=True)

# --- Result Schemas ---
class ResultCreate(BaseModel):
    submission_id: int
    session_id: int
    student_id: int
    score: float
    grade: str
    integrity_status: str = "VERIFIED"
    feedback: Optional[str] = None

class ResultResponse(BaseModel):
    id: int
    submission_id: int
    session_id: int
    student_id: int
    score: float
    grade: str
    integrity_status: str
    feedback: Optional[str] = None
    released_at: datetime

    model_config = ConfigDict(from_attributes=True)
