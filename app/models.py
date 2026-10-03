import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database import Base

class UserRole:
    STUDENT = "student"
    INVIGILATOR = "invigilator"
    ADMIN = "admin"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), default=UserRole.STUDENT, nullable=False)
    full_name = Column(String(100), nullable=False)
    student_id = Column(String(30), unique=True, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    created_sessions = relationship("ExamSession", back_populates="invigilator")
    verifications = relationship("IdentityVerification", back_populates="student")
    submissions = relationship("ExamSubmission", back_populates="student")
    results = relationship("ExamResult", back_populates="student")


class ExamSession(Base):
    __tablename__ = "exam_sessions"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(150), nullable=False)
    course_code = Column(String(20), index=True, nullable=False)
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime, nullable=False)
    invigilator_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    invigilator = relationship("User", back_populates="created_sessions")
    verifications = relationship("IdentityVerification", back_populates="session", cascade="all, delete-orphan")
    submissions = relationship("ExamSubmission", back_populates="session", cascade="all, delete-orphan")
    results = relationship("ExamResult", back_populates="session", cascade="all, delete-orphan")


class IdentityVerification(Base):
    __tablename__ = "identity_verifications"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("exam_sessions.id"), nullable=False)
    student_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    verification_status = Column(String(20), default="PENDING", nullable=False)  # VERIFIED, REJECTED, PENDING
    confidence_score = Column(Float, nullable=False)
    biometric_reference = Column(String(255), nullable=True)
    verified_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    session = relationship("ExamSession", back_populates="verifications")
    student = relationship("User", back_populates="verifications")


class ExamSubmission(Base):
    __tablename__ = "exam_submissions"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("exam_sessions.id"), nullable=False)
    student_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    filename = Column(String(255), nullable=False)
    file_path = Column(String(500), nullable=False)
    file_hash = Column(String(64), nullable=False)  # SHA256 hex digest
    status = Column(String(20), default="SUBMITTED", nullable=False)  # SUBMITTED, FLAGGED, EVALUATED
    submitted_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    session = relationship("ExamSession", back_populates="submissions")
    student = relationship("User", back_populates="submissions")
    result = relationship("ExamResult", back_populates="submission", uselist=False)


class ExamResult(Base):
    __tablename__ = "exam_results"

    id = Column(Integer, primary_key=True, index=True)
    submission_id = Column(Integer, ForeignKey("exam_submissions.id"), nullable=False)
    session_id = Column(Integer, ForeignKey("exam_sessions.id"), nullable=False)
    student_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    score = Column(Float, nullable=False)
    grade = Column(String(5), nullable=False)
    integrity_status = Column(String(20), default="VERIFIED", nullable=False)  # VERIFIED, TAMPERED, FLAGGED
    feedback = Column(Text, nullable=True)
    released_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    submission = relationship("ExamSubmission", back_populates="result")
    session = relationship("ExamSession", back_populates="results")
    student = relationship("User", back_populates="results")
