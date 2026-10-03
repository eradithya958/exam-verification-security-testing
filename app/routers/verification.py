from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import ExamSession, IdentityVerification, User
from app.schemas import (
    ExamSessionCreate,
    ExamSessionResponse,
    BiometricVerifyRequest,
    BiometricVerifyResponse
)
from app.security import get_current_user, require_role
from app.mock_biometric import verify_student_biometrics

router = APIRouter(prefix="/sessions", tags=["Exam Sessions & Verification"])

@router.post("/", response_model=ExamSessionResponse, status_code=status.HTTP_201_CREATED)
def create_session(
    session_data: ExamSessionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("invigilator"))
):
    if session_data.end_time <= session_data.start_time:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Session end time must be after start time"
        )
    
    new_session = ExamSession(
        title=session_data.title,
        course_code=session_data.course_code.upper(),
        start_time=session_data.start_time,
        end_time=session_data.end_time,
        invigilator_id=current_user.id,
        is_active=True
    )
    db.add(new_session)
    db.commit()
    db.refresh(new_session)
    return new_session

@router.get("/", response_model=List[ExamSessionResponse])
def list_active_sessions(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return db.query(ExamSession).filter(ExamSession.is_active == True).all()

@router.get("/{session_id}", response_model=ExamSessionResponse)
def get_session(
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    session = db.query(ExamSession).filter(ExamSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exam session not found")
    return session

@router.post("/{session_id}/verify-identity", response_model=BiometricVerifyResponse)
def verify_identity(
    session_id: int,
    request: BiometricVerifyRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("student"))
):
    session = db.query(ExamSession).filter(ExamSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exam session not found")
    if not session.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Exam session is closed")

    # Mock external biometric verification
    student_id_val = current_user.student_id or str(current_user.id)
    is_verified, score, bio_ref = verify_student_biometrics(student_id_val, request.biometric_data)

    verification_status = "VERIFIED" if is_verified else "REJECTED"

    verification = IdentityVerification(
        session_id=session_id,
        student_id=current_user.id,
        verification_status=verification_status,
        confidence_score=score,
        biometric_reference=bio_ref
    )
    db.add(verification)
    db.commit()
    db.refresh(verification)
    
    if not is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Biometric identity verification failed. Confidence score: {score}"
        )

    return verification

@router.get("/{session_id}/verifications", response_model=List[BiometricVerifyResponse])
def list_session_verifications(
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("invigilator"))
):
    session = db.query(ExamSession).filter(ExamSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exam session not found")
    
    return db.query(IdentityVerification).filter(IdentityVerification.session_id == session_id).all()
