from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.database import get_db
from app.models import ExamResult, ExamSubmission, ExamSession, User
from app.schemas import ResultCreate, ResultResponse
from app.security import get_current_user, require_role

router = APIRouter(prefix="/results", tags=["Exam Results"])

@router.post("/", response_model=ResultResponse, status_code=status.HTTP_201_CREATED)
def publish_result(
    result_data: ResultCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("invigilator"))
):
    # Verify submission exists
    submission = db.query(ExamSubmission).filter(ExamSubmission.id == result_data.submission_id).first()
    if not submission:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Submission not found")
    
    # Check if result already exists for this submission
    existing = db.query(ExamResult).filter(ExamResult.submission_id == result_data.submission_id).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Result already published for this submission")

    new_result = ExamResult(
        submission_id=result_data.submission_id,
        session_id=result_data.session_id,
        student_id=result_data.student_id,
        score=result_data.score,
        grade=result_data.grade,
        integrity_status=result_data.integrity_status,
        feedback=result_data.feedback
    )
    db.add(new_result)
    
    submission.status = "EVALUATED"
    db.commit()
    db.refresh(new_result)
    return new_result

@router.get("/student/me", response_model=List[ResultResponse])
def get_my_results(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("student"))
):
    """Secure endpoint: Returns all results belonging to the authenticated student."""
    return db.query(ExamResult).filter(ExamResult.student_id == current_user.id).all()

@router.get("/{result_id}", response_model=ResultResponse)
def get_result_by_id(
    result_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Remediated: Enforces strict row-level ownership authorization.
    Students can only view their own results; invigilators can view all results.
    """
    result = db.query(ExamResult).filter(ExamResult.id == result_id).first()
    if not result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Result not found")
    
    # Remediated IDOR: Verify ownership if requester is a student
    if current_user.role == "student" and result.student_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You are not authorized to view another student's exam result."
        )

    return result

@router.get("/search/query", response_model=List[dict])
def search_results(
    query: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("invigilator"))
):
    """
    Remediated: Uses parameterized SQLAlchemy ORM filtering instead of raw SQL concatenation.
    Prevents SQL injection attacks entirely.
    """
    search_pattern = f"%{query}%"
    records = (
        db.query(ExamResult, User, ExamSession)
        .join(User, ExamResult.student_id == User.id)
        .join(ExamSession, ExamResult.session_id == ExamSession.id)
        .filter(
            (User.username.ilike(search_pattern)) | (User.full_name.ilike(search_pattern))
        )
        .all()
    )
    
    results = [
        {
            "id": result.id,
            "score": result.score,
            "grade": result.grade,
            "integrity_status": result.integrity_status,
            "username": user.username,
            "full_name": user.full_name,
            "course_code": session.course_code
        }
        for result, user, session in records
    ]
    return results
