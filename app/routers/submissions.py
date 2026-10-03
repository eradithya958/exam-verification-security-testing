import os
import hashlib
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.config import settings
from app.models import ExamSession, ExamSubmission, IdentityVerification, User
from app.schemas import SubmissionResponse
from app.security import get_current_user, require_role

router = APIRouter(prefix="/submissions", tags=["Exam Submissions"])

@router.post("/upload", response_model=SubmissionResponse, status_code=status.HTTP_201_CREATED)
async def upload_submission(
    session_id: int = Form(...),
    provided_hash: Optional[str] = Form(None),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("student"))
):
    # Verify session exists and is active
    session = db.query(ExamSession).filter(ExamSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exam session not found")
    if not session.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Exam session is closed")

    # Check that the student completed identity verification
    verification = db.query(IdentityVerification).filter(
        IdentityVerification.session_id == session_id,
        IdentityVerification.student_id == current_user.id,
        IdentityVerification.verification_status == "VERIFIED"
    ).first()

    if not verification:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Student must successfully complete biometric verification before submitting exam"
        )

    # Remediated: Secure file upload validation
    # 1. Sanitize filename against directory traversal & validate length
    clean_filename = os.path.basename(file.filename)
    if not clean_filename or len(clean_filename) > 200:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid filename format or length")

    # 2. Enforce extension whitelist upfront
    allowed_extensions = {".pdf", ".zip", ".txt", ".docx"}
    _, ext = os.path.splitext(clean_filename.lower())
    if ext not in allowed_extensions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file type. Allowed formats: {', '.join(allowed_extensions)}"
        )

    # 3. Read file content and compute integrity hash
    content = await file.read()
    if len(content) == 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is empty")

    computed_hash = hashlib.sha256(content).hexdigest()

    # Integrity verification check
    if provided_hash and provided_hash.lower() != computed_hash.lower():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Integrity check failed: provided hash does not match computed content hash"
        )

    # 3. Store file under unique, collision-resistant UUID filename
    import uuid
    unique_storage_name = f"{uuid.uuid4().hex}_{clean_filename}"
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    saved_path = os.path.join(settings.UPLOAD_DIR, unique_storage_name)
    
    with open(saved_path, "wb") as f:
        f.write(content)

    submission = ExamSubmission(
        session_id=session_id,
        student_id=current_user.id,
        filename=clean_filename,
        file_path=saved_path,
        file_hash=computed_hash,
        status="SUBMITTED"
    )
    db.add(submission)
    db.commit()
    db.refresh(submission)

    return submission

@router.get("/{submission_id}", response_model=SubmissionResponse)
def get_submission(
    submission_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    submission = db.query(ExamSubmission).filter(ExamSubmission.id == submission_id).first()
    if not submission:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Submission not found")
    
    # Students can only view their own submission; invigilators can view any
    if current_user.role == "student" and submission.student_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied to this submission")
    
    return submission

@router.get("/session/{session_id}", response_model=List[SubmissionResponse])
def get_session_submissions(
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("invigilator"))
):
    session = db.query(ExamSession).filter(ExamSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exam session not found")
    
    return db.query(ExamSubmission).filter(ExamSubmission.session_id == session_id).all()
