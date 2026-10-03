import datetime
from app.database import SessionLocal, engine, Base
from app.models import User, ExamSession
from app.security import get_password_hash

def seed():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # Create invigilator if not exists
        invigilator = db.query(User).filter(User.username == "prof_alan").first()
        if not invigilator:
            invigilator = User(
                username="prof_alan",
                email="alan@university.edu",
                hashed_password=get_password_hash("AlanPassword123!"),
                role="invigilator",
                full_name="Prof. Alan Turing"
            )
            db.add(invigilator)
            db.commit()
            db.refresh(invigilator)
        
        # Create exam session 1 if not exists
        session = db.query(ExamSession).filter(ExamSession.id == 1).first()
        if not session:
            session = ExamSession(
                id=1,
                title="Distributed Computing Final Exam",
                course_code="CS-950",
                start_time=datetime.datetime.utcnow(),
                end_time=datetime.datetime.utcnow() + datetime.timedelta(hours=4),
                invigilator_id=invigilator.id,
                is_active=True
            )
            db.add(session)
            db.commit()
            print("[INFO] Seeded invigilator and active ExamSession ID 1.")
        else:
            print("[INFO] ExamSession 1 already exists.")
    finally:
        db.close()

if __name__ == "__main__":
    seed()
