import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends  # type: ignore
from sqlalchemy import create_engine, Column, Integer, String, Text, ForeignKey, DateTime, Float  # type: ignore
from sqlalchemy.orm import sessionmaker, declarative_base, Session  # type: ignore
import json
from fastapi import HTTPException  # type: ignore
from pydantic import BaseModel  # type: ignore
from typing import List

# Database connection
DATABASE_URL = "postgresql://postgres:root@localhost/phishing_db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

# FastAPI app
app = FastAPI()

# WebSocket connection manager


class ConnectionManager:
    def __init__(self):
        self.active_connections = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            await connection.send_json(message)


manager = ConnectionManager()

# Database models
Base = declarative_base()


class PhishingEmail(Base):
    __tablename__ = "phishing_emails"
    id = Column(Integer, primary_key=True, index=True)
    uid = Column(String(50), unique=True, nullable=False)
    sender = Column(String(255))
    subject = Column(Text)
    body = Column(Text)
    detected_at = Column(DateTime, default=datetime.datetime.utcnow)
    confidence = Column(Float)
    status = Column(String(20), nullable=False, default="unverified")


class EmailURL(Base):
    __tablename__ = "email_urls"
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey(
        "phishing_emails.id", ondelete="CASCADE"))
    url = Column(String, nullable=False)
    status = Column(String, nullable=False, default="unchecked")


class EmailData(BaseModel):
    uid: str
    sender: str
    subject: str
    body: str
    confidence: float
    urls: List[str] = []


Base.metadata.create_all(engine)

# Dependency: Get DB session


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# API to fetch all phishing emails


@app.get("/emails")
def get_emails(db: Session = Depends(get_db)):
    return db.query(PhishingEmail).all()

# WebSocket for real-time updates


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()  # Keep connection alive
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Function to save phishing email and notify clients


def save_email_and_notify(email_data, db):
    """Save phishing email and its URLs, then notify clients."""
    try:
        print("📩 Saving phishing email:", email_data)

        # Check if email with this UID already exists
        existing_email = db.query(PhishingEmail).filter_by(
            uid=email_data["uid"]).first()
        if existing_email:
            print("⚠ Email already exists in DB, skipping insert.")
            return None  # Skip duplicate entries

        # Create email entry
        email_entry = PhishingEmail(
            uid=email_data["uid"],
            sender=email_data["sender"],
            subject=email_data["subject"],
            body=email_data["body"],
            confidence=email_data["confidence"],
            status="unverified"
        )
        db.add(email_entry)
        db.commit()
        db.refresh(email_entry)

        # Store URLs (if any)
        stored_urls = []
        for url in email_data.get("urls", []):
            url_entry = EmailURL(email_id=email_entry.id,
                                 url=url, status="unchecked")
            db.add(url_entry)
            stored_urls.append(url_entry)

        db.commit()  # Commit all changes

        print("✅ Email saved successfully.")

        # Send update to dashboard
        data = {
            "type": "new_email",
            "email": {
                "id": email_entry.id,
                "sender": email_entry.sender,
                "subject": email_entry.subject,
                "body": email_entry.body,
                "confidence": email_entry.confidence,
                "urls": [url_entry.url for url_entry in stored_urls]
            }
        }

        return data

    except Exception as e:
        db.rollback()  # Rollback if error occurs
        print(f"⚠ Error saving email: {e}")


@app.post("/save_email")
def save_email(email_data: EmailData, db: Session = Depends(get_db)):
    """API endpoint to save a phishing email and notify clients."""
    data = save_email_and_notify(email_data.dict(), db)

    if data:
        # Broadcast update to WebSocket clients
        import asyncio
        asyncio.create_task(manager.broadcast(data))
        return {"message": "Email saved successfully"}
    else:
        raise HTTPException(status_code=400, detail="Email already exists")
