from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from datetime import datetime
from dateutil.parser import parse as parse_date
from PIL import Image
import os, uuid
from .. import models
from ..database import get_db
from ..config import settings
router = APIRouter(prefix="/screenshots", tags=["screenshots"])
os.makedirs(settings.SCREENSHOT_STORAGE_PATH, exist_ok=True)
os.makedirs(os.path.join(settings.SCREENSHOT_STORAGE_PATH, "thumbs"), exist_ok=True)
@router.post("/upload")
async def upload(file: UploadFile = File(...), employee_id: str = Form(...), active_window: str = Form(""), active_app: str = Form(""), timestamp: str = Form(""), db: Session = Depends(get_db)):
    emp = db.query(models.Employee).filter(models.Employee.employee_id == employee_id).first()
    if not emp: raise HTTPException(status_code=404)
    fn = f"{employee_id}_{uuid.uuid4().hex[:8]}.jpg"
    fp = os.path.join(settings.SCREENSHOT_STORAGE_PATH, fn)
    tp = os.path.join(settings.SCREENSHOT_STORAGE_PATH, "thumbs", fn)
    content = await file.read()
    with open(fp, "wb") as f: f.write(content)
    try:
        img = Image.open(fp); img.thumbnail((320, 180)); img.save(tp, "JPEG", quality=60)
    except: tp = fp
    ts = parse_date(timestamp) if timestamp else datetime.utcnow()
    ss = models.Screenshot(employee_id=emp.id, file_path=fp, thumbnail_path=tp, timestamp=ts, active_window=active_window[:300], active_app=active_app[:100])
    db.add(ss); emp.is_online = True; emp.last_seen = datetime.utcnow(); db.commit()
    return {"status": "ok", "id": ss.id}
@router.get("/{eid}")
def list_ss(eid: str, skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    emp = db.query(models.Employee).filter((models.Employee.employee_id == eid) | (models.Employee.id == int(eid) if eid.isdigit() else False)).first()
    return db.query(models.Screenshot).filter(models.Screenshot.employee_id == emp.id).order_by(models.Screenshot.timestamp.desc()).offset(skip).limit(limit).all() if emp else []
@router.get("/file/{sid}")
def get_file(sid: int, db: Session = Depends(get_db)):
    ss = db.query(models.Screenshot).filter(models.Screenshot.id == sid).first()
    if not ss or not os.path.exists(ss.file_path): raise HTTPException(status_code=404)
    return FileResponse(ss.file_path, media_type="image/jpeg")
