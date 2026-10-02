from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from datetime import datetime
from dateutil.parser import parse as parse_date
from .. import models, schemas
from ..database import get_db
router = APIRouter(prefix="/activities", tags=["activities"])
def get_emp_id(db, eid):
    emp = db.query(models.Employee).filter(models.Employee.employee_id == eid).first()
    return emp.id if emp else None
@router.post("/app")
def bulk_app(data: schemas.BulkAppActivity, db: Session = Depends(get_db)):
    c = 0
    for a in data.activities:
        eid = get_emp_id(db, a.employee_id)
        if not eid: continue
        db.add(models.AppActivity(employee_id=eid, app_name=a.app_name, window_title=a.window_title or "", category=a.category or "neutral", duration_seconds=a.duration_seconds or 0, start_time=parse_date(a.start_time) if a.start_time else datetime.utcnow(), end_time=parse_date(a.end_time) if a.end_time else datetime.utcnow())); c += 1
    db.commit(); return {"status": "ok", "count": c}
@router.post("/web")
def bulk_web(data: schemas.BulkWebActivity, db: Session = Depends(get_db)):
    c = 0
    for a in data.activities:
        eid = get_emp_id(db, a.employee_id)
        if not eid: continue
        db.add(models.WebActivity(employee_id=eid, url=a.url or "", domain=a.domain or "", page_title=a.page_title or "", category=a.category or "neutral", start_time=parse_date(a.timestamp) if a.timestamp else datetime.utcnow())); c += 1
    db.commit(); return {"status": "ok", "count": c}
@router.post("/keystrokes")
def bulk_keys(data: schemas.BulkKeystroke, db: Session = Depends(get_db)):
    c = 0
    for a in data.activities:
        eid = get_emp_id(db, a.employee_id)
        if not eid: continue
        db.add(models.KeystrokeLog(employee_id=eid, app_name=a.app_name or "", window_title=a.window_title or "", keystroke_count=a.keystroke_count, timestamp=parse_date(a.timestamp) if a.timestamp else datetime.utcnow(), interval_seconds=a.interval_seconds or 60)); c += 1
    db.commit(); return {"status": "ok", "count": c}
@router.get("/app/{eid}")
def get_app(eid: str, db: Session = Depends(get_db)):
    e = get_emp_id(db, eid)
    return db.query(models.AppActivity).filter(models.AppActivity.employee_id == e).order_by(models.AppActivity.start_time.desc()).limit(100).all() if e else []
@router.get("/web/{eid}")
def get_web(eid: str, db: Session = Depends(get_db)):
    e = get_emp_id(db, eid)
    return db.query(models.WebActivity).filter(models.WebActivity.employee_id == e).order_by(models.WebActivity.start_time.desc()).limit(100).all() if e else []
@router.get("/keystrokes/{eid}")
def get_keys(eid: str, db: Session = Depends(get_db)):
    e = get_emp_id(db, eid)
    return db.query(models.KeystrokeLog).filter(models.KeystrokeLog.employee_id == e).order_by(models.KeystrokeLog.timestamp.desc()).limit(100).all() if e else []
