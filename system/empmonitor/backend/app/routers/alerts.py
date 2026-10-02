from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Optional, List
from .. import models, schemas
from ..database import get_db
router = APIRouter(prefix="/alerts", tags=["alerts"])
@router.get("", response_model=List[schemas.AlertResponse])
def list_alerts(severity: Optional[str] = None, is_read: Optional[bool] = None, skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    q = db.query(models.Alert)
    if severity: q = q.filter(models.Alert.severity == severity)
    if is_read is not None: q = q.filter(models.Alert.is_read == is_read)
    return q.order_by(models.Alert.created_at.desc()).offset(skip).limit(limit).all()
@router.post("", response_model=schemas.AlertResponse)
def create_alert(a: schemas.AlertCreate, db: Session = Depends(get_db)):
    d = models.Alert(**a.dict()); db.add(d); db.commit(); db.refresh(d); return d
@router.patch("/{aid}/read")
def mark_read(aid: int, db: Session = Depends(get_db)):
    a = db.query(models.Alert).filter(models.Alert.id == aid).first()
    if not a: raise HTTPException(status_code=404)
    a.is_read = True; db.commit(); return {"status": "ok"}
@router.patch("/read-all")
def mark_all(db: Session = Depends(get_db)):
    db.query(models.Alert).filter(models.Alert.is_read == False).update({"is_read": True}); db.commit(); return {"status": "ok"}
@router.get("/summary")
def summary(db: Session = Depends(get_db)):
    r = db.query(models.Alert.severity, func.count()).filter(models.Alert.is_read == False).group_by(models.Alert.severity).all()
    return {x[0]: x[1] for x in r}
