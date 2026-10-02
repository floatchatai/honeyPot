from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from .. import models, schemas
from ..database import get_db
router = APIRouter(prefix="/policies", tags=["policies"])
@router.get("", response_model=List[schemas.PolicyResponse])
def list_p(db: Session = Depends(get_db)): return db.query(models.Policy).all()
@router.post("", response_model=schemas.PolicyResponse)
def create_p(p: schemas.PolicyCreate, db: Session = Depends(get_db)):
    d = models.Policy(**p.dict()); db.add(d); db.commit(); db.refresh(d); return d
@router.put("/{pid}", response_model=schemas.PolicyResponse)
def update_p(pid: int, p: schemas.PolicyCreate, db: Session = Depends(get_db)):
    d = db.query(models.Policy).filter(models.Policy.id == pid).first()
    if not d: raise HTTPException(status_code=404)
    for k, v in p.dict(exclude_unset=True).items(): setattr(d, k, v)
    db.commit(); db.refresh(d); return d
@router.delete("/{pid}")
def delete_p(pid: int, db: Session = Depends(get_db)):
    d = db.query(models.Policy).filter(models.Policy.id == pid).first()
    if not d: raise HTTPException(status_code=404)
    db.delete(d); db.commit(); return {"status": "ok"}
