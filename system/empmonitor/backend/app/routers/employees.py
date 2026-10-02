from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import Optional, List
from datetime import datetime
from .. import models, schemas
from ..database import get_db

router = APIRouter(prefix="/employees", tags=["employees"])

@router.get("", response_model=List[schemas.EmployeeResponse])
def list_employees(search: Optional[str] = None, department: Optional[str] = None, is_online: Optional[bool] = None, skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    q = db.query(models.Employee)
    if search: q = q.filter(models.Employee.name.ilike(f"%{search}%"))
    if department: q = q.filter(models.Employee.department == department)
    if is_online is not None: q = q.filter(models.Employee.is_online == is_online)
    return q.offset(skip).limit(limit).all()

@router.post("/register", response_model=schemas.EmployeeResponse)
def register_agent(emp: schemas.EmployeeCreate, db: Session = Depends(get_db)):
    return create_employee(emp=emp, db=db)

@router.post("/heartbeat")
def heartbeat_post(req: schemas.HeartbeatRequest, db: Session = Depends(get_db)):
    eid = req.employee_id
    if not eid:
        return {"status": "error", "message": "no employee_id"}
    emp = db.query(models.Employee).filter(
        (models.Employee.employee_id == eid)
    ).first()
    if emp:
        emp.is_online = True
        emp.last_seen = datetime.utcnow()
        db.commit()
        return {"status": "ok"}
    return {"status": "not_found"}

@router.get("/{eid}", response_model=schemas.EmployeeResponse)
def get_employee(eid: str, db: Session = Depends(get_db)):
    return db.query(models.Employee).filter((models.Employee.employee_id == eid) | (models.Employee.id == int(eid) if eid.isdigit() else False)).first()

@router.post("", response_model=schemas.EmployeeResponse)
def create_employee(emp: schemas.EmployeeCreate, db: Session = Depends(get_db)):
    existing = db.query(models.Employee).filter(models.Employee.employee_id == emp.employee_id).first()
    if existing:
        for k, v in emp.dict(exclude_unset=True).items():
            if v is not None: setattr(existing, k, v)
        existing.is_online = True; existing.last_seen = datetime.utcnow()
        db.commit(); db.refresh(existing); return existing
    db_emp = models.Employee(**emp.dict(), is_online=True, last_seen=datetime.utcnow())
    db.add(db_emp); db.commit(); db.refresh(db_emp); return db_emp

@router.patch("/{eid}/heartbeat")
def heartbeat(eid: str, req: schemas.HeartbeatRequest, db: Session = Depends(get_db)):
    emp = db.query(models.Employee).filter((models.Employee.employee_id == eid) | (models.Employee.id == int(eid) if eid.isdigit() else False)).first()
    if emp: emp.is_online = True; emp.last_seen = datetime.utcnow(); db.commit()
    return {"status": "ok"}
