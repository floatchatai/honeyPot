from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from .. import models, schemas
from ..database import get_db
router = APIRouter(prefix="/analytics", tags=["analytics"])
@router.get("/dashboard", response_model=schemas.DashboardStats)
def dashboard(db: Session = Depends(get_db)):
    total = db.query(models.Employee).count()
    online = db.query(models.Employee).filter(models.Employee.is_online == True).count()
    alerts = db.query(models.Alert).filter(models.Alert.is_read == False).count()
    ss = db.query(models.Screenshot).count()
    pt = db.query(func.sum(models.AppActivity.duration_seconds)).filter(models.AppActivity.category == "productive").scalar() or 0
    tt = db.query(func.sum(models.AppActivity.duration_seconds)).scalar() or 1
    return schemas.DashboardStats(total_employees=total, online_count=online, avg_productivity=round((pt/tt)*100,1) if tt > 0 else 0, total_alerts=alerts, total_screenshots=ss)
@router.get("/apps")
def top_apps(db: Session = Depends(get_db)):
    r = db.query(models.AppActivity.app_name, models.AppActivity.category, func.sum(models.AppActivity.duration_seconds).label("s"), func.count().label("c")).group_by(models.AppActivity.app_name, models.AppActivity.category).order_by(func.sum(models.AppActivity.duration_seconds).desc()).limit(20).all()
    return [{"app_name": x[0], "category": x[1], "total_seconds": x[2], "sessions": x[3]} for x in r]
@router.get("/websites")
def top_sites(db: Session = Depends(get_db)):
    r = db.query(models.WebActivity.domain, models.WebActivity.category, func.count().label("v")).group_by(models.WebActivity.domain, models.WebActivity.category).order_by(func.count().desc()).limit(20).all()
    return [{"domain": x[0], "category": x[1], "visits": x[2]} for x in r]
@router.get("/departments")
def depts(db: Session = Depends(get_db)):
    r = db.query(models.Employee.department, func.count()).group_by(models.Employee.department).all()
    return [{"department": x[0] or "Other", "employees": x[1]} for x in r]
