from pydantic import BaseModel
from typing import Optional, List, Any
from datetime import datetime

class Token(BaseModel):
    access_token: str
    token_type: str
class LoginRequest(BaseModel):
    username: str
    password: str
class UserResponse(BaseModel):
    id: int
    username: str
    email: Optional[str] = None
    is_admin: bool
    class Config:
        from_attributes = True
class EmployeeCreate(BaseModel):
    employee_id: str
    name: str
    email: Optional[str] = None
    department: Optional[str] = None
    designation: Optional[str] = None
    computer_name: Optional[str] = None
    os_info: Optional[str] = None
    agent_version: Optional[str] = None
class EmployeeResponse(BaseModel):
    id: int
    employee_id: str
    name: str
    email: Optional[str] = None
    department: Optional[str] = None
    designation: Optional[str] = None
    computer_name: Optional[str] = None
    os_info: Optional[str] = None
    agent_version: Optional[str] = None
    is_online: bool = False
    last_seen: Optional[datetime] = None
    created_at: Optional[datetime] = None
    class Config:
        from_attributes = True
class HeartbeatRequest(BaseModel):
    employee_id: Optional[str] = None
    is_online: bool = True
    idle_seconds: Optional[float] = 0
    timestamp: Optional[str] = None
class AppActivityCreate(BaseModel):
    employee_id: str
    app_name: str
    window_title: Optional[str] = ""
    category: Optional[str] = "neutral"
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration_seconds: Optional[int] = 0
class BulkAppActivity(BaseModel):
    activities: List[AppActivityCreate]
class WebActivityCreate(BaseModel):
    employee_id: str
    url: Optional[str] = ""
    domain: Optional[str] = ""
    page_title: Optional[str] = ""
    category: Optional[str] = "neutral"
    browser: Optional[str] = ""
    timestamp: Optional[str] = None
class BulkWebActivity(BaseModel):
    activities: List[WebActivityCreate]
class KeystrokeCreate(BaseModel):
    employee_id: str
    app_name: Optional[str] = ""
    window_title: Optional[str] = ""
    keystroke_count: int = 0
    timestamp: Optional[str] = None
    interval_seconds: Optional[int] = 60
class BulkKeystroke(BaseModel):
    activities: List[KeystrokeCreate]
class AlertCreate(BaseModel):
    employee_id: Optional[int] = None
    alert_type: str
    severity: str = "medium"
    message: str
class AlertResponse(BaseModel):
    id: int
    employee_id: Optional[int] = None
    alert_type: str
    severity: str
    message: str
    is_read: bool
    created_at: Optional[datetime] = None
    class Config:
        from_attributes = True
class PolicyCreate(BaseModel):
    name: str
    description: Optional[str] = None
    policy_type: str
    rules: Optional[Any] = None
    is_active: bool = True
class PolicyResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    policy_type: str
    rules: Optional[Any] = None
    is_active: bool
    created_at: Optional[datetime] = None
    class Config:
        from_attributes = True
class DashboardStats(BaseModel):
    total_employees: int = 0
    online_count: int = 0
    avg_productivity: float = 0
    total_alerts: int = 0
    total_screenshots: int = 0
