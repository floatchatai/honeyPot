from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True)
    hashed_password = Column(String(200), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class Employee(Base):
    __tablename__ = "employees"
    id = Column(Integer, primary_key=True, index=True)
    employee_id = Column(String(20), unique=True, index=True, nullable=False)
    name = Column(String(100), nullable=False)
    email = Column(String(100))
    department = Column(String(50))
    designation = Column(String(100))
    computer_name = Column(String(100))
    os_info = Column(String(200))
    agent_version = Column(String(20))
    is_online = Column(Boolean, default=False)
    last_seen = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    screenshots = relationship("Screenshot", back_populates="employee")
    app_activities = relationship("AppActivity", back_populates="employee")
    web_activities = relationship("WebActivity", back_populates="employee")
    keystroke_logs = relationship("KeystrokeLog", back_populates="employee")
    alerts = relationship("Alert", back_populates="employee")

class Screenshot(Base):
    __tablename__ = "screenshots"
    id = Column(Integer, primary_key=True, index=True)
    employee_id = Column(Integer, ForeignKey("employees.id"))
    file_path = Column(String(500))
    thumbnail_path = Column(String(500))
    timestamp = Column(DateTime, default=datetime.utcnow)
    active_window = Column(String(300))
    active_app = Column(String(100))
    employee = relationship("Employee", back_populates="screenshots")

class AppActivity(Base):
    __tablename__ = "app_activities"
    id = Column(Integer, primary_key=True, index=True)
    employee_id = Column(Integer, ForeignKey("employees.id"))
    app_name = Column(String(100))
    window_title = Column(String(300))
    category = Column(String(20), default="neutral")
    start_time = Column(DateTime)
    end_time = Column(DateTime)
    duration_seconds = Column(Integer, default=0)
    employee = relationship("Employee", back_populates="app_activities")

class WebActivity(Base):
    __tablename__ = "web_activities"
    id = Column(Integer, primary_key=True, index=True)
    employee_id = Column(Integer, ForeignKey("employees.id"))
    url = Column(String(500))
    domain = Column(String(200))
    page_title = Column(String(300))
    category = Column(String(20), default="neutral")
    start_time = Column(DateTime)
    end_time = Column(DateTime)
    duration_seconds = Column(Integer, default=0)
    employee = relationship("Employee", back_populates="web_activities")

class KeystrokeLog(Base):
    __tablename__ = "keystroke_logs"
    id = Column(Integer, primary_key=True, index=True)
    employee_id = Column(Integer, ForeignKey("employees.id"))
    app_name = Column(String(100))
    window_title = Column(String(300))
    keystroke_count = Column(Integer, default=0)
    timestamp = Column(DateTime, default=datetime.utcnow)
    interval_seconds = Column(Integer, default=60)
    employee = relationship("Employee", back_populates="keystroke_logs")

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    employee_id = Column(Integer, ForeignKey("employees.id"))
    alert_type = Column(String(50))
    severity = Column(String(20), default="medium")
    message = Column(Text)
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    employee = relationship("Employee", back_populates="alerts")

class Policy(Base):
    __tablename__ = "policies"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text)
    policy_type = Column(String(50))
    rules = Column(JSON)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
