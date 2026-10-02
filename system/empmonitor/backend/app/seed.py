from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import random
from . import models
from .auth import get_password_hash

def seed_database(db: Session):
    if db.query(models.User).count() > 0: return
    db.add(models.User(username="admin", email="admin@company.com", hashed_password=get_password_hash("admin123"), is_admin=True))
    emps_data = [("EMP001","Aarav Sharma","Engineering","Software Engineer"),("EMP002","Priya Patel","Marketing","Marketing Manager"),("EMP003","Rohan Gupta","Engineering","Sr. Developer"),("EMP004","Ananya Singh","Sales","Sales Executive"),("EMP005","Vikram Reddy","HR","HR Coordinator"),("EMP006","Sneha Iyer","Finance","Finance Analyst"),("EMP007","Arjun Nair","Engineering","DevOps Engineer"),("EMP008","Meera Kumar","Marketing","Content Writer"),("EMP009","Karthik Rao","Engineering","QA Engineer"),("EMP010","Divya Joshi","Engineering","Frontend Developer"),("EMP011","Rahul Verma","Sales","Sales Manager"),("EMP012","Pooja Mehta","Finance","Sr. Analyst"),("EMP013","Aditya Das","Engineering","Backend Developer"),("EMP014","Neha Kapoor","HR","HR Manager"),("EMP015","Siddharth Bhat","Engineering","Team Lead")]
    emps = []
    for eid, name, dept, desg in emps_data:
        e = models.Employee(employee_id=eid, name=name, email=name.lower().replace(" ", ".") + "@company.com", department=dept, designation=desg, computer_name=f"DESK-{eid[-3:]}", os_info="Windows 11 Pro (x64)", agent_version="2.0.0", is_online=random.random()>0.3, last_seen=datetime.utcnow()-timedelta(minutes=random.randint(0,120)))
        db.add(e); emps.append(e)
    db.flush()
    apps = [("VS Code","productive"),("Chrome","neutral"),("Slack","productive"),("Excel","productive"),("Zoom","productive"),("Spotify","unproductive"),("WhatsApp","unproductive"),("Outlook","productive"),("Terminal","productive"),("YouTube","unproductive"),("Figma","productive"),("Teams","productive")]
    sites = [("github.com","productive"),("stackoverflow.com","productive"),("youtube.com","unproductive"),("linkedin.com","neutral"),("twitter.com","unproductive"),("docs.google.com","productive"),("reddit.com","unproductive"),("figma.com","productive")]
    for emp in emps:
        for day in range(7):
            base = datetime.utcnow() - timedelta(days=day)
            for hour in range(9,18):
                app, cat = random.choice(apps); start = base.replace(hour=hour, minute=random.randint(0,59)); dur = random.randint(60,3600)
                db.add(models.AppActivity(employee_id=emp.id, app_name=app, window_title=f"{app} - Work", category=cat, start_time=start, end_time=start+timedelta(seconds=dur), duration_seconds=dur))
            for _ in range(random.randint(5,15)):
                site, cat = random.choice(sites)
                db.add(models.WebActivity(employee_id=emp.id, url=f"https://{site}/page", domain=site, page_title=f"{site}", category=cat, start_time=base.replace(hour=random.randint(9,17), minute=random.randint(0,59))))
            for hour in range(9,18):
                db.add(models.KeystrokeLog(employee_id=emp.id, app_name=random.choice(apps)[0], window_title="Work", keystroke_count=random.randint(100,3000), timestamp=base.replace(hour=hour, minute=30), interval_seconds=3600))
    alert_msgs = [("policy_violation","critical","Accessed blocked website: netflix.com"),("idle_exceeded","medium","Idle for more than 30 minutes"),("unauthorized_app","high","Used unauthorized app: BitTorrent"),("unauthorized_site","low","Visited restricted site"),("policy_violation","high","Working outside hours")]
    for emp in random.sample(emps, 10):
        for _ in range(random.randint(1,3)):
            at, sv, ms = random.choice(alert_msgs)
            db.add(models.Alert(employee_id=emp.id, alert_type=at, severity=sv, message=ms, is_read=random.random()>0.5, created_at=datetime.utcnow()-timedelta(hours=random.randint(1,168))))
    for name, desc, pt, rules in [("Block Social Media","Block social media","site_blacklist",["instagram.com","facebook.com"]),("Idle Timeout","Alert on idle > 30 min","idle_timeout",{"minutes":30}),("Screenshot Interval","Every 5 min","screenshot_interval",{"seconds":300}),("Working Hours","9-6 Mon-Fri","working_hours",{"start":"09:00","end":"18:00"})]:
        db.add(models.Policy(name=name, description=desc, policy_type=pt, rules=rules, is_active=True))
    db.commit()
    print("Database seeded!")
