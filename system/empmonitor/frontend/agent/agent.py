"""
EmpMonitor Agent - Employee Activity Monitoring
Connects to: http://139.64.178.194/api/v1

TRANSPARENT monitoring agent - employees are notified that monitoring is active.
A visible system tray icon is displayed at all times.
"""

import os, sys, json, time, threading, logging, sqlite3, socket, platform, io, base64, shutil
from datetime import datetime, timedelta
from pathlib import Path

# --- Configuration ---
AGENT_DIR = os.path.dirname(os.path.abspath(sys.argv[0] if not getattr(sys, 'frozen', False) else sys.executable))
CONFIG_PATH = os.path.join(AGENT_DIR, "config.json")
DB_PATH = os.path.join(AGENT_DIR, "buffer.db")
LOG_PATH = os.path.join(AGENT_DIR, "service.log")

DEFAULT_CONFIG = {
    "server_url": "http://139.64.178.194/api/v1",
    "screenshot_interval": 300,
    "app_track_interval": 30,
    "keystroke_interval": 300,
    "web_history_interval": 300,
    "sync_interval": 60,
    "agent_id": "",
    "auth_token": ""
}

# --- Logging ---
logging.basicConfig(
    filename=LOG_PATH, level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
log = logging.getLogger("EmpMonitor")

def load_config():
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, 'r') as f:
                cfg = json.load(f)
                for k, v in DEFAULT_CONFIG.items():
                    if k not in cfg:
                        cfg[k] = v
                return cfg
    except:
        pass
    return dict(DEFAULT_CONFIG)

def save_config(cfg):
    try:
        with open(CONFIG_PATH, 'w') as f:
            json.dump(cfg, f, indent=2)
    except:
        pass

config = load_config()

# --- System Tray Notification (Transparent Monitoring) ---
def show_tray_icon():
    """Show a visible system tray icon indicating monitoring is active."""
    if sys.platform != 'win32':
        return
    try:
        import ctypes
        from ctypes import wintypes

        # Show a Windows balloon notification
        class NOTIFYICONDATA(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("hWnd", wintypes.HWND),
                ("uID", wintypes.UINT),
                ("uFlags", wintypes.UINT),
                ("uCallbackMessage", wintypes.UINT),
                ("hIcon", wintypes.HICON),
                ("szTip", ctypes.c_wchar * 128),
                ("dwState", wintypes.DWORD),
                ("dwStateMask", wintypes.DWORD),
                ("szInfo", ctypes.c_wchar * 256),
                ("uVersion", wintypes.UINT),
                ("szInfoTitle", ctypes.c_wchar * 64),
                ("dwInfoFlags", wintypes.DWORD),
            ]

        shell32 = ctypes.windll.shell32
        user32 = ctypes.windll.user32

        NIF_ICON = 0x02
        NIF_TIP = 0x04
        NIF_INFO = 0x10
        NIM_ADD = 0x00
        NIIF_INFO = 0x01

        # Get default app icon
        hIcon = user32.LoadIconW(None, ctypes.cast(32516, ctypes.c_wchar_p))  # IDI_SHIELD

        nid = NOTIFYICONDATA()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATA)
        nid.hWnd = 0
        nid.uID = 1001
        nid.uFlags = NIF_ICON | NIF_TIP | NIF_INFO
        nid.hIcon = hIcon
        nid.szTip = "EmpMonitor - Activity Monitoring Active"
        nid.szInfo = "Your computer activity is being monitored by your organization. Screenshots, app usage, and web activity are tracked."
        nid.szInfoTitle = "Employee Monitoring Active"
        nid.dwInfoFlags = NIIF_INFO

        shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid))
        log.info("Tray notification displayed - monitoring is visible to employee")
    except Exception as e:
        log.warning(f"Could not show tray icon: {e}")
        # Fallback: show a message box
        try:
            ctypes.windll.user32.MessageBoxW(
                0,
                "Your computer activity is being monitored by your organization.\n\n"
                "This includes: screenshots, application usage, web browsing, and keyboard activity.\n\n"
                "This notification is shown for transparency. Click OK to acknowledge.",
                "Employee Monitoring Active",
                0x40  # MB_ICONINFORMATION
            )
        except:
            pass

# --- Local SQLite Buffer ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS buffer (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        data_type TEXT, payload TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        synced INTEGER DEFAULT 0
    )''')
    conn.commit()
    conn.close()

def buffer_data(data_type, payload):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO buffer (data_type, payload) VALUES (?, ?)",
                  (data_type, json.dumps(payload)))
        conn.commit()
        conn.close()
    except Exception as e:
        log.error(f"Buffer write error: {e}")

def get_unsynced():
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT id, data_type, payload FROM buffer WHERE synced=0 ORDER BY id LIMIT 50")
        rows = c.fetchall()
        conn.close()
        return rows
    except:
        return []

def mark_synced(ids):
    if not ids:
        return
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.executemany("UPDATE buffer SET synced=1 WHERE id=?", [(i,) for i in ids])
        conn.commit()
        conn.close()
    except:
        pass

def cleanup_old():
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("DELETE FROM buffer WHERE synced=1 AND created_at < datetime('now', '-7 days')")
        conn.commit()
        conn.close()
    except:
        pass

# --- HTTP Helper ---
import requests as req

def api_post(endpoint, data=None, files=None):
    url = config["server_url"].rstrip("/") + endpoint
    headers = {}
    if config.get("auth_token"):
        headers["Authorization"] = f"Bearer {config['auth_token']}"
    try:
        if files:
            r = req.post(url, data=data, files=files, headers=headers, timeout=15)
        else:
            headers["Content-Type"] = "application/json"
            r = req.post(url, json=data, headers=headers, timeout=15)
        if r.status_code == 401:
            authenticate()
            headers["Authorization"] = f"Bearer {config['auth_token']}"
            if files:
                r = req.post(url, data=data, files=files, headers=headers, timeout=15)
            else:
                r = req.post(url, json=data, headers=headers, timeout=15)
        return r
    except Exception as e:
        log.debug(f"API error {endpoint}: {e}")
        return None

def api_get(endpoint):
    url = config["server_url"].rstrip("/") + endpoint
    headers = {}
    if config.get("auth_token"):
        headers["Authorization"] = f"Bearer {config['auth_token']}"
    try:
        r = req.get(url, headers=headers, timeout=10)
        return r
    except:
        return None

def authenticate():
    try:
        url = config["server_url"].rstrip("/") + "/login"
        r = req.post(url, json={"username": "agent", "password": "agent123"}, timeout=10)
        if r.status_code == 200:
            token = r.json().get("access_token", "")
            config["auth_token"] = token
            save_config(config)
            log.info("Authenticated with server")
            return True
    except:
        pass
    return False

def register_agent():
    hostname = socket.gethostname()
    os_info = f"{platform.system()} {platform.release()} ({platform.machine()})"
    emp_id = config.get("agent_id") or f"AGT-{hostname[-6:].upper()}"
    data = {
        "employee_id": emp_id,
        "name": hostname,
        "computer_name": hostname,
        "os_info": os_info,
        "agent_version": "2.0.0",
        "department": "Monitored",
        "designation": "Employee"
    }
    r = api_post("/employees/register", data)
    if r and r.status_code in (200, 201):
        config["agent_id"] = emp_id
        save_config(config)
        log.info(f"Registered agent: {emp_id}")
    else:
        buffer_data("register", data)

# --- Screenshot Module ---
def screenshot_worker():
    try:
        from PIL import ImageGrab
    except ImportError:
        log.warning("PIL not available, screenshots disabled")
        return
    while True:
        try:
            img = ImageGrab.grab()
            buf = io.BytesIO()
            img.save(buf, format='JPEG', quality=50, optimize=True)
            buf.seek(0)
            img_b64 = base64.b64encode(buf.getvalue()).decode()
            payload = {
                "employee_id": config.get("agent_id", ""),
                "timestamp": datetime.utcnow().isoformat(),
                "image_data": img_b64
            }
            r = api_post("/screenshots/upload", payload)
            if not r or r.status_code not in (200, 201):
                buffer_data("screenshot", payload)
            log.debug("Screenshot captured")
        except Exception as e:
            log.error(f"Screenshot error: {e}")
        time.sleep(config.get("screenshot_interval", 300))

# --- App Tracking Module ---
def app_tracking_worker():
    try:
        import psutil
    except ImportError:
        log.warning("psutil not available, app tracking disabled")
        return

    if sys.platform == 'win32':
        try:
            import ctypes
            from ctypes import wintypes
            user32 = ctypes.windll.user32
            def get_active_window():
                hwnd = user32.GetForegroundWindow()
                length = user32.GetWindowTextLengthW(hwnd)
                buf = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buf, length + 1)
                pid = wintypes.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                try:
                    proc = psutil.Process(pid.value)
                    return proc.name(), buf.value
                except:
                    return "Unknown", buf.value
        except:
            def get_active_window():
                return "Unknown", "Unknown"
    else:
        def get_active_window():
            return "Unknown", "Unknown"

    while True:
        try:
            app_name, window_title = get_active_window()
            if app_name and app_name != "Unknown":
                cat = categorize_app(app_name)
                payload = {
                    "employee_id": config.get("agent_id", ""),
                    "app_name": app_name.replace(".exe", ""),
                    "window_title": window_title[:200] if window_title else "",
                    "category": cat,
                    "start_time": datetime.utcnow().isoformat(),
                    "duration_seconds": config.get("app_track_interval", 30)
                }
                r = api_post("/activities/app", payload)
                if not r or r.status_code not in (200, 201):
                    buffer_data("app_activity", payload)
        except Exception as e:
            log.error(f"App tracking error: {e}")
        time.sleep(config.get("app_track_interval", 30))

def categorize_app(name):
    name = name.lower()
    productive = ["code", "visual studio", "excel", "word", "outlook", "teams",
                   "terminal", "powershell", "cmd", "notepad++", "pycharm",
                   "intellij", "eclipse", "slack", "zoom", "figma", "photoshop"]
    unproductive = ["spotify", "netflix", "whatsapp", "telegram", "instagram",
                     "facebook", "tiktok", "game", "steam", "discord"]
    for p in productive:
        if p in name:
            return "productive"
    for u in unproductive:
        if u in name:
            return "unproductive"
    return "neutral"

# --- Web History Module ---
def web_history_worker():
    while True:
        try:
            entries = read_browser_history()
            for entry in entries[-20:]:
                payload = {
                    "employee_id": config.get("agent_id", ""),
                    "url": entry["url"][:500],
                    "domain": entry["domain"],
                    "page_title": entry["title"][:200],
                    "category": categorize_site(entry["domain"]),
                    "start_time": entry["timestamp"]
                }
                r = api_post("/activities/web", payload)
                if not r or r.status_code not in (200, 201):
                    buffer_data("web_activity", payload)
        except Exception as e:
            log.error(f"Web history error: {e}")
        time.sleep(config.get("web_history_interval", 300))

def read_browser_history():
    entries = []
    local = os.environ.get("LOCALAPPDATA", "")
    paths = [
        os.path.join(local, r"Google\Chrome\User Data\Default\History"),
        os.path.join(local, r"Microsoft\Edge\User Data\Default\History"),
    ]
    for hist_path in paths:
        if not os.path.exists(hist_path):
            continue
        tmp = os.path.join(AGENT_DIR, "hist_tmp.db")
        try:
            shutil.copy2(hist_path, tmp)
            conn = sqlite3.connect(tmp)
            c = conn.cursor()
            cutoff = int((datetime.now() - timedelta(minutes=10)).timestamp() * 1000000) + 11644473600000000
            c.execute("SELECT url, title, last_visit_time FROM urls WHERE last_visit_time > ? ORDER BY last_visit_time DESC LIMIT 20", (cutoff,))
            for url, title, visit_time in c.fetchall():
                try:
                    domain = url.split("/")[2] if "/" in url else url
                except:
                    domain = url
                ts = datetime(1601, 1, 1) + timedelta(microseconds=visit_time)
                entries.append({
                    "url": url, "domain": domain,
                    "title": title or "", "timestamp": ts.isoformat()
                })
            conn.close()
        except:
            pass
        finally:
            try: os.remove(tmp)
            except: pass
    return entries

def categorize_site(domain):
    domain = domain.lower()
    productive = ["github", "stackoverflow", "docs.google", "office", "azure",
                   "aws", "jira", "confluence", "figma", "notion"]
    unproductive = ["youtube", "facebook", "instagram", "twitter", "reddit",
                     "netflix", "tiktok", "twitch", "pinterest"]
    for p in productive:
        if p in domain:
            return "productive"
    for u in unproductive:
        if u in domain:
            return "unproductive"
    return "neutral"

# --- Keystroke Counter Module ---
keystroke_count = 0
keystroke_lock = threading.Lock()

def keystroke_listener():
    global keystroke_count
    try:
        from pynput import keyboard
    except ImportError:
        log.warning("pynput not available, keystroke counting disabled")
        return

    def on_press(key):
        global keystroke_count
        with keystroke_lock:
            keystroke_count += 1

    listener = keyboard.Listener(on_press=on_press)
    listener.daemon = True
    listener.start()

    while True:
        time.sleep(config.get("keystroke_interval", 300))
        with keystroke_lock:
            count = keystroke_count
            keystroke_count = 0
        if count > 0:
            payload = {
                "employee_id": config.get("agent_id", ""),
                "app_name": "System",
                "window_title": "Keystroke Count",
                "keystroke_count": count,
                "timestamp": datetime.utcnow().isoformat(),
                "interval_seconds": config.get("keystroke_interval", 300)
            }
            r = api_post("/activities/keystrokes", payload)
            if not r or r.status_code not in (200, 201):
                buffer_data("keystroke", payload)

# --- Sync Worker ---
def sync_worker():
    while True:
        try:
            rows = get_unsynced()
            synced_ids = []
            for row_id, data_type, payload_str in rows:
                try:
                    payload = json.loads(payload_str)
                    endpoint_map = {
                        "screenshot": "/screenshots/upload",
                        "app_activity": "/activities/app",
                        "web_activity": "/activities/web",
                        "keystroke": "/activities/keystrokes",
                        "register": "/employees/register"
                    }
                    ep = endpoint_map.get(data_type)
                    if ep:
                        r = api_post(ep, payload)
                        if r and r.status_code in (200, 201):
                            synced_ids.append(row_id)
                except:
                    synced_ids.append(row_id)
            mark_synced(synced_ids)
            cleanup_old()
        except Exception as e:
            log.error(f"Sync error: {e}")
        time.sleep(config.get("sync_interval", 60))

# --- Heartbeat ---
def heartbeat_worker():
    while True:
        try:
            payload = {
                "employee_id": config.get("agent_id", ""),
                "is_online": True,
                "agent_version": "2.0.0"
            }
            api_post("/employees/heartbeat", payload)
        except:
            pass
        time.sleep(60)

# --- Main ---
def main():
    log.info("EmpMonitor Agent starting (transparent mode)...")

    # Show tray icon and notification to employee
    tray_thread = threading.Thread(target=show_tray_icon, daemon=True, name="TrayIcon")
    tray_thread.start()

    init_db()
    authenticate()
    register_agent()

    threads = [
        threading.Thread(target=screenshot_worker, daemon=True, name="Screenshots"),
        threading.Thread(target=app_tracking_worker, daemon=True, name="AppTracker"),
        threading.Thread(target=web_history_worker, daemon=True, name="WebHistory"),
        threading.Thread(target=keystroke_listener, daemon=True, name="Keystrokes"),
        threading.Thread(target=sync_worker, daemon=True, name="Sync"),
        threading.Thread(target=heartbeat_worker, daemon=True, name="Heartbeat"),
    ]

    for t in threads:
        t.start()
        log.info(f"Started {t.name}")

    log.info("All modules running (transparent mode)")

    # Keep main thread alive
    while True:
        time.sleep(60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("Agent stopped")
    except Exception as e:
        log.error(f"Fatal error: {e}")
        time.sleep(10)
        main()
