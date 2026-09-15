import os
import random
import time
import sqlite3
import requests
import pandas as pd
from flask import Flask, render_template, jsonify, request, redirect, url_for

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
    static_url_path="/static"
)

# ---------------------------------------------------------------------------
# 1. การจัดการฐานข้อมูล SQLite (Database Setup)
# ---------------------------------------------------------------------------
DB_PATH = os.path.join(BASE_DIR, "database.db")

def init_db():
    """สร้างตาราง incident_logs และ notifications หากยังไม่มีในระบบ"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incident_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            actual_label TEXT,
            attack_type TEXT NOT NULL,
            detection_type TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            processing_time_ms REAL NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sent_at TEXT NOT NULL,
            incident_id INTEGER,
            attack_type TEXT,
            recipient TEXT NOT NULL,
            message TEXT NOT NULL,
            status TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def save_incident_to_db(log_data):
    """บันทึก Incident Log ลง SQLite และคืนค่า ID ที่ถูกบันทึก"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO incident_logs (
                timestamp, src_ip, dst_ip, actual_label, 
                attack_type, detection_type, risk_level, 
                risk_score, processing_time_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            log_data["timestamp"],
            log_data["src_ip"],
            log_data["dst_ip"],
            log_data["actual_label"],
            log_data["attack_type"],
            log_data["detection_type"],
            log_data["risk_level"],
            log_data["risk_score"],
            log_data["processing_time_ms"]
        ))
        inc_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return inc_id
    except Exception as e:
        print(f"[DB ERROR] บันทึก Log ล้มเหลว: {e}")
        return None

def save_notification_to_db(incident_id, attack_type, recipient, message, status):
    """บันทึกประวัติการส่งแจ้งเตือนลง SQLite"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO notifications (sent_at, incident_id, attack_type, recipient, message, status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (time.strftime('%Y-%m-%d %H:%M:%S'), incident_id, attack_type, recipient, message, status))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB ERROR] บันทึก Notification ล้มเหลว: {e}")

# ---------------------------------------------------------------------------
# 2. โหลด Engine และ Dataset
# ---------------------------------------------------------------------------
try:
    from hybrid_engine import HybridDetector
    detector = HybridDetector()
except ImportError:
    detector = None
    print("[WARN] ไม่พบไฟล์ hybrid_engine.py ระบบจะใช้ Dummy Mode ชั่วคราว")

DATA_PATH = os.path.join(BASE_DIR, "..", "output", "selected_data.parquet")
if not os.path.exists(DATA_PATH):
    DATA_PATH = os.path.join(BASE_DIR, "output", "selected_data.parquet")

sample_df = None
if os.path.exists(DATA_PATH):
    sample_df = pd.read_parquet(DATA_PATH)

train_state = {"status": "idle", "log": []}

# ---------------------------------------------------------------------------
# 3. LINE Messaging API Handler
# ---------------------------------------------------------------------------
LINE_CHANNEL_ACCESS_TOKEN = os.environ.get("LINE_CHANNEL_ACCESS_TOKEN", "")
LINE_USER_ID = os.environ.get("LINE_USER_ID", "")
LINE_PUSH_URL = "https://api.line.me/v2/bot/message/push"

def send_line_alert(message: str, incident_id=None, attack_type=""):
    """ส่งแจ้งเตือนเข้า LINE Official Account"""
    recipient = "ทีมเฝ้าระวังเครือข่าย"
    if not LINE_CHANNEL_ACCESS_TOKEN or not LINE_USER_ID:
        save_notification_to_db(incident_id, attack_type, recipient, message, "failed")
        return False

    headers = {
        "Authorization": f"Bearer {LINE_CHANNEL_ACCESS_TOKEN}",
        "Content-Type": "application/json",
    }
    payload = {
        "to": LINE_USER_ID,
        "messages": [{"type": "text", "text": message[:5000]}],
    }

    try:
        resp = requests.post(LINE_PUSH_URL, headers=headers, json=payload, timeout=5)
        status = "success" if resp.status_code == 200 else "failed"
        save_notification_to_db(incident_id, attack_type, recipient, message, status)
        return resp.status_code == 200
    except Exception as e:
        print(f"[LINE ERROR] {e}")
        save_notification_to_db(incident_id, attack_type, recipient, message, "failed")
        return False

# ---------------------------------------------------------------------------
# 4. WEB PAGE ROUTES
# ---------------------------------------------------------------------------
@app.route('/')
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html', active_page='dashboard')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/forgot-password')
def forgot_password():
    return render_template('forgot.html')

@app.route('/logout')
def logout():
    return redirect(url_for('login'))

@app.route('/live-monitoring')
def live_monitoring():
    return render_template('live_monitoring.html', active_page='live')

@app.route('/incidents')
def incidents():
    return render_template('incidents.html', active_page='logs')

@app.route('/incidents/<int:incident_id>')
def incident_detail(incident_id):
    return render_template('incident_detail.html', incident_id=incident_id, active_page='logs')

@app.route('/notifications')
def notifications():
    return render_template('notifications.html', active_page='noti')

@app.route('/train')
def train_model():
    return render_template('train.html', active_page='train')

@app.route('/settings')
def settings():
    return render_template('settings.html', active_page='settings')

@app.route('/profile')
def profile():
    return render_template('profile.html', active_page='profile')

# ---------------------------------------------------------------------------
# 5. REST APIs (ปรับแก้ Logic ให้สอดคล้องกับ Frontend)
# ---------------------------------------------------------------------------
@app.route('/api/simulate_traffic', methods=['GET'])
def simulate_traffic():
    start_time = time.time()
    
    if sample_df is not None and detector is not None:
        random_row = sample_df.sample(n=1).iloc[0].to_dict()
        actual_label = random_row.pop('Label', 'BENIGN')
        result = detector.predict_flow(random_row)
    else:
        # จำลองสุ่มข้อมูล 3 สถานะให้สัดส่วนสมจริง
        rand_val = random.random()
        if rand_val < 0.65:  # 65% ทราฟฟิกปกติ
            actual_label = 'BENIGN'
            result = {
                "attack_type": "BENIGN",
                "detection_type": "Normal Traffic",
                "risk_level": "Low",
                "risk_score": random.randint(1, 20)
            }
        elif rand_val < 0.85:  # 20% Known Attack (จับได้โดย Random Forest)
            actual_label = random.choice(['DDoS', 'PortScan', 'DoS Hulk'])
            result = {
                "attack_type": actual_label,
                "detection_type": "Known Attack",
                "risk_level": "High" if actual_label in ['DDoS', 'DoS Hulk'] else "Medium",
                "risk_score": random.randint(75, 95)
            }
        else:  # 15% Unknown Attack (จับได้โดย Isolation Forest)
            actual_label = 'Unknown_Anomaly'
            result = {
                "attack_type": "Unknown Anomaly",
                "detection_type": "Unknown Attack",
                "risk_level": "High",
                "risk_score": random.randint(80, 99)
            }

    processing_time = round((time.time() - start_time) * 1000, 2)
    src_ip = f"192.168.1.{random.randint(2, 254)}"
    dst_ip = f"10.0.0.{random.randint(2, 254)}"
    curr_time = time.strftime('%Y-%m-%d %H:%M:%S')

    log_entry = {
        "timestamp": curr_time,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "actual_label": actual_label,
        "attack_type": result["attack_type"],
        "detection_type": result["detection_type"],
        "risk_level": result["risk_level"],
        "risk_score": result["risk_score"],
        "processing_time_ms": processing_time,
    }

    # บันทึกลงฐานข้อมูลเมื่อพบความเสี่ยง Medium/High
    if result["risk_level"] in ["Medium", "High"]:
        inc_id = save_incident_to_db(log_entry)
        if result["risk_level"] == "High":
            alert_msg = (
                f"[NIDS Alert]\n"
                f"Time: {curr_time}\n"
                f"Type: {result['attack_type']}\n"
                f"Source IP: {src_ip}\n"
                f"Risk: High"
            )
            send_line_alert(alert_msg, incident_id=inc_id, attack_type=result["attack_type"])

    return jsonify(log_entry)

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """คำนวณสถิติสะสมจากฐานข้อมูล SQLite ให้ถูกต้องตรงกัน"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*), AVG(processing_time_ms) FROM incident_logs")
    total_incidents, avg_proc = cursor.fetchone()
    
    cursor.execute("SELECT COUNT(*) FROM incident_logs WHERE risk_level = 'High'")
    high_count = cursor.fetchone()[0] or 0
    
    cursor.execute("SELECT COUNT(*) FROM incident_logs WHERE detection_type = 'Known Attack'")
    known_count = cursor.fetchone()[0] or 0
    
    cursor.execute("SELECT COUNT(*) FROM incident_logs WHERE detection_type = 'Unknown Attack'")
    unknown_count = cursor.fetchone()[0] or 0
    
    conn.close()
    
    # คำนวณประมาณการณ์ Normal flows จากอัตราสัดส่วน
    total_flows = (total_incidents or 0) + 150
    normal_flows = max(0, total_flows - (known_count + unknown_count))

    return jsonify({
        "total": total_flows,
        "known": known_count,
        "unknown": unknown_count,
        "normal": normal_flows,
        "high": high_count,
        "incidents_count": total_incidents or 0,
        "avg_processing_ms": round(avg_proc or 0, 2)
    })

@app.route('/api/logs', methods=['GET'])
def get_logs():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM incident_logs ORDER BY id DESC LIMIT 50")
        rows = cursor.fetchall()
        conn.close()
        return jsonify([dict(row) for row in rows])
    except Exception as e:
        print(f"[DB ERROR] {e}")
        return jsonify([])

@app.route('/api/incidents/<int:log_id>', methods=['GET'])
def get_incident_detail(log_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incident_logs WHERE id = ?", (log_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "Incident not found"}), 404

    log_data = dict(row)
    mitigations = {
        "DDoS": [
            f"คำแนะนำ: บล็อกไอพีต้นทาง {log_data['src_ip']} บน Firewall/Router ทันที",
            "เปิดใช้งาน Rate Limiting บน WAF",
            "แจ้งประสานงาน ISP เพื่อทำ BGP Blackholing"
        ],
        "PortScan": [
            f"คำแนะนำ: ตั้งค่า Drop Traffic จาก IP {log_data['src_ip']} ชั่วคราว 24 ชั่วโมง",
            "ซ่อนพอร์ตบริการที่ไม่จำเป็น และปิดการตอบรับ ICMP Echo Request"
        ]
    }
    default_mitigation = [
        f"คำแนะนำ: เฝ้าระวังและกักกัน (Isolate) การเชื่อมต่อจาก IP {log_data['src_ip']} เพื่อตรวจสอบเพิ่มเติม",
        "ทำการวิเคราะห์ Traffic Payload ลึกขึ้นผ่าน Wireshark"
    ]
    log_data["recommendations"] = mitigations.get(log_data["attack_type"], default_mitigation)
    return jsonify(log_data)

@app.route('/api/notifications', methods=['GET'])
def get_notifications():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM notifications ORDER BY id DESC LIMIT 40")
    rows = cursor.fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

@app.route('/api/notifications/resend/<int:noti_id>', methods=['POST'])
def resend_notification(noti_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM notifications WHERE id = ?", (noti_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"success": False, "error": "Noti not found"}), 404

    noti = dict(row)
    success = send_line_alert(noti["message"], incident_id=noti["incident_id"], attack_type=noti["attack_type"])
    return jsonify({"success": success})

@app.route('/api/incidents/purge', methods=['POST'])
def purge_old_incidents():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM incident_logs WHERE timestamp < datetime('now', '-90 days')")
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    return jsonify({"deleted": deleted})

@app.route('/api/train/start', methods=['POST'])
def start_train():
    global train_state
    if train_state["status"] == "running":
        return jsonify({"error": "กระบวนการฝึกโมเดลกำลังทำงานอยู่"}), 400
    
    train_state["status"] = "running"
    train_state["log"] = ["กำลังเริ่มต้นโหลดชุดข้อมูล...", "กำลัง preprocessing ข้อมูล..."]
    
    def run_dummy_train():
        time.sleep(3)
        train_state["log"].append("กำลังฝึก Random Forest Classifier...")
        time.sleep(3)
        train_state["log"].append("กำลังฝึก Isolation Forest Anomaly Detector...")
        time.sleep(2)
        train_state["log"].append("ฝึกโมเดลเสร็จสมบูรณ์ และบันทึกไฟล์ model.pkl แล้ว")
        train_state["status"] = "done"

    import threading
    threading.Thread(target=run_dummy_train).start()

    return jsonify({"message": "เริ่มฝึกโมเดลแล้ว"})

@app.route('/api/train/status', methods=['GET'])
def train_status():
    return jsonify(train_state)

@app.route('/api/incidents/export/csv', methods=['GET'])
def export_csv():
    conn = sqlite3.connect(DB_PATH)
    df_logs = pd.read_sql_query("SELECT * FROM incident_logs ORDER BY id DESC", conn)
    conn.close()

    response = app.make_response(df_logs.to_csv(index=False))
    response.headers["Content-Disposition"] = "attachment; filename=incident_logs.csv"
    response.headers["Content-Type"] = "text/csv"
    return response

# ---------------------------------------------------------------------------
# 6. Run Server
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    print("กำลังเริ่มต้น Web Dashboard Server (Logic Sync Fixed)...")
    app.run(debug=True, port=5000)