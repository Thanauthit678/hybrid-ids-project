# ---------------------------------------------------------------------------
# เอาโค้ดชุดนี้ไปแปะเพิ่มใน app.py (แทนที่ route เดิมของ @app.route('/'))
# แต่ละ route ใส่ active_page ให้ตรงกับปุ่มใน sidebar เพื่อให้ highlight ปุ่มที่ถูกต้อง
# ---------------------------------------------------------------------------

# ---------- หน้า Auth (ยังไม่มี logic ตรวจสอบรหัสผ่านจริง เป็นแค่ route เปล่าไว้ก่อน) ----------

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
    # TODO: เคลียร์ session ตอนทำระบบ authentication จริง
    return redirect(url_for('login'))


# ---------- หน้าแอปหลัก ----------

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html', active_page='dashboard')


@app.route('/live')
def live_monitoring():
    return render_template('live_monitoring.html', active_page='live')


@app.route('/incidents')
def incidents():
    return render_template('incidents.html', active_page='logs')


@app.route('/incidents/<int:incident_id>')
def incident_detail(incident_id):
    return render_template('incident_detail.html', active_page='logs', incident_id=incident_id)


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
