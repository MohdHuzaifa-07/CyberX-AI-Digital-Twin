# ============================================
# Cyber Sentinel - Main Application
# Author: Mohammed Huzaifa
# Project: AI-Powered Cybersecurity Digital Twin
# Tech Stack: Flask, MySQL, LDAP, Scikit-learn
# ============================================

from flask import Flask, request, render_template, redirect, url_for, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import mysql.connector
from ldap3 import Server, Connection, ALL
import bcrypt
from flask_mail import Mail, Message
from dotenv import load_dotenv
import os

load_dotenv()

from models.AI_agent3.session_hijacking import run_session_model
from models.AI_agent2.XSS_attack_prediction import run_xss_model
from models.AI_agent1.sql_injection_detection import run_sql_model

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# -------------------- DATABASE CONFIG --------------------
db_config = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', ''),
    'database': os.getenv('DB_NAME', 'registration_db')
}

# -------------------- MAIL CONFIG --------------------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')
mail = Mail(app)

# -------------------- LDAP CONFIG --------------------
ldap_server_url = "ldap://127.0.0.1:389"
ldap_user_dn = "cn=admin,dc=cyberx,dc=local"
ldap_password = os.getenv('LDAP_PASSWORD', 'admin')
ldap_base_dn = "dc=cyberx,dc=local"

# -------------------- LOGIN MANAGER --------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access the dashboard.'

class User(UserMixin):
    def __init__(self, id, username, email):
        self.id = id
        self.username = username
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    try:
        db = mysql.connector.connect(**db_config)
        cursor = db.cursor(buffered=True)
        cursor.execute("SELECT id, name, email FROM users WHERE id=%s", (user_id,))
        result = cursor.fetchone()
        cursor.close()
        db.close()
        if result:
            return User(id=result[0], username=result[1], email=result[2])
        return None
    except Exception as e:
        print(f"User load error: {e}")
        return None

# -------------------- ATTACK LOG HELPER --------------------
def log_attack(username, attack_type, payload, result, confidence):
    try:
        db = mysql.connector.connect(**db_config)
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO attack_logs (username, attack_type, payload, result, confidence) VALUES (%s, %s, %s, %s, %s)",
            (username, attack_type, payload, result, confidence)
        )
        db.commit()
        cursor.close()
        db.close()
    except Exception as e:
        print(f"Log Error: {e}")

# -------------------- ROUTES --------------------

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/home')
@login_required
def home():
    threat_count = session.get('threat_count', 0)
    risk_level, risk_color = get_risk_level(threat_count)
    return render_template('home.html',
                           threat_count=threat_count,
                           risk_level=risk_level,
                           risk_color=risk_color,
                           username=current_user.username)

# -------------------- CONTACT --------------------
@app.route('/contact', methods=['POST'])
@login_required
def contact():
    firstname = request.form.get('firstname', '').strip()
    lastname = request.form.get('lastname', '').strip()
    email = request.form.get('email', '').strip()
    message = request.form.get('message', '').strip()

    if not all([firstname, lastname, email, message]):
        contact_success = False
    else:
        try:
            msg = Message(
                subject=f"New Contact Message from {firstname} {lastname}",
                recipients=[os.getenv('MAIL_USERNAME')],
                body=f"Name: {firstname} {lastname}\nEmail: {email}\n\nMessage:\n{message}"
            )
            mail.send(msg)
            contact_success = True
        except Exception as e:
            print(f"Mail Error: {e}")
            contact_success = False

    threat_count = session.get('threat_count', 0)
    risk_level, risk_color = get_risk_level(threat_count)
    return render_template('home.html',
                           contact_success=contact_success,
                           threat_count=threat_count,
                           risk_level=risk_level,
                           risk_color=risk_color,
                           username=current_user.username)

# -------------------- XSS --------------------
@app.route('/xss', methods=['GET', 'POST'])
@login_required
def xss():
    threat_count = session.get('threat_count', 0)

    if request.method == 'POST':
        result = run_xss_model()
        if result.get('accuracy', 0) > 0.9:
            threat_count += 1
            session['threat_count'] = threat_count

        risk_level, risk_color = get_risk_level(threat_count)
        return render_template('home.html',
                               xss_result=result,
                               show_xss=True,
                               threat_count=threat_count,
                               risk_level=risk_level,
                               risk_color=risk_color,
                               username=current_user.username)

    risk_level, risk_color = get_risk_level(threat_count)
    return render_template('home.html',
                           show_xss=False,
                           threat_count=threat_count,
                           risk_level=risk_level,
                           risk_color=risk_color,
                           username=current_user.username)

# -------------------- SQL --------------------
@app.route('/sql', methods=['GET', 'POST'])
@login_required
def sql():
    threat_count = session.get('threat_count', 0)
    results = None
    show_table = False

    if request.method == 'POST':
        results = run_sql_model()
        show_table = True
        attacks = sum(1 for r in results if "Detected" in r['Result'])
        threat_count += attacks
        session['threat_count'] = threat_count

    risk_level, risk_color = get_risk_level(threat_count)
    return render_template('home.html',
                           results=results,
                           show_table=show_table,
                           threat_count=threat_count,
                           risk_level=risk_level,
                           risk_color=risk_color,
                           username=current_user.username)

# -------------------- SESSION --------------------
@app.route('/session', methods=['GET', 'POST'])
@login_required
def session_route():
    threat_count = session.get('threat_count', 0)
    session_result = None
    show_session = False

    if request.method == 'POST':
        session_result = run_session_model()
        show_session = True
        if session_result.get('accuracy', 0) < 0.95:
            threat_count += 1
            session['threat_count'] = threat_count

    risk_level, risk_color = get_risk_level(threat_count)
    return render_template('home.html',
                           session_result=session_result,
                           show_session=show_session,
                           threat_count=threat_count,
                           risk_level=risk_level,
                           risk_color=risk_color,
                           username=current_user.username)

# -------------------- REGISTER --------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not email or not password:
            return render_template('register.html', error='All fields are required')
        if len(password) < 6:
            return render_template('register.html', error='Password must be at least 6 characters')
        if len(username) < 3:
            return render_template('register.html', error='Username must be at least 3 characters')

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # -------- MYSQL SAVE --------
        try:
            db = mysql.connector.connect(**db_config)
            cursor = db.cursor(buffered=True)
            cursor.execute(
                "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
                (username, email, hashed_password)
            )
            db.commit()
            cursor.close()
            db.close()
        except mysql.connector.IntegrityError:
            return render_template('register.html', error='Username or email already exists')
        except mysql.connector.Error as e:
            print(f"DB Register Error: {e}")
            return render_template('register.html', error='Database error. Please try again later')

        # -------- LDAP SAVE --------
        try:
            server = Server(ldap_server_url, get_info=ALL)
            conn = Connection(server, user=ldap_user_dn, password=ldap_password)
            if conn.bind():
                user_dn = f"cn={username},{ldap_base_dn}"
                conn.add(
                    dn=user_dn,
                    object_class=['inetOrgPerson'],
                    attributes={
                        'cn': username,
                        'sn': username,
                        'mail': email,
                        'userPassword': password
                    }
                )
                conn.unbind()
            else:
                return render_template('register.html', error='Registration service temporarily unavailable')
        except Exception as e:
            print(f"LDAP Register Error: {e}")
            return render_template('register.html', error='Registration service temporarily unavailable')

        return redirect('/login')

    return render_template('register.html')

# -------------------- LOGIN --------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            return render_template('login.html', error='Username and password required')

        try:
            db = mysql.connector.connect(**db_config)
            cursor = db.cursor(buffered=True)
            cursor.execute("SELECT id, name, email, password FROM users WHERE name=%s", (username,))
            result = cursor.fetchone()
            cursor.close()
            db.close()

            if result:
                stored_password = result[3]
                if isinstance(stored_password, str):
                    stored_password = stored_password.encode('utf-8')

                if bcrypt.checkpw(password.encode('utf-8'), stored_password):
                    user = User(id=result[0], username=result[1], email=result[2])
                    login_user(user, remember=False)
                    session['threat_count'] = 0
                    return redirect(url_for('home'))
                else:
                    return render_template('login.html', error='Invalid username or password')
            else:
                return render_template('login.html', error='Invalid username or password')

        except mysql.connector.Error as e:
            print(f"Login DB Error: {e}")
            return render_template('login.html', error='Login service temporarily unavailable')

    return render_template('login.html')

# -------------------- LOGOUT --------------------
@app.route('/logout')
@login_required
def logout():
    session.clear()
    logout_user()
    return redirect(url_for('login'))

# -------------------- LIVE PAYLOAD TESTING --------------------

@app.route('/sql_live', methods=['POST'])
@login_required
def sql_live():
    threat_count = session.get('threat_count', 0)
    payload = request.form.get('payload', '').strip()

    if len(payload) > 500:
        return render_template('home.html', sql_live_result={"error": "Payload too long"},
                               threat_count=threat_count, username=current_user.username)

    # ✅ Real ML model
    from models.AI_agent1.sql_injection_detection import predict_sql_payload
    result = predict_sql_payload(payload)

    if result['is_attack']:
        threat_count += 1
        session['threat_count'] = threat_count

    log_attack(
        username=current_user.username,
        attack_type="SQL Injection",
        payload=payload,
        result="Attack Detected" if result['is_attack'] else "Safe",
        confidence=result['confidence']
    )

    risk_level, risk_color = get_risk_level(threat_count)
    return render_template('home.html',
                           sql_live_result=result,
                           show_table=False,
                           threat_count=threat_count,
                           risk_level=risk_level,
                           risk_color=risk_color,
                           username=current_user.username)

@app.route('/xss_live', methods=['POST'])
@login_required
def xss_live():
    threat_count = session.get('threat_count', 0)
    from models.AI_agent2.XSS_attack_prediction import predict_xss_payload

    payload = request.form.get('payload', '').strip()

    if len(payload) > 500:
        return render_template('home.html', xss_live_result={"error": "Payload too long"},
                               threat_count=threat_count, username=current_user.username)

    # ✅ Real ML model
    result = predict_xss_payload(payload)

    if result['is_attack']:
        threat_count += 1
        session['threat_count'] = threat_count

    log_attack(
        username=current_user.username,
        attack_type="XSS Attack",
        payload=payload,
        result="Attack Detected" if result['is_attack'] else "Safe",
        confidence=result['confidence']
    )

    risk_level, risk_color = get_risk_level(threat_count)
    return render_template('home.html',
                           xss_live_result=result,
                           show_xss=False,
                           threat_count=threat_count,
                           risk_level=risk_level,
                           risk_color=risk_color,
                           username=current_user.username)

@app.route('/session_live', methods=['POST'])
@login_required
def session_live():
    threat_count = session.get('threat_count', 0)
    payload = request.form.get('payload', '').strip()

    if len(payload) > 500:
        return render_template('home.html', session_live_result={"error": "Payload too long"},
                               threat_count=threat_count, username=current_user.username)

    # ✅ Real ML model
    from models.AI_agent3.session_hijacking import predict_session_payload
    result = predict_session_payload(payload)

    if result['is_attack']:
        threat_count += 1
        session['threat_count'] = threat_count

    log_attack(
        username=current_user.username,
        attack_type="Session Hijacking",
        payload=payload,
        result="Attack Detected" if result['is_attack'] else "Safe",
        confidence=result['confidence']
    )

    risk_level, risk_color = get_risk_level(threat_count)
    return render_template('home.html',
                           session_live_result=result,
                           show_session=False,
                           threat_count=threat_count,
                           risk_level=risk_level,
                           risk_color=risk_color,
                           username=current_user.username)

# -------------------- ATTACK LOG --------------------
@app.route('/attack_log')
@login_required
def attack_log():
    try:
        db = mysql.connector.connect(**db_config)
        cursor = db.cursor(buffered=True)
        cursor.execute(
            "SELECT attack_type, payload, result, confidence, timestamp FROM attack_logs WHERE username=%s ORDER BY timestamp DESC LIMIT 50",
            (current_user.username,)
        )
        logs = cursor.fetchall()
        cursor.close()
        db.close()
    except Exception as e:
        print(f"Log fetch error: {e}")
        logs = []

    threat_count = session.get('threat_count', 0)
    risk_level, risk_color = get_risk_level(threat_count)
    return render_template('home.html',
                           attack_logs=logs,
                           show_logs=True,
                           threat_count=threat_count,
                           risk_level=risk_level,
                           risk_color=risk_color,
                           username=current_user.username)

# -------------------- RISK --------------------
def get_risk_level(threat_count):
    if threat_count < 3:
        return "LOW", "lightgreen"
    elif threat_count < 6:
        return "MEDIUM", "orange"
    else:
        return "HIGH", "red"

# -------------------- RUN --------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=os.getenv('FLASK_DEBUG', 'False') == 'True')