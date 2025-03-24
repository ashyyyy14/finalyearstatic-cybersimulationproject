
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import os
from flask_socketio import SocketIO, emit
import json
import time
import random
import string
import sqlite3
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = "your_secret_key"
socketio = SocketIO(app)
encryption_key = Fernet.generate_key()
cipher = Fernet(encryption_key)
key_file_path = "../cybersimulations/venv/encryption_key.key"
key_dir = os.path.dirname(key_file_path)
key_file_path = "encryption_key.key"
if not os.path.exists(key_dir):
    os.makedirs(key_dir)

with open(key_file_path, "wb") as key_file:
    key_file.write(encryption_key)

key_file_path = os.path.join(os.path.dirname(__file__), "encryption_key.key")
with open(key_file_path, "wb") as key_file:
    key_file.write(encryption_key)

with open("../cybersimulations/venv/encryption_key.key", "wb") as key_file:
    key_file.write(encryption_key)

users = {"user1": "password123", "admin": "adminpass", "ashita":"bhoomi2811"}
DB_NAME = "cybersimulations.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    try:
        # Create table for brute-force logs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS bruteforce_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username_attempted TEXT,
                password_attempted TEXT,
                result TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()  # Commit only after successful table creation
    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
    finally:
        if conn:
            conn.close()  # Ensure the connection is closed

    print("✅ Database initialized successfully.")

init_db()

@app.route("/")
def home():
    """Route for the homepage."""
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username in users and users[username] == password:
            session["user"] = username
            return redirect(url_for("dashboard"))
        else:
            return "Invalid credentials, please try again."
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user" in session:
        completed_simulations = session.get("completed_simulations", [])
        return render_template("dashboard.html", username=session["user"], completed_simulations=completed_simulations)
    return redirect(url_for("login"))

@app.route("/logout")
def logout():
    """Route to log the user out."""
    session.pop("user", None)  # Clear the session
    return redirect(url_for("home"))

@app.route("/simulate_phishing", methods=["GET", "POST"])
def simulate_phishing():
    if request.method == "POST" and "username" in request.form and "password" in request.form:
        username = request.form.get("username")
        password = request.form.get("password")

        # Encrypt and store the credentials
        encrypted_username = cipher.encrypt(username.encode()).decode()
        encrypted_password = cipher.encrypt(password.encode()).decode()

        with open("logs/phishing_log.txt", "a") as f:
            f.write(f"{encrypted_username}|{encrypted_password}\n")

        return jsonify({"success": True, "username": username, "password": password})

    return render_template("simulate_phishing.html")

@app.route("/view_phishing_logs")
def view_phishing_logs():
    decrypted_entries = []

    try:
        with open("logs/phishing_log.txt", "r") as f:
            for line in f:
                encrypted_username, encrypted_password = line.strip().split("|")

                # Decrypt credentials
                decrypted_username = cipher.decrypt(encrypted_username.encode()).decode()
                decrypted_password = cipher.decrypt(encrypted_password.encode()).decode()

                decrypted_entries.append({"username": decrypted_username, "password": decrypted_password})

    except Exception as e:
        return f"Error reading logs: {str(e)}", 500

    return render_template("phishing_logs.html", logs=decrypted_entries)
@app.route("/phishing_success")
def phishing_success():
    username = request.args.get("username", "N/A")  # Get from URL parameters
    password = request.args.get("password", "N/A")
    return render_template("phishing_success.html", username=username, password=password)

@app.route("/realtime_bruteforce", methods=["GET"])
def realtime_bruteforce():
    return render_template("bruteforce_realtime.html")


@socketio.on('start_simulation')
def handle_start_simulation():
    for i in range(1, 101):
        username = f"admin{i}"
        password = f"pass{i}"
        result = "Failed" if i < 100 else "Success"  # Success on the last attempt
        socketio.emit('update', {'username': username, 'password': password, 'result': result})
        time.sleep(0.1)

    socketio.emit('simulation_complete')  # Emit completion event after the loop

"""def generate_attempts():
    for i in range(5):
        data = {"username": "user" + str(i), "password": "pass" + str(i), "result": "Failed"}
        print(f"data: {json.dumps(data)}\n\n")

generate_attempts()"""

@app.route('/success_bruteforce', methods=["GET"])
def success_bruteforce():
    return render_template("success_bruteforce.html")

@app.route("/simulate_sql_injection", methods=["GET", "POST"])
def simulate_sql_injection():
    fake_database = [
        {"username": "admin", "password": "password123"},
        {"username": "user1", "password": "pass1"},
        {"username": "hacker", "password": "exploit"}
    ]

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Simulate a vulnerable SQL query
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        print(f"Simulated SQL Query: {query}")  # For demonstration

        # Check if the username contains SQL injection patterns
        if "OR" in username.upper() or "1=1" in username or "--" in username:
            # Return fake database results for successful injection
            fake_result = [
                {"username": "ashita", "password": "ashita@123"},
                {"username": "admin100", "password": "pass100"}
            ]
            return jsonify(
                {"success": True, "message": f"Injection Successful! SQL Query: {query}", "data": fake_result})
        # Otherwise, simulate a login failure
        return jsonify({"success": False, "message": f"Login Failed. SQL Query: {query}"})

    return render_template("simulate_sql_injection.html")

@app.route("/simulate_keylogger", methods=["GET", "POST"])
def simulate_keylogger():
    if request.method == "POST":
        # Capture keystrokes from the form
        captured_data = {
            "Card Number": request.form.get("card_number", ""),
            "Cardholder Name": request.form.get("cardholder_name", ""),
            "Expiry Date": request.form.get("expiry_date", ""),
            "CVV": request.form.get("cvv", ""),
            "Billing Address": request.form.get("billing_address", "")
        }

        print("Captured Keystrokes:", captured_data)  # Debugging log
        return render_template("keylogger_result.html", captured_data=captured_data)

    return render_template("simulate_keylogger.html")



@app.route("/fake_antivirus")
def fake_antivirus():
    return render_template("fake_antivirus.html")

@app.route("/start_fake_scan")
def start_fake_scan():
    threats = [
        {"name": "Trojan.Generic", "severity": "High"},
        {"name": "Spyware.KeyLogger", "severity": "Medium"},
        {"name": "Adware.Popups", "severity": "Low"},
        {"name": "Worm.AutoRun", "severity": "High"},
        {"name": "Ransomware.Locky", "severity": "Critical"},
        {"name": "Malware.Injector", "severity": "High"},
    ]

    scan_results = []
    for _ in range(random.randint(3, 6)):  # Randomize the number of threats
        issue = random.choice(threats)
        scan_results.append(issue)
        time.sleep(1)

    return jsonify(scan_results)

@app.route("/fix_issues")
def fix_issues():
    return redirect(url_for("security_tips", attack_type="fake_antivirus"))

@app.route("/security_tips/<attack_type>")
def security_tips(attack_type):
    return render_template("security_tips.html", attack_type=attack_type)

if __name__ == "__main__":
    app.run(debug=True)

