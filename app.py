from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3, os, smtplib, random
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecret")

DB_NAME = "users.db"

# ---------------- DATABASE SETUP ----------------
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    # Create table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE,
                  email TEXT UNIQUE,
                  password TEXT,
                  role TEXT)''')
    
    # Check if admin exists
    c.execute("SELECT * FROM users WHERE username=? OR email=?", ("admin", "admin@example.com"))
    if not c.fetchone():
        c.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                  ("admin", "admin@example.com", "admin123", "admin"))

    # Check if dbmanager exists
    c.execute("SELECT * FROM users WHERE username=? OR email=?", ("dbmanager", "22052204@kiit.ac.in"))
    if not c.fetchone():
        c.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                  ("dbmanager", "22052204@kiit.ac.in", "dbpass123", "dbmanager"))

    conn.commit()
    conn.close()

# ---------------- HELPER FUNCTIONS ----------------
def send_otp_email(to_email, otp):
    sender = os.getenv("EMAIL_USER")      
    sender_pass = os.getenv("EMAIL_PASS")  

    msg = MIMEMultipart()
    msg["From"] = sender
    msg["To"] = to_email
    msg["Subject"] = "Password Reset OTP"

    body = f"Your OTP for password reset is: {otp}"
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender, sender_pass)
        server.sendmail(sender, to_email, msg.as_string())
        server.quit()
        print("OTP sent successfully")
        return True
    except Exception as e:
        print("Email error:", e)
        return False

# ---------------- ROUTES ----------------
@app.route("/")
def home():
    if "user" in session:
        return render_template("home.html", user=session["user"], role=session["role"])
    return redirect(url_for("login"))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                      (username, email, password, "user"))
            conn.commit()
            conn.close()
            return redirect(url_for("login"))
        except:
            return "Username or Email already exists!"
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()
        conn.close()

        if user:
            session["user"] = user[1]
            session["role"] = user[4]
            return redirect(url_for("home"))
        else:
            return "Invalid Credentials!"
    return render_template("login.html")

@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = request.form["email"]

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email=?", (email,))
        user = c.fetchone()
        conn.close()

        if user:
            otp = str(random.randint(1000, 9999))
            session["otp"] = otp
            session["reset_email"] = email
            send_otp_email(email, otp)
            return redirect(url_for("verify_otp"))
        else:
            return "Email not registered!"
    return render_template("forgot.html")

@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    if request.method == "POST":
        entered = request.form["otp"]
        if entered == session.get("otp"):
            return redirect(url_for("reset_password"))
        else:
            return "Invalid OTP!"
    return render_template("verify.html")

@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        new_pass = request.form["password"]
        email = session.get("reset_email")

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("UPDATE users SET password=? WHERE email=?", (new_pass, email))
        conn.commit()
        conn.close()

        session.pop("otp", None)
        session.pop("reset_email", None)

        return redirect(url_for("login"))
    return render_template("reset.html")

@app.route("/admin")
def admin():
    if "role" in session and session["role"] in ["admin", "dbmanager"]:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT username, email, role FROM users")
        users = c.fetchall()
        conn.close()
        return render_template("admin.html", users=users)
    return "Access Denied!"

@app.route("/logout")
def logout():
    session.pop("user", None)
    session.pop("role", None)
    return redirect(url_for("login"))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
