from flask import Flask, render_template, request, redirect, session
import sqlite3
import os
import hashlib
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "supersecret")
DB_PATH = "data/secure.db"
FERNET_KEY = os.environ.get("FERNET_KEY", Fernet.generate_key().decode())

def get_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, is_admin INTEGER DEFAULT 0)")
    try:
        admin_pass = hashlib.sha256("letmein".encode()).hexdigest()
        c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)", ("litlepig", admin_pass))
    except sqlite3.IntegrityError:
        pass
    conn.commit()
    conn.close()

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form["username"]
        pwd = hashlib.sha256(request.form["password"].encode()).hexdigest()
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=? AND password=?", (user, pwd))
        row = cur.fetchone()
        if row:
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            session["is_admin"] = row["is_admin"]
            session["login_attempts"] = 0
            return redirect("/dashboard")
        else:
            session["login_attempts"] = session.get("login_attempts", 0) + 1
            if session["login_attempts"] >= 4:
                session.clear()
                return render_template("wolf.html")
            return render_template("login.html", error="Not by the hair of my chinny, chin, chin!", attempts=session["login_attempts"])
    return render_template("login.html", attempts=session.get("login_attempts", 0))



@app.route("/dashboard")
def dashboard():
    if not session.get("user_id"):
        return redirect("/")
    return render_template("dashboard.html")    

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8080)
