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
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS passwords (id INTEGER PRIMARY KEY, name TEXT, username TEXT, password TEXT, owner_id INTEGER)")
    username = "litlepig"
    password = hashlib.sha256("letmein".encode()).hexdigest()
    try:
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    except sqlite3.IntegrityError:
        pass
    conn.commit()
    conn.close()

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = hashlib.sha256(request.form["password"].encode()).hexdigest()
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()
        conn.close()
        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect("/dashboard")
        else:
            return render_template("login.html", error="Login inválido")
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/")
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM passwords WHERE owner_id=?", (session["user_id"],))
    passwords = c.fetchall()
    conn.close()
    return render_template("dashboard.html", passwords=passwords)

@app.route("/add", methods=["POST"])
def add_password():
    if "user_id" not in session:
        return redirect("/")
    name = request.form["name"]
    uname = request.form["username"]
    pwd = request.form["password"]
    f = Fernet(FERNET_KEY.encode())
    encrypted = f.encrypt(pwd.encode())
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO passwords (name, username, password, owner_id) VALUES (?, ?, ?, ?)", (name, uname, encrypted, session["user_id"]))
    conn.commit()
    conn.close()
    return redirect("/dashboard")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8080)
