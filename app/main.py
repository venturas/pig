from flask import Flask, render_template, request, redirect, session, url_for
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
    c.execute("CREATE TABLE IF NOT EXISTS collections (id INTEGER PRIMARY KEY, name TEXT, owner_id INTEGER)")
    c.execute("""CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY,
        title TEXT, username TEXT, password TEXT,
        url TEXT, notes TEXT,
        collection_id INTEGER, owner_id INTEGER
    )""")
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
            return redirect("/dashboard")
        else:
            return render_template("login.html", error="Login inválido")
    return render_template("login.html")

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user_id" not in session:
        return redirect("/")
    conn = get_db()
    cur = conn.cursor()
    if request.method == "POST":
        f = Fernet(FERNET_KEY.encode())
        enc_pwd = f.encrypt(request.form["password"].encode())
        cur.execute("INSERT INTO passwords (title, username, password, url, notes, collection_id, owner_id) VALUES (?, ?, ?, ?, ?, ?, ?)", (
            request.form["title"], request.form["username"], enc_pwd,
            request.form["url"], request.form["notes"],
            request.form["collection_id"], session["user_id"]
        ))
        conn.commit()
    cur.execute("SELECT * FROM collections WHERE owner_id=? OR ?=1", (session["user_id"], session["is_admin"]))
    collections = cur.fetchall()
    cur.execute("""SELECT p.*, c.name as collection_name FROM passwords p
                   LEFT JOIN collections c ON p.collection_id = c.id
                   WHERE p.owner_id=?""", (session["user_id"],))
    passwords = cur.fetchall()
    return render_template("dashboard.html", collections=collections, passwords=passwords)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if not session.get("is_admin"):
        return redirect("/")
    conn = get_db()
    cur = conn.cursor()
    if request.method == "POST":
        user = request.form["username"]
        pwd = hashlib.sha256(request.form["password"].encode()).hexdigest()
        cur.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)", (user, pwd, int(request.form.get("is_admin", 0))))
        conn.commit()
    cur.execute("SELECT * FROM users")
    users = cur.fetchall()
    return render_template("admin.html", users=users)

@app.route("/collection", methods=["POST"])
def add_collection():
    if "user_id" not in session:
        return redirect("/")
    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO collections (name, owner_id) VALUES (?, ?)", (request.form["name"], session["user_id"]))
    conn.commit()
    return redirect("/dashboard")

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8080)
