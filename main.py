from flask import Flask, render_template_string, request, jsonify
import sqlite3, secrets, time

app = Flask(__name__)

# Время жизни ключа (24ч)
TTL = 60 * 60 * 24

HTML = open("index.html", encoding="utf-8").read()

def init_db():
    with sqlite3.connect("keys.db") as con:
        con.execute("CREATE TABLE IF NOT EXISTS keys (key TEXT, created INTEGER, used INTEGER)")
init_db()

@app.route("/")
def index():
    new_key = secrets.token_hex(8)
    with sqlite3.connect("keys.db") as con:
        con.execute("INSERT INTO keys (key, created, used) VALUES (?, ?, ?)", (new_key, int(time.time()), 0))
    return render_template_string(HTML, key=new_key)

@app.route("/check")
def check():
    key = request.args.get("key", "")
    with sqlite3.connect("keys.db") as con:
        row = con.execute("SELECT created, used FROM keys WHERE key=?", (key,)).fetchone()
        if not row:
            return "invalid"
        created, used = row
        if used:
            return "invalid"
        if time.time() - created > TTL:
            return "expected"
        con.execute("UPDATE keys SET used=1 WHERE key=?", (key,))
        return "valid"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
