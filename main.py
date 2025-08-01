import os
import random
import string
import sqlite3
import base64
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, redirect, send_from_directory

app = Flask(__name__)
DB_NAME = 'keys.db'

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            key TEXT PRIMARY KEY,
            gmail TEXT,
            created_at TEXT,
            used INTEGER DEFAULT 0,
            hwid TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def generate_key(length=12):
    chars = string.ascii_lowercase + string.digits
    return ''.join(random.choices(chars, k=length))

@app.route('/api/get_key')
def get_key():
    gmail = request.args.get('gmail')
    if not gmail:
        return jsonify({'error': 'gmail is required'}), 400

    now = datetime.utcnow()
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('SELECT created_at FROM keys WHERE gmail = ? ORDER BY created_at DESC LIMIT 1', (gmail,))
    row = c.fetchone()

    if row:
        last_created = datetime.fromisoformat(row[0])
        if now - last_created < timedelta(hours=24):
            conn.close()
            return jsonify({'error': 'Key already issued to this Gmail in last 24h'}), 429

    key = generate_key()
    created_at = now.isoformat()
    c.execute('INSERT INTO keys (key, gmail, created_at, used, hwid) VALUES (?, ?, ?, 0, NULL)', (key, gmail, created_at))
    conn.commit()
    conn.close()

    raw_data = f"{gmail}:{key}".encode()
    encoded = base64.urlsafe_b64encode(raw_data).decode()

    return jsonify({
        'key': key,
        'link': f'{request.host_url.rstrip("/")}/verify/{encoded}'
    })

@app.route('/api/verify_key')
def verify_key():
    key = request.args.get('key')
    hwid = request.args.get('hwid')
    if not key or not hwid:
        return "invalid"

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('SELECT gmail, created_at, used, hwid FROM keys WHERE key = ?', (key,))
    row = c.fetchone()

    if not row:
        conn.close()
        return "invalid"

    gmail, created_at_str, used, stored_hwid = row
    created_at = datetime.fromisoformat(created_at_str)

    if datetime.utcnow() - created_at > timedelta(hours=24):
        conn.close()
        return "expired"

    if stored_hwid is None:
        c.execute('UPDATE keys SET hwid = ?, used = 1 WHERE key = ?', (hwid, key))
        conn.commit()
        conn.close()
        return "valid"

    if hwid != stored_hwid:
        conn.close()
        return "hwid_mismatch"

    if used:
        conn.close()
        return "used"

    c.execute('UPDATE keys SET used = 1 WHERE key = ?', (key,))
    conn.commit()
    conn.close()
    return "valid"

@app.route('/verify/<encoded>')
def verify_encoded(encoded):
    try:
        decoded = base64.urlsafe_b64decode(encoded).decode()
        gmail, key = decoded.split(":", 1)
        return redirect(f"/api/verify_key?key={key}&hwid=unknown")
    except Exception:
        return "invalid encoded string", 400

@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/style.css')
def serve_css():
    return send_from_directory('.', 'style.css')

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
