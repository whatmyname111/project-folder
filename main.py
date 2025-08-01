import os
import random
import string
import sqlite3
import base64
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_from_directory, redirect

app = Flask(__name__)
DB_NAME = 'keys.db'

# Инициализация базы данных
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            key TEXT PRIMARY KEY,
            created_at TEXT,
            used INTEGER DEFAULT 0,
            hwid TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Генерация случайного ключа
def generate_key(length=12):
    chars = string.ascii_lowercase + string.digits
    return ''.join(random.choices(chars, k=length))

# Эндпоинт для генерации ключа
@app.route('/api/get_key')
def get_key():
    hwid = request.args.get('hwid')
    if not hwid:
        return jsonify({'error': 'hwid is required'}), 400

    now = datetime.utcnow()
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('SELECT created_at FROM keys WHERE hwid = ? ORDER BY created_at DESC LIMIT 1', (hwid,))
    row = c.fetchone()

    if row:
        last_created = datetime.fromisoformat(row[0])
        if now - last_created < timedelta(hours=24):
            conn.close()
            return jsonify({'error': 'Key already issued within last 24 hours'}), 429

    key = generate_key()
    created_at = now.isoformat()
    c.execute('INSERT INTO keys (key, created_at, used, hwid) VALUES (?, ?, 0, ?)', (key, created_at, hwid))
    conn.commit()
    conn.close()

    raw_data = f"{hwid}:{key}".encode()
    encoded = base64.urlsafe_b64encode(raw_data).decode()

    return jsonify({
        'key': key,
        'link': f'{request.host_url.rstrip("/")}/verify/{encoded}'
    })

# Эндпоинт для проверки ключа
@app.route('/api/verify_key')
def verify_key():
    key = request.args.get('key')
    hwid = request.args.get('hwid')
    if not key or not hwid:
        return "invalid"

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('SELECT created_at, used, hwid FROM keys WHERE key = ?', (key,))
    row = c.fetchone()
    conn.close()

    if not row:
        return "invalid"
    created_at_str, used, stored_hwid = row
    created_at = datetime.fromisoformat(created_at_str)

    if hwid != stored_hwid:
        return "hwid_mismatch"
    if used:
        return "used"
    if datetime.utcnow() - created_at > timedelta(hours=24):
        return "expired"

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('UPDATE keys SET used = 1 WHERE key = ?', (key,))
    conn.commit()
    conn.close()

    return "valid"

# Декодирование и редирект на верификацию
@app.route('/verify/<encoded>')
def verify_encoded(encoded):
    try:
        decoded = base64.urlsafe_b64decode(encoded).decode()
        hwid, key = decoded.split(":", 1)
        return redirect(f"/api/verify_key?key={key}&hwid={hwid}")
    except Exception:
        return "invalid encoded string", 400

# Отдача файлов
@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/style.css')
def serve_css():
    return send_from_directory('.', 'style.css')

# Запуск
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
