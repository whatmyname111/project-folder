import os
import random
import string
import sqlite3
import base64
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_from_directory

app = Flask(__name__)
DB_NAME = 'keys.db'

# Получение настоящего IP при работе через прокси (Render)
@app.before_request
def fix_render_proxy():
    if 'X-Forwarded-For' in request.headers:
        request.remote_addr = request.headers['X-Forwarded-For'].split(',')[0].strip()

# Инициализация базы данных
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            key TEXT PRIMARY KEY,
            created_at TEXT,
            used INTEGER DEFAULT 0
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            hwid TEXT PRIMARY KEY,
            ip TEXT,
            cookies TEXT,
            key TEXT,
            registered_at TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Генерация ключа
def generate_key(length=19, prefix="Free_"):
    chars = string.ascii_lowercase + string.digits
    return prefix + ''.join(random.choices(chars, k=length))

# Эндпоинт генерации ключа
@app.route('/api/get_key')
def get_key():
    key = generate_key()
    created_at = datetime.utcnow().isoformat()

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('INSERT INTO keys (key, created_at, used) VALUES (?, ?, 0)', (key, created_at))
    conn.commit()
    conn.close()

    return jsonify({'key': key})

# Эндпоинт проверки ключа
@app.route('/api/verify_key')
def verify_key():
    key = request.args.get('key')
    if not key:
        return "invalid"

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('SELECT created_at, used FROM keys WHERE key = ?', (key,))
    row = c.fetchone()
    conn.close()

    if not row:
        return "invalid"

    created_at_str, used = row
    created_at = datetime.fromisoformat(created_at_str)

    if used:
        return "used"

    if datetime.utcnow() - created_at > timedelta(hours=24):
        return "expired"

    return "valid"

# Эндпоинт регистрации пользователя
@app.route('/api/save_user', methods=['POST'])
def save_user():
    data = request.json
    ip = request.remote_addr or 'unknown_ip'
    cookies = data.get('cookies', '')
    hwid = data.get('hwid', '')
    key = data.get('key', '')

    if not hwid or not key:
        return jsonify({'status': 'error', 'message': 'Missing hwid or key'}), 400

    # Проверка ключа на валидность и срок
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('SELECT created_at, used FROM keys WHERE key = ?', (key,))
    row = c.fetchone()

    if not row:
        conn.close()
        return jsonify({'status': 'error', 'message': 'Invalid key'}), 400

    created_at_str, used = row
    created_at = datetime.fromisoformat(created_at_str)

    if used:
        conn.close()
        return jsonify({'status': 'error', 'message': 'Key already used'}), 400

    if datetime.utcnow() - created_at > timedelta(hours=24):
        conn.close()
        return jsonify({'status': 'error', 'message': 'Key expired'}), 400

    # Проверка, зарегистрирован ли уже этот hwid
    c.execute('SELECT key, registered_at FROM users WHERE hwid = ?', (hwid,))
    user_row = c.fetchone()

    if user_row:
        existing_key, registered_at = user_row
        conn.close()
        return jsonify({
            "status": "exists",
            "key": existing_key,
            "registered_at": registered_at
        })

    # Регистрируем нового пользователя
    registered_at = datetime.utcnow().isoformat()
    c.execute('INSERT INTO users (hwid, ip, cookies, key, registered_at) VALUES (?, ?, ?, ?, ?)',
              (hwid, ip, cookies, key, registered_at))
    c.execute('UPDATE keys SET used = 1 WHERE key = ?', (key,))
    conn.commit()
    conn.close()

    return jsonify({
        "status": "saved",
        "key": key,
        "registered_at": registered_at
    })

# Отдача index.html
@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

# Отдача style.css
@app.route('/style.css')
def serve_css():
    return send_from_directory('.', 'style.css')

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
