import os
import random
import string
import sqlite3
import base64
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_from_directory

app = Flask(__name__)

DB_NAME = 'keys.db'

# Инициализация базы данных SQLite
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    # Таблица для ключей
    c.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            key TEXT PRIMARY KEY,
            created_at TEXT,
            used INTEGER DEFAULT 0
        )
    ''')
    # Таблица для пользователей
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            cookies TEXT,
            hwid TEXT,
            key TEXT,
            registered_at TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

# Генерация ключа: только строчные буквы и цифры, длина 16
def generate_key(length=16):
    chars = string.ascii_lowercase + string.digits
    key_part = ''.join(random.choices(chars, k=length))
    return f"Tw3ch1k_{key_part}"

# Эндпоинт для получения нового ключа
@app.route('/api/get_key')
def get_key():
    key = generate_key()
    created_at = datetime.utcnow().isoformat()

    conn = get_db_connection()
    c = conn.cursor()
    c.execute('INSERT INTO keys (key, created_at, used) VALUES (?, ?, 0)', (key, created_at))
    conn.commit()
    conn.close()

    return jsonify({'key': key})

# Эндпоинт для проверки ключа
@app.route('/api/verify_key')
def verify_key():
    key = request.args.get('key')

    if not key:
        return "invalid"

    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT created_at, used FROM keys WHERE key = ?', (key,))
    row = c.fetchone()
    conn.close()

    if not row:
        return "invalid"

    created_at_str, used = row['created_at'], row['used']
    created_at = datetime.fromisoformat(created_at_str)

    if used:
        return "used"

    if datetime.utcnow() - created_at > timedelta(hours=24):
        return "expired"

    # Отмечаем ключ как использованный
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('UPDATE keys SET used = 1 WHERE key = ?', (key,))
    conn.commit()
    conn.close()

    return "valid"

# Эндпоинт для сохранения пользователя (IP, cookies, hwid, key, дата регистрации)
@app.route('/api/save_user', methods=['POST'])
def save_user():
    data = request.json
    ip = request.remote_addr or 'unknown_ip'
    cookies = data.get('cookies', '')
    hwid = data.get('hwid', '')
    key = data.get('key', '')

    user_id = hwid or base64.b64encode(ip.encode()).decode()

    conn = get_db_connection()
    c = conn.cursor()

    # Проверяем есть ли пользователь
    c.execute('SELECT key, registered_at FROM users WHERE user_id = ?', (user_id,))
    row = c.fetchone()

    if row:
        existing_key, registered_at = row['key'], row['registered_at']
        conn.close()
        return jsonify({
            "status": "exists",
            "key": existing_key,
            "registered_at": registered_at
        })

    # Если пользователя нет — создаём новую запись с текущей датой
    registered_at = datetime.utcnow().isoformat()
    c.execute('INSERT INTO users (user_id, cookies, hwid, key, registered_at) VALUES (?, ?, ?, ?, ?)',
              (user_id, cookies, hwid, key, registered_at))
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
