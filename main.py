import os
import random
import string
import sqlite3
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_from_directory

app = Flask(__name__)

DB_NAME = 'keys.db'

# Инициализация базы данных SQLite
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
    conn.commit()
    conn.close()

init_db()

# Генерация ключа: только строчные буквы и цифры, длина 12
def generate_key(length=12):
    chars = string.ascii_lowercase + string.digits
    return ''.join(random.choices(chars, k=length))

# Эндпоинт для получения нового ключа
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

# Эндпоинт для проверки ключа
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

    # Отмечаем ключ как использованный
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('UPDATE keys SET used = 1 WHERE key = ?', (key,))
    conn.commit()
    conn.close()

    return "valid"

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
