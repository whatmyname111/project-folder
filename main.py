from flask import Flask, request, jsonify, send_file
import json
import os
from datetime import datetime, timedelta
import threading
import string
import random

app = Flask(__name__)

KEYS_FILE = "keys.json"
KEY_LENGTH = 12
KEY_TTL_HOURS = 24

lock = threading.Lock()

def load_keys():
    if not os.path.exists(KEYS_FILE):
        return {}
    with open(KEYS_FILE, "r") as f:
        try:
            return json.load(f)
        except:
            return {}

def save_keys(keys):
    with open(KEYS_FILE, "w") as f:
        json.dump(keys, f, indent=4)

def generate_key(length=KEY_LENGTH):
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def cleanup_keys():
    while True:
        with lock:
            keys = load_keys()
            now = datetime.utcnow()
            keys_to_delete = []
            for k, v in keys.items():
                expires_at = datetime.fromisoformat(v["expires_at"])
                if now > expires_at:
                    keys_to_delete.append(k)
            for k in keys_to_delete:
                del keys[k]
            if keys_to_delete:
                save_keys(keys)
        # Ждем 1 час перед следующей проверкой
        threading.Event().wait(3600)

@app.route('/')
def index():
    return send_file('index.html')

@app.route('/style.css')
def style():
    return send_file('style.css')

@app.route('/api/get_key')
def get_key():
    with lock:
        keys = load_keys()
        # Генерим уникальный ключ
        while True:
            key = generate_key()
            if key not in keys:
                break
        now = datetime.utcnow()
        expires_at = now + timedelta(hours=KEY_TTL_HOURS)
        keys[key] = {
            "used": False,
            "created_at": now.isoformat(),
            "expires_at": expires_at.isoformat()
        }
        save_keys(keys)
    return jsonify({"key": key})

@app.route('/api/check', methods=['POST'])
def check_key():
    data = request.get_json(force=True)
    key = data.get('key', '').strip().upper()

    with lock:
        keys = load_keys()
        if key not in keys:
            return jsonify({"status": "invalid"})

        key_data = keys[key]
        expires_at = datetime.fromisoformat(key_data["expires_at"])
        now = datetime.utcnow()

        if now > expires_at:
            return jsonify({"status": "expected"})  # истек, но в базе

        if key_data["used"]:
            return jsonify({"status": "invalid"})

        # Если ключ активируется впервые
        keys[key]["used"] = True
        save_keys(keys)
        return jsonify({"status": "valid"})

if __name__ == '__main__':
    # Запускаем очистку ключей в отдельном потоке
    cleaner = threading.Thread(target=cleanup_keys, daemon=True)
    cleaner.start()
    app.run(host='0.0.0.0', port=10000)
