from flask import Flask, request, jsonify, send_file, make_response
from flask_cors import CORS
import json
import os
from datetime import datetime, timedelta
import threading
import string
import random
import time

app = Flask(__name__)
CORS(app)  # Разрешаем CORS для всех доменов (можно сузить)

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
        time.sleep(3600)

@app.route('/')
def index():
    return send_file('index.html')

@app.route('/style.css')
def style():
    return send_file('style.css')

@app.route('/api/get_key')
def get_key():
    cookie_key = request.cookies.get('user_key')
    now = datetime.utcnow()

    with lock:
        keys = load_keys()

        if cookie_key and cookie_key in keys:
            key_data = keys[cookie_key]
            expires_at = datetime.fromisoformat(key_data["expires_at"])
            if now < expires_at and not key_data["used"]:
                resp = make_response(jsonify({"key": cookie_key}))
                resp.set_cookie('user_key', cookie_key, max_age=KEY_TTL_HOURS*3600)
                return resp

        # Генерируем новый ключ
        while True:
            key = generate_key()
            if key not in keys:
                break

        expires_at = now + timedelta(hours=KEY_TTL_HOURS)
        keys[key] = {
            "used": False,
            "created_at": now.isoformat(),
            "expires_at": expires_at.isoformat()
        }
        save_keys(keys)

        resp = make_response(jsonify({"key": key}))
        resp.set_cookie('user_key', key, max_age=KEY_TTL_HOURS*3600)
        return resp

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
            del keys[key]
            save_keys(keys)
            return jsonify({"status": "expired"})

        if key_data["used"]:
            return jsonify({"status": "invalid"})

        keys[key]["used"] = True
        save_keys(keys)
        return jsonify({"status": "valid"})

if __name__ == '__main__':
    cleaner = threading.Thread(target=cleanup_keys, daemon=True)
    cleaner.start()
    app.run(host='0.0.0.0', port=10000)
