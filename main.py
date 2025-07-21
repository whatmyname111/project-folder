from flask import Flask, request, jsonify, send_file
import json, os
from datetime import datetime, timedelta
import random, string

app = Flask(__name__)

KEYS_FILE = 'keys.json'
KEY_LENGTH = 16
KEY_TTL_HOURS = 24

def load_keys():
    if not os.path.exists(KEYS_FILE):
        return {}
    with open(KEYS_FILE, 'r') as f:
        return json.load(f)

def save_keys(keys):
    with open(KEYS_FILE, 'w') as f:
        json.dump(keys, f, indent=4)

def generate_key(length=KEY_LENGTH):
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

@app.route('/')
def index():
    return send_file('index.html')

@app.route('/style.css')
def style():
    return send_file('style.css')

@app.route('/api/get_key')
def get_key():
    keys = load_keys()
    while True:
        key = generate_key()
        if key not in keys:
            break
    expires_at = (datetime.utcnow() + timedelta(hours=KEY_TTL_HOURS)).isoformat()
    keys[key] = {
        "used": False,
        "created_at": datetime.utcnow().isoformat(),
        "expires_at": expires_at
    }
    save_keys(keys)
    return jsonify({"key": key})

@app.route('/api/check', methods=['POST'])
def check_key():
    data = request.get_json()
    key = data.get('key', '').strip().upper()
    keys = load_keys()

    if key not in keys:
        return jsonify({"status": "invalid"})

    key_data = keys[key]
    expires_at = datetime.fromisoformat(key_data['expires_at'])

    if datetime.utcnow() > expires_at:
        return jsonify({"status": "expired"})

    if key_data['used']:
        return jsonify({"status": "invalid"})

    keys[key]['used'] = True
    save_keys(keys)

    return jsonify({"status": "valid"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
