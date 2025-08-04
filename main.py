import os
import random
import string
import base64
import requests
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_from_directory

app = Flask(__name__)

SUPABASE_URL = 'https://kuhunkdgbtedgrujwxoy.supabase.co'
SUPABASE_KEY = os.environ.get('SUPABASE_KEY') or 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imt1aHVua2RnYnRlZGdydWp3eG95Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTQyOTMyODEsImV4cCI6MjA2OTg2OTI4MX0.N5I9bGTroqMDD9g0b-3lqMMip0NFRDTH30dh_hQ9kJY'
SUPABASE_HEADERS = {
    'apikey': SUPABASE_KEY,
    'Authorization': f'Bearer {SUPABASE_KEY}',
    'Content-Type': 'application/json'
}

def generate_key(length=16):
    CUSTOM_LETTERS = 'aoItlcxrfbwnO'
    CUSTOM_DIGITS = '1236890'
    digits_count = int(length * 0.7)
    letters_count = length - digits_count
    digits = random.choices(CUSTOM_DIGITS, k=digits_count)
    letters = random.choices(CUSTOM_LETTERS, k=letters_count)
    key_chars = digits + letters
    random.shuffle(key_chars)
    key = ''.join(key_chars)
    return f"Tw3ch1k_{key}"
@app.route('/api/get_key')
def get_key():
    key = generate_key()
    created_at = datetime.utcnow().isoformat()

    data = {
        "key": key,
        "created_at": created_at,
        "used": False
    }

    res = requests.post(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS, json=data)

    if res.status_code == 201:
        return jsonify({"key": key})
    else:
        return jsonify({"error": "Failed to save key", "details": res.text}), 500

@app.route('/api/verify_key')
def verify_key():
    key = request.args.get('key')
    if not key:
        return "invalid"

    res = requests.get(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{key}", headers=SUPABASE_HEADERS)
    if res.status_code != 200 or not res.json():
        return "invalid"

    key_data = res.json()[0]
    created_at = datetime.fromisoformat(key_data['created_at'])
    used = key_data['used']

    if used:
        return "used"

    if datetime.utcnow() - created_at > timedelta(hours=24):
        return "expired"

    # Обновление used = true
    update_res = requests.patch(
        f"{SUPABASE_URL}/rest/v1/keys?key=eq.{key}",
        headers=SUPABASE_HEADERS,
        json={"used": True}
    )
    if update_res.status_code == 204:
        return "valid"
    else:
        return "error"

@app.route('/api/save_user', methods=['POST'])
def save_user():
    data = request.json
    ip = request.remote_addr or 'unknown_ip'
    cookies = data.get('cookies', '')
    hwid = data.get('hwid', '')
    key = data.get('key', '')

    user_id = hwid or base64.b64encode(ip.encode()).decode()

    # Проверяем наличие пользователя
    res = requests.get(f"{SUPABASE_URL}/rest/v1/users?user_id=eq.{user_id}", headers=SUPABASE_HEADERS)
    if res.status_code != 200:
        return jsonify({"error": "Failed to query user", "details": res.text}), 500

    rows = res.json()
    if rows:
        return jsonify({
            "status": "exists",
            "key": rows[0]["key"],
            "registered_at": rows[0]["registered_at"]
        })

    registered_at = datetime.utcnow().isoformat()
    user_data = {
        "user_id": user_id,
        "cookies": cookies,
        "hwid": hwid,
        "key": key,
        "registered_at": registered_at
    }

    res = requests.post(f"{SUPABASE_URL}/rest/v1/users", headers=SUPABASE_HEADERS, json=user_data)
    if res.status_code == 201:
        return jsonify({
            "status": "saved",
            "key": key,
            "registered_at": registered_at
        })
    else:
        return jsonify({"error": "Failed to save user", "details": res.text}), 500

@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/style.css')
def serve_css():
    return send_from_directory('.', 'style.css')

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
