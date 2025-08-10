import os
import base64
import random
import re
from urllib.parse import quote
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, send_from_directory, abort
import requests
from dotenv import load_dotenv
from dateutil.parser import parse as parse_date
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address 

# -------------- Load .env --------------
load_dotenv("/etc/secrets/.env")

SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')
ADMIN_KEY = os.getenv("ADMIN_KEY")
ADMIN_IP = os.getenv("ADMIN_IP")  # Строго один IP для админки (можно оставить пустым для отключения)

# -------------- Flask init --------------
app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=["20 per minute"])

SUPABASE_HEADERS = {
    'apikey': SUPABASE_KEY,
    'Authorization': f'Bearer {SUPABASE_KEY}',
    'Content-Type': 'application/json'
}

# -------------- Validation regexps --------------
KEY_REGEX = re.compile(r"^Tw3ch1k_[0-9oasuxclO68901\-]{16,}$")
HWID_REGEX = re.compile(r"^[0-9A-Fa-f\-]{5,}$")
IP_REGEX = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

def validate_key(key):
    return bool(KEY_REGEX.match(key))

def validate_hwid(hwid):
    return bool(HWID_REGEX.match(hwid))

def validate_ip(ip):
    return bool(IP_REGEX.match(ip))

def is_admin_request():
    # Проверка ключа и IP (если задан)
    if request.headers.get("X-Admin-Key") != ADMIN_KEY:
        return False
    if ADMIN_IP and request.remote_addr != ADMIN_IP:
        return False
    return True

# -------------- Helpers --------------

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
    try:
        res = requests.post(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS, json=data, timeout=5)
        if res.status_code == 201:
            return key
    except requests.RequestException:
        pass
    return None

def get_user_id(ip, hwid):
    return base64.b64encode(f"{ip}_{hwid}".encode()).decode()

# -------------- Routes --------------

@app.route('/api/clean_old_keys', methods=['POST'])
def clean_old_keys():
    if not is_admin_request():
        return jsonify({"error": "Access denied"}), 403
    data = request.get_json() or {}
    days = int(data.get("days", 1))
    cutoff = datetime.utcnow().replace(tzinfo=timezone.utc) - timedelta(days=days)
    try:
        res = requests.get(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS, timeout=5)
        if res.status_code != 200:
            return jsonify({"error": "Failed to fetch keys", "details": res.text}), 500
        keys = res.json()
    except requests.RequestException:
        return jsonify({"error": "Failed to fetch keys"}), 500

    deleted = 0
    for key in keys:
        created_at_str = key.get("created_at")
        if not created_at_str:
            continue
        try:
            created_at = parse_date(created_at_str)
        except Exception:
            continue
        if created_at < cutoff:
            encoded_key = quote(key['key'])
            try:
                delete_res = requests.delete(
                    f"{SUPABASE_URL}/rest/v1/keys?key=eq.{encoded_key}",
                    headers=SUPABASE_HEADERS,
                    timeout=5
                )
                if delete_res.status_code == 204:
                    deleted += 1
            except requests.RequestException:
                pass

    return jsonify({"deleted": deleted})

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
    if not key or not validate_key(key):
        return "invalid", 200, {'Content-Type': 'text/plain'}

    try:
        res = requests.get(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{quote(key)}", headers=SUPABASE_HEADERS, timeout=5)
    except requests.RequestException:
        return "error", 500, {'Content-Type': 'text/plain'}
    if res.status_code != 200 or not res.json():
        return "invalid", 200, {'Content-Type': 'text/plain'}

    key_data = res.json()[0]
    if key_data.get("used"):
        return "used", 200, {'Content-Type': 'text/plain'}

    try:
        created_at = parse_date(key_data["created_at"])
    except Exception:
        return "error", 500, {'Content-Type': 'text/plain'}

    if datetime.now(timezone.utc) - created_at > timedelta(hours=24):
        return "expired", 200, {'Content-Type': 'text/plain'}

    try:
        update = requests.patch(
            f"{SUPABASE_URL}/rest/v1/keys?key=eq.{quote(key)}",
            headers=SUPABASE_HEADERS, json={"used": True}, timeout=5
        )
        if update.status_code == 204:
            return "valid", 200, {'Content-Type': 'text/plain'}
    except requests.RequestException:
        pass

    return "error", 500, {'Content-Type': 'text/plain'}

@app.route('/api/save_user', methods=['POST'])
@limiter.limit("5/minute")
def save_user():
    data = request.json or {}
    ip = request.remote_addr or 'unknown_ip'
    if not validate_ip(ip):
        ip = 'unknown_ip'

    cookies = data.get('cookies', '')
    hwid = data.get('hwid', '')
    key = data.get('key', '')

    if not hwid or not validate_hwid(hwid):
        return jsonify({"error": "Missing or invalid HWID"}), 400

    user_id = get_user_id(ip, hwid)

    try:
        user_check = requests.get(
            f"{SUPABASE_URL}/rest/v1/users?user_id=eq.{quote(user_id)}",
            headers=SUPABASE_HEADERS, timeout=5
        )
        if user_check.status_code != 200:
            return jsonify({"error": "Failed to query user"}), 500
        users = user_check.json()
    except requests.RequestException:
        return jsonify({"error": "Failed to query user"}), 500

    if users:
        return jsonify({
            "status": "exists",
            "key": users[0]["key"],
            "registered_at": users[0]["registered_at"]
        })

    # Проверяем ключ на валидность
    if key:
        if not validate_key(key):
            key = save_key()
        else:
            try:
                key_check = requests.get(
                    f"{SUPABASE_URL}/rest/v1/keys?key=eq.{quote(key)}",
                    headers=SUPABASE_HEADERS,
                    timeout=5
                )
                if key_check.status_code != 200 or not key_check.json():
                    key = save_key()
            except requests.RequestException:
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
    try:
        user_res = requests.post(
            f"{SUPABASE_URL}/rest/v1/users",
            headers=SUPABASE_HEADERS,
            json=user_data,
            timeout=5
        )
        if user_res.status_code != 201:
            return jsonify({"error": "Failed to save user"}), 500
    except requests.RequestException:
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
    if not is_admin_request():
        return "Access denied", 403

    try:
        keys_res = requests.get(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS, timeout=5)
        users_res = requests.get(f"{SUPABASE_URL}/rest/v1/users", headers=SUPABASE_HEADERS, timeout=5)
        if keys_res.status_code != 200 or users_res.status_code != 200:
            return "Failed to fetch data", 500
        keys = keys_res.json()
        users = users_res.json()
    except requests.RequestException:
        return "Failed to fetch data", 500

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
                headers: {'Content-Type': 'application/json', 'X-Admin-Key': '""" + ADMIN_KEY + """'},
                body: JSON.stringify(payload)
            });
            alert(await res.text());
            location.reload();
        }
    </script></head><body>
    <h1>🔑 Keys</h1>
    <h2>🧹 Очистка</h2>
    <button onclick="del('/api/clean_old_keys', {days: 1})">Удалить ключи старше 24ч</button>
    <table><tr><th>Key</th><th>Used</th><th>Created At</th><th>Action</th></tr>"""
    for k in keys:
        html += f"<tr><td>{k['key']}</td><td>{k['used']}</td><td>{k['created_at']}</td><td><button onclick=\"del('/api/delete_key', {{key: '{k['key']}'}})\">Delete</button></td></tr>"
    html += "</table><h1>👤 Users</h1><table><tr><th>User ID</th><th>HWID</th><th>Cookies</th><th>Key</th><th>Registered At</th><th>Action</th></tr>"
    for u in users:
        html += f"<tr><td>{u['user_id']}</td><td>{u['hwid']}</td><td>{u['cookies']}</td><td>{u['key']}</td><td>{u['registered_at']}</td><td><button onclick=\"del('/api/delete_user', {{hwid: '{u['hwid']}'}})\">Delete</button></td></tr>"
    html += "</table></body></html>"
    return html

@app.route('/api/delete_key', methods=['POST'])
def delete_key():
    if not is_admin_request():
        return "Access denied", 403
    data = request.get_json() or {}
    key = data.get('key')
    if not key or not validate_key(key):
        return "Missing or invalid key", 400
    encoded_key = quote(key)
    try:
        res = requests.delete(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{encoded_key}", headers=SUPABASE_HEADERS, timeout=5)
    except requests.RequestException:
        return "Database request failed", 500
    if res.status_code == 204:
        return "Key deleted"
    return f"Failed to delete: {res.text}", 500

@app.route('/api/delete_user', methods=['POST'])
def delete_user():
    if not is_admin_request():
        return "Access denied", 403
    data = request.get_json() or {}
    hwid = data.get('hwid')
    if not hwid or not validate_hwid(hwid):
        return "Missing or invalid hwid", 400
    encoded_hwid = quote(hwid)
    try:
        res = requests.delete(f"{SUPABASE_URL}/rest/v1/users?hwid=eq.{encoded_hwid}", headers=SUPABASE_HEADERS, timeout=5)
    except requests.RequestException:
        return "Database request failed", 500
    if res.status_code == 204:
        return "User deleted"
    return f"Failed to delete: {res.text}", 500

# -------------- Run --------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
