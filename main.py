import os
import base64
import random
import re
import ipaddress
from urllib.parse import quote
from datetime import datetime, timedelta, timezone

import requests
from dotenv import load_dotenv
from dateutil.parser import parse as parse_date
from flask import Flask, request, jsonify, send_from_directory, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC 
# ----------------------
# Constants / Config
# ----------------------
load_dotenv('/etc/secrets/.env')

SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')
ADMIN_KEY = os.getenv('ADMIN_KEY')
ADMIN_IP = os.getenv('ADMIN_IP')
ADMIN_PASS = os.getenv('ADMIN_PASS')

SUPABASE_HEADERS = {
    'apikey': SUPABASE_KEY,
    'Authorization': f"Bearer {SUPABASE_KEY}",
    'Content-Type': 'application/json'
}

# Regex
KEY_REGEX = re.compile(r'^Tw3ch1k_[0-9oasuxclO68901\-]{16,}$')
HWID_REGEX = re.compile(r'^[0-9A-Fa-f\-]{5,}$')

# Error messages
ERR_DB_FAIL = 'Database request failed'
ERR_ACCESS_DENIED = 'Access denied'
ERR_SAVE_KEY = 'Failed to save key'

# Flask app
app = Flask(__name__)
app.secret_key = os.getenv("ADMIN_SESSION_KEY")  # секрет для сессий
app.config['SESSION_COOKIE_NAME'] = os.getenv("sskk")
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
CORS(app, resources={r"/api/*": {"origins": ["ads.luarmor.net", "curl"]}})
limiter = Limiter(get_remote_address, app=app, default_limits=['20 per minute'])

# ----------------------
# Utility functions
# ----------------------
def validate_key(key: str) -> bool:
    return bool(KEY_REGEX.match(key))

def validate_hwid(hwid: str) -> bool:
    return bool(HWID_REGEX.match(hwid))

def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_admin_request() -> bool:
    """Check if request has valid admin key"""
    admin_header = request.headers.get('X-Admin-Key')
    admin_arg = request.args.get('d')
    key = admin_header or admin_arg
    return key == ADMIN_KEY

def generate_key(length: int = 16) -> str:
    chars_main = 'oasuxclO'
    chars_digits = '68901'
    num_digits = int(length * 0.7)
    num_main = length - num_digits
    key_chars = random.choices(chars_digits, k=num_digits) + random.choices(chars_main, k=num_main)
    random.shuffle(key_chars)
    key_str = ''.join(key_chars)
    return "Tw3ch1k_" + "-".join([key_str[i:i+4] for i in range(0, len(key_str), 4)])

def save_key(key: str = None) -> str:
    """Generate and save key to Supabase"""
    key = key or generate_key()
    payload = {
        'key': key,
        'created_at': datetime.now().isoformat(),
        'used': False
    }
    try:
        resp = requests.post(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS, json=payload, timeout=5)
        if resp.status_code == 201:
            return key
    except requests.RequestException:
        pass
    return None

def get_user_id(ip: str, hwid: str) -> str:
    return base64.b64encode(f"{ip}_{hwid}".encode()).decode()

# ----------------------
# API Routes
# ----------------------
@app.route('/api/clean_old_keys', methods=['POST'])
def clean_old_keys():
    if not is_admin_request():
        return jsonify({'error': ERR_ACCESS_DENIED}), 403

    data = request.get_json() or {}
    days = int(data.get('days', 1))
    threshold = datetime.now().replace(tzinfo=timezone.utc) - timedelta(days=days)

    try:
        resp = requests.get(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS, timeout=5)
        if resp.status_code != 200:
            return jsonify({'error': 'Failed to fetch keys', 'details': resp.text}), 500
        keys = resp.json()
    except requests.RequestException:
        return jsonify({'error': 'Failed to fetch keys'}), 500

    deleted_count = 0
    for key_entry in keys:
        created = key_entry.get('created_at')
        if not created:
            continue
        try:
            created_dt = parse_date(created)
        except Exception:
            continue
        if created_dt < threshold:
            try:
                k = quote(key_entry['key'])
                del_resp = requests.delete(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{k}", headers=SUPABASE_HEADERS, timeout=5)
                if del_resp.status_code == 204:
                    deleted_count += 1
            except requests.RequestException:
                pass
    return jsonify({'deleted': deleted_count})

@app.route('/api/get_key')
@limiter.limit('10/minute')
def get_key():
    key = save_key()
    if not key:
        return jsonify({'error': ERR_SAVE_KEY}), 500
    return jsonify({'key': key})

@app.route('/api/verify_key')
@limiter.limit('20/minute')
def verify_key():
    key = request.args.get('key')
    ADMIN_GAME = os.getenv("ADMIN_GAME")
    if key == ADMIN_GAME:
        return "valid", 200, {'Content-Type': 'text/plain'}
        
    if not key or not validate_key(key):
        return 'invalid', 200, {'Content-Type': 'text/plain'}    
    try:
        resp = requests.get(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{quote(key)}", headers=SUPABASE_HEADERS, timeout=5)
    except requests.RequestException:
        return 'error', 500, {'Content-Type': 'text/plain'}

    if resp.status_code != 200 or not resp.json():
        return 'invalid', 200, {'Content-Type': 'text/plain'}

    key_data = resp.json()[0]
    if key_data.get('used'):
        return 'used', 200, {'Content-Type': 'text/plain'}

    try:
        created_at = parse_date(key_data['created_at'])
    except Exception:
        return 'error', 500, {'Content-Type': 'text/plain'}

    if datetime.now(timezone.utc) - created_at > timedelta(hours=24):
        return 'expired', 200, {'Content-Type': 'text/plain'}

    try:
        patch_resp = requests.patch(
            f"{SUPABASE_URL}/rest/v1/keys?key=eq.{quote(key)}",
            headers=SUPABASE_HEADERS,
            json={'used': True},
            timeout=5
        )
        if patch_resp.status_code == 204:
            return 'valid', 200, {'Content-Type': 'text/plain'}
    except requests.RequestException:
        pass

    return 'error', 500, {'Content-Type': 'text/plain'}

@app.route('/api/save_user', methods=['POST'])
@limiter.limit('50/minute')
def save_user():
    data = request.json or {}
    remote_ip = request.remote_addr or 'unknown_ip'
    if not validate_ip(remote_ip):
        remote_ip = 'unknown_ip'

    hwid = data.get('hwid')
    cookies = data.get('cookies', '')
    key = data.get('key')

    if not hwid or not validate_hwid(hwid):
        return jsonify({'error': 'Missing or invalid HWID'}), 400

    user_id = get_user_id(remote_ip, hwid)

    try:
        resp = requests.get(f"{SUPABASE_URL}/rest/v1/users?user_id=eq.{quote(user_id)}", headers=SUPABASE_HEADERS, timeout=5)
        if resp.status_code != 200:
            return jsonify({'error': 'Failed to query user'}), 500
        existing_users = resp.json()
    except requests.RequestException:
        return jsonify({'error': 'Failed to query user'}), 500

    if existing_users:
        u = existing_users[0]
        return jsonify({'status': 'exists', 'key': u['key'], 'registered_at': u['registered_at']})

    if key:
        if not validate_key(key):
            key = save_key()
        else:
            try:
                resp = requests.get(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{quote(key)}", headers=SUPABASE_HEADERS, timeout=5)
                if resp.status_code != 200 or not resp.json():
                    key = save_key()
            except requests.RequestException:
                key = save_key()
    else:
        key = save_key()

    if not key:
        return jsonify({'error': ERR_SAVE_KEY}), 500

    payload = {
        'user_id': user_id,
        'cookies': cookies,
        'hwid': hwid,
        'key': key,
        'registered_at': datetime.utcnow().isoformat()
    }

    try:
        resp = requests.post(f"{SUPABASE_URL}/rest/v1/users", headers=SUPABASE_HEADERS, json=payload, timeout=5)
        if resp.status_code != 201:
            return jsonify({'error': 'Failed to save user'}), 500
    except requests.RequestException:
        return jsonify({'error': 'Failed to save user'}), 500

    return jsonify({'status': 'saved', 'key': key, 'registered_at': payload['registered_at']})

# ----------------------
# Static Routes
# ----------------------
@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/style.css')
def serve_css():
    return send_from_directory('.', 'style.css')

# ----------------------
# Admin Panel
# ----------------------
@app.route('/user/admin', methods=['GET', 'POST'])
def admin_panel():
    session.permanent = True  # включаем постоянную сессию
    if session.get('admin_xd'):
        return render_admin_page()

    if request.method == "POST":
        if request.is_json:
            data = request.get_json()
            passwrd = data.get("passwrd")
        else:
            passwrd = request.form.get("passwrd")

        if passwrd == ADMIN_PASS or is_admin_request():
            session['admin_xd'] = True
            return render_admin_page()
        else:
            return "Неверный пароль!", 403

    return '''
        <form method="post">
            Пароль: <input type="password" name="passwrd">
            <input type="submit" value="Войти">
        </form>
    '''

def render_admin_page():
    try:
        # Получаем данные из Supabase
        keys_resp = requests.get(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS, timeout=5)
        users_resp = requests.get(f"{SUPABASE_URL}/rest/v1/users", headers=SUPABASE_HEADERS, timeout=5)
        if keys_resp.status_code != 200 or users_resp.status_code != 200:
            return 'Failed to fetch data', 500
        keys_data = keys_resp.json()
        users_data = users_resp.json()
    except requests.RequestException:
        return 'Failed to fetch data', 500

    # HTML с темной темой и кнопками
    html = f"""
    <html>
    <head>
        <title>Admin Panel</title>
        <style>
            body {{ font-family: Arial; padding: 20px; background-color:#1e1e2f; color:#fff; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 30px; }}
            th, td {{ border: 1px solid #444; padding: 8px; text-align: left; }}
            th {{ background: #333; }}
            button {{
                padding: 5px 10px;
                cursor: pointer;
                border: none;
                border-radius: 5px;
                color: #fff;
            }}
            .delete-key {{ background-color:#e74c3c; }}
            .delete-user {{ background-color:#c0392b; }}
            .clean-old {{ background-color:#3498db; margin-bottom:15px; }}
        </style>
        <script>
            function deleteKey(key) {{
                fetch('/api/delete_key', {{
                    method: 'POST',
                    headers: {{'Content-Type':'application/json','X-Admin-Key':'{ADMIN_KEY}'}},
                    body: JSON.stringify({{key:key}})
                }}).then(r => r.text()).then(alert);
            }}
            function deleteUser(hwid) {{
                fetch('/api/delete_user', {{
                    method: 'POST',
                    headers: {{'Content-Type':'application/json','X-Admin-Key':'{ADMIN_KEY}'}},
                    body: JSON.stringify({{hwid:hwid}})
                }}).then(r => r.text()).then(alert);
            }}
            function cleanOldKeys() {{
                let days = prompt("Удалить ключи старше (дней):", "1");
                if (!days) return;
                fetch('/api/clean_old_keys', {{
                    method: 'POST',
                    headers: {{'Content-Type':'application/json','X-Admin-Key':'{ADMIN_KEY}'}},
                    body: JSON.stringify({{days: parseInt(days)}})
                }})
                .then(r => r.json())
                .then(data => alert("Удалено ключей: " + data.deleted));
            }}
        </script>
    </head>
    <body>
        <h1>Admin Panel</h1>
        <button class="clean-old" onclick="cleanOldKeys()">Удалить старые ключи</button>
        <h2>Keys</h2>
        <table>
            <tr><th>Key</th><th>Used</th><th>Created At</th><th>Action</th></tr>
    """

    # Таблица ключей
    for k in keys_data:
        html += f"<tr><td>{k['key']}</td><td>{k['used']}</td><td>{k['created_at']}</td>"
        html += f"<td><button class='delete-key' onclick=\"deleteKey('{k['key']}')\">Delete</button></td></tr>"

    # Таблица пользователей
    html += "</table><h2>Users</h2><table><tr><th>User ID</th><th>HWID</th><th>Cookies</th><th>Key</th><th>Registered At</th><th>Action</th></tr>"

    for u in users_data:
        html += f"<tr><td>{u['user_id']}</td><td>{u['hwid']}</td><td>{u['cookies']}</td><td>{u['key']}</td><td>{u['registered_at']}</td>"
        html += f"<td><button class='delete-user' onclick=\"deleteUser('{u['hwid']}')\">Delete</button></td></tr>"

    html += "</table></body></html>"

    return html

    html += "<h1>Keys</h1><table><tr><th>Key</th><th>Used</th><th>Created At</th><th>Action</th></tr>"
    for k in keys_data:
        html += f"<tr><td>{k['key']}</td><td>{k['used']}</td><td>{k['created_at']}</td>"
        html += f"<td><button onclick=\"deleteKey('{k['key']}')\">Delete</button></td></tr>"
    html += "</table>"

    html += "<h1>Users</h1><table><tr><th>User ID</th><th>HWID</th><th>Cookies</th><th>Key</th><th>Registered At</th><th>Action</th></tr>"
    for u in users_data:
        html += f"<tr><td>{u['user_id']}</td><td>{u['hwid']}</td><td>{u['cookies']}</td><td>{u['key']}</td><td>{u['registered_at']}</td>"
        html += f"<td><button onclick=\"deleteUser('{u['hwid']}')\">Delete</button></td></tr>"
    html += "</table></body></html>"
    return html

# ----------------------
# Delete Endpoints
# ----------------------
@app.route('/api/delete_key', methods=['POST'])
def delete_key():
    if not is_admin_request():
        return ERR_ACCESS_DENIED, 403

    data = request.get_json() or {}
    key = data.get('key')
    if not key or not validate_key(key):
        return 'Missing or invalid key', 400

    try:
        resp = requests.delete(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{quote(key)}", headers=SUPABASE_HEADERS, timeout=5)
    except requests.RequestException:
        return ERR_DB_FAIL, 500

    if resp.status_code == 204:
        return 'Key deleted'
    return f"Failed to delete: {resp.text}", 500

@app.route('/api/delete_user', methods=['POST'])
def delete_user():
    if not is_admin_request():
        return ERR_ACCESS_DENIED, 403

    data = request.get_json() or {}
    hwid = data.get('hwid')
    if not hwid or not validate_hwid(hwid):
        return 'Missing or invalid hwid', 400

    try:
        resp = requests.delete(f"{SUPABASE_URL}/rest/v1/users?hwid=eq.{quote(hwid)}", headers=SUPABASE_HEADERS, timeout=5)
    except requests.RequestException:
        return ERR_DB_FAIL, 500

    if resp.status_code == 204:
        return 'User deleted'
    return f"Failed to delete: {resp.text}", 500

# ----------------------
# Run app
# ----------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
