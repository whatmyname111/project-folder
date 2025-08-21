import os
import base64
import secrets
import re
import ipaddress
import html
import hashlib
from urllib.parse import quote
from datetime import datetime, timedelta, timezone

import httpx
from dotenv import load_dotenv
from dateutil.parser import parse as parse_date
from flask import Flask, request, jsonify, send_from_directory, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ----------------------
# Constants / Config
# ----------------------
load_dotenv('/etc/secrets/.env')

SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')
ADMIN_KEY = os.getenv('ADMIN_KEY')
ADMIN_IP = os.getenv('ADMIN_IP')  # Unused, but kept for compatibility
ADMIN_PASS = os.getenv('ADMIN_PASS')
ENCRYPTION_SECRET = os.getenv('ENCRYPTION_SECRET')
ENCRYPTION_SALT = base64.b64decode(os.getenv('ENCRYPTION_SALT', 'c29tZV9zYWx0Xw=='))  # Default for demo, set in env

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
def get_fernet():
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=ENCRYPTION_SALT,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(ENCRYPTION_SECRET.encode()))
    return Fernet(key)

fernet = get_fernet()

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

def is_admin_session() -> bool:
    return session.get('admin_xd', False)

def generate_key(length: int = 16) -> str:
    chars_main = 'oasuxclO'
    chars_digits = '68901'
    num_digits = int(length * 0.7)
    num_main = length - num_digits
    key_chars = [secrets.choice(chars_digits) for _ in range(num_digits)] + [secrets.choice(chars_main) for _ in range(num_main)]
    secrets.SystemRandom().shuffle(key_chars)  # Secure shuffle
    key_str = ''.join(key_chars)
    return "Tw3ch1k_" + "-".join([key_str[i:i+4] for i in range(0, len(key_str), 4)])

def save_key(key: str = None) -> str:
    """Generate and save key to Supabase"""
    key = key or generate_key()
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    key_enc = fernet.encrypt(key.encode()).decode()
    payload = {
        'key_hash': key_hash,
        'key_enc': key_enc,
        'created_at': datetime.now().isoformat(),
        'used': False
    }
    try:
        resp = httpx.post(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS, json=payload, timeout=5)
        if resp.status_code == 201:
            return key
    except httpx.RequestError:
        pass
    return None

def get_user_id(ip: str, hwid: str) -> str:
    return hashlib.sha256(f"{ip}_{hwid}".encode()).hexdigest()

# ----------------------
# API Routes
# ----------------------
@app.route('/api/clean_old_keys', methods=['POST'])
def clean_old_keys():
    if not is_admin_session():
        return jsonify({'error': ERR_ACCESS_DENIED}), 403

    data = request.get_json() or {}
    days = int(data.get('days', 1))
    threshold = datetime.now().replace(tzinfo=timezone.utc) - timedelta(days=days)

    try:
        resp = httpx.get(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS, timeout=5)
        if resp.status_code != 200:
            return jsonify({'error': 'Failed to fetch keys', 'details': resp.text}), 500
        keys = resp.json()
    except httpx.RequestError:
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
                del_resp = httpx.delete(f"{SUPABASE_URL}/rest/v1/keys?key_hash=eq.{quote(key_entry['key_hash'])}", headers=SUPABASE_HEADERS, timeout=5)
                if del_resp.status_code == 204:
                    deleted_count += 1
            except httpx.RequestError:
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
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    try:
        resp = httpx.get(f"{SUPABASE_URL}/rest/v1/keys?key_hash=eq.{quote(key_hash)}", headers=SUPABASE_HEADERS, timeout=5)
    except httpx.RequestError:
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
        patch_resp = httpx.patch(
            f"{SUPABASE_URL}/rest/v1/keys?key_hash=eq.{quote(key_hash)}",
            headers=SUPABASE_HEADERS,
            json={'used': True},
            timeout=5
        )
        if patch_resp.status_code == 204:
            return 'valid', 200, {'Content-Type': 'text/plain'}
    except httpx.RequestError:
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
        resp = httpx.get(f"{SUPABASE_URL}/rest/v1/users?user_id=eq.{quote(user_id)}", headers=SUPABASE_HEADERS, timeout=5)
        if resp.status_code != 200:
            return jsonify({'error': 'Failed to query user'}), 500
        existing_users = resp.json()
    except httpx.RequestError:
        return jsonify({'error': 'Failed to query user'}), 500

    if existing_users:
        u = existing_users[0]
        user_key = fernet.decrypt(u['key_enc'].encode()).decode()
        return jsonify({'status': 'exists', 'key': user_key, 'registered_at': u['registered_at']})

    if key:
        if not validate_key(key):
            key = save_key()
        else:
            key_hash = hashlib.sha256(key.encode()).hexdigest()
            try:
                resp = httpx.get(f"{SUPABASE_URL}/rest/v1/keys?key_hash=eq.{quote(key_hash)}", headers=SUPABASE_HEADERS, timeout=5)
                if resp.status_code != 200 or not resp.json():
                    key = save_key()
            except httpx.RequestError:
                key = save_key()
    else:
        key = save_key()

    if not key:
        return jsonify({'error': ERR_SAVE_KEY}), 500

    hwid_enc = fernet.encrypt(hwid.encode()).decode()
    cookies_enc = fernet.encrypt(cookies.encode()).decode()
    key_enc = fernet.encrypt(key.encode()).decode()
    registered_at = datetime.now().isoformat()
    payload = {
        'user_id': user_id,
        'hwid_enc': hwid_enc,
        'cookies_enc': cookies_enc,
        'key_enc': key_enc,
        'registered_at': registered_at
    }

    try:
        resp = httpx.post(f"{SUPABASE_URL}/rest/v1/users", headers=SUPABASE_HEADERS, json=payload, timeout=5)
        if resp.status_code != 201:
            return jsonify({'error': 'Failed to save user'}), 500
    except httpx.RequestError:
        return jsonify({'error': 'Failed to save user'}), 500

    return jsonify({'status': 'saved', 'key': key, 'registered_at': registered_at})

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

        if passwrd == ADMIN_PASS or is_admin_session():
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
        keys_resp = httpx.get(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS, timeout=5)
        users_resp = httpx.get(f"{SUPABASE_URL}/rest/v1/users", headers=SUPABASE_HEADERS, timeout=5)
        if keys_resp.status_code != 200 or users_resp.status_code != 200:
            return 'Failed to fetch data', 500
        keys_data = keys_resp.json()
        users_data = users_resp.json()
    except httpx.RequestError:
        return 'Failed to fetch data', 500

    # Decrypt for display
    for k in keys_data:
        k['key_dec'] = fernet.decrypt(k['key_enc'].encode()).decode()
    for u in users_data:
        u['hwid_dec'] = fernet.decrypt(u['hwid_enc'].encode()).decode()
        u['cookies_dec'] = fernet.decrypt(u['cookies_enc'].encode()).decode()
        u['key_dec'] = fernet.decrypt(u['key_enc'].encode()).decode()

    # HTML с темной темой и кнопками
    html_content = f"""
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
                    headers: {{'Content-Type':'application/json'}},
                    body: JSON.stringify({{key:key}})
                }}).then(r => r.text()).then(alert);
            }}
            function deleteUser(user_id) {{
                fetch('/api/delete_user', {{
                    method: 'POST',
                    headers: {{'Content-Type':'application/json'}},
                    body: JSON.stringify({{user_id:user_id}})
                }}).then(r => r.text()).then(alert);
            }}
            function cleanOldKeys() {{
                let days = prompt("Удалить ключи старше (дней):", "1");
                if (!days) return;
                fetch('/api/clean_old_keys', {{
                    method: 'POST',
                    headers: {{'Content-Type':'application/json'}},
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
        html_content += f"<tr><td>{html.escape(k['key_dec'])}</td><td>{html.escape(str(k['used']))}</td><td>{html.escape(k['created_at'])}</td>"
        html_content += f"<td><button class='delete-key' onclick=\"deleteKey('{html.escape(k['key_dec'])}')\">Delete</button></td></tr>"

    # Таблица пользователей
    html_content += "</table><h2>Users</h2><table><tr><th>User ID</th><th>HWID</th><th>Cookies</th><th>Key</th><th>Registered At</th><th>Action</th></tr>"

    for u in users_data:
        html_content += f"<tr><td>{html.escape(u['user_id'])}</td><td>{html.escape(u['hwid_dec'])}</td><td>{html.escape(u['cookies_dec'])}</td><td>{html.escape(u['key_dec'])}</td><td>{html.escape(u['registered_at'])}</td>"
        html_content += f"<td><button class='delete-user' onclick=\"deleteUser('{html.escape(u['user_id'])}')\">Delete</button></td></tr>"

    html_content += "</table></body></html>"

    return html_content

# ----------------------
# Delete Endpoints
# ----------------------
@app.route('/api/delete_key', methods=['POST'])
def delete_key():
    if not is_admin_session():
        return ERR_ACCESS_DENIED, 403

    data = request.get_json() or {}
    key = data.get('key')
    if not key or not validate_key(key):
        return 'Missing or invalid key', 400

    key_hash = hashlib.sha256(key.encode()).hexdigest()
    try:
        resp = httpx.delete(f"{SUPABASE_URL}/rest/v1/keys?key_hash=eq.{quote(key_hash)}", headers=SUPABASE_HEADERS, timeout=5)
    except httpx.RequestError:
        return ERR_DB_FAIL, 500

    if resp.status_code == 204:
        return 'Key deleted'
    return f"Failed to delete: {resp.text}", 500

@app.route('/api/delete_user', methods=['POST'])
def delete_user():
    if not is_admin_session():
        return ERR_ACCESS_DENIED, 403

    data = request.get_json() or {}
    user_id = data.get('user_id')
    if not user_id:
        return 'Missing user_id', 400

    try:
        resp = httpx.delete(f"{SUPABASE_URL}/rest/v1/users?user_id=eq.{quote(user_id)}", headers=SUPABASE_HEADERS, timeout=5)
    except httpx.RequestError:
        return ERR_DB_FAIL, 500

    if resp.status_code == 204:
        return 'User deleted'
    return f"Failed to delete: {resp.text}", 500

# ----------------------
# Run app
# ----------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
