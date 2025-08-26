import os
import base64
import random
import re
import ipaddress
import hashlib
from urllib.parse import quote
from datetime import datetime, timedelta, timezone
from functools import wraps
import html
import threading
import time
import requests
from dotenv import load_dotenv
from dateutil.parser import parse as parse_date
from flask import Flask, request, jsonify, send_from_directory, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS

load_dotenv('/etc/secrets/.env')

SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')
SECRET_KEY = os.getenv("SECRET_KEY")
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
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
CORS(app, resources={r"/api/*": {"origins": ["https://www.roblox.com", "https://*.robloxlabs.com"]}})
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

def get_user_id(ip: str, hwid: str) -> str:
    return base64.b64encode(f"{ip}_{hwid}".encode()).decode()

def safe_html(s: str) -> str:
    return html.escape(s)

def generate_key(length: int = 16) -> str:
    chars_main = 'oasuxclO'
    chars_digits = '68901'
    num_digits = int(length * 0.7)
    num_main = length - num_digits
    key_chars = random.choices(chars_digits, k=num_digits) + random.choices(chars_main, k=num_main)
    random.shuffle(key_chars)
    key_str = ''.join(key_chars)
    return "Tw3ch1k_" + "-".join([key_str[i:i+4] for i in range(0, len(key_str), 4)])

def cleanup_old_keys_and_users():
    while True:
        try:
            # Время 24 часа назад
            threshold = datetime.now(timezone.utc) - timedelta(hours=24)

            # Получаем все ключи
            resp = requests.get(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS, timeout=10)
            if resp.status_code != 200:
                print("Failed to fetch keys")
                time.sleep(86400)
                continue

            keys = resp.json()
            for key_entry in keys:
                created_at = key_entry.get('created_at')
                key_value = key_entry.get('key')
                if not created_at or not key_value:
                    continue
                created_dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                if created_dt < threshold:
                    # Удаляем ключ
                    try:
                        del_resp = requests.delete(
                            f"{SUPABASE_URL}/rest/v1/keys?key=eq.{quote(key_value)}",
                            headers=SUPABASE_HEADERS,
                            timeout=5
                        )
                        if del_resp.status_code == 204:
                            print(f"Deleted key {key_value}")
                            # Удаляем пользователей с этим ключом
                            user_del = requests.delete(
                                f"{SUPABASE_URL}/rest/v1/users?key=eq.{quote(key_value)}",
                                headers=SUPABASE_HEADERS,
                                timeout=5
                            )
                            if user_del.status_code == 204:
                                print(f"Deleted users with key {key_value}")
                    except requests.RequestException:
                        pass

        except Exception as e:
            print("Cleanup error:", e)

        # Ждём 24 часа
        time.sleep(24 * 3600)

# Запуск в отдельном потоке
threading.Thread(target=cleanup_old_keys_and_users, daemon=True).start()
def save_key(key: str = None) -> str:
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

# ----------------------
# Admin decorators
# ----------------------
def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        secret = request.args.get('d')
        if secret != SECRET_KEY or not session.get('admin_authenticated'):
            return "Ur not admin!", 403
        return f(*args, **kwargs)
    return wrapper

# ----------------------
# API Routes
# ----------------------
@app.route('/api/clean_old_keys', methods=['POST'])
@require_admin
def clean_old_keys():
    data = request.get_json() or {}
    days = int(data.get('days', 1))
    threshold = datetime.now(timezone.utc) - timedelta(days=days)
    try:
        resp = requests.get(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS, timeout=5)
        keys = resp.json() if resp.status_code == 200 else []
    except requests.RequestException:
        return jsonify({'error': ERR_DB_FAIL}), 500

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
        existing_users = resp.json() if resp.status_code == 200 else []
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
def admin_login():
    session.permanent = True
    if session.get('admin_authenticated'):
        return render_admin_page()

    if request.method == "POST":
        passwrd = request.form.get("passwrd") or (request.get_json() or {}).get("passwrd")
        if not passwrd:
            return "Missing password", 400

        hashed_input = hashlib.sha256(passwrd.encode()).hexdigest()
        hashed_admin = hashlib.sha256(ADMIN_PASS.encode()).hexdigest()
        if hashed_input == hashed_admin:
            session['admin_authenticated'] = True
            return render_admin_page()
        else:
            return "Неверный пароль!", 403

    return '''
        <form method="post">
            Пароль: <input type="password" name="passwrd">
            <input type="submit" value="Войти">
        </form>
    '''

@require_admin
def render_admin_page():
    try:
        keys_resp = requests.get(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS, timeout=5)
        users_resp = requests.get(f"{SUPABASE_URL}/rest/v1/users", headers=SUPABASE_HEADERS, timeout=5)
        if keys_resp.status_code != 200 or users_resp.status_code != 200:
            return 'Failed to fetch data', 500
        keys_data = keys_resp.json()
        users_data = users_resp.json()
    except requests.RequestException:
        return 'Failed to fetch data', 500

    html_content = f"""
    <html>
    <head>
        <title>Admin Panel</title>
        <style>
            body {{ font-family: Arial; padding: 20px; background-color:#1e1e2f; color:#fff; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 30px; }}
            th, td {{ border: 1px solid #444; padding: 8px; text-align: left; }}
            th {{ background: #333; }}
            button {{ padding: 5px 10px; cursor:pointer; border:none; border-radius:5px; color:#fff; }}
            .delete-key {{ background-color:#e74c3c; }}
            .delete-user {{ background-color:#c0392b; }}
            .clean-old {{ background-color:#3498db; margin-bottom:15px; }}
        </style>
        <script>
            async function fetchPost(url, data) {{
                const res = await fetch(url, {{
                    method:'POST',
                    headers:{{'Content-Type':'application/json'}},
                    body:JSON.stringify(data)
                }});
                return res.json().catch(()=>res.text());
            }}
            async function deleteKey(key){{alert(await fetchPost('/api/delete_key',{{key:key}}));}}
            async function deleteUser(hwid){{alert(await fetchPost('/api/delete_user',{{hwid:hwid}}));}}
            async function cleanOldKeys(){{
                let days = prompt("Удалить ключи старше (дней):","1"); if(!days) return;
                let data = await fetchPost('/api/clean_old_keys',{{days:parseInt(days)}})
                alert("Удалено ключей: "+data.deleted)
            }}
        </script>
    </head>
    <body>
        <h1>Admin Panel</h1>
        <button class="clean-old" onclick="cleanOldKeys()">Удалить старые ключи</button>
        <h2>Keys</h2>
        <table>
            <tr><th>Key</th><th>Used</th><th>Created At</th><th>Action</th></tr>
            {''.join(f"<tr><td>{safe_html(k['key'])}</td><td>{k['used']}</td><td>{safe_html(k['created_at'])}</td>"
                     f"<td><button class='delete-key' onclick=\"deleteKey('{safe_html(k['key'])}')\">Delete</button></td></tr>" 
                     for k in keys_data)}
        </table>
        <h2>Users</h2>
        <table>
            <tr><th>User ID</th><th>HWID</th><th>Cookies</th><th>Key</th><th>Registered At</th><th>Action</th></tr>
            {''.join(f"<tr><td>{safe_html(u['user_id'])}</td><td>{safe_html(u['hwid'])}</td><td>{safe_html(u['cookies'])}</td>"
                     f"<td>{safe_html(u['key'])}</td><td>{safe_html(u['registered_at'])}</td>"
                     f"<td><button class='delete-user' onclick=\"deleteUser('{safe_html(u['hwid'])}')\">Delete</button></td></tr>"
                     for u in users_data)}
        </table>
    </body>
    </html>
    """
    return html_content

# ----------------------
# Delete endpoints
# ----------------------
@app.route('/api/delete_key', methods=['POST'])
@require_admin
def delete_key():
    data = request.get_json() or {}
    key = data.get('key')
    if not key or not validate_key(key):
        return 'Missing or invalid key', 400
    try:
        resp = requests.delete(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{quote(key)}", headers=SUPABASE_HEADERS, timeout=5)
    except requests.RequestException:
        return ERR_DB_FAIL, 500
    return 'Key deleted' if resp.status_code == 204 else f"Failed: {resp.text}", 500

@app.route('/api/delete_user', methods=['POST'])
@require_admin
def delete_user():
    data = request.get_json() or {}
    hwid = data.get('hwid')
    if not hwid or not validate_hwid(hwid):
        return 'Missing or invalid hwid', 400
    try:
        resp = requests.delete(f"{SUPABASE_URL}/rest/v1/users?hwid=eq.{quote(hwid)}", headers=SUPABASE_HEADERS, timeout=5)
    except requests.RequestException:
        return ERR_DB_FAIL, 500
    return 'User deleted' if resp.status_code == 204 else f"Failed: {resp.text}", 500

# ----------------------
# Run app
# ----------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
оптимизируй код
