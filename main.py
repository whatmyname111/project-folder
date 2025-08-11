import os
import base64
import random
import re
from urllib.parse import quote
from datetime import datetime, timedelta, timezone
from quart import Quart, request, jsonify, send_from_directory, abort
from dotenv import load_dotenv
from dateutil.parser import parse as parse_date
from quart_limiter import Limiter
from quart_limiter.util import get_remote_address
import aiohttp

# -------------- Load .env --------------
load_dotenv("/etc/secrets/.env")

SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')
ADMIN_KEY = os.getenv("ADMIN_KEY")
ADMIN_IP = os.getenv("ADMIN_IP")

# -------------- Quart init --------------
app = Quart(__name__)
limiter = Limiter(app, key_func=get_remote_address, default_limits=["20 per minute"])

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
    key_from_header = request.headers.get("X-Admin-Key")
    key_from_arg = request.args.get('d')
    key = key_from_header or key_from_arg
    return key == ADMIN_KEY

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

async def save_key(key=None):
    key = key or generate_key()
    created_at = datetime.utcnow().isoformat()
    data = {"key": key, "created_at": created_at, "used": False}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS, json=data, timeout=5) as res:
                if res.status == 201:
                    return key
    except Exception:
        pass
    return None

def get_user_id(ip, hwid):
    return base64.b64encode(f"{ip}_{hwid}".encode()).decode()

# -------------- Routes --------------

@app.route('/api/clean_old_keys', methods=['POST'])
async def clean_old_keys():
    if not is_admin_request():
        return jsonify({"error": "Access denied"}), 403

    data = await request.get_json() or {}
    days = int(data.get("days", 1))
    cutoff = datetime.utcnow().replace(tzinfo=timezone.utc) - timedelta(days=days)

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS, timeout=5) as res:
                if res.status != 200:
                    text = await res.text()
                    return jsonify({"error": "Failed to fetch keys", "details": text}), 500
                keys = await res.json()
    except Exception:
        return jsonify({"error": "Failed to fetch keys"}), 500

    deleted = 0
    async with aiohttp.ClientSession() as session:
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
                    async with session.delete(
                        f"{SUPABASE_URL}/rest/v1/keys?key=eq.{encoded_key}",
                        headers=SUPABASE_HEADERS,
                        timeout=5
                    ) as delete_res:
                        if delete_res.status == 204:
                            deleted += 1
                except Exception:
                    pass

    return jsonify({"deleted": deleted})

@app.route('/api/get_key')
@limiter.limit("10/minute")
async def get_key():
    key = await save_key()
    if not key:
        return jsonify({"error": "Failed to save key"}), 500
    return jsonify({"key": key})

@app.route('/api/verify_key')
@limiter.limit("20/minute")
async def verify_key():
    key = request.args.get('key')
    if not key or not validate_key(key):
        return "invalid", 200, {'Content-Type': 'text/plain'}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{quote(key)}", headers=SUPABASE_HEADERS, timeout=5) as res:
                if res.status != 200:
                    return "invalid", 200, {'Content-Type': 'text/plain'}
                data = await res.json()
    except Exception:
        return "error", 500, {'Content-Type': 'text/plain'}

    if not data:
        return "invalid", 200, {'Content-Type': 'text/plain'}

    key_data = data[0]
    if key_data.get("used"):
        return "used", 200, {'Content-Type': 'text/plain'}

    try:
        created_at = parse_date(key_data["created_at"])
    except Exception:
        return "error", 500, {'Content-Type': 'text/plain'}

    if datetime.now(timezone.utc) - created_at > timedelta(hours=24):
        return "expired", 200, {'Content-Type': 'text/plain'}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.patch(
                f"{SUPABASE_URL}/rest/v1/keys?key=eq.{quote(key)}",
                headers=SUPABASE_HEADERS, json={"used": True}, timeout=5
            ) as update:
                if update.status == 204:
                    return "valid", 200, {'Content-Type': 'text/plain'}
    except Exception:
        pass

    return "error", 500, {'Content-Type': 'text/plain'}

@app.route('/api/save_user', methods=['POST'])
@limiter.limit("5/minute")
async def save_user():
    data = await request.get_json() or {}
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
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{SUPABASE_URL}/rest/v1/users?user_id=eq.{quote(user_id)}",
                headers=SUPABASE_HEADERS, timeout=5
            ) as user_check:
                if user_check.status != 200:
                    return jsonify({"error": "Failed to query user"}), 500
                users = await user_check.json()
    except Exception:
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
            key = await save_key()
        else:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        f"{SUPABASE_URL}/rest/v1/keys?key=eq.{quote(key)}",
                        headers=SUPABASE_HEADERS,
                        timeout=5
                    ) as key_check:
                        if key_check.status != 200 or not await key_check.json():
                            key = await save_key()
            except Exception:
                key = await save_key()
    else:
        key = await save_key()

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
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{SUPABASE_URL}/rest/v1/users",
                headers=SUPABASE_HEADERS,
                json=user_data,
                timeout=5
            ) as user_res:
                if user_res.status != 201:
                    return jsonify({"error": "Failed to save user"}), 500
    except Exception:
        return jsonify({"error": "Failed to save user"}), 500

    return jsonify({
        "status": "saved",
        "key": key,
        "registered_at": registered_at
    })

@app.route('/')
async def serve_index():
    return await send_from_directory('.', 'index.html')

@app.route('/style.css')
async def serve_css():
    return await send_from_directory('.', 'style.css')

@app.route('/user/admin')
async def admin_panel():
    if not is_admin_request():
        return "Access denied", 403

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS, timeout=5) as keys_res:
                async with session.get(f"{SUPABASE_URL}/rest/v1/users", headers=SUPABASE_HEADERS, timeout=5) as users_res:
                    if keys_res.status != 200 or users_res.status != 200:
                        return "Failed to fetch data", 500
                    keys = await keys_res.json()
                    users = await users_res.json()
    except Exception:
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
async def delete_key():
    if not is_admin_request():
        return "Access denied", 403
    data = await request.get_json() or {}
    key = data.get('key')
    if not key or not validate_key(key):
        return "Missing or invalid key", 400
    encoded_key = quote(key)
    try:
        async with aiohttp.ClientSession() as session:
            async with session.delete(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{encoded_key}", headers=SUPABASE_HEADERS, timeout=5) as res:
                if res.status == 204:
                    return "Key deleted"
                text = await res.text()
                return f"Failed to delete: {text}", 500
    except Exception:
        return "Database request failed", 500

@app.route('/api/delete_user', methods=['POST'])
async def delete_user():
    if not is_admin_request():
        return "Access denied", 403
    data = await request.get_json() or {}
    hwid = data.get('hwid')
    if not hwid or not validate_hwid(hwid):
        return "Missing or invalid hwid", 400
    encoded_hwid = quote(hwid)
    try:
        async with aiohttp.ClientSession() as session:
            async with session.delete(f"{SUPABASE_URL}/rest/v1/users?hwid=eq.{encoded_hwid}", headers=SUPABASE_HEADERS, timeout=5) as res:
                if res.status == 204:
                    return "User deleted"
                text = await res.text()
                return f"Failed to delete: {text}", 500
    except Exception:
        return "Database request failed", 500

# -------------- Run --------------
if __name__ == '__main__':
    import hypercorn.asyncio
    import asyncio

    config = hypercorn.Config()
    config.bind = ["0.0.0.0:" + os.environ.get("PORT", "5000")]

    asyncio.run(hypercorn.asyncio.serve(app, config))
