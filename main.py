# async_api.py
import os
import re
import html
import hashlib
import asyncio
from urllib.parse import quote
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
from dateutil.parser import parse as parse_date

from quart import Quart, request, jsonify, session, redirect, url_for, render_template_string, abort
import aiohttp

# -------------- Load .env --------------
load_dotenv("/etc/secrets/.env")  # измените путь при необходимости

SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')
ADMIN_KEY = os.getenv("ADMIN_KEY")
ADMIN_IP = os.getenv("ADMIN_IP")  # опционально: разрешённый IP для админа
SECRET_KEY = os.getenv("SECRET_KEY") or os.urandom(24).hex()

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("SUPABASE_URL and SUPABASE_KEY must be set in env")

# -------------- App --------------
app = Quart(__name__)
app.secret_key = SECRET_KEY

# -------------- HTTP client --------------
# aiohttp ClientSession should be reused
aio_session = aiohttp.ClientSession(
    headers={
        'apikey': SUPABASE_KEY,
        'Authorization': f'Bearer {SUPABASE_KEY}',
        'Content-Type': 'application/json'
    },
    raise_for_status=False
)

# -------------- Validation regexps --------------
KEY_REGEX = re.compile(r"^Tw3ch1k_[0-9oasuxclO68901\-]{16,}$")
HWID_REGEX = re.compile(r"^[0-9A-Fa-f\-]{5,}$")
IP_REGEX = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

def validate_key(key: str) -> bool:
    return bool(key and KEY_REGEX.match(key))

def validate_hwid(hwid: str) -> bool:
    return bool(hwid and HWID_REGEX.match(hwid))

def validate_ip(ip: str) -> bool:
    return bool(ip and IP_REGEX.match(ip))

# -------------- Utilities --------------
def get_client_ip(req) -> str:
    # Prefer X-Forwarded-For if behind proxy/load balancer
    xff = req.headers.get('X-Forwarded-For')
    if xff:
        ip = xff.split(',')[0].strip()
    else:
        ip = req.remote_addr or 'unknown_ip'
    return ip

def get_user_id(ip: str, hwid: str) -> str:
    # Use SHA256 to avoid easy decoding and collisions on 'unknown_ip'
    h = hashlib.sha256(f"{ip}_{hwid}".encode())
    return h.hexdigest()

def now_utc():
    return datetime.now(timezone.utc)

def ensure_tz(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

# ---------------- Simple in-memory rate limiter ----------------
# NOTE: For production use Redis or another centralized store.
_rate_limits = {}  # { (key, route): [timestamps...] }
RATE_LIMITS = {
    # route_name: (max_calls, per_seconds)
    "get_key": (10, 60),
    "verify_key": (20, 60),
    "save_user": (5, 60),
    "admin_actions": (3, 60),
}

def rate_limit_key():
    # use IP from request for rate limiting (best-effort)
    ip = get_client_ip(request)
    return ip

def is_rate_limited(route_name: str) -> bool:
    ip = rate_limit_key()
    bucket = _rate_limits.setdefault((ip, route_name), [])
    max_calls, per_seconds = RATE_LIMITS.get(route_name, (1000, 60))
    now_ts = now_utc().timestamp()
    # drop old
    while bucket and bucket[0] <= now_ts - per_seconds:
        bucket.pop(0)
    if len(bucket) >= max_calls:
        return True
    bucket.append(now_ts)
    return False

# ---------------- Helpers interacting with Supabase ----------------
async def supabase_get(path: str, params: str = ""):
    url = f"{SUPABASE_URL}/rest/v1/{path}{params}"
    async with aio_session.get(url, timeout=10) as r:
        text = await r.text()
        return r.status, text, await _maybe_json(r)

async def supabase_post(path: str, json_data: dict):
    url = f"{SUPABASE_URL}/rest/v1/{path}"
    async with aio_session.post(url, json=json_data, timeout=10) as r:
        text = await r.text()
        return r.status, text, await _maybe_json(r)

async def supabase_patch(path: str, json_data: dict):
    url = f"{SUPABASE_URL}/rest/v1/{path}"
    async with aio_session.patch(url, json=json_data, timeout=10) as r:
        text = await r.text()
        return r.status, text, await _maybe_json(r)

async def supabase_delete(path: str):
    url = f"{SUPABASE_URL}/rest/v1/{path}"
    async with aio_session.delete(url, timeout=10) as r:
        text = await r.text()
        return r.status, text, await _maybe_json(r)

async def _maybe_json(resp: aiohttp.ClientResponse):
    ct = resp.headers.get('Content-Type', '')
    if 'application/json' in ct:
        try:
            return await resp.json()
        except Exception:
            return None
    return None

# ---------------- Key generation/saving ----------------
def generate_key(length=16):
    CUSTOM_LETTERS = 'oasuxclO'
    CUSTOM_DIGITS = '68901'
    digits_count = int(length * 0.7)
    letters_count = length - digits_count
    key_chars = [random_char for random_char in (CUSTOM_DIGITS * digits_count)]  # fallback
    # simpler deterministic distribution
    import random
    key_chars = random.choices(CUSTOM_DIGITS, k=digits_count) + random.choices(CUSTOM_LETTERS, k=letters_count)
    random.shuffle(key_chars)
    key = ''.join(key_chars)
    return f"Tw3ch1k_" + '-'.join([key[i:i+4] for i in range(0, len(key), 4)])

async def save_key_to_db(key: str = None):
    key = key or generate_key()
    created_at = now_utc().isoformat()
    data = {"key": key, "created_at": created_at, "used": False}
    status, text, json_body = await supabase_post("keys", data)
    if status in (201, 200):
        return key
    return None

# ---------------- Auth helpers ----------------
def is_admin_logged_in() -> bool:
    return session.get("is_admin", False) is True

def require_admin():
    if not is_admin_logged_in():
        abort(403)

# ---------------- Routes ----------------

@app.route('/user/login', methods=['POST'])
async def admin_login():
    json_data = await request.get_json(force=True, silent=True) or {}
    provided = json_data.get("admin_key") or request.headers.get("X-Admin-Key")
    if not provided:
        return jsonify({"error": "missing admin key"}), 400
    if provided != ADMIN_KEY:
        return jsonify({"error": "invalid admin key"}), 403
    # optional IP lock
    ip = get_client_ip(request)
    if ADMIN_IP and ip != ADMIN_IP:
        return jsonify({"error": "admin login from forbidden IP"}), 403
    session["is_admin"] = True
    session["admin_ip"] = ip
    # set a CSRF token if you want
    session["csrf_token"] = hashlib.sha256(os.urandom(16)).hexdigest()
    return jsonify({"status": "ok"})

@app.route('/user/logout', methods=['POST'])
async def admin_logout():
    session.clear()
    return jsonify({"status": "logged_out"})

@app.route('/api/clean_old_keys', methods=['POST'])
async def clean_old_keys():
    # admin required + rate limit
    require_admin()
    if is_rate_limited("admin_actions"):
        return jsonify({"error": "rate_limited"}), 429

    data = await request.get_json(force=True, silent=True) or {}
    days = int(data.get("days", 1))
    cutoff = now_utc() - timedelta(days=days)

    status, text, keys_json = await supabase_get("keys")
    if status != 200 or not isinstance(keys_json, list):
        return jsonify({"error": "Failed to fetch keys", "details": text}), 500

    deleted = 0
    for key_obj in keys_json:
        created_at_str = key_obj.get("created_at")
        if not created_at_str:
            continue
        try:
            created_at = ensure_tz(parse_date(created_at_str))
        except Exception:
            continue
        if created_at < cutoff:
            encoded_key = quote(key_obj['key'], safe='')
            st, txt, _ = await supabase_delete(f"keys?key=eq.{encoded_key}")
            if st == 204:
                deleted += 1

    return jsonify({"deleted": deleted})

@app.route('/api/get_key', methods=['GET'])
async def get_key():
    if is_rate_limited("get_key"):
        return jsonify({"error": "rate_limited"}), 429
    key = await save_key_to_db()
    if not key:
        return jsonify({"error": "Failed to save key"}), 500
    return jsonify({"key": key})

@app.route('/api/verify_key', methods=['GET'])
async def verify_key():
    if is_rate_limited("verify_key"):
        return "rate_limited", 429, {'Content-Type': 'text/plain'}

    key = request.args.get('key')
    if not key or not validate_key(key):
        return "invalid", 200, {'Content-Type': 'text/plain'}

    encoded = quote(key, safe='')
    st, txt, json_body = await supabase_get(f"keys", params=f"?key=eq.{encoded}")
    if st != 200 or not json_body:
        return "invalid", 200, {'Content-Type': 'text/plain'}

    key_data = json_body[0]
    if key_data.get("used"):
        return "used", 200, {'Content-Type': 'text/plain'}

    try:
        created_at = ensure_tz(parse_date(key_data["created_at"]))
    except Exception:
        return "error", 500, {'Content-Type': 'text/plain'}

    if now_utc() - created_at > timedelta(hours=24):
        return "expired", 200, {'Content-Type': 'text/plain'}

    # Try to atomically set used=True
    st2, txt2, _ = await supabase_patch(f"keys?key=eq.{encoded}", {"used": True})
    if st2 in (204, 200):
        return "valid", 200, {'Content-Type': 'text/plain'}

    return "error", 500, {'Content-Type': 'text/plain'}

@app.route('/api/save_user', methods=['POST'])
async def save_user():
    if is_rate_limited("save_user"):
        return jsonify({"error": "rate_limited"}), 429

    data = await request.get_json(force=True, silent=True) or {}
    ip = get_client_ip(request)
    if not validate_ip(ip):
        ip = 'unknown_ip'

    cookies = data.get('cookies', '')
    hwid = data.get('hwid', '')
    key = data.get('key', '')

    if not hwid or not validate_hwid(hwid):
        return jsonify({"error": "Missing or invalid HWID"}), 400

    user_id = get_user_id(ip, hwid)

    # Check existing user
    enc_user_id = quote(user_id, safe='')
    st, txt, users_json = await supabase_get("users", params=f"?user_id=eq.{enc_user_id}")
    if st != 200:
        return jsonify({"error": "Failed to query user"}), 500
    if users_json:
        # return existing
        return jsonify({
            "status": "exists",
            "key": users_json[0].get("key"),
            "registered_at": users_json[0].get("registered_at")
        })

    # If key provided: require it to be valid (do NOT auto-create new on invalid)
    if key:
        if not validate_key(key):
            return jsonify({"error": "Provided key invalid"}), 400
        enc_key = quote(key, safe='')
        st_k, txt_k, key_json = await supabase_get("keys", params=f"?key=eq.{enc_key}")
        if st_k != 200 or not key_json:
            return jsonify({"error": "Provided key not found"}), 400
        # Check used/expiry
        kdata = key_json[0]
        if kdata.get("used"):
            return jsonify({"error": "Provided key already used"}), 400
        try:
            created_k = ensure_tz(parse_date(kdata["created_at"]))
        except Exception:
            return jsonify({"error": "Invalid key created_at"}), 400
        if now_utc() - created_k > timedelta(hours=24):
            return jsonify({"error": "Provided key expired"}), 400
        # mark used
        st_upd, txt_upd, _ = await supabase_patch(f"keys?key=eq.{enc_key}", {"used": True})
        if st_upd not in (200, 204):
            return jsonify({"error": "Failed to mark key used"}), 500
    else:
        # no key provided -> generate and save one
        key = await save_key_to_db()
        if not key:
            return jsonify({"error": "Failed to save key"}), 500

    registered_at = now_utc().isoformat()
    user_data = {
        "user_id": user_id,
        "cookies": cookies,
        "hwid": hwid,
        "key": key,
        "registered_at": registered_at
    }
    st_u, txt_u, _ = await supabase_post("users", user_data)
    if st_u not in (201, 200):
        return jsonify({"error": "Failed to save user", "details": txt_u}), 500

    return jsonify({
        "status": "saved",
        "key": key,
        "registered_at": registered_at
    })

# Admin panel (GET) - protected and safe: does not leak admin key
ADMIN_HTML_TEMPLATE = """
<!doctype html>
<html>
  <head><meta charset="utf-8"><title>Admin Panel</title>
  <style>
    body { font-family: monospace; background: #121212; color: #eee; padding: 20px; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
    th, td { border: 1px solid #666; padding: 8px; }
    th { background: #222; }
    button { background: #f33; color: white; border: none; padding: 4px 8px; cursor: pointer; }
  </style>
  <script>
    async function post(url, payload) {
      const res = await fetch(url, {
        method: "POST",
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
      });
      const txt = await res.text();
      alert(txt);
      location.reload();
    }
  </script>
  </head>
  <body>
    <h1>🔑 Keys</h1>
    <h2>🧹 Очистка</h2>
    <button onclick="post('/api/clean_old_keys', {days: 1})">Удалить ключи старше 24ч</button>
    <table><tr><th>Key</th><th>Used</th><th>Created At</th><th>Action</th></tr>
    {% for k in keys %}
      <tr><td>{{k.key}}</td><td>{{k.used}}</td><td>{{k.created_at}}</td>
      <td><button onclick="post('/api/delete_key', {key: '{{k.key|e}}'})">Delete</button></td></tr>
    {% endfor %}
    </table>
    <h1>👤 Users</h1>
    <table><tr><th>User ID</th><th>HWID</th><th>Cookies</th><th>Key</th><th>Registered At</th><th>Action</th></tr>
    {% for u in users %}
      <tr><td>{{u.user_id}}</td><td>{{u.hwid}}</td><td>{{u.cookies}}</td><td>{{u.key}}</td><td>{{u.registered_at}}</td>
      <td><button onclick="post('/api/delete_user', {hwid: '{{u.hwid|e}}'})">Delete</button></td></tr>
    {% endfor %}
    </table>
  </body>
</html>
"""

@app.route('/user/admin', methods=['GET'])
async def admin_panel():
    require_admin()
    if is_rate_limited("admin_actions"):
        return "rate_limited", 429
    st_k, txt_k, keys_json = await supabase_get("keys")
    st_u, txt_u, users_json = await supabase_get("users")
    if st_k != 200 or st_u != 200:
        return "Failed to fetch data", 500
    # sanitize values by relying on template autoescape (quart uses jinja2)
    keys = keys_json or []
    users = users_json or []
    return await render_template_string(ADMIN_HTML_TEMPLATE, keys=keys, users=users)

@app.route('/api/delete_key', methods=['POST'])
async def delete_key():
    require_admin()
    if is_rate_limited("admin_actions"):
        return "rate_limited", 429
    data = await request.get_json(force=True, silent=True) or {}
    key = data.get('key')
    if not key or not validate_key(key):
        return "Missing or invalid key", 400
    encoded_key = quote(key, safe='')
    st, txt, _ = await supabase_delete(f"keys?key=eq.{encoded_key}")
    if st == 204:
        return "Key deleted"
    return f"Failed to delete: {txt}", 500

@app.route('/api/delete_user', methods=['POST'])
async def delete_user():
    require_admin()
    if is_rate_limited("admin_actions"):
        return "rate_limited", 429
    data = await request.get_json(force=True, silent=True) or {}
    hwid = data.get('hwid')
    if not hwid or not validate_hwid(hwid):
        return "Missing or invalid hwid", 400
    encoded_hwid = quote(hwid, safe='')
    st, txt, _ = await supabase_delete(f"users?hwid=eq.{encoded_hwid}")
    if st == 204:
        return "User deleted"
    return f"Failed to delete: {txt}", 500

# -------------- Shutdown cleanup --------------
@app.before_serving
async def startup():
    pass

@app.after_serving
async def shutdown():
    await aio_session.close()

# -------------- Run --------------
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", 5000)))
    args = parser.parse_args()
    app.run(host=args.host, port=args.port)
