import os, base64, random, re
from urllib.parse import quote
from datetime import datetime, timedelta, timezone

from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_admin import Admin
from flask_admin.base import BaseView, expose
from flask_bootstrap import Bootstrap5
import requests
from dotenv import load_dotenv
from dateutil.parser import parse as parse_date

# ---------- CONFIG ----------
load_dotenv('/etc/secrets/.env')
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')
ADMIN_KEY = os.getenv('ADMIN_KEY')

SUPABASE_HEADERS = {
    'apikey': SUPABASE_KEY,
    'Authorization': f"Bearer {SUPABASE_KEY}",
    'Content-Type': 'application/json'
}

KEY_REGEX = re.compile(r'^Tw3ch1k_[0-9oasuxclO68901\-]{16,}$')
HWID_REGEX = re.compile(r'^[0-9A-Fa-f\-]{5,}$')
IP_REGEX = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')

app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=['20 per minute'])
bootstrap = Bootstrap5(app)
admin = Admin(app, name='Admin Panel', template_mode='bootstrap5')

# ---------- UTILS ----------
def validate_key(key): return bool(KEY_REGEX.match(key))
def validate_hwid(hwid): return bool(HWID_REGEX.match(hwid))
def validate_ip(ip): return bool(IP_REGEX.match(ip))
def is_admin_request(): 
    return (request.headers.get('X-Admin-Key') == ADMIN_KEY) or (request.args.get('d') == ADMIN_KEY)

def generate_key(length=16):
    chars = 'oasuxclO'
    nums = '68901'
    num_count = int(length * 0.7)
    char_count = length - num_count
    parts = random.choices(nums, k=num_count) + random.choices(chars, k=char_count)
    random.shuffle(parts)
    key_body = ''.join(parts)
    return f"Tw3ch1k_" + '-'.join([key_body[i:i+4] for i in range(0, len(key_body), 4)])

def get_user_id(ip, hwid):
    return base64.b64encode(f"{ip}_{hwid}".encode()).decode()

def save_key(key=None):
    key = key or generate_key()
    data = {'key': key, 'created_at': datetime.utcnow().isoformat(), 'used': False}
    try:
        resp = requests.post(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS, json=data, timeout=5)
        if resp.status_code == 201: return key
    except requests.RequestException: pass
    return None

# ---------- ROUTES ----------
@app.route('/api/get_key')
@limiter.limit('10/minute')
def get_key():
    key = save_key()
    if not key: return jsonify({'error': 'Failed to save key'}), 500
    return jsonify({'key': key})

@app.route('/api/verify_key')
@limiter.limit('20/minute')
def verify_key():
    key = request.args.get('key')
    if not key or not validate_key(key):
        return 'invalid', 200, {'Content-Type': 'text/plain'}
    try:
        resp = requests.get(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{quote(key)}", headers=SUPABASE_HEADERS, timeout=5)
        if resp.status_code != 200 or not resp.json(): return 'invalid', 200, {'Content-Type': 'text/plain'}
        key_data = resp.json()[0]
        if key_data.get('used'): return 'used', 200, {'Content-Type': 'text/plain'}
        created = parse_date(key_data['created_at'])
        if datetime.now(timezone.utc) - created > timedelta(hours=24): return 'expired', 200, {'Content-Type': 'text/plain'}
        patch = requests.patch(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{quote(key)}",
                               headers=SUPABASE_HEADERS, json={'used': True}, timeout=5)
        if patch.status_code == 204: return 'valid', 200, {'Content-Type': 'text/plain'}
    except requests.RequestException: return 'error', 500
    return 'error', 500

@app.route('/api/save_user', methods=['POST'])
@limiter.limit('5/minute')
def save_user():
    data = request.json or {}
    ip = request.remote_addr or 'unknown_ip'
    if not validate_ip(ip): ip = 'unknown_ip'
    hwid = data.get('hwid')
    cookies = data.get('cookies', '')
    key = data.get('key') or save_key()
    if not hwid or not validate_hwid(hwid): return jsonify({'error': 'Invalid HWID'}), 400
    user_id = get_user_id(ip, hwid)
    payload = {'user_id': user_id, 'hwid': hwid, 'cookies': cookies, 'key': key, 'registered_at': datetime.utcnow().isoformat()}
    try:
        resp = requests.post(f"{SUPABASE_URL}/rest/v1/users", headers=SUPABASE_HEADERS, json=payload, timeout=5)
        if resp.status_code != 201: return jsonify({'error': 'Failed to save user'}), 500
    except requests.RequestException:
        return jsonify({'error': 'Failed to save user'}), 500
    return jsonify({'status': 'saved', 'key': key})

# ---------- ADMIN PANEL ----------
class AdminView(BaseView):
    @expose('/')
    def index(self):
        try:
            keys_resp = requests.get(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS, timeout=5)
            users_resp = requests.get(f"{SUPABASE_URL}/rest/v1/users", headers=SUPABASE_HEADERS, timeout=5)
            keys = keys_resp.json() if keys_resp.status_code==200 else []
            users = users_resp.json() if users_resp.status_code==200 else []
        except requests.RequestException:
            keys, users = [], []
        return self.render('admin.html', keys=keys, users=users, admin_key=ADMIN_KEY)

admin.add_view(AdminView(name='Dashboard'))

# ---------- STATIC FILES ----------
@app.route('/')
def index(): return send_from_directory('.', 'index.html')
@app.route('/style.css')
def css(): return send_from_directory('.', 'style.css')

# ---------- RUN ----------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
