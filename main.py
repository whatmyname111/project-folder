import os
import random
import base64
import requests
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_from_directory
from dateutil.parser import isoparse  # <-- импорт для корректного парсинга даты

app = Flask(__name__)

SUPABASE_URL = 'https://kuhunkdgbtedgrujwxoy.supabase.co'
SUPABASE_KEY = os.environ.get('SUPABASE_KEY') or 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imt1aHVua2RnYnRlZGdydWp3eG95Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTQyOTMyODEsImV4cCI6MjA2OTg2OTI4MX0.N5I9bGTroqMDD9g0b-3lqMMip0NFRDTH30dh_hQ9kJY'
SUPABASE_HEADERS = {
    'apikey': SUPABASE_KEY,
    'Authorization': f'Bearer {SUPABASE_KEY}',
    'Content-Type': 'application/json'
}

def generate_key(length=16):
    CUSTOM_LETTERS = 'oasuxclO'
    CUSTOM_DIGITS = '68901'

    digits_count = int(length * 0.7)
    letters_count = length - digits_count

    if digits_count <= len(CUSTOM_DIGITS):
        digits = random.sample(CUSTOM_DIGITS, k=digits_count)
    else:
        digits = random.choices(CUSTOM_DIGITS, k=digits_count)

    if letters_count <= len(CUSTOM_LETTERS):
        letters = random.sample(CUSTOM_LETTERS, k=letters_count)
    else:
        letters = random.choices(CUSTOM_LETTERS, k=letters_count)

    key_chars = digits + letters
    random.shuffle(key_chars)
    key = ''.join(key_chars)

    ddp = '-'.join([key[i:i+4] for i in range(0, len(key), 4)])
    return f"Tw3ch1k_{ddp}"
    
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

    try:
        res = requests.get(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{key}", headers=SUPABASE_HEADERS)
        if res.status_code != 200:
            return "invalid"

        data = res.json()
        if not data:
            return "invalid"

        key_data = data[0]
        created_at = isoparse(key_data['created_at'])  # <-- исправлено
        used = key_data['used']

        if used:
            return "used"

        if datetime.utcnow() - created_at > timedelta(hours=24):
            return "expired"

        update_res = requests.patch(
            f"{SUPABASE_URL}/rest/v1/keys?key=eq.{key}",
            headers=SUPABASE_HEADERS,
            json={"used": True}
        )
        if update_res.status_code == 204:
            return "valid"
        else:
            return "error"

    except Exception as e:
        return f"Server error: {e}", 500

@app.route('/api/save_user', methods=['POST'])
def save_user():
    data = request.json
    ip = request.remote_addr or 'unknown_ip'
    cookies = data.get('cookies', '')
    hwid = data.get('hwid', '')
    key = data.get('key', '')

    user_id = hwid or base64.b64encode(ip.encode()).decode()

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

@app.route('/user/admin')
def admin_panel():
    access_key = request.args.get('d')
    if access_key != '22042013':
        return "Access denied", 403

    keys_res = requests.get(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS)
    users_res = requests.get(f"{SUPABASE_URL}/rest/v1/users", headers=SUPABASE_HEADERS)

    if keys_res.status_code != 200 or users_res.status_code != 200:
        return "Failed to load data", 500

    keys = keys_res.json()
    users = users_res.json()

    html = """
    <html>
    <head>
        <title>Admin Panel</title>
        <style>
            body { font-family: monospace; background: #121212; color: #eee; padding: 20px; }
            table { border-collapse: collapse; margin-bottom: 30px; width: 100%; }
            th, td { border: 1px solid #666; padding: 8px; text-align: left; }
            th { background: #222; }
            button { background: #f33; color: white; border: none; padding: 4px 8px; cursor: pointer; }
        </style>
        <script>
            async function deleteKey(key) {
                const res = await fetch('/api/delete_key?key=' + encodeURIComponent(key));
                alert(await res.text());
                location.reload();
            }
            async function deleteUser(id) {
                const res = await fetch('/api/delete_user?user_id=' + encodeURIComponent(id));
                alert(await res.text());
                location.reload();
            }
        </script>
    </head>
    <body>
        <h1>🔑 Keys</h1>
        <table>
            <tr><th>Key</th><th>Used</th><th>Created At</th><th>Action</th></tr>
    """

    for k in keys:
        html += f"<tr><td>{k['key']}</td><td>{k['used']}</td><td>{k['created_at']}</td><td><button onclick=\"deleteKey('{k['key']}')\">Delete</button></td></tr>"

    html += """
        </table>
        <h1>👤 Users</h1>
        <table>
            <tr><th>User ID</th><th>HWID</th><th>Cookies</th><th>Key</th><th>Registered At</th><th>Action</th></tr>
    """

    for u in users:
        html += f"<tr><td>{u['user_id']}</td><td>{u['hwid']}</td><td>{u['cookies']}</td><td>{u['key']}</td><td>{u['registered_at']}</td><td><button onclick=\"deleteUser('{u['user_id']}')\">Delete</button></td></tr>"

    html += "</table></body></html>"
    return html

@app.route('/api/delete_key')
def delete_key():
    key = request.args.get('key')
    if not key:
        return "Missing key", 400

    res = requests.delete(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{key}", headers=SUPABASE_HEADERS)
    if res.status_code == 204:
        return "Key deleted"
    return f"Failed to delete: {res.text}", 500

@app.route('/api/delete_user')
def delete_user():
    user_id = request.args.get('user_id')
    if not user_id:
        return "Missing user_id", 400

    res = requests.delete(f"{SUPABASE_URL}/rest/v1/users?user_id=eq.{user_id}", headers=SUPABASE_HEADERS)
    if res.status_code == 204:
        return "User deleted"
    return f"Failed to delete: {res.text}", 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
