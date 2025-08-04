import os
import random
import base64
import requests
import load_dotenv from dotenv
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_from_directory

load_dotenv("/etc/secrets/.env")
app = Flask(__name__)

SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')
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

    digits = random.choices(CUSTOM_DIGITS, k=digits_count)
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
    data = {"key": key, "created_at": created_at, "used": False}
    res = requests.post(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS, json=data)
    return jsonify({"key": key}) if res.status_code == 201 else jsonify({"error": "Failed to save key"}), 500


@app.route('/api/verify_key')
def verify_key():
    key = request.args.get('key')
    if not key:
        return "invalid"
    res = requests.get(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{key}", headers=SUPABASE_HEADERS)
    if res.status_code != 200 or not res.json():
        return "invalid"
    key_data = res.json()[0]
    if key_data["used"]:
        return "used"
    if datetime.utcnow() - datetime.fromisoformat(key_data["created_at"]) > timedelta(hours=24):
        return "expired"
    update_res = requests.patch(
        f"{SUPABASE_URL}/rest/v1/keys?key=eq.{key}",
        headers=SUPABASE_HEADERS,
        json={"used": True}
    )
    return "valid" if update_res.status_code == 204 else "error"

@app.route('/api/save_user', methods=['POST'])
def save_user():
    data = request.json
    ip = request.remote_addr or 'unknown_ip'
    cookies = data.get('cookies', '')
    hwid = data.get('hwid', '')
    key = data.get('key', '')

    user_id = hwid or base64.b64encode(ip.encode()).decode()

    # 1. Проверяем, есть ли пользователь
    user_res = requests.get(f"{SUPABASE_URL}/rest/v1/users?user_id=eq.{user_id}", headers=SUPABASE_HEADERS)
    if user_res.status_code != 200:
        return jsonify({"error": "Failed to query user", "details": user_res.text}), 500

    users = user_res.json()
    if users:
        # Пользователь есть — возвращаем данные
        user = users[0]
        return jsonify({
            "status": "exists",
            "key": user["key"],
            "registered_at": user["registered_at"]
        })

    # 2. Пользователя нет — проверяем ключ из запроса
    if key:
        key_res = requests.get(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{key}", headers=SUPABASE_HEADERS)
        if key_res.status_code != 200:
            return jsonify({"error": "Failed to query key", "details": key_res.text}), 500
        if not key_res.json():
            # Ключ из запроса не валиден, сгенерируем новый
            key = generate_key()
            created_at = datetime.utcnow().isoformat()
            key_data = {"key": key, "created_at": created_at, "used": False}
            key_save_res = requests.post(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS, json=key_data)
            if key_save_res.status_code != 201:
                return jsonify({"error": "Failed to save key", "details": key_save_res.text}), 500
    else:
        # Ключ не передан — генерируем новый
        key = generate_key()
        created_at = datetime.utcnow().isoformat()
        key_data = {"key": key, "created_at": created_at, "used": False}
        key_save_res = requests.post(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS, json=key_data)
        if key_save_res.status_code != 201:
            return jsonify({"error": "Failed to save key", "details": key_save_res.text}), 500

    # 3. Сохраняем пользователя
    registered_at = datetime.utcnow().isoformat()
    user_data = {
        "user_id": user_id,
        "cookies": cookies,
        "hwid": hwid,
        "key": key,
        "registered_at": registered_at
    }
    user_save_res = requests.post(f"{SUPABASE_URL}/rest/v1/users", headers=SUPABASE_HEADERS, json=user_data)
    if user_save_res.status_code == 201:
        return jsonify({
            "status": "saved",
            "key": key,
            "registered_at": registered_at
        })
    else:
        return jsonify({"error": "Failed to save user", "details": user_save_res.text}), 500

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
    <html><head><title>Admin Panel</title>
    <style>
        body { font-family: monospace; background: #121212; color: #eee; padding: 20px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #666; padding: 8px; }
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
    </script></head><body>
    <h1>🔑 Keys</h1><table><tr><th>Key</th><th>Used</th><th>Created At</th><th>Action</th></tr>
    """
    for k in keys:
        html += f"<tr><td>{k['key']}</td><td>{k['used']}</td><td>{k['created_at']}</td><td><button onclick=\"deleteKey('{k['key']}')\">Delete</button></td></tr>"
    html += "</table><h1>👤 Users</h1><table><tr><th>User ID</th><th>HWID</th><th>Cookies</th><th>Key</th><th>Registered At</th><th>Action</th></tr>"
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
    return "Key deleted" if res.status_code == 204 else f"Failed to delete: {res.text}", 500


@app.route('/api/delete_user')
def delete_user():
    user_id = request.args.get('user_id')
    if not user_id:
        return "Missing user_id", 400
    res = requests.delete(f"{SUPABASE_URL}/rest/v1/users?user_id=eq.{user_id}", headers=SUPABASE_HEADERS)
    return "User deleted" if res.status_code == 204 else f"Failed to delete: {res.text}", 500


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
