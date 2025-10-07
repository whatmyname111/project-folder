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
import psutil
import json
from collections import defaultdict, deque
from dotenv import load_dotenv
from dateutil.parser import parse as parse_date
from flask import Flask, request, jsonify, send_from_directory, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from flask_caching import Cache

load_dotenv('/etc/secrets/.env')

SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')
SECRET_KEY = os.getenv("SECRET_KEY")
ADMIN_PASS = os.getenv('ADMIN_PASS')
WEBHOOK_URLS = os.getenv('WEBHOOK_URLS', '').split(',')

SUPABASE_HEADERS = {
    'apikey': SUPABASE_KEY,
    'Authorization': f"Bearer {SUPABASE_KEY}",
    'Content-Type': 'application/json'
}

# Regex
KEY_REGEX = re.compile(r'^Apex_[a-f0-9]{35}$')
HWID_REGEX = re.compile(r'^[0-9A-Fa-f\-]{5,}$')

# Error messages
ERR_DB_FAIL = 'Database request failed'
ERR_ACCESS_DENIED = 'Access denied'
ERR_SAVE_KEY = 'Failed to save key'

# Система ролей
USER_ROLES = {
    'user': 1,
    'premium': 2, 
    'admin': 3
}

# Flask app
app = Flask(__name__)
app.secret_key = os.getenv("ADMIN_SESSION_KEY")
app.config['SESSION_COOKIE_NAME'] = os.getenv("sskk")
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

CORS(app, resources={r"/api/*": {"origins": ["https://www.roblox.com", "https://*.robloxlabs.com"]}})

# Лимитеры
limiter = Limiter(get_remote_address, app=app, default_limits=['20 per minute'])
hwid_limiter = Limiter(get_hwid_identifier, app=app, default_limits=['100/day', '10/minute'])

# Кэширование
cache = Cache(config={'CACHE_TYPE': 'SimpleCache'})
cache.init_app(app)

# Статистика в памяти
stats_data = {
    'daily_users': deque(maxlen=1000),
    'key_verifications': deque(maxlen=5000),
    'api_calls': defaultdict(int),
    'errors': deque(maxlen=1000)
}

# ----------------------
# Utility functions
# ----------------------
def get_hwid_identifier():
    hwid = request.json.get('hwid') if request.json else None
    return hwid or get_remote_address()

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

def generate_key(length: int = 35) -> str:
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    key_str = ''.join(random.choices(chars, k=length))
    hashed_key = hashlib.sha256(key_str.encode()).hexdigest()[:35]
    return f"Apex_{hashed_key}"

def trigger_webhooks(event_type: str, data: dict):
    for url in WEBHOOK_URLS:
        if url:
            try:
                requests.post(url, json={'event': event_type, 'data': data}, timeout=5)
            except:
                pass

def update_stats(event_type: str, data: dict = None):
    today = datetime.now().date().isoformat()
    stats_data['api_calls'][today] += 1
    
    if event_type == 'new_user':
        stats_data['daily_users'].append({
            'timestamp': datetime.now().isoformat(),
            'hwid': data.get('hwid'),
            'ip': data.get('ip')
        })
    elif event_type == 'key_verify':
        stats_data['key_verifications'].append({
            'timestamp': datetime.now().isoformat(),
            'key': data.get('key'),
            'result': data.get('result')
        })
    elif event_type == 'error':
        stats_data['errors'].append({
            'timestamp': datetime.now().isoformat(),
            'error': data.get('error'),
            'endpoint': data.get('endpoint')
        })

def backup_database():
    try:
        # Бэкап ключей
        keys_resp = requests.get(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS, timeout=10)
        users_resp = requests.get(f"{SUPABASE_URL}/rest/v1/users", headers=SUPABASE_HEADERS, timeout=10)
        
        if keys_resp.status_code == 200 and users_resp.status_code == 200:
            backup_data = {
                'timestamp': datetime.now().isoformat(),
                'keys': keys_resp.json(),
                'users': users_resp.json()
            }
            
            # Сохраняем в файл (в продакшене можно в облачное хранилище)
            backup_dir = 'backups'
            os.makedirs(backup_dir, exist_ok=True)
            filename = f"{backup_dir}/backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            with open(filename, 'w') as f:
                json.dump(backup_data, f, indent=2)
                
            # Удаляем старые бэкапы (оставляем последние 10)
            backups = sorted([f for f in os.listdir(backup_dir) if f.startswith('backup_')])
            for old_backup in backups[:-10]:
                os.remove(os.path.join(backup_dir, old_backup))
                
    except Exception as e:
        print(f"Backup error: {e}")

def send_daily_report():
    yesterday = (datetime.now() - timedelta(days=1)).date()
    daily_users = len([u for u in stats_data['daily_users'] 
                      if datetime.fromisoformat(u['timestamp']).date() == yesterday])
    daily_verifications = len([v for v in stats_data['key_verifications'] 
                             if datetime.fromisoformat(v['timestamp']).date() == yesterday])
    
    report = f"""
📊 Ежедневный отчет ({yesterday}):
• Новых пользователей: {daily_users}
• Проверок ключей: {daily_verifications}
• API вызовов: {stats_data['api_calls'].get(yesterday.isoformat(), 0)}
• Ошибок: {len([e for e in stats_data['errors'] if datetime.fromisoformat(e['timestamp']).date() == yesterday])}
"""
    print(report)  # Вместо Telegram просто выводим в консоль

# ----------------------
# Admin decorators
# ----------------------
def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('admin_authenticated'):
            return "Ur not admin!", 403
        return f(*args, **kwargs)
    return wrapper

def require_role(role):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user_role = session.get('role', 'user')
            if USER_ROLES[user_role] >= USER_ROLES[role]:
                return f(*args, **kwargs)
            return "Access denied", 403
        return wrapper
    return decorator

# ----------------------
# Background tasks
# ----------------------
def cleanup_old_keys_and_users():
    while True:
        try:
            threshold = datetime.now(timezone.utc) - timedelta(hours=24)
            resp = requests.get(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS, timeout=10)
            
            if resp.status_code == 200:
                keys = resp.json()
                for key_entry in keys:
                    created_at = key_entry.get('created_at')
                    key_value = key_entry.get('key')
                    if not created_at or not key_value:
                        continue
                    created_dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    if created_dt < threshold:
                        try:
                            del_resp = requests.delete(
                                f"{SUPABASE_URL}/rest/v1/keys?key=eq.{quote(key_value)}",
                                headers=SUPABASE_HEADERS,
                                timeout=5
                            )
                            if del_resp.status_code == 204:
                                print(f"Deleted key {key_value}")
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
            print(f"Cleanup error: {e}")
            update_stats('error', {'error': str(e), 'endpoint': 'cleanup'})

        time.sleep(24 * 3600)

def scheduled_tasks():
    """Задачи по расписанию"""
    while True:
        try:
            now = datetime.now()
            
            # Бэкап каждый день в 2:00
            if now.hour == 2 and now.minute == 0:
                backup_database()
            
            # Отчет каждый день в 9:00
            if now.hour == 9 and now.minute == 0:
                send_daily_report()
                
            time.sleep(60)  # Проверяем каждую минуту
            
        except Exception as e:
            print(f"Scheduled task error: {e}")
            time.sleep(300)

# Запуск фоновых задач
threading.Thread(target=cleanup_old_keys_and_users, daemon=True).start()
threading.Thread(target=scheduled_tasks, daemon=True).start()

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
    except requests.RequestException as e:
        update_stats('error', {'error': str(e), 'endpoint': 'save_key'})
    return None

# ----------------------
# API Routes
# ----------------------
@app.route('/api/health')
def health_check():
    """Проверка здоровья системы"""
    try:
        # Проверяем подключение к базе
        db_resp = requests.get(f"{SUPABASE_URL}/rest/v1/keys?limit=1", headers=SUPABASE_HEADERS, timeout=5)
        db_status = 'connected' if db_resp.status_code == 200 else 'disconnected'
    except:
        db_status = 'disconnected'
    
    status = {
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'database': db_status,
        'memory_usage': f"{psutil.Process().memory_info().rss / 1024 / 1024:.2f} MB",
        'active_threads': threading.active_count(),
        'uptime': time.time() - app_start_time
    }
    return jsonify(status)

@app.route('/api/stats')
@require_admin
def get_stats():
    """Статистика системы"""
    today = datetime.now().date()
    
    stats = {
        'total_users': len(stats_data['daily_users']),
        'total_verifications': len(stats_data['key_verifications']),
        'daily_users': len([u for u in stats_data['daily_users'] if datetime.fromisoformat(u['timestamp']).date() == today]),
        'daily_verifications': len([v for v in stats_data['key_verifications'] if datetime.fromisoformat(v['timestamp']).date() == today]),
        'api_calls_today': stats_data['api_calls'].get(today.isoformat(), 0),
        'recent_errors': list(stats_data['errors'])[-10:],
        'system': {
            'memory': psutil.virtual_memory()._asdict(),
            'cpu': psutil.cpu_percent(),
            'disk': psutil.disk_usage('/')._asdict()
        }
    }
    return jsonify(stats)

@app.route('/api/active_users')
@require_admin  
def get_active_users():
    """Активные пользователи за последние 24 часа"""
    threshold = datetime.now() - timedelta(hours=24)
    active_users = [u for u in stats_data['daily_users'] 
                   if datetime.fromisoformat(u['timestamp']) > threshold]
    return jsonify({'active_users': len(active_users), 'users': active_users[-50:]})

@app.route('/api/clean_old_keys', methods=['POST'])
@require_admin
def clean_old_keys():
    data = request.get_json() or {}
    days = int(data.get('days', 1))
    threshold = datetime.now(timezone.utc) - timedelta(days=days)
    
    try:
        resp = requests.get(f"{SUPABASE_URL}/rest/v1/keys", headers=SUPABASE_HEADERS, timeout=5)
        keys = resp.json() if resp.status_code == 200 else []
    except requests.RequestException as e:
        update_stats('error', {'error': str(e), 'endpoint': 'clean_old_keys'})
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
@cache.cached(timeout=30, query_string=True)
def verify_key():
    update_stats('api_call', {'endpoint': 'verify_key'})
    
    key = request.args.get('key')
    ADMIN_GAME = os.getenv("ADMIN_GAME")
    
    if key == ADMIN_GAME:
        update_stats('key_verify', {'key': key, 'result': 'valid_admin'})
        return "valid", 200, {'Content-Type': 'text/plain'}
        
    if not key or not validate_key(key):
        update_stats('key_verify', {'key': key, 'result': 'invalid_format'})
        return 'invalid', 200, {'Content-Type': 'text/plain'}    
    
    try:
        resp = requests.get(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{quote(key)}", headers=SUPABASE_HEADERS, timeout=5)
    except requests.RequestException as e:
        update_stats('error', {'error': str(e), 'endpoint': 'verify_key'})
        return 'error', 500, {'Content-Type': 'text/plain'}

    if resp.status_code != 200 or not resp.json():
        update_stats('key_verify', {'key': key, 'result': 'invalid'})
        return 'invalid', 200, {'Content-Type': 'text/plain'}

    key_data = resp.json()[0]
    if key_data.get('used'):
        update_stats('key_verify', {'key': key, 'result': 'used'})
        return 'used', 200, {'Content-Type': 'text/plain'}

    try:
        created_at = parse_date(key_data['created_at'])
    except Exception as e:
        update_stats('error', {'error': str(e), 'endpoint': 'verify_key'})
        return 'error', 500, {'Content-Type': 'text/plain'}

    if datetime.now(timezone.utc) - created_at > timedelta(hours=24):
        update_stats('key_verify', {'key': key, 'result': 'expired'})
        return 'expired', 200, {'Content-Type': 'text/plain'}

    try:
        patch_resp = requests.patch(
            f"{SUPABASE_URL}/rest/v1/keys?key=eq.{quote(key)}",
            headers=SUPABASE_HEADERS,
            json={'used': True},
            timeout=5
        )
        if patch_resp.status_code == 204:
            update_stats('key_verify', {'key': key, 'result': 'valid'})
            return 'valid', 200, {'Content-Type': 'text/plain'}
    except requests.RequestException as e:
        update_stats('error', {'error': str(e), 'endpoint': 'verify_key'})

    return 'error', 500, {'Content-Type': 'text/plain'}

@app.route('/api/save_user', methods=['POST'])
@hwid_limiter.limit('50/minute')
def save_user():
    update_stats('api_call', {'endpoint': 'save_user'})
    
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
    except requests.RequestException as e:
        update_stats('error', {'error': str(e), 'endpoint': 'save_user'})
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
    except requests.RequestException as e:
        update_stats('error', {'error': str(e), 'endpoint': 'save_user'})
        return jsonify({'error': 'Failed to save user'}), 500

    # Триггерим вебхуки и обновляем статистику
    update_stats('new_user', {'hwid': hwid, 'ip': remote_ip, 'key': key})
    trigger_webhooks('new_user', {'hwid': hwid, 'ip': remote_ip, 'key': key})

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
# Admin Panel (расширенная)
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
            session['role'] = 'admin'
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
    except requests.RequestException as e:
        update_stats('error', {'error': str(e), 'endpoint': 'admin_panel'})
        return 'Failed to fetch data', 500

    # Получаем статистику для дашборда
    stats_resp = get_stats()
    stats_json = stats_resp.get_json() if hasattr(stats_resp, 'get_json') else {}

    html_content = f"""
    <html>
    <head>
        <title>Admin Panel Pro</title>
        <style>
            body {{ font-family: Arial; padding: 20px; background-color:#1e1e2f; color:#fff; }}
            .dashboard {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 30px; }}
            .stat-card {{ background: #2d2d44; padding: 15px; border-radius: 8px; }}
            .stat-value {{ font-size: 24px; font-weight: bold; color: #3498db; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 30px; }}
            th, td {{ border: 1px solid #444; padding: 8px; text-align: left; }}
            th {{ background: #333; }}
            button {{ padding: 5px 10px; cursor:pointer; border:none; border-radius:5px; color:#fff; }}
            .delete-key {{ background-color:#e74c3c; }}
            .delete-user {{ background-color:#c0392b; }}
            .clean-old {{ background-color:#3498db; margin-bottom:15px; }}
            .refresh {{ background-color:#27ae60; }}
            .search-box {{ margin: 15px 0; padding: 8px; width: 300px; }}
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
            
            async function deleteKey(key){{
                if(confirm('Delete key: ' + key + '?')) {{
                    alert(await fetchPost('/api/delete_key',{{key:key}}));
                    location.reload();
                }}
            }}
            
            async function deleteUser(hwid){{
                if(confirm('Delete user with HWID: ' + hwid + '?')) {{
                    alert(await fetchPost('/api/delete_user',{{hwid:hwid}}));
                    location.reload();
                }}
            }}
            
            async function cleanOldKeys(){{
                let days = prompt("Удалить ключи старше (дней):","1"); 
                if(!days) return;
                let data = await fetchPost('/api/clean_old_keys',{{days:parseInt(days)}})
                alert("Удалено ключей: "+data.deleted);
                location.reload();
            }}
            
            function searchTable(tableId, inputId) {{
                var input = document.getElementById(inputId);
                var filter = input.value.toLowerCase();
                var table = document.getElementById(tableId);
                var tr = table.getElementsByTagName("tr");
                
                for (var i = 1; i < tr.length; i++) {{
                    var td = tr[i].getElementsByTagName("td");
                    var show = false;
                    for (var j = 0; j < td.length; j++) {{
                        if (td[j].innerHTML.toLowerCase().indexOf(filter) > -1) {{
                            show = true;
                            break;
                        }}
                    }}
                    tr[i].style.display = show ? "" : "none";
                }}
            }}
            
            function exportToCSV(tableId, filename) {{
                var table = document.getElementById(tableId);
                var csv = [];
                var rows = table.querySelectorAll('tr');
                
                for (var i = 0; i < rows.length; i++) {{
                    var row = [], cols = rows[i].querySelectorAll('td, th');
                    
                    for (var j = 0; j < cols.length; j++) {{
                        row.push('"' + cols[j].innerText + '"');
                    }}
                    
                    csv.push(row.join(','));
                }}
                
                var csvFile = new Blob([csv.join('\\n')], {{type: 'text/csv'}});
                var downloadLink = document.createElement('a');
                downloadLink.download = filename;
                downloadLink.href = window.URL.createObjectURL(csvFile);
                downloadLink.style.display = 'none';
                document.body.appendChild(downloadLink);
                downloadLink.click();
            }}
        </script>
    </head>
    <body>
        <h1>🚀 Admin Panel Pro</h1>
        
        <!-- Дашборд со статистикой -->
        <div class="dashboard">
            <div class="stat-card">
                <div>Всего пользователей</div>
                <div class="stat-value">{stats_json.get('total_users', 0)}</div>
            </div>
            <div class="stat-card">
                <div>Пользователей сегодня</div>
                <div class="stat-value">{stats_json.get('daily_users', 0)}</div>
            </div>
            <div class="stat-card">
                <div>Проверок ключей</div>
                <div class="stat-value">{stats_json.get('total_verifications', 0)}</div>
            </div>
            <div class="stat-card">
                <div>API вызовов сегодня</div>
                <div class="stat-value">{stats_json.get('api_calls_today', 0)}</div>
            </div>
        </div>

        <div style="margin-bottom: 20px;">
            <button class="clean-old" onclick="cleanOldKeys()">🗑️ Удалить старые ключи</button>
            <button class="refresh" onclick="location.reload()">🔄 Обновить</button>
            <button onclick="exportToCSV('keysTable', 'keys_export.csv')">📊 Экспорт ключей</button>
            <button onclick="exportToCSV('usersTable', 'users_export.csv')">📊 Экспорт пользователей</button>
        </div>

        <h2>🔑 Keys ({len(keys_data)})</h2>
        <input type="text" class="search-box" id="keysSearch" onkeyup="searchTable('keysTable', 'keysSearch')" placeholder="Поиск по ключам...">
        <table id="keysTable">
            <tr><th>Key</th><th>Used</th><th>Created At</th><th>Action</th></tr>
            {''.join(f"<tr><td>{safe_html(k['key'])}</td><td>{k['used']}</td><td>{safe_html(k['created_at'])}</td>"
                     f"<td><button class='delete-key' onclick=\"deleteKey('{safe_html(k['key'])}')\">Delete</button></td></tr>" 
                     for k in keys_data)}
        </table>
        
        <h2>👥 Users ({len(users_data)})</h2>
        <input type="text" class="search-box" id="usersSearch" onkeyup="searchTable('usersTable', 'usersSearch')" placeholder="Поиск по пользователям...">
        <table id="usersTable">
            <tr><th>User ID</th><th>HWID</th><th>Cookies</th><th>Key</th><th>Registered At</th><th>Action</th></tr>
            {''.join(f"<tr><td>{safe_html(u['user_id'])}</td><td>{safe_html(u['hwid'])}</td><td>{safe_html(u['cookies'][:50])}...</td>"
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
@app.route("/api/checkUpdate/KeySystem", methods = ['GET'])
def checkUpdate():
    return jsonify({"update_available": False})

@app.route("/api/AntiKick", methods = ['GET'])
def antikick():
    return "pastefy.app/0vPA1qOu/raw"

@app.route("/api/GetScript/KeySystem", methods = ['GET'])
def GetScript():
    return jsonify({'loadURL':''})

@app.route('/api/delete_key', methods=['POST'])
@require_admin
def delete_key():
    data = request.get_json() or {}
    key = data.get('key')
    if not key or not validate_key(key):
        return 'Missing or invalid key', 400
    try:
        resp = requests.delete(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{quote(key)}", headers=SUPABASE_HEADERS, timeout=5)
    except requests.RequestException as e:
        update_stats('error', {'error': str(e), 'endpoint': 'delete_key'})
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
    except requests.RequestException as e:
        update_stats('error', {'error': str(e), 'endpoint': 'delete_user'})
        return ERR_DB_FAIL, 500
    return 'User deleted' if resp.status_code == 204 else f"Failed: {resp.text}", 500

# ----------------------
# Run app
# ----------------------
app_start_time = time.time()

if __name__ == '__main__':
    # Создаем папку для бэкапов при старте
    os.makedirs('backups', exist_ok=True)
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
