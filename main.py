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
import logging
from typing import Optional, Dict, Any, List, Tuple

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Загрузка переменных окружения
load_dotenv('/etc/secrets/.env')

# Константы
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')
SECRET_KEY = os.getenv("SECRET_KEY")
ADMIN_PASS = os.getenv('ADMIN_PASS')
ADMIN_GAME = os.getenv("ADMIN_GAME")

SUPABASE_HEADERS = {
    'apikey': SUPABASE_KEY,
    'Authorization': f"Bearer {SUPABASE_KEY}",
    'Content-Type': 'application/json'
}

# Regex patterns
KEY_REGEX = re.compile(r'^Tw3ch1k_[0-9oasuxclO68901\-]{16,}$')
HWID_REGEX = re.compile(r'^[0-9A-Fa-f\-]{5,}$')

# Error messages
ERR_DB_FAIL = 'Database request failed'
ERR_ACCESS_DENIED = 'Access denied'
ERR_SAVE_KEY = 'Failed to save key'

# Кэш для часто используемых данных
KEY_CACHE: Dict[str, Any] = {}
CACHE_TIMEOUT = 300  # 5 минут

class SupabaseClient:
    """Класс для работы с Supabase API"""
    
    def __init__(self, url: str, headers: dict):
        self.url = url
        self.headers = headers
        self.session = requests.Session()
        self.session.headers.update(headers)
        self.timeout = 10
    
    def get(self, endpoint: str, params: Optional[dict] = None) -> Optional[dict]:
        """GET запрос к Supabase"""
        try:
            response = self.session.get(f"{self.url}/{endpoint}", params=params, timeout=self.timeout)
            if response.status_code == 200:
                return response.json()
            return None
        except requests.RequestException as e:
            logger.error(f"Supabase GET error: {e}")
            return None
    
    def post(self, endpoint: str, data: dict) -> bool:
        """POST запрос к Supabase"""
        try:
            response = self.session.post(f"{self.url}/{endpoint}", json=data, timeout=self.timeout)
            return response.status_code in (201, 200)
        except requests.RequestException as e:
            logger.error(f"Supabase POST error: {e}")
            return False
    
    def patch(self, endpoint: str, data: dict) -> bool:
        """PATCH запрос к Supabase"""
        try:
            response = self.session.patch(f"{self.url}/{endpoint}", json=data, timeout=self.timeout)
            return response.status_code == 204
        except requests.RequestException as e:
            logger.error(f"Supabase PATCH error: {e}")
            return False
    
    def delete(self, endpoint: str) -> bool:
        """DELETE запрос к Supabase"""
        try:
            response = self.session.delete(f"{self.url}/{endpoint}", timeout=self.timeout)
            return response.status_code == 204
        except requests.RequestException as e:
            logger.error(f"Supabase DELETE error: {e}")
            return False

# Инициализация клиента Supabase
supabase = SupabaseClient(SUPABASE_URL, SUPABASE_HEADERS)

# Flask app
app = Flask(__name__)
app.secret_key = os.getenv("ADMIN_SESSION_KEY", "fallback_secret_key")
app.config.update({
    'SESSION_COOKIE_NAME': os.getenv("sskk", "session_cookie"),
    'SESSION_COOKIE_SECURE': True,
    'SESSION_COOKIE_HTTPONLY': True,
    'SESSION_COOKIE_SAMESITE': 'Lax',
    'PERMANENT_SESSION_LIFETIME': timedelta(days=7)
})

CORS(app, resources={r"/api/*": {"origins": ["https://www.roblox.com", "https://*.robloxlabs.com"]}})
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=['200 per hour', '50 per minute'],
    storage_uri="memory://"
)

# ----------------------
# Utility functions
# ----------------------
def validate_key(key: str) -> bool:
    """Проверка валидности ключа"""
    return bool(KEY_REGEX.match(key)) if key else False

def validate_hwid(hwid: str) -> bool:
    """Проверка валидности HWID"""
    return bool(HWID_REGEX.match(hwid)) if hwid else False

def validate_ip(ip: str) -> bool:
    """Проверка валидности IP адреса"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_user_id(ip: str, hwid: str) -> str:
    """Генерация уникального ID пользователя"""
    return base64.b64encode(f"{ip}_{hwid}".encode()).decode()

def safe_html(s: str) -> str:
    """Экранирование HTML символов"""
    return html.escape(str(s)) if s else ""

def generate_key(length: int = 16) -> str:
    """Генерация ключа"""
    chars_main = 'oasuxclO'
    chars_digits = '68901'
    num_digits = int(length * 0.7)
    num_main = length - num_digits
    key_chars = random.choices(chars_digits, k=num_digits) + random.choices(chars_main, k=num_main)
    random.shuffle(key_chars)
    key_str = ''.join(key_chars)
    return "Tw3ch1k_" + "-".join([key_str[i:i+4] for i in range(0, len(key_str), 4)])

def get_cached_data(key: str) -> Optional[Any]:
    """Получение данных из кэша"""
    if key in KEY_CACHE:
        data, timestamp = KEY_CACHE[key]
        if time.time() - timestamp < CACHE_TIMEOUT:
            return data
        del KEY_CACHE[key]
    return None

def set_cached_data(key: str, data: Any) -> None:
    """Сохранение данных в кэш"""
    KEY_CACHE[key] = (data, time.time())

def cleanup_old_keys_and_users():
    """Фоновая задача для очистки старых ключей и пользователей"""
    while True:
        try:
            threshold = datetime.now(timezone.utc) - timedelta(hours=24)
            keys = supabase.get("rest/v1/keys") or []
            
            for key_entry in keys:
                created_at = key_entry.get('created_at')
                key_value = key_entry.get('key')
                
                if not created_at or not key_value:
                    continue
                
                try:
                    created_dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    if created_dt < threshold:
                        # Удаляем ключ
                        if supabase.delete(f"rest/v1/keys?key=eq.{quote(key_value)}"):
                            logger.info(f"Deleted key {key_value}")
                            # Удаляем пользователей с этим ключом
                            supabase.delete(f"rest/v1/users?key=eq.{quote(key_value)}")
                except ValueError:
                    continue

        except Exception as e:
            logger.error(f"Cleanup error: {e}")

        time.sleep(24 * 3600)  # Ждём 24 часа

# Запуск фоновой задачи
threading.Thread(target=cleanup_old_keys_and_users, daemon=True).start()

def save_key(key: Optional[str] = None) -> Optional[str]:
    """Сохранение ключа в базу данных"""
    key = key or generate_key()
    payload = {
        'key': key,
        'created_at': datetime.now(timezone.utc).isoformat(),
        'used': False
    }
    
    if supabase.post("rest/v1/keys", payload):
        return key
    return None

# ----------------------
# Admin decorators
# ----------------------
def require_admin(f):
    """Декоратор для проверки прав администратора"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        secret = request.args.get('d')
        if secret != SECRET_KEY and not session.get('admin_authenticated'):
            return "Access denied!", 403
        return f(*args, **kwargs)
    return wrapper

# ----------------------
# API Routes
# ----------------------
@app.route('/api/clean_old_keys', methods=['POST'])
@require_admin
def clean_old_keys():
    """Очистка старых ключей"""
    data = request.get_json() or {}
    days = int(data.get('days', 1))
    threshold = datetime.now(timezone.utc) - timedelta(days=days)
    
    keys = supabase.get("rest/v1/keys") or []
    deleted_count = 0
    
    for key_entry in keys:
        created = key_entry.get('created_at')
        if not created:
            continue
        
        try:
            created_dt = parse_date(created)
            if created_dt < threshold:
                k = quote(key_entry['key'])
                if supabase.delete(f"rest/v1/keys?key=eq.{k}"):
                    deleted_count += 1
        except Exception:
            continue
    
    return jsonify({'deleted': deleted_count})

@app.route('/api/get_key')
@limiter.limit('10/minute')
def get_key():
    """Получение нового ключа"""
    key = save_key()
    if not key:
        return jsonify({'error': ERR_SAVE_KEY}), 500
    return jsonify({'key': key})

@app.route('/api/verify_key')
@limiter.limit('20/minute')
def verify_key():
    """Проверка валидности ключа"""
    key = request.args.get('key')
    
    # Проверка административного ключа
    if key == ADMIN_GAME:
        return "valid", 200, {'Content-Type': 'text/plain'}
    
    # Проверка валидности ключа
    if not key or not validate_key(key):
        return 'invalid', 200, {'Content-Type': 'text/plain'}
    
    # Проверка кэша
    cache_key = f"key_{key}"
    cached_result = get_cached_data(cache_key)
    if cached_result:
        return cached_result, 200, {'Content-Type': 'text/plain'}
    
    # Запрос к базе данных
    key_data = supabase.get(f"rest/v1/keys?key=eq.{quote(key)}")
    if not key_data:
        return 'invalid', 200, {'Content-Type': 'text/plain'}
    
    key_entry = key_data[0] if key_data else {}
    if key_entry.get('used'):
        result = 'used'
        set_cached_data(cache_key, result)
        return result, 200, {'Content-Type': 'text/plain'}
    
    # Проверка времени создания
    try:
        created_at = parse_date(key_entry['created_at'])
        if datetime.now(timezone.utc) - created_at > timedelta(hours=24):
            result = 'expired'
            set_cached_data(cache_key, result)
            return result, 200, {'Content-Type': 'text/plain'}
    except Exception:
        return 'error', 500, {'Content-Type': 'text/plain'}
    
    # Помечаем ключ как использованный
    if supabase.patch(f"rest/v1/keys?key=eq.{quote(key)}", {'used': True}):
        result = 'valid'
        set_cached_data(cache_key, result)
        return result, 200, {'Content-Type': 'text/plain'}
    
    return 'error', 500, {'Content-Type': 'text/plain'}

@app.route('/api/save_user', methods=['POST'])
@limiter.limit('50/minute')
def save_user():
    """Сохранение данных пользователя"""
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
    
    # Проверка существующего пользователя
    existing_users = supabase.get(f"rest/v1/users?user_id=eq.{quote(user_id)}") or []
    if existing_users:
        user = existing_users[0]
        return jsonify({
            'status': 'exists', 
            'key': user['key'], 
            'registered_at': user['registered_at']
        })
    
    # Валидация и генерация ключа
    if key and validate_key(key):
        key_data = supabase.get(f"rest/v1/keys?key=eq.{quote(key)}")
        if not key_data:
            key = save_key()
    else:
        key = save_key()
    
    if not key:
        return jsonify({'error': ERR_SAVE_KEY}), 500
    
    # Сохранение пользователя
    payload = {
        'user_id': user_id,
        'cookies': cookies[:1000],  # Ограничение длины
        'hwid': hwid,
        'key': key,
        'registered_at': datetime.utcnow().isoformat()
    }
    
    if supabase.post("rest/v1/users", payload):
        return jsonify({
            'status': 'saved', 
            'key': key, 
            'registered_at': payload['registered_at']
        })
    
    return jsonify({'error': 'Failed to save user'}), 500

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
    """Административная панель"""
    session.permanent = True
    if session.get('admin_authenticated'):
        return render_admin_page()
    
    if request.method == "POST":
        password = request.form.get("passwrd") or (request.get_json() or {}).get("passwrd")
        if not password:
            return "Missing password", 400
        
        hashed_input = hashlib.sha256(password.encode()).hexdigest()
        hashed_admin = hashlib.sha256(ADMIN_PASS.encode()).hexdigest()
        
        if hashed_input == hashed_admin:
            session['admin_authenticated'] = True
            return render_admin_page()
        
        return "Неверный пароль!", 403
    
    return '''
        <form method="post">
            Пароль: <input type="password" name="passwrd">
            <input type="submit" value="Войти">
        </form>
    '''

def render_admin_page() -> str:
    """Рендеринг административной панели"""
    keys_data = supabase.get("rest/v1/keys") or []
    users_data = supabase.get("rest/v1/users") or []
    
    keys_html = "".join(
        f"<tr><td>{safe_html(k['key'])}</td><td>{k['used']}</td>"
        f"<td>{safe_html(k['created_at'])}</td>"
        f"<td><button class='delete-key' onclick=\"deleteKey('{safe_html(k['key'])}')\">Delete</button></td></tr>"
        for k in keys_data
    )
    
    users_html = "".join(
        f"<tr><td>{safe_html(u['user_id'])}</td><td>{safe_html(u['hwid'])}</td>"
        f"<td>{safe_html(u['cookies'][:50])}{'...' if len(u['cookies']) > 50 else ''}</td>"
        f"<td>{safe_html(u['key'])}</td><td>{safe_html(u['registered_at'])}</td>"
        f"<td><button class='delete-user' onclick=\"deleteUser('{safe_html(u['hwid'])}')\">Delete</button></td></tr>"
        for u in users_data
    )
    
    return f"""
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
            async function deleteKey(key){{
                const result = await fetchPost('/api/delete_key',{{key:key}});
                alert(typeof result === 'string' ? result : result.message);
                location.reload();
            }}
            async function deleteUser(hwid){{
                const result = await fetchPost('/api/delete_user',{{hwid:hwid}});
                alert(typeof result === 'string' ? result : result.message);
                location.reload();
            }}
            async function cleanOldKeys(){{
                let days = prompt("Удалить ключи старше (дней):","1"); 
                if(!days) return;
                let data = await fetchPost('/api/clean_old_keys',{{days:parseInt(days)}});
                alert("Удалено ключей: "+data.deleted);
                location.reload();
            }}
        </script>
    </head>
    <body>
        <h1>Admin Panel</h1>
        <button class="clean-old" onclick="cleanOldKeys()">Удалить старые ключи</button>
        
        <h2>Keys ({len(keys_data)})</h2>
        <table>
            <tr><th>Key</th><th>Used</th><th>Created At</th><th>Action</th></tr>
            {keys_html}
        </table>
        
        <h2>Users ({len(users_data)})</h2>
        <table>
            <tr><th>User ID</th><th>HWID</th><th>Cookies</th><th>Key</th><th>Registered At</th><th>Action</th></tr>
            {users_html}
        </table>
    </body>
    </html>
    """

# ----------------------
# Delete endpoints
# ----------------------
@app.route('/api/delete_key', methods=['POST'])
@require_admin
def delete_key():
    """Удаление ключа"""
    data = request.get_json() or {}
    key = data.get('key')
    
    if not key or not validate_key(key):
        return jsonify({'error': 'Missing or invalid key'}), 400
    
    if supabase.delete(f"rest/v1/keys?key=eq.{quote(key)}"):
        return jsonify({'message': 'Key deleted'})
    
    return jsonify({'error': ERR_DB_FAIL}), 500

@app.route('/api/delete_user', methods=['POST'])
@require_admin
def delete_user():
    """Удаление пользователя"""
    data = request.get_json() or {}
    hwid = data.get('hwid')
    
    if not hwid or not validate_hwid(hwid):
        return jsonify({'error': 'Missing or invalid hwid'}), 400
    
    if supabase.delete(f"rest/v1/users?hwid=eq.{quote(hwid)}"):
        return jsonify({'message': 'User deleted'})
    
    return jsonify({'error': ERR_DB_FAIL}), 500

# ----------------------
# Health check endpoint
# ----------------------
@app.route('/health')
def health_check():
    """Проверка работоспособности сервиса"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})

# ----------------------
# Error handlers
# ----------------------
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(429)
def rate_limit_exceeded(error):
    return jsonify({'error': 'Rate limit exceeded'}), 429

# ----------------------
# Run app
# ----------------------
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
