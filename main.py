import os
import base64
import random
import re
from urllib.parse import quote
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, send_from_directory, render_template
import requests
from dotenv import load_dotenv
from dateutil.parser import parse as parse_date
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, login_required
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_migrate import Migrate

# Загрузка переменных окружения
load_dotenv()

# Константы
_M = 'Database request failed'
_L = 'user_id'
_K = 'Failed to save key'
_J = 'cookies'
_I = 'POST'
_H = 'Access denied'
_G = 'created_at'
_F = 'registered_at'
_E = 'hwid'
_D = 'used'
_C = 'Content-Type'
_B = 'error'
_A = 'key'

# Инициализация приложения
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'secret-key-123')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///admin.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECURITY_PASSWORD_SALT'] = os.getenv('SECURITY_PASSWORD_SALT', 'salt-123')
app.config['SECURITY_REGISTERABLE'] = True
app.config['SECURITY_SEND_REGISTER_EMAIL'] = False
app.config['SECURITY_USER_IDENTITY_ATTRIBUTES'] = ['email']
app.config['SECURITY_POST_LOGIN_VIEW'] = '/admin/'

# Инициализация расширений
db = SQLAlchemy(app)
Bootstrap(app)
migrate = Migrate(app, db)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=['20 per minute'],
    storage_uri="memory://",
)

# Модели для аутентификации
roles_users = db.Table(
    'roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary=roles_users,
                         backref=db.backref('users', lazy='dynamic'))

# Настройка Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

# Настройка Flask-Admin
class AdminModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.has_role('admin')

admin = Admin(app, name='Admin Panel', template_mode='bootstrap3')
admin.add_view(AdminModelView(User, db.session))
admin.add_view(AdminModelView(Role, db.session))

# Конфигурация Supabase
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')
ADMIN_KEY = os.getenv('ADMIN_KEY')
ADMIN_IP = os.getenv('ADMIN_IP')
SUPABASE_HEADERS = {
    'apikey': SUPABASE_KEY,
    'Authorization': f"Bearer {SUPABASE_KEY}",
    _C: 'application/json'
}

# Регулярные выражения
KEY_REGEX = re.compile('^Tw3ch1k_[0-9oasuxclO68901\\-]{16,}$')
HWID_REGEX = re.compile('^[0-9A-Fa-f\\-]{5,}$')
IP_REGEX = re.compile('^\\d{1,3}(\\.\\d{1,3}){3}$')

# Вспомогательные функции
def validate_key(key):
    return bool(KEY_REGEX.match(key))

def validate_hwid(hwid):
    return bool(HWID_REGEX.match(hwid))

def validate_ip(ip):
    return bool(IP_REGEX.match(ip))

def is_admin_request():
    admin_key = request.headers.get('X-Admin-Key') or request.args.get('d')
    return admin_key == ADMIN_KEY

def generate_key(length=16):
    chars = '68901'
    special_chars = 'oasuxclO'
    key_part = ''.join(random.choices(chars, k=int(length * 0.7)) + 
                random.choices(special_chars, k=length - int(length * 0.7)))
    random.shuffle(key_part)
    return f"Tw3ch1k_" + '-'.join([key_part[i:i+4] for i in range(0, len(key_part), 4)])

def save_key(key=None):
    key = key or generate_key()
    created_at = datetime.utcnow().isoformat()
    payload = {_A: key, _G: created_at, _D: False}
    
    try:
        response = requests.post(
            f"{SUPABASE_URL}/rest/v1/keys",
            headers=SUPABASE_HEADERS,
            json=payload,
            timeout=5
        )
        if response.status_code == 201:
            return key
    except requests.RequestException:
        pass
    return None

def get_user_id(ip, hwid):
    return base64.b64encode(f"{ip}_{hwid}".encode()).decode()

# Маршруты API
@app.route('/api/clean_old_keys', methods=[_I])
def clean_old_keys():
    if not is_admin_request():
        return jsonify({_B: _H}), 403
    
    data = request.get_json() or {}
    days = int(data.get('days', 1))
    cutoff_date = datetime.utcnow().replace(tzinfo=timezone.utc) - timedelta(days=days)
    
    try:
        response = requests.get(
            f"{SUPABASE_URL}/rest/v1/keys",
            headers=SUPABASE_HEADERS,
            timeout=5
        )
        if response.status_code != 200:
            return jsonify({_B: 'Failed to fetch keys', 'details': response.text}), 500
        keys = response.json()
    except requests.RequestException:
        return jsonify({_B: 'Failed to fetch keys'}), 500
    
    deleted = 0
    for key_data in keys:
        created_at = key_data.get(_G)
        if not created_at:
            continue
        try:
            created_date = parse_date(created_at)
        except Exception:
            continue
        
        if created_date < cutoff_date:
            key = quote(key_data[_A])
            try:
                delete_response = requests.delete(
                    f"{SUPABASE_URL}/rest/v1/keys?key=eq.{key}",
                    headers=SUPABASE_HEADERS,
                    timeout=5
                )
                if delete_response.status_code == 204:
                    deleted += 1
            except requests.RequestException:
                pass
    
    return jsonify({'deleted': deleted})

@app.route('/api/get_key')
@limiter.limit('10/minute')
def get_key():
    key = save_key()
    if not key:
        return jsonify({_B: _K}), 500
    return jsonify({_A: key})

@app.route('/api/verify_key')
@limiter.limit('20/minute')
def verify_key():
    key = request.args.get(_A)
    if not key or not validate_key(key):
        return 'invalid', 200, {_C: 'text/plain'}
    
    try:
        response = requests.get(
            f"{SUPABASE_URL}/rest/v1/keys?key=eq.{quote(key)}",
            headers=SUPABASE_HEADERS,
            timeout=5
        )
    except requests.RequestException:
        return _B, 500, {_C: 'text/plain'}
    
    if response.status_code != 200 or not response.json():
        return 'invalid', 200, {_C: 'text/plain'}
    
    key_data = response.json()[0]
    if key_data.get(_D):
        return _D, 200, {_C: 'text/plain'}
    
    try:
        created_date = parse_date(key_data[_G])
    except Exception:
        return _B, 500, {_C: 'text/plain'}
    
    if datetime.now(timezone.utc) - created_date > timedelta(hours=24):
        return 'expired', 200, {_C: 'text/plain'}
    
    try:
        update_response = requests.patch(
            f"{SUPABASE_URL}/rest/v1/keys?key=eq.{quote(key)}",
            headers=SUPABASE_HEADERS,
            json={_D: True},
            timeout=5
        )
        if update_response.status_code == 204:
            return 'valid', 200, {_C: 'text/plain'}
    except requests.RequestException:
        pass
    
    return _B, 500, {_C: 'text/plain'}

@app.route('/api/save_user', methods=[_I])
@limiter.limit('5/minute')
def save_user():
    data = request.json or {}
    ip = request.remote_addr or 'unknown_ip'
    
    if not validate_ip(ip):
        ip = 'unknown_ip'
    
    cookies = data.get(_J, '')
    hwid = data.get(_E, '')
    key = data.get(_A, '')
    
    if not hwid or not validate_hwid(hwid):
        return jsonify({_B: 'Missing or invalid HWID'}), 400
    
    user_id = get_user_id(ip, hwid)
    
    try:
        response = requests.get(
            f"{SUPABASE_URL}/rest/v1/users?user_id=eq.{quote(user_id)}",
            headers=SUPABASE_HEADERS,
            timeout=5
        )
        if response.status_code != 200:
            return jsonify({_B: 'Failed to query user'}), 500
        user_data = response.json()
    except requests.RequestException:
        return jsonify({_B: 'Failed to query user'}), 500
    
    if user_data:
        return jsonify({
            'status': 'exists',
            _A: user_data[0][_A],
            _F: user_data[0][_F]
        })
    
    if key:
        if not validate_key(key):
            key = save_key()
        else:
            try:
                key_response = requests.get(
                    f"{SUPABASE_URL}/rest/v1/keys?key=eq.{quote(key)}",
                    headers=SUPABASE_HEADERS,
                    timeout=5
                )
                if key_response.status_code != 200 or not key_response.json():
                    key = save_key()
            except requests.RequestException:
                key = save_key()
    else:
        key = save_key()
    
    if not key:
        return jsonify({_B: _K}), 500
    
    registered_at = datetime.utcnow().isoformat()
    payload = {
        _L: user_id,
        _J: cookies,
        _E: hwid,
        _A: key,
        _F: registered_at
    }
    
    try:
        save_response = requests.post(
            f"{SUPABASE_URL}/rest/v1/users",
            headers=SUPABASE_HEADERS,
            json=payload,
            timeout=5
        )
        if save_response.status_code != 201:
            return jsonify({_B: 'Failed to save user'}), 500
    except requests.RequestException:
        return jsonify({_B: 'Failed to save user'}), 500
    
    return jsonify({
        'status': 'saved',
        _A: key,
        _F: registered_at
    })

# Статические маршруты
@app.route('/')
def serve_index():
    return send_from_directory('static', 'index.html')

@app.route('/style.css')
def serve_css():
    return send_from_directory('static', 'style.css')

# Админ-панель
@app.route('/user/admin')
@login_required
def admin_panel():
    if not current_user.has_role('admin'):
        return _H, 403
    
    try:
        keys_response = requests.get(
            f"{SUPABASE_URL}/rest/v1/keys",
            headers=SUPABASE_HEADERS,
            timeout=5
        )
        users_response = requests.get(
            f"{SUPABASE_URL}/rest/v1/users",
            headers=SUPABASE_HEADERS,
            timeout=5
        )
        
        if keys_response.status_code != 200 or users_response.status_code != 200:
            return 'Failed to fetch data', 500
        
        keys = keys_response.json()
        users = users_response.json()
    except requests.RequestException:
        return 'Failed to fetch data', 500
    
    return render_template(
        'admin_panel.html',
        keys=keys,
        users=users,
        admin_key=ADMIN_KEY
    )

@app.route('/api/delete_key', methods=[_I])
@login_required
def delete_key():
    if not current_user.has_role('admin'):
        return _H, 403
    
    data = request.get_json() or {}
    key = data.get(_A)
    
    if not key or not validate_key(key):
        return 'Missing or invalid key', 400
    
    try:
        response = requests.delete(
            f"{SUPABASE_URL}/rest/v1/keys?key=eq.{quote(key)}",
            headers=SUPABASE_HEADERS,
            timeout=5
        )
    except requests.RequestException:
        return _M, 500
    
    if response.status_code == 204:
        return 'Key deleted'
    return f"Failed to delete: {response.text}", 500

@app.route('/api/delete_user', methods=[_I])
@login_required
def delete_user():
    if not current_user.has_role('admin'):
        return _H, 403
    
    data = request.get_json() or {}
    hwid = data.get(_E)
    
    if not hwid or not validate_hwid(hwid):
        return 'Missing or invalid hwid', 400
    
    try:
        response = requests.delete(
            f"{SUPABASE_URL}/rest/v1/users?hwid=eq.{quote(hwid)}",
            headers=SUPABASE_HEADERS,
            timeout=5
        )
    except requests.RequestException:
        return _M, 500
    
    if response.status_code == 204:
        return 'User deleted'
    return f"Failed to delete: {response.text}", 500

# Создание первого администратора
@app.before_first_request
def create_first_admin():
    db.create_all()
    if not User.query.filter_by(email='admin@example.com').first():
        user_datastore.create_user(
            email='admin@example.com',
            password=os.getenv('ADMIN_PASSWORD', 'admin123')
        )
        db.session.commit()
        user = User.query.filter_by(email='admin@example.com').first()
        if not Role.query.filter_by(name='admin').first():
            user_datastore.create_role(name='admin', description='Administrator')
            db.session.commit()
        user_datastore.add_role_to_user(user, 'admin')
        db.session.commit()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
