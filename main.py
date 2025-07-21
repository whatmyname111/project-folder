from flask import Flask, render_template_string, request
import random, string, json, os
from datetime import datetime, timedelta

app = Flask(__name__)
KEYS_FILE = 'keys.json'

# Генерация случайного ключа
def generate_key():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=20))

# Загрузка ключей
def load_keys():
    if not os.path.exists(KEYS_FILE):
        return {}
    with open(KEYS_FILE, 'r') as f:
        return json.load(f)

# Сохранение ключей
def save_keys(keys):
    with open(KEYS_FILE, 'w') as f:
        json.dump(keys, f)

@app.route('/')
def index():
    return render_template_string(open("index.html").read())

@app.route('/get_key', methods=['GET'])
def get_key():
    keys = load_keys()
    key = generate_key()
    expire_time = (datetime.now() + timedelta(hours=24)).isoformat()
    keys[key] = { "expires": expire_time, "used": False }
    save_keys(keys)
    return key

@app.route('/verify', methods=['POST'])
def verify_key():
    key = request.form.get('key')
    keys = load_keys()
    data = keys.get(key)

    if not data:
        return 'INVALID'
    if data['used']:
        return 'USED'
    if datetime.fromisoformat(data['expires']) < datetime.now():
        return 'EXPIRED'

    keys[key]['used'] = True
    save_keys(keys)
    return 'VALID'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
