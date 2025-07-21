from flask import Flask, render_template, request, jsonify
import random
import string
import json
import os
import time
from datetime import datetime, timedelta

app = Flask(__name__)

DB_FILE = "keys.json"
KEY_LENGTH = 12
KEY_TTL_SECONDS = 24 * 60 * 60  # 24 часа

# Создаём файл, если его нет
if not os.path.exists(DB_FILE):
    with open(DB_FILE, "w") as f:
        json.dump({}, f)

def load_keys():
    with open(DB_FILE, "r") as f:
        return json.load(f)

def save_keys(data):
    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=4)

def generate_key():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=KEY_LENGTH))

@app.route("/")
def index():
    ip = request.remote_addr
    keys = load_keys()

    # Удаляем просроченные ключи
    now = time.time()
    keys = {k: v for k, v in keys.items() if now - v["created"] < KEY_TTL_SECONDS}

    if ip in keys:
        key = keys[ip]["key"]
        message = "You already received your key, use it!"
    else:
        key = generate_key()
        keys[ip] = {
            "key": key,
            "created": now,
            "used": False
        }
        save_keys(keys)
        message = "Your key has been generated!"

    return render_template("index.html", key=key, message=message)

@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.get_json()
    key = data.get("key", "").strip().upper()

    keys = load_keys()
    now = time.time()

    # Найдём запись с таким ключом (по значению key, не по ip)
    found_entry = None
    found_ip = None
    for ip, info in keys.items():
        if info["key"] == key:
            found_entry = info
            found_ip = ip
            break

    if not found_entry:
        # Ключа нет в базе
        return jsonify({"status": "invalid"})

    # Проверяем время жизни
    elapsed = now - found_entry["created"]
    if elapsed > KEY_TTL_SECONDS:
        return jsonify({"status": "expected"})  # истек, но ещё не удалён

    # Проверяем использован ли ключ
    if found_entry.get("used", False):
        return jsonify({"status": "invalid"})

    # Если ключ ещё не активирован - активируем
    keys[found_ip]["used"] = True
    save_keys(keys)
    return jsonify({"status": "valid"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
