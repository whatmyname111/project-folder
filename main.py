_M='Database request failed'
_L='user_id'
_K='Failed to save key'
_J='cookies'
_I='POST'
_H='Access denied'
_G='created_at'
_F='registered_at'
_E='hwid'
_D='used'
_C='Content-Type'
_B='error'
_A='key'
import os,base64,random,re
from urllib.parse import quote
from datetime import datetime,timedelta,timezone
from flask import Flask,request,jsonify,send_from_directory,abort
import requests
from dotenv import load_dotenv
from dateutil.parser import parse as parse_date
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bleach
def clean_input(data):
    if isinstance(data, str):
        return bleach.clean(data)
    elif isinstance(data, dict):
        return {k: clean_input(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [clean_input(i) for i in data]
    return data
load_dotenv('/etc/secrets/.env')
SUPABASE_URL=os.getenv('SUPABASE_URL')
SUPABASE_KEY=os.getenv('SUPABASE_KEY')
ADMIN_KEY=os.getenv('ADMIN_KEY')
ADMIN_IP=os.getenv('ADMIN_IP')
app=Flask(__name__)
ALLOWED_REFERRER = os.getenv('ALLOWED_REFERRER', 'https://lootdest.org/s?WSs4Ll3G&data=hXHoIYLoVaaSF3KyHWRw9WYwNPpnxgRmSwQZ5/m9J12x8yLQvYBBioH3Ajyld/Md')
REDIRECT_URL = os.getenv('REDIRECT_URL', 'https://autoreplayscriptget.onrender.com')
limiter=Limiter(get_remote_address,app=app,default_limits=['20 per minute'])
SUPABASE_HEADERS={'apikey':SUPABASE_KEY,'Authorization':f"Bearer {SUPABASE_KEY}",_C:'application/json'}
KEY_REGEX=re.compile('^Tw3ch1k_[0-9oasuxclO68901\\-]{16,}$')
HWID_REGEX=re.compile('^[0-9A-Fa-f\\-]{5,}$')
IP_REGEX=re.compile('^\\d{1,3}(\\.\\d{1,3}){3}$')
def validate_key(key):return bool(KEY_REGEX.match(key))
def validate_hwid(hwid):return bool(HWID_REGEX.match(hwid))
def validate_ip(ip):return bool(IP_REGEX.match(ip))
def is_admin_request():A=request.headers.get('X-Admin-Key');B=request.args.get('d');C=A or B;return C==ADMIN_KEY
def generate_key(length=16):A=length;E='oasuxclO';F='68901';B=int(A*.7);G=A-B;C=random.choices(F,k=B)+random.choices(E,k=G);random.shuffle(C);D=''.join(C);return f"Tw3ch1k_"+'-'.join([D[A:A+4]for A in range(0,len(D),4)])
def save_key(key=None):
	A=key;A=A or generate_key();B=datetime.utcnow().isoformat();C={_A:A,_G:B,_D:False}
	try:
		D=requests.post(f"{SUPABASE_URL}/rest/v1/keys",headers=SUPABASE_HEADERS,json=C,timeout=5)
		if D.status_code==201:return A
	except requests.RequestException:pass
def get_user_id(ip,hwid):return base64.b64encode(f"{ip}_{hwid}".encode()).decode()
@app.route('/api/clean_old_keys',methods=[_I])
def clean_old_keys():
	E='Failed to fetch keys'
	if not is_admin_request():return jsonify({_B:_H}),403
	F=request.get_json()or{};G=int(F.get('days',1));H=datetime.utcnow().replace(tzinfo=timezone.utc)-timedelta(days=G)
	try:
		A=requests.get(f"{SUPABASE_URL}/rest/v1/keys",headers=SUPABASE_HEADERS,timeout=5)
		if A.status_code!=200:return jsonify({_B:E,'details':A.text}),500
		I=A.json()
	except requests.RequestException:return jsonify({_B:E}),500
	B=0
	for C in I:
		D=C.get(_G)
		if not D:continue
		try:J=parse_date(D)
		except Exception:continue
		if J<H:
			K=quote(C[_A])
			try:
				L=requests.delete(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{K}",headers=SUPABASE_HEADERS,timeout=5)
				if L.status_code==204:B+=1
			except requests.RequestException:pass
	return jsonify({'deleted':B})
def check_referrer():
    ref = request.referrer or ''
    return ALLOWED_REFERRER in ref

@app.before_request
def block_invalid_referrer():
    # проверяем только обычные маршруты, можно исключить админку
    if request.endpoint not in ['admin_panel']:
        if not check_referrer():
            html = f"""
            <html>
            <head><title>Access Denied</title><meta http-equiv="refresh" content="5; url={REDIRECT_URL}" /></head>
            <body>
            <h1>🚫 Access Denied</h1>
            <p>Redirecting...</p>
            </body>
            </html>
            """
            return html, 403
@app.route('/api/get_key')
@limiter.limit('10/minute')
def get_key():
	A=save_key()
	if not A:return jsonify({_B:_K}),500
	return jsonify({_A:A})
@app.route('/api/verify_key')
@limiter.limit('20/minute')
def verify_key():
	E='invalid';A='text/plain';B=request.args.get(_A)
	if not B or not validate_key(B):return E,200,{_C:A}
	try:C=requests.get(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{quote(B)}",headers=SUPABASE_HEADERS,timeout=5)
	except requests.RequestException:return _B,500,{_C:A}
	if C.status_code!=200 or not C.json():return E,200,{_C:A}
	D=C.json()[0]
	if D.get(_D):return _D,200,{_C:A}
	try:F=parse_date(D[_G])
	except Exception:return _B,500,{_C:A}
	if datetime.now(timezone.utc)-F>timedelta(hours=24):return'expired',200,{_C:A}
	try:
		G=requests.patch(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{quote(B)}",headers=SUPABASE_HEADERS,json={_D:True},timeout=5)
		if G.status_code==204:return'valid',200,{_C:A}
	except requests.RequestException:pass
	return _B,500,{_C:A}
@app.route('/api/save_user',methods=[_I])
@limiter.limit('5/minute')
def save_user():
	M='Failed to save user';L='status';K='Failed to query user';J='unknown_ip';C=request.json or{};D=request.remote_addr or J
	if not validate_ip(D):D=J
	N=C.get(_J,'');B=C.get(_E,'');A=C.get(_A,'')
	if not B or not validate_hwid(B):return jsonify({_B:'Missing or invalid HWID'}),400
	F=get_user_id(D,B)
	try:
		G=requests.get(f"{SUPABASE_URL}/rest/v1/users?user_id=eq.{quote(F)}",headers=SUPABASE_HEADERS,timeout=5)
		if G.status_code!=200:return jsonify({_B:K}),500
		E=G.json()
	except requests.RequestException:return jsonify({_B:K}),500
	if E:return jsonify({L:'exists',_A:E[0][_A],_F:E[0][_F]})
	if A:
		if not validate_key(A):A=save_key()
		else:
			try:
				H=requests.get(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{quote(A)}",headers=SUPABASE_HEADERS,timeout=5)
				if H.status_code!=200 or not H.json():A=save_key()
			except requests.RequestException:A=save_key()
	else:A=save_key()
	if not A:return jsonify({_B:_K}),500
	I=datetime.utcnow().isoformat();O={_L:F,_J:N,_E:B,_A:A,_F:I}
	try:
		P=requests.post(f"{SUPABASE_URL}/rest/v1/users",headers=SUPABASE_HEADERS,json=O,timeout=5)
		if P.status_code!=201:return jsonify({_B:M}),500
	except requests.RequestException:return jsonify({_B:M}),500
	return jsonify({L:'saved',_A:A,_F:I})
@app.route('/')
def serve_index():return send_from_directory('.','index.html')
@app.route('/style.css')
def serve_css():return send_from_directory('.','style.css')
@app.route('/user/admin')
def admin_panel():
	F='Failed to fetch data'
	if not is_admin_request():return _H,403
	try:
		D=requests.get(f"{SUPABASE_URL}/rest/v1/keys",headers=SUPABASE_HEADERS,timeout=5);E=requests.get(f"{SUPABASE_URL}/rest/v1/users",headers=SUPABASE_HEADERS,timeout=5)
		if D.status_code!=200 or E.status_code!=200:return F,500
		G=D.json();H=E.json()
	except requests.RequestException:return F,500
	B='<html><head><title>Admin Panel</title><style>\n\n        body { font-family: monospace; background: #121212; color: #eee; padding: 20px; }\n\n        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }\n\n        th, td { border: 1px solid #666; padding: 8px; }\n\n        th { background: #222; }\n\n        button { background: #f33; color: white; border: none; padding: 4px 8px; cursor: pointer; }\n\n    </style><script>\n\n        async function del(url, payload) {\n\n            const res = await fetch(url, {\n\n                method: "POST",\n\n                headers: {\'Content-Type\': \'application/json\', \'X-Admin-Key\': \''+ADMIN_KEY+'\'},\n\n                body: JSON.stringify(payload)\n\n            });\n\n            alert(await res.text());\n\n            location.reload();\n\n        }\n\n    </script></head><body>\n\n    <h1>🔑 Keys</h1>\n\n    <h2>🧹 Очистка</h2>\n\n    <button onclick="del(\'/api/clean_old_keys\', {days: 1})">Удалить ключи старше 24ч</button>\n\n    <table><tr><th>Key</th><th>Used</th><th>Created At</th><th>Action</th></tr>'
	for C in G:B+=f"<tr><td>{C[_A]}</td><td>{C[_D]}</td><td>{C[_G]}</td><td><button onclick=\"del('/api/delete_key', {{key: '{C[_A]}'}})\">Delete</button></td></tr>"
	B+='</table><h1>👤 Users</h1><table><tr><th>User ID</th><th>HWID</th><th>Cookies</th><th>Key</th><th>Registered At</th><th>Action</th></tr>'
	for A in H:B+=f"<tr><td>{A[_L]}</td><td>{A[_E]}</td><td>{A[_J]}</td><td>{A[_A]}</td><td>{A[_F]}</td><td><button onclick=\"del('/api/delete_user', {{hwid: '{A[_E]}'}})\">Delete</button></td></tr>"
	B+='</table></body></html>';return B
@app.route('/api/delete_key',methods=[_I])
def delete_key():
	if not is_admin_request():return _H,403
	C=request.get_json()or{};A=C.get(_A)
	if not A or not validate_key(A):return'Missing or invalid key',400
	D=quote(A)
	try:B=requests.delete(f"{SUPABASE_URL}/rest/v1/keys?key=eq.{D}",headers=SUPABASE_HEADERS,timeout=5)
	except requests.RequestException:return _M,500
	if B.status_code==204:return'Key deleted'
	return f"Failed to delete: {B.text}",500
@app.route('/api/delete_user',methods=[_I])
def delete_user():
	if not is_admin_request():return _H,403
	C=request.get_json()or{};A=C.get(_E)
	if not A or not validate_hwid(A):return'Missing or invalid hwid',400
	D=quote(A)
	try:B=requests.delete(f"{SUPABASE_URL}/rest/v1/users?hwid=eq.{D}",headers=SUPABASE_HEADERS,timeout=5)
	except requests.RequestException:return _M,500
	if B.status_code==204:return'User deleted'
	return f"Failed to delete: {B.text}",500
if __name__=='__main__':app.run(host='0.0.0.0',port=int(os.environ.get('PORT',5000)))
