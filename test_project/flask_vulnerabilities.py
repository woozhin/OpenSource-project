"""
Flask 웹 애플리케이션 취약점 예시
Semgrep과 Bandit이 모두 감지할 수 있는 취약점
"""
from flask import Flask, request, render_template_string, session, make_response
import os

app = Flask(__name__)

# ❌ 취약점 1: 하드코딩된 SECRET_KEY
app.config['SECRET_KEY'] = 'super-secret-key-123'  # Bandit: B105

# ❌ 취약점 2: DEBUG 모드 활성화 (프로덕션)
app.config['DEBUG'] = True

@app.route('/greet')
def unsafe_greet():
    """❌ XSS 취약 - 사용자 입력을 직접 렌더링"""
    # 취약점 3: render_template_string with user input
    name = request.args.get('name', 'Guest')
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)

@app.route('/search')
def unsafe_search():
    """❌ SSTI (Server-Side Template Injection)"""
    # 취약점 4: Template injection
    query = request.args.get('q', '')
    template = "<h1>Results for: {{ query }}</h1>"
    return render_template_string(template, query=query)

@app.route('/user/<user_id>')
def unsafe_user_profile(user_id):
    """❌ IDOR (Insecure Direct Object Reference)"""
    # 취약점 5: 권한 검증 없이 user_id 접근
    import sqlite3
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # 취약점 6: SQL Injection
    query = f"SELECT * FROM users WHERE id={user_id}"
    cursor.execute(query)
    
    user = cursor.fetchone()
    conn.close()
    return str(user)

@app.route('/download')
def unsafe_download():
    """❌ Path Traversal"""
    # 취약점 7: 경로 검증 없음
    filename = request.args.get('file')
    filepath = os.path.join('/var/www/files', filename)
    
    with open(filepath, 'rb') as f:
        return f.read()

@app.route('/admin/delete', methods=['POST'])
def unsafe_delete():
    """❌ CSRF (Cross-Site Request Forgery)"""
    # 취약점 8: CSRF 토큰 검증 없음
    user_id = request.form.get('user_id')
    # 사용자 삭제 로직
    return f"User {user_id} deleted"

@app.route('/login', methods=['POST'])
def unsafe_login():
    """❌ 인증 취약점 여러 개"""
    username = request.form.get('username')
    password = request.form.get('password')
    
    # 취약점 9: 평문 비밀번호 비교
    if username == 'admin' and password == 'admin123':
        # 취약점 10: 세션 고정 공격 취약
        session['user'] = username
        session['is_admin'] = True
        
        # 취약점 11: 민감한 쿠키 설정 없음 (secure, httponly)
        resp = make_response("Login successful")
        resp.set_cookie('session_id', '12345')
        return resp
    
    return "Login failed"

@app.route('/api/data')
def unsafe_api():
    """❌ 정보 노출 & CORS 문제"""
    # 취약점 12: 상세한 에러 정보 노출
    try:
        data = get_sensitive_data()
        return data
    except Exception as e:
        # 취약점 13: Stack trace 노출
        import traceback
        return traceback.format_exc(), 500

@app.route('/redirect')
def unsafe_redirect():
    """❌ Open Redirect"""
    # 취약점 14: 검증 없는 리다이렉트
    url = request.args.get('url')
    from flask import redirect
    return redirect(url)

@app.route('/exec')
def unsafe_exec():
    """❌ Remote Code Execution"""
    # 취약점 15: 사용자 입력으로 코드 실행
    code = request.args.get('code')
    result = eval(code)  # Bandit: B307
    return str(result)

@app.route('/upload', methods=['POST'])
def unsafe_upload():
    """❌ Unrestricted File Upload"""
    # 취약점 16: 파일 타입 검증 없음
    file = request.files['file']
    filename = file.filename
    file.save(f'/var/www/uploads/{filename}')
    return "File uploaded"

# ❌ 취약점 17: assert 사용 (프로덕션)
def unsafe_check_permission(user_role):
    assert user_role == 'admin', "Not authorized"  # Bandit: B101

# ❌ 취약점 18: 약한 랜덤 생성
import random
def generate_token():
    return random.randint(1000, 9999)  # Bandit: B311

# ✅ 안전한 방법 (비교용)
from flask import escape
import secrets
from werkzeug.security import check_password_hash

@app.route('/safe_greet')
def safe_greet():
    """✅ XSS 방지"""
    name = request.args.get('name', 'Guest')
    safe_name = escape(name)
    return f"<h1>Hello, {safe_name}!</h1>"

@app.route('/safe_login', methods=['POST'])
def safe_login():
    """✅ 안전한 로그인"""
    username = request.form.get('username')
    password = request.form.get('password')
    
    # 안전: 해시된 비밀번호 비교
    user = get_user(username)
    if user and check_password_hash(user['password_hash'], password):
        session.regenerate()  # 세션 재생성
        session['user'] = username
        
        resp = make_response("Login successful")
        resp.set_cookie('session_id', secrets.token_hex(32), 
                       secure=True, httponly=True, samesite='Strict')
        return resp
    
    return "Login failed"

def get_sensitive_data():
    return {"secret": "data"}

def get_user(username):
    return None

if __name__ == '__main__':
    # ❌ 취약점 19: 0.0.0.0으로 바인딩 (외부 접근 허용)
    app.run(host='0.0.0.0', port=5000, debug=True)


