"""
취약점이 있는 Flask 애플리케이션 예제
테스트 목적으로 여러 보안 취약점을 포함하고 있습니다.
"""
import os
import pickle
import subprocess
from flask import Flask, request, render_template_string

app = Flask(__name__)

# 취약점 1: 하드코딩된 비밀번호
DATABASE_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"
SECRET_KEY = "my-secret-key-12345"

# 취약점 2: SQL Injection
@app.route('/user/<username>')
def get_user(username):
    import sqlite3
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # SQL Injection 취약점
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return str(cursor.fetchall())

# 취약점 3: Command Injection
@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')
    # Command Injection 취약점
    result = os.system(f'ping -c 1 {host}')
    return f"Ping result: {result}"

# 취약점 4: eval 사용
@app.route('/calc')
def calculate():
    expr = request.args.get('expr', '1+1')
    # eval 사용 취약점
    result = eval(expr)
    return f"Result: {result}"

# 취약점 5: Pickle deserialization
@app.route('/load')
def load_data():
    data = request.args.get('data')
    # 안전하지 않은 deserialization
    obj = pickle.loads(data.encode())
    return str(obj)

# 취약점 6: XSS (Cross-Site Scripting)
@app.route('/hello/<name>')
def hello(name):
    # XSS 취약점 - 사용자 입력을 그대로 렌더링
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)

# 취약점 7: 파일 권한 문제
def create_temp_file():
    filename = "/tmp/secret.txt"
    # 잘못된 파일 권한
    with open(filename, 'w') as f:
        f.write("sensitive data")
    os.chmod(filename, 0o777)  # 모든 사용자에게 읽기/쓰기 권한

# 취약점 8: subprocess shell=True
@app.route('/execute')
def execute_command():
    cmd = request.args.get('cmd')
    # Shell injection 취약점
    output = subprocess.check_output(cmd, shell=True)
    return output

# 취약점 9: Debug mode 활성화
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')  # Debug mode는 프로덕션에서 위험


