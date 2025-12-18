"""
REST API 예제 - 보안 취약점 포함
"""
from flask import Flask, request, jsonify
import jwt

app = Flask(__name__)

# 취약점 1: Rate limiting 없음
@app.route('/api/login', methods=['POST'])
def login():
    # 무제한 로그인 시도 가능 (Brute Force 공격에 취약)
    username = request.json.get('username')
    password = request.json.get('password')
    
    if username == 'admin' and password == 'admin123':
        token = jwt.encode({'user': username}, 'secret', algorithm='HS256')
        return jsonify({'token': token})
    return jsonify({'error': 'Invalid credentials'}), 401

# 취약점 2: 권한 검증 없음
@app.route('/api/admin/users', methods=['GET'])
def get_all_users():
    # 관리자 권한 체크 없이 모든 사용자 정보 노출
    users = [
        {'id': 1, 'username': 'admin', 'email': 'admin@example.com'},
        {'id': 2, 'username': 'user1', 'email': 'user1@example.com'}
    ]
    return jsonify(users)

# 취약점 3: IDOR (Insecure Direct Object Reference)
@app.route('/api/user/<int:user_id>', methods=['GET'])
def get_user(user_id):
    # 사용자가 자신의 정보인지 확인하지 않음
    user = {'id': user_id, 'username': f'user{user_id}'}
    return jsonify(user)

# 취약점 4: 민감한 에러 정보 노출
@app.route('/api/query')
def query_database():
    try:
        # 데이터베이스 쿼리
        raise Exception("Database connection failed: host=10.0.0.5, user=admin")
    except Exception as e:
        # 상세한 에러 메시지를 클라이언트에 노출
        return jsonify({'error': str(e)}), 500

# 취약점 5: CORS 설정 문제
@app.after_request
def after_request(response):
    # 모든 도메인에서 접근 허용
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', '*')
    response.headers.add('Access-Control-Allow-Methods', '*')
    return response

# 취약점 6: JWT 검증 없음
@app.route('/api/protected')
def protected_route():
    token = request.headers.get('Authorization')
    # 토큰 검증 없이 진행
    return jsonify({'message': 'Protected data'})

# 취약점 7: 파일 업로드 검증 없음
@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    
    file = request.files['file']
    # 파일 타입, 크기 검증 없음
    file.save(f'/uploads/{file.filename}')
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(debug=True)


