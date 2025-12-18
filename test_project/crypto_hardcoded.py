"""
암호화 및 하드코딩된 비밀정보 취약점 예시
Bandit과 Semgrep이 모두 감지할 수 있는 취약점
"""
import hashlib
import hmac
from Crypto.Cipher import DES, AES
import jwt
import requests

# ❌ 취약점 1~10: 하드코딩된 비밀정보
API_KEY = "sk-1234567890abcdef"  # Bandit: B105
SECRET_KEY = "my-secret-key-12345"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"  # Bandit: B105
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DB_PASSWORD = "admin123"  # Bandit: B105
STRIPE_API_KEY = "sk_live_51234567890"
OAUTH_SECRET = "oauth-secret-abc123"
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
JWT_SECRET = "jwt-secret-key-2024"
ENCRYPTION_KEY = b"sixteen byte key"  # Bandit: B105

# ❌ 취약점 11: 약한 해시 알고리즘 - MD5
def hash_password_md5(password):
    """MD5는 충돌 공격에 취약"""
    return hashlib.md5(password.encode()).hexdigest()  # Bandit: B303

# ❌ 취약점 12: 약한 해시 알고리즘 - SHA1
def hash_password_sha1(password):
    """SHA1도 더 이상 안전하지 않음"""
    return hashlib.sha1(password.encode()).hexdigest()  # Bandit: B303

# ❌ 취약점 13: DES 암호화 (약한 암호화)
def encrypt_with_des(plaintext):
    """DES는 56비트 키로 매우 취약"""
    key = b'8bytekey'
    cipher = DES.new(key, DES.MODE_ECB)  # Bandit: B305
    # ECB 모드도 취약함
    return cipher.encrypt(plaintext.ljust(8).encode())

# ❌ 취약점 14: 약한 AES 모드 (ECB)
def encrypt_with_aes_ecb(plaintext):
    """ECB 모드는 패턴이 보임"""
    key = b'Sixteen byte key'
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext.ljust(16).encode())

# ❌ 취약점 15: 하드코딩된 IV
def encrypt_with_fixed_iv(plaintext):
    """고정된 IV는 보안 약화"""
    key = b'Sixteen byte key'
    iv = b'fixed_iv_1234567'  # Bandit: B105
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(plaintext.ljust(16).encode())

# ❌ 취약점 16: JWT 검증 없음
def decode_jwt_unsafe(token):
    """JWT 서명 검증 안 함"""
    decoded = jwt.decode(token, options={"verify_signature": False})
    return decoded

# ❌ 취약점 17: 약한 JWT 알고리즘
def create_jwt_with_none():
    """'none' 알고리즘은 서명 없음"""
    payload = {"user_id": 123}
    token = jwt.encode(payload, None, algorithm='none')
    return token

# ❌ 취약점 18: SSL 검증 비활성화
def unsafe_https_request(url):
    """SSL 인증서 검증 안 함"""
    response = requests.get(url, verify=False)  # Bandit: B501
    return response.text

# ❌ 취약점 19: 평문 HTTP 사용
def send_credentials_http(username, password):
    """HTTPS 대신 HTTP 사용"""
    url = "http://api.example.com/login"  # 평문 전송!
    data = {"username": username, "password": password}
    response = requests.post(url, json=data)
    return response.json()

# ❌ 취약점 20: 약한 암호화 모드
import ssl
def create_insecure_ssl_context():
    """약한 SSL/TLS 설정"""
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # TLSv1은 취약
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context

# ❌ 취약점 21: 비밀번호를 로그에 기록
import logging
def log_user_credentials(username, password):
    """민감한 정보 로깅"""
    logging.info(f"User {username} logged in with password {password}")

# ❌ 취약점 22: 하드코딩된 데이터베이스 연결 정보
def connect_to_database():
    """데이터베이스 자격증명 하드코딩"""
    import psycopg2
    conn = psycopg2.connect(
        host="db.example.com",
        database="production_db",
        user="admin",
        password="SuperSecret123!"  # Bandit: B105
    )
    return conn

# ❌ 취약점 23: 약한 HMAC 알고리즘
def sign_with_md5_hmac(message, key):
    """HMAC-MD5는 약함"""
    return hmac.new(key.encode(), message.encode(), hashlib.md5).hexdigest()

# ❌ 취약점 24: 민감한 정보를 평문 파일에 저장
def save_api_keys_to_file():
    """API 키를 평문으로 저장"""
    with open('config.txt', 'w') as f:
        f.write(f"API_KEY={API_KEY}\n")
        f.write(f"SECRET_KEY={SECRET_KEY}\n")

# ❌ 취약점 25: 환경변수 없이 하드코딩
class Config:
    """설정 클래스에 하드코딩"""
    DATABASE_URL = "postgresql://user:pass@localhost/db"  # Bandit: B105
    REDIS_PASSWORD = "redis_pass_123"  # Bandit: B105
    SMTP_PASSWORD = "email_password"  # Bandit: B105

# ✅ 안전한 방법 (비교용)
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2

def safe_hash_password(password):
    """✅ bcrypt 또는 Argon2 사용"""
    import bcrypt
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed

def safe_encrypt_aes_gcm(plaintext, key):
    """✅ AES-GCM 모드 사용"""
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return nonce + tag + ciphertext

def safe_get_config():
    """✅ 환경변수에서 읽기"""
    api_key = os.getenv('API_KEY')
    secret_key = os.getenv('SECRET_KEY')
    db_password = os.getenv('DB_PASSWORD')
    return api_key, secret_key, db_password

def safe_https_request(url):
    """✅ SSL 검증 활성화"""
    response = requests.get(url, verify=True)
    return response.text

def safe_jwt_decode(token, secret):
    """✅ JWT 서명 검증"""
    decoded = jwt.decode(token, secret, algorithms=['HS256'])
    return decoded

if __name__ == "__main__":
    # 이런 코드는 절대 사용하면 안 됨!
    password = "user_password_123"
    weak_hash = hash_password_md5(password)
    print(f"Weak MD5 hash: {weak_hash}")


