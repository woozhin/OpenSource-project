"""
암호화 관련 취약점 예제
"""
import hashlib
import random
from Crypto.Cipher import DES, ARC4
from Crypto.Random import get_random_bytes

# 취약점 1: 약한 해시 알고리즘 (MD5)
def hash_password_weak(password):
    return hashlib.md5(password.encode()).hexdigest()

# 취약점 2: SHA-1 사용
def hash_password_sha1(password):
    return hashlib.sha1(password.encode()).hexdigest()

# 취약점 3: 약한 암호화 알고리즘 (DES)
def encrypt_des(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)

# 취약점 4: 약한 난수 생성
def generate_token():
    # random 모듈은 암호학적으로 안전하지 않음
    return random.randint(1000, 9999)

# 취약점 5: 하드코딩된 암호화 키
ENCRYPTION_KEY = b"12345678"  # 8 bytes for DES

def encrypt_data(data):
    cipher = DES.new(ENCRYPTION_KEY, DES.MODE_ECB)
    return cipher.encrypt(data)

# 취약점 6: RC4 사용 (약한 암호화)
def encrypt_rc4(data, key):
    cipher = ARC4.new(key)
    return cipher.encrypt(data)

# 올바른 방법 (비교용)
def hash_password_secure(password):
    import bcrypt
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def generate_secure_token():
    import secrets
    return secrets.token_hex(16)


