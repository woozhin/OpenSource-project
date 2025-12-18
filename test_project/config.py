"""
설정 파일 - 하드코딩된 비밀정보 포함
"""

# 취약점: 하드코딩된 데이터베이스 자격증명
DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'user': 'admin',
    'password': 'P@ssw0rd123',  # 하드코딩된 비밀번호
    'database': 'myapp'
}

# 취약점: 하드코딩된 API 키들
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXX"

# 취약점: JWT 시크릿
JWT_SECRET = "super-secret-jwt-key-do-not-share"

# 취약점: 암호화 키
ENCRYPTION_KEY = "my-encryption-key-123"

# 올바른 방법 (비교용)
# import os
# DB_PASSWORD = os.environ.get('DB_PASSWORD')
# AWS_ACCESS_KEY = os.environ.get('AWS_ACCESS_KEY')


