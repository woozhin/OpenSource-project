"""
매우 간단한 취약점 테스트 - Semgrep이 100% 찾아야 함
"""
import os

# ❌ 명백한 Command Injection
user_input = input("Enter filename: ")
os.system("cat " + user_input)

# ❌ 명백한 SQL Injection
import sqlite3
username = input("Username: ")
query = f"SELECT * FROM users WHERE name = '{username}'"
conn = sqlite3.connect('db.sqlite')
conn.execute(query)

# ❌ 명백한 하드코딩된 비밀번호
PASSWORD = "admin123"
API_KEY = "sk-1234567890"

# ❌ 명백한 eval 사용
code = input("Enter code: ")
eval(code)


