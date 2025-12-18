"""
SQL Injection 취약점 예시
Semgrep과 Bandit이 모두 감지할 수 있는 취약점
"""
import sqlite3
import mysql.connector

def unsafe_login(username, password):
    """❌ SQL Injection 취약 - 사용자 입력을 직접 쿼리에 삽입"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # 취약점 1: 문자열 포맷팅으로 SQL 쿼리 생성
    query = "SELECT * FROM users WHERE username='%s' AND password='%s'" % (username, password)
    cursor.execute(query)
    
    result = cursor.fetchone()
    conn.close()
    return result

def unsafe_search(search_term):
    """❌ SQL Injection 취약 - f-string 사용"""
    conn = sqlite3.connect('products.db')
    cursor = conn.cursor()
    
    # 취약점 2: f-string으로 SQL 쿼리 생성
    query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"
    cursor.execute(query)
    
    results = cursor.fetchall()
    conn.close()
    return results

def unsafe_delete(user_id):
    """❌ SQL Injection 취약 - 문자열 연결"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # 취약점 3: 문자열 연결로 SQL 쿼리 생성
    query = "DELETE FROM users WHERE id=" + user_id
    cursor.execute(query)
    
    conn.commit()
    conn.close()

def unsafe_mysql_query(table_name, column_name):
    """❌ SQL Injection 취약 - MySQL"""
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="password123",  # ❌ 하드코딩된 비밀번호
        database="mydb"
    )
    
    cursor = db.cursor()
    
    # 취약점 4: 테이블명과 컬럼명을 사용자 입력으로 받음
    sql = f"SELECT {column_name} FROM {table_name}"
    cursor.execute(sql)
    
    results = cursor.fetchall()
    db.close()
    return results

# ✅ 안전한 방법 (비교용)
def safe_login(username, password):
    """✅ Parameterized Query 사용"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # 안전: Parameterized query
    query = "SELECT * FROM users WHERE username=? AND password=?"
    cursor.execute(query, (username, password))
    
    result = cursor.fetchone()
    conn.close()
    return result

if __name__ == "__main__":
    # 공격 예시
    malicious_input = "admin' OR '1'='1"
    unsafe_login(malicious_input, "anything")


