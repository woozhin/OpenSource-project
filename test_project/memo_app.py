"""
메모 애플리케이션 - 비즈니스 로직 취약점 예제
Bandit은 찾지 못하지만 LLM은 찾을 수 있는 취약점들
"""
from flask import Flask, request, render_template

app = Flask(__name__)

# 취약점 1: Global 변수 사용 (Race Condition)
memo_text = ""
user_sessions = {}

# 취약점 2: XSS - 사용자 입력을 검증 없이 저장/출력
@app.route("/memo")
def memo():
    global memo_text
    text = request.args.get("memo", "")
    # 입력 검증 없음!
    memo_text += text + "\n"
    return render_template("memo.html", memo=memo_text)

# 취약점 3: IDOR (Insecure Direct Object Reference)
@app.route("/user/<user_id>")
def get_user_data(user_id):
    # 권한 검증 없이 user_id로 바로 접근
    user_data = {"id": user_id, "secret": "my_secret_data"}
    return user_data

# 취약점 4: 파일 경로 검증 없음 (Path Traversal)
@app.route("/download")
def download_file():
    filename = request.args.get("file")
    # 경로 검증 없이 바로 사용
    with open(f"/uploads/{filename}", "r") as f:
        return f.read()

# 취약점 5: Race Condition - 계좌 이체
balance = 1000

@app.route("/transfer")
def transfer_money():
    global balance
    amount = int(request.args.get("amount", 0))
    
    # Race condition: 여러 요청이 동시에 오면 문제 발생
    if balance >= amount:
        balance -= amount
        return f"전송 완료. 잔액: {balance}"
    return "잔액 부족"

# 취약점 6: Rate limiting 없는 민감한 작업
@app.route("/reset_password")
def reset_password():
    email = request.args.get("email")
    # Rate limiting 없음 - 무한 시도 가능
    send_reset_email(email)
    return "이메일 전송됨"

def send_reset_email(email):
    # 이메일 전송 로직
    pass

# 취약점 7: 클라이언트에서 받은 가격 그대로 사용
@app.route("/checkout")
def checkout():
    # 클라이언트에서 보낸 가격을 신뢰
    price = float(request.args.get("price"))
    item = request.args.get("item")
    
    # 서버에서 가격을 재확인하지 않음!
    process_payment(price)
    return f"{item} 구매 완료: ${price}"

def process_payment(amount):
    # 결제 처리
    pass

# 취약점 8: 관리자 기능에 권한 검증 없음
@app.route("/admin/delete_user")
def delete_user():
    user_id = request.args.get("user_id")
    # 관리자인지 확인하지 않음!
    delete_user_from_db(user_id)
    return f"사용자 {user_id} 삭제됨"

def delete_user_from_db(user_id):
    # DB에서 사용자 삭제
    pass

if __name__ == "__main__":
    app.run(debug=True)


