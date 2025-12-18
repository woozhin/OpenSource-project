/**
 * 프론트엔드 JavaScript - 보안 취약점 예제
 */

// 취약점 1: XSS - innerHTML 직접 사용
function displayUserInput() {
    const userInput = document.getElementById('userInput').value;
    // XSS 취약점 - 사용자 입력을 직접 HTML에 삽입
    document.getElementById('output').innerHTML = userInput;
}

// 취약점 2: 민감 정보를 클라이언트에 저장
const API_KEY = "sk-1234567890abcdef";
const SECRET_TOKEN = "my-secret-token-12345";

// 취약점 3: eval 사용
function executeCode(code) {
    // eval 사용은 위험
    eval(code);
}

// 취약점 4: localStorage에 민감 정보 저장
function saveCredentials(username, password) {
    localStorage.setItem('username', username);
    localStorage.setItem('password', password);  // 비밀번호를 평문으로 저장
}

// 취약점 5: 클라이언트 측에서만 권한 검증
function deleteUser(userId) {
    if (isAdmin) {  // 클라이언트 측 검증만 존재
        fetch(`/api/users/${userId}`, { method: 'DELETE' });
    }
}

// 취약점 6: CORS 문제를 우회하려는 시도
async function fetchData(url) {
    // 안전하지 않은 외부 리소스 로드
    const response = await fetch(url, {
        mode: 'no-cors'
    });
    return response.json();
}

// 취약점 7: 클릭재킹 방지 없음
function openIframe(url) {
    const iframe = document.createElement('iframe');
    iframe.src = url;  // X-Frame-Options 헤더 확인 없음
    document.body.appendChild(iframe);
}

// 취약점 8: SQL 쿼리를 클라이언트에서 생성
function searchUsers(searchTerm) {
    const query = `SELECT * FROM users WHERE name LIKE '%${searchTerm}%'`;
    // 이 쿼리를 서버로 전송
    fetch('/api/query', {
        method: 'POST',
        body: JSON.stringify({ query: query })
    });
}

// 취약점 9: HTTP로 민감 정보 전송
function login(username, password) {
    fetch('http://example.com/login', {  // HTTPS가 아닌 HTTP 사용
        method: 'POST',
        body: JSON.stringify({ username, password })
    });
}

// 올바른 방법 (비교용)
function displayUserInputSecure() {
    const userInput = document.getElementById('userInput').value;
    // textContent 사용으로 XSS 방지
    document.getElementById('output').textContent = userInput;
}

function saveCredentialsSecure(username) {
    // 비밀번호는 저장하지 않음
    sessionStorage.setItem('username', username);
}


