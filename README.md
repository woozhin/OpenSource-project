# 🔒 통합 보안 취약점 분석 시스템

**Semgrep + Bandit + Claude AI**를 활용한 자동화된 보안 취약점 분석 도구

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Semgrep](https://img.shields.io/badge/Semgrep-Latest-green.svg)](https://semgrep.dev/)
[![Bandit](https://img.shields.io/badge/Bandit-Latest-orange.svg)](https://github.com/PyCQA/bandit)
[![Claude](https://img.shields.io/badge/Claude-AI-purple.svg)](https://www.anthropic.com/)

---

## 📋 목차

- [소개](#-소개)
- [주요 기능](#-주요-기능)
- [설치](#-설치)
- [사용 방법](#-사용-방법)
- [Semgrep 규칙 다운로드](#-semgrep-규칙-다운로드)
- [분석 결과](#-분석-결과)
- [예시 취약점 파일](#-예시-취약점-파일)
- [문제 해결](#-문제-해결)

---

## 🎯 소개

이 도구는 **3가지 강력한 보안 분석 도구**를 결합하여 프론트엔드와 백엔드 코드의 보안 취약점을 자동으로 탐지하고 상세한 보고서를 생성합니다.

### 분석 워크플로우

```
📁 코드 스캔
    ↓
🔍 Semgrep 분석 (OWASP Top 10 + 다양한 언어)
    ↓
🐍 Bandit 분석 (Python 특화)
    ↓
🤖 Claude AI 분석 (추가 취약점 발견)
    ↓
📊 통합 HTML 보고서 생성
```

---

## ✨ 주요 기능

### 🔍 3중 보안 분석

1. **Semgrep**
   - 7,000개 이상의 보안 규칙
   - OWASP Top 10 전체 커버
   - Python, JavaScript, Java, Go 등 다양한 언어 지원
   - SQL Injection, XSS, Command Injection 등 탐지

2. **Bandit**
   - Python 특화 정적 분석
   - 하드코딩된 비밀번호/API 키 탐지
   - 약한 암호화 알고리즘 탐지
   - 위험한 함수(eval, exec, pickle) 탐지

3. **Claude AI**
   - 정적 분석 도구가 놓친 취약점 추가 발견
   - 컨텍스트 기반 심층 분석
   - 비즈니스 로직 취약점 탐지
   - 한글로 상세한 설명 제공

### 📊 보고서 기능

- ✅ 심각도별 분류 (Critical/High/Medium/Low)
- ✅ 코드 스니펫 및 수정 방안 제공
- ✅ CWE ID 및 OWASP 매핑
- ✅ 도구별 발견 내역 구분

---

## 🚀 설치

### 1. 필수 요구사항

- **Python 3.8 이상**
- **Git** (Semgrep 규칙 다운로드용)
- **Anthropic API Key** (Claude AI)

### 2. 프로젝트 클론

```bash
git clone https://github.com/your-repo/security-analyzer.git
cd security-analyzer
```

### 3. 의존성 설치

**Windows:**
```powershell
pip install -r requirements_integrated.txt
```

**Linux/Mac:**
```bash
pip3 install -r requirements_integrated.txt
```

### 4. API 키 설정

**방법 : 코드 직접 수정**

`main.py` 파일의 마지막 부분에서:
```python
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "YOUR_API_KEY_HERE")
```
위 코드를 찾아 `"YOUR_API_KEY_HERE"` 부분에 실제 API 키를 입력하세요.

---

## 📖 사용 방법

### 빠른 시작 (3단계)

#### 1단계: Semgrep 규칙 다운로드 (처음 한 번만)

```powershell
python download_semgrep_rules.py
```

**출력 예시:**
```
🔍 Semgrep 규칙 다운로드 중...
  ✓ 규칙 다운로드 완료!
  📊 다운로드된 규칙 파일: 2000+개
```

#### 2단계: 분석 실행

```powershell
python main.py
```

#### 3단계: 경로 입력

```
📁 분석할 프로젝트 폴더 경로를 입력하세요:
> C:\Users\user\my-project

📄 보고서 파일명을 입력하세요:
> security_report.html
```

---

## 🔧 Semgrep 규칙 다운로드

### 자동 다운로드

```powershell
python download_semgrep_rules.py
```

**다운로드 내용:**
- 7,000개 이상의 보안 규칙
- Python, JavaScript, Java, Go 등 다양한 언어
- 약 200MB 디스크 공간 필요
- 다운로드 시간: 1~3분

### 수동 다운로드 (Git 없을 때)

1. 다운로드: https://github.com/returntocorp/semgrep-rules/archive/refs/heads/develop.zip
2. 압축 해제
3. 폴더명을 `semgrep-rules`로 변경
4. 프로젝트 루트에 배치

### 규칙 업데이트

```powershell
python download_semgrep_rules.py
```

기존 규칙이 있으면 자동으로 최신 버전으로 업데이트됩니다.

---

## 📊 분석 결과

### 출력 예시

```
======================================================================
🔒 통합 보안 취약점 분석 시스템
======================================================================

✅ Semgrep 규칙: C:\...\semgrep-rules

🔍 Semgrep으로 보안 분석 중...
  ✓ Semgrep 분석 완료
    - 발견된 이슈: 25개
    - ERROR: 8개
    - WARNING: 12개
    - INFO: 5개

🔍 Bandit으로 Python 코드 분석 중...
  ✓ Bandit 분석 완료
    - 발견된 이슈: 15개
    - HIGH: 3개
    - MEDIUM: 8개
    - LOW: 4개

🤖 Claude API를 통한 보안 분석...
  ✓ LLM 분석 완료

📄 HTML 보고서 생성 완료: security_report.html

======================================================================
✅ 분석 완료!
📊 총 45개의 취약점 발견
   【정적 분석 도구】
   - Semgrep: 25개
   - Bandit: 15개
   【LLM 추가 발견】
   - Claude AI: 5개
======================================================================
```

### HTML 보고서 구성

- **요약 대시보드**: 전체 취약점 개수 및 심각도 분포
- **Semgrep 분석 결과**: OWASP Top 10 기반 취약점
- **Bandit 분석 결과**: Python 특화 취약점
- **취약점 상세 정보**:
  - 심각도 (Critical/High/Medium/Low)
  - 카테고리 (SQL Injection, XSS 등)
  - 위치 (파일명:라인번호)
  - 문제 코드 스니펫
  - 영향 분석
  - 수정 방안
  - CWE ID

---

## 🧪 예시 취약점 파일

`test_project/` 폴더에 다양한 취약점 예시가 포함되어 있습니다:

### Python 취약점

| 파일 | 취약점 |
|------|--------|
| `sql_injection.py` | SQL Injection (6개 변형) |
| `command_injection.py` | OS Command Injection (9개) |
| `path_traversal.py` | Path Traversal, Deserialization (10개) |
| `flask_vulnerabilities.py` | Flask 웹앱 취약점 (19개) |
| `crypto_hardcoded.py` | 하드코딩, 약한 암호화 (25개) |
| `file_permission.py` | 파일 권한, Race Condition (15개) |

### JavaScript 취약점

| 파일 | 취약점 |
|------|--------|
| `xss_vulnerable.js` | XSS, CSRF, Open Redirect (12개) |
| `frontend.js` | 프론트엔드 보안 이슈 |

### 테스트 실행

```powershell
python main.py
```

입력:
```
> C:\path\to\test_project
> test_report.html
```

**예상 결과**: 50개 이상의 취약점 발견

---

## 🛠️ 문제 해결

### 1. Semgrep이 취약점을 찾지 못함

**증상:**
```
✓ Semgrep 분석 완료
  - 발견된 이슈: 0개
```

**해결:**
```powershell
# 규칙 다운로드
python download_semgrep_rules.py

# 직접 테스트
C:\...\semgrep.exe --config semgrep-rules/python/lang/security test.py
```

### 2. Git이 설치되지 않음

**증상:**
```
✗ Git이 설치되어 있지 않습니다!
```

**해결:**
- **방법 1**: Git 설치 - https://git-scm.com/download/win
- **방법 2**: 수동 다운로드 (위 "Semgrep 규칙 다운로드" 참고)

### 3. API 키 오류

**증상:**
```
❌ API 키를 설정해주세요!
```

**해결:**
```powershell
# 환경 변수 설정
$env:ANTHROPIC_API_KEY="sk-ant-api03-xxxxx"

# 또는 main.py 파일 수정
```

### 4. Python 버전 문제

**증상:**
```
ModuleNotFoundError: No module named 'anthropic'
```

**해결:**
```powershell
# Python 버전 확인 (3.8 이상 필요)
python --version

# 의존성 재설치
pip install -r requirements_integrated.txt
```

### 5. Semgrep 실행 파일을 찾을 수 없음

**증상:**
```
✗ Semgrep을 찾을 수 없습니다.
```

**해결:**
```powershell
# Semgrep 설치
pip install semgrep

# 설치 확인
semgrep --version
```

### 6. 인코딩 오류 (Windows)

**증상:**
```
UnicodeEncodeError: 'cp949' codec can't encode character
```

**해결:**
코드가 이미 UTF-8 강제 설정을 포함하고 있습니다. 그래도 문제가 있다면:

```powershell
# PowerShell 인코딩 설정
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
```

---

## 📁 프로젝트 구조

```
security-analyzer/
├── .gitignore                        # Git 제외 규칙
├── main.py                           # 메인 실행 파일
├── download_semgrep_rules.py         # 규칙 다운로드 스크립트
├── requirements_integrated.txt       # Python 의존성
├── README.md                         # 이 파일
├── semgrep-rules/                    # 다운로드된 Semgrep 규칙 (자동 생성, Git 제외)
└── test_project/                     # 예시 취약점 파일
    ├── sql_injection.py
    ├── command_injection.py
    ├── path_traversal.py
    ├── xss_vulnerable.js
    ├── flask_vulnerabilities.py
    ├── crypto_hardcoded.py
    ├── file_permission.py
    └── ...
```

---

## 🎯 지원하는 취약점 타입

### OWASP Top 10 (2021)

| OWASP | 취약점 | 탐지 도구 |
|-------|--------|-----------|
| A01 | Broken Access Control (IDOR) | Semgrep, Claude |
| A02 | Cryptographic Failures | Semgrep, Bandit |
| A03 | Injection (SQL, Command, Code) | Semgrep, Bandit |
| A04 | Insecure Design | Claude |
| A05 | Security Misconfiguration | Semgrep, Bandit |
| A06 | Vulnerable Components | Semgrep |
| A07 | Authentication Failures | Semgrep, Claude |
| A08 | Software and Data Integrity | Semgrep, Bandit |
| A09 | Logging Failures | Semgrep |
| A10 | SSRF | Semgrep |

### 추가 탐지 취약점

- **프론트엔드**: XSS, CSRF, Open Redirect, DOM-based XSS
- **백엔드**: Path Traversal, File Inclusion, XXE, Deserialization
- **암호화**: 약한 해시(MD5, SHA1), 약한 암호화(DES), 하드코딩된 키
- **인증**: 평문 비밀번호, JWT 취약점, 세션 고정
- **설정**: Debug 모드, 과도한 권한, 약한 랜덤

---

## 🔒 보안 및 프라이버시

- ✅ 모든 분석은 **로컬**에서 실행됩니다
- ✅ Claude API는 **분석 결과**만 전송 (전체 코드 아님)
- ✅ API 키는 **환경 변수** 사용 권장
- ✅ 생성된 보고서는 **민감정보 마스킹** 가능

---

## 📚 참고 자료

- **Semgrep 공식 문서**: https://semgrep.dev/docs
- **Bandit 공식 문서**: https://bandit.readthedocs.io
- **Claude AI**: https://www.anthropic.com/claude
- **OWASP Top 10**: https://owasp.org/www-project-top-ten
- **CWE (Common Weakness Enumeration)**: https://cwe.mitre.org

---

## 💡 사용 팁

### 1. CI/CD 통합
```yaml
# GitHub Actions 예시
- name: Security Scan
  run: |
    python download_semgrep_rules.py
    python main.py --auto
```

### 2. 커스텀 규칙 추가
```yaml
# semgrep-rules/custom/my-rule.yaml
rules:
  - id: custom-vulnerability
    pattern: dangerous_function(...)
    message: Custom security rule
    languages: [python]
    severity: ERROR
```

### 3. 특정 파일 제외
```python
# main.py 수정
exclude_patterns = [
    '*/node_modules/*',
    '*/venv/*',
    '*/test/*'
]
```

---

MIT License

---

*마지막 업데이트: 2025년 12월 18일*
