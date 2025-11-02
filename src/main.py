import anthropic
import os
from datetime import datetime
from pathlib import Path
import json
import html

class SecurityAnalyzer:
    def __init__(self, api_key):
        """
        클로드 API를 사용한 보안 취약점 분석기 초기화
        
        Args:
            api_key: Anthropic API 키
        """
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = "claude-sonnet-4-5-20250929"
        
        # 지원하는 파일 확장자
        self.supported_extensions = {
            # 프론트엔드
            '.js', '.jsx', '.ts', '.tsx', '.vue', '.html', '.css', '.scss', '.sass',
            # 백엔드
            '.py', '.java', '.php', '.go', '.rb', '.cs', '.cpp', '.c', '.h', '.rs', '.swift',
            # 설정 파일
            '.json', '.yml', '.yaml', '.xml', '.env', '.config'
        }
        
        # 제외할 디렉토리
        self.exclude_dirs = {
            'node_modules', '.git', '__pycache__', 'venv', 'env', 
            'dist', 'build', '.next', '.nuxt', 'coverage', '.pytest_cache',
            'target', 'bin', 'obj', 'vendor', 'bower_components'
        }
        
        # 제외할 파일 패턴
        self.exclude_files = {
            '.min.js', '.min.css', '.map', '.lock', 
            'package-lock.json', 'yarn.lock', 'Pipfile.lock'
        }
    
    def scan_directory(self, directory_path):
        """
        디렉토리를 스캔하여 모든 코드 파일 찾기
        
        Args:
            directory_path: 스캔할 디렉토리 경로
            
        Returns:
            파일 경로 리스트
        """
        code_files = []
        directory = Path(directory_path)
        
        if not directory.exists():
            print(f"✗ 디렉토리를 찾을 수 없습니다: {directory_path}")
            return []
        
        print(f"\n📂 디렉토리 스캔 중: {directory_path}")
        
        for root, dirs, files in os.walk(directory):
            # 제외할 디렉토리 필터링
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs and not d.startswith('.')]
            
            for file in files:
                # 파일 확장자 확인
                if any(file.endswith(ext) for ext in self.supported_extensions):
                    # 제외할 파일 패턴 확인
                    if not any(pattern in file for pattern in self.exclude_files):
                        file_path = Path(root) / file
                        code_files.append(str(file_path))
        
        print(f"✓ {len(code_files)}개의 코드 파일 발견")
        return code_files
    
    def categorize_files(self, file_paths):
        """
        파일들을 프론트엔드/백엔드/설정 파일로 분류
        
        Args:
            file_paths: 파일 경로 리스트
            
        Returns:
            카테고리별로 분류된 딕셔너리
        """
        categories = {
            'frontend': [],
            'backend': [],
            'config': []
        }
        
        frontend_exts = {'.js', '.jsx', '.ts', '.tsx', '.vue', '.html', '.css', '.scss', '.sass'}
        backend_exts = {'.py', '.java', '.php', '.go', '.rb', '.cs', '.cpp', '.c', '.h', '.rs', '.swift'}
        config_exts = {'.json', '.yml', '.yaml', '.xml', '.env', '.config'}
        
        for file_path in file_paths:
            ext = Path(file_path).suffix
            if ext in frontend_exts:
                categories['frontend'].append(file_path)
            elif ext in backend_exts:
                categories['backend'].append(file_path)
            elif ext in config_exts:
                categories['config'].append(file_path)
        
        print(f"\n📊 파일 분류:")
        print(f"  - 프론트엔드: {len(categories['frontend'])}개")
        print(f"  - 백엔드: {len(categories['backend'])}개")
        print(f"  - 설정 파일: {len(categories['config'])}개")
        
        return categories
    
    def read_code_files(self, file_paths, max_file_size=500000):
        """
        코드 파일들을 읽어서 딕셔너리로 반환
        
        Args:
            file_paths: 분석할 파일 경로 리스트
            max_file_size: 최대 파일 크기 (바이트, 기본 500KB)
            
        Returns:
            파일명과 내용을 담은 딕셔너리
        """
        code_files = {}
        skipped_files = []
        
        for file_path in file_paths:
            try:
                file_size = os.path.getsize(file_path)
                
                # 파일 크기 체크
                if file_size > max_file_size:
                    skipped_files.append(f"{file_path} (크기: {file_size // 1024}KB)")
                    continue
                
                with open(file_path, 'r', encoding='utf-8') as f:
                    code_files[file_path] = f.read()
                    
            except UnicodeDecodeError:
                # 바이너리 파일 건너뛰기
                skipped_files.append(f"{file_path} (바이너리)")
            except Exception as e:
                print(f"✗ 파일 읽기 실패 {file_path}: {e}")
                skipped_files.append(f"{file_path} (오류: {str(e)})")
        
        if skipped_files:
            print(f"\n⚠ 건너뛴 파일 ({len(skipped_files)}개):")
            for skipped in skipped_files[:5]:  # 최대 5개만 표시
                print(f"  - {skipped}")
            if len(skipped_files) > 5:
                print(f"  ... 외 {len(skipped_files) - 5}개")
        
        print(f"\n✓ {len(code_files)}개 파일 읽기 완료")
        return code_files
    
    def analyze_security_batch(self, code_files, batch_size=10):
        """
        클로드 API를 사용하여 코드의 보안 취약점 분석 (배치 처리)
        
        Args:
            code_files: 파일명과 코드 내용을 담은 딕셔너리
            batch_size: 한 번에 분석할 파일 개수
            
        Returns:
            분석 결과 리스트
        """
        all_vulnerabilities = []
        file_items = list(code_files.items())
        total_batches = (len(file_items) + batch_size - 1) // batch_size
        
        print(f"\n🔍 보안 분석 시작 (총 {total_batches}개 배치)")
        
        for i in range(0, len(file_items), batch_size):
            batch = dict(file_items[i:i + batch_size])
            batch_num = i // batch_size + 1
            
            print(f"\n📦 배치 {batch_num}/{total_batches} 분석 중... ({len(batch)}개 파일)")
            
            result = self.analyze_security(batch)
            if result:
                parsed = self.parse_analysis_result(result)
                vulnerabilities = parsed.get('vulnerabilities', [])
                all_vulnerabilities.extend(vulnerabilities)
                print(f"   ✓ {len(vulnerabilities)}개 취약점 발견")
        
        return all_vulnerabilities
    
    def analyze_security(self, code_files):
        """
        클로드 API를 사용하여 코드의 보안 취약점 분석
        
        Args:
            code_files: 파일명과 코드 내용을 담은 딕셔너리
            
        Returns:
            분석 결과 텍스트
        """
        # 코드 파일들을 프롬프트에 포함할 형식으로 변환
        code_context = []
        for file_path, content in code_files.items():
            # 상대 경로로 표시
            rel_path = Path(file_path).name if len(file_path) > 50 else file_path
            code_context.append(f"\n## 파일: {rel_path}\n```\n{content}\n```")
        
        code_text = "\n".join(code_context)
        
        # 보안 분석 프롬프트
        prompt = f"""당신은 보안 전문가입니다. 다음 코드들을 분석하여 보안 취약점을 찾아주세요.

{code_text}

다음 항목들을 중점적으로 분석해주세요:

1. **인증 및 권한 관리**
   - 약한 인증 메커니즘
   - 권한 검증 누락
   - 세션 관리 취약점

2. **입력 검증**
   - SQL Injection
   - XSS (Cross-Site Scripting)
   - Command Injection
   - Path Traversal

3. **데이터 보호**
   - 민감 정보 노출
   - 암호화 미사용 또는 약한 암호화
   - 하드코딩된 비밀번호/API 키

4. **API 보안**
   - CORS 설정 문제
   - Rate Limiting 부재
   - API 엔드포인트 노출

5. **프론트엔드 보안**
   - 클라이언트 측 검증만 의존
   - 민감 정보의 클라이언트 저장
   - 안전하지 않은 외부 리소스 사용

6. **기타 보안 이슈**
   - 에러 처리 미흡
   - 로깅 문제
   - 의존성 취약점

각 취약점에 대해 다음 정보를 JSON 형식으로 제공해주세요:

{{
  "vulnerabilities": [
    {{
      "severity": "Critical|High|Medium|Low",
      "category": "카테고리명",
      "title": "취약점 제목",
      "description": "취약점 상세 설명",
      "location": "파일명 및 라인 번호",
      "code_snippet": "문제가 되는 코드",
      "impact": "잠재적 영향",
      "recommendation": "수정 방안",
      "cwe_id": "CWE ID (해당되는 경우)"
    }}
  ],
  "summary": {{
    "total_vulnerabilities": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
  }},
  "overall_assessment": "전체적인 보안 수준 평가"
}}

코드에서 발견된 모든 보안 취약점을 빠짐없이 분석해주세요."""

        print("\n🔍 클로드 API를 통한 보안 분석 시작...")
        
        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=16000,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            result = message.content[0].text
            print("✓ 분석 완료")
            return result
            
        except Exception as e:
            print(f"✗ 분석 중 오류 발생: {e}")
            return None
    
    def parse_analysis_result(self, analysis_text):
        """
        클로드의 분석 결과에서 JSON 데이터 추출
        
        Args:
            analysis_text: 클로드의 분석 결과 텍스트
            
        Returns:
            파싱된 JSON 딕셔너리
        """
        try:
            # JSON 블록 찾기
            start = analysis_text.find('{')
            end = analysis_text.rfind('}') + 1
            
            if start != -1 and end > start:
                json_str = analysis_text[start:end]
                return json.loads(json_str)
            else:
                # JSON을 찾지 못한 경우 기본 구조 반환
                return {
                    "vulnerabilities": [],
                    "summary": {
                        "total_vulnerabilities": 0,
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0
                    },
                    "overall_assessment": analysis_text
                }
        except json.JSONDecodeError:
            print("⚠ JSON 파싱 실패, 원본 텍스트 사용")
            return {
                "vulnerabilities": [],
                "summary": {
                    "total_vulnerabilities": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0
                },
                "overall_assessment": analysis_text
            }
    
    def generate_html_report(self, analysis_data, output_path="security_report.html"):
        """
        분석 결과를 HTML 보고서로 생성
        
        Args:
            analysis_data: 파싱된 분석 결과 딕셔너리
            output_path: 출력 파일 경로
        """
        vulnerabilities = analysis_data.get("vulnerabilities", [])
        summary = analysis_data.get("summary", {})
        assessment = analysis_data.get("overall_assessment", "")
        project_info = analysis_data.get("project_info", {})
        
        # 심각도별 색상
        severity_colors = {
            "Critical": "#dc3545",
            "High": "#fd7e14",
            "Medium": "#ffc107",
            "Low": "#28a745"
        }
        
        # 프로젝트 정보 HTML
        project_info_html = ""
        if project_info:
            project_info_html = f"""
            <div class="project-info">
                <h2>📁 프로젝트 정보</h2>
                <div class="info-grid">
                    <div class="info-item">
                        <span class="info-label">프로젝트명:</span>
                        <span class="info-value">{project_info.get('name', 'N/A')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">경로:</span>
                        <span class="info-value">{project_info.get('path', 'N/A')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">총 파일:</span>
                        <span class="info-value">{project_info.get('total_files', 0)}개</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">프론트엔드:</span>
                        <span class="info-value">{project_info.get('frontend_files', 0)}개</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">백엔드:</span>
                        <span class="info-value">{project_info.get('backend_files', 0)}개</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">설정 파일:</span>
                        <span class="info-value">{project_info.get('config_files', 0)}개</span>
                    </div>
                </div>
            </div>
            """
        
        # 취약점 HTML 생성
        vulnerabilities_html = ""
        for idx, vuln in enumerate(vulnerabilities, 1):
            severity = vuln.get("severity", "Medium")
            color = severity_colors.get(severity, "#6c757d")
            
            # 코드 스니펫 HTML 이스케이프 처리
            code_snippet = html.escape(vuln.get('code_snippet', 'N/A'))
            
            vulnerabilities_html += f"""
            <div class="vulnerability-card">
                <div class="vulnerability-header">
                    <h3>#{idx} {html.escape(vuln.get('title', 'Unknown'))}</h3>
                    <span class="severity-badge" style="background-color: {color};">
                        {severity}
                    </span>
                </div>
                <div class="vulnerability-body">
                    <p><strong>카테고리:</strong> {html.escape(vuln.get('category', 'N/A'))}</p>
                    <p><strong>위치:</strong> <code>{html.escape(vuln.get('location', 'N/A'))}</code></p>
                    
                    <div class="section">
                        <h4>설명</h4>
                        <p>{html.escape(vuln.get('description', 'N/A'))}</p>
                    </div>
                    
                    <div class="section">
                        <h4>영향</h4>
                        <p>{html.escape(vuln.get('impact', 'N/A'))}</p>
                    </div>
                    
                    <div class="section">
                        <h4>문제 코드</h4>
                        <pre><code>{code_snippet}</code></pre>
                    </div>
                    
                    <div class="section recommendation">
                        <h4>수정 방안</h4>
                        <p>{html.escape(vuln.get('recommendation', 'N/A'))}</p>
                    </div>
                    
                    {f'<p class="cwe"><strong>CWE ID:</strong> {html.escape(vuln.get("cwe_id", ""))}</p>' if vuln.get('cwe_id') else ''}
                </div>
            </div>
            """
        
        # HTML 템플릿
        html_template = f"""
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>보안 취약점 분석 보고서</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header .date {{
            opacity: 0.9;
            font-size: 0.9em;
        }}
        
        .project-info {{
            padding: 30px;
            background-color: #f8f9fa;
            border-bottom: 1px solid #e0e0e0;
        }}
        
        .project-info h2 {{
            color: #667eea;
            margin-bottom: 20px;
            font-size: 1.5em;
        }}
        
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }}
        
        .info-item {{
            background: white;
            padding: 15px;
            border-radius: 6px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }}
        
        .info-label {{
            font-weight: bold;
            color: #666;
            display: block;
            margin-bottom: 5px;
            font-size: 0.9em;
        }}
        
        .info-value {{
            color: #333;
            font-size: 1.1em;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background-color: #f8f9fa;
        }}
        
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .summary-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }}
        
        .summary-card .label {{
            color: #666;
            font-size: 0.9em;
        }}
        
        .summary-card.critical .number {{ color: #dc3545; }}
        .summary-card.high .number {{ color: #fd7e14; }}
        .summary-card.medium .number {{ color: #ffc107; }}
        .summary-card.low .number {{ color: #28a745; }}
        .summary-card.total .number {{ color: #667eea; }}
        
        .assessment {{
            padding: 30px;
            background-color: #fff3cd;
            border-left: 4px solid #ffc107;
            margin: 20px 30px;
            white-space: pre-line;
        }}
        
        .assessment h2 {{
            color: #856404;
            margin-bottom: 15px;
        }}
        
        .content {{
            padding: 30px;
        }}
        
        .vulnerability-card {{
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
            transition: box-shadow 0.3s;
        }}
        
        .vulnerability-card:hover {{
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }}
        
        .vulnerability-header {{
            background-color: #f8f9fa;
            padding: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #e0e0e0;
        }}
        
        .vulnerability-header h3 {{
            color: #333;
            font-size: 1.3em;
        }}
        
        .severity-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            font-size: 0.9em;
        }}
        
        .vulnerability-body {{
            padding: 20px;
        }}
        
        .section {{
            margin: 15px 0;
        }}
        
        .section h4 {{
            color: #667eea;
            margin-bottom: 8px;
            font-size: 1.1em;
        }}
        
        .recommendation {{
            background-color: #d4edda;
            padding: 15px;
            border-radius: 4px;
            border-left: 4px solid #28a745;
        }}
        
        .recommendation h4 {{
            color: #155724;
        }}
        
        code {{
            background-color: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }}
        
        pre {{
            background-color: #282c34;
            color: #abb2bf;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            margin: 10px 0;
        }}
        
        pre code {{
            background: none;
            padding: 0;
            color: inherit;
        }}
        
        .cwe {{
            margin-top: 10px;
            color: #666;
            font-size: 0.9em;
        }}
        
        .footer {{
            background-color: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 1px solid #e0e0e0;
        }}
        
        @media print {{
            body {{
                background-color: white;
            }}
            .container {{
                box-shadow: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 보안 취약점 분석 보고서</h1>
            <p class="date">생성 일시: {datetime.now().strftime('%Y년 %m월 %d일 %H:%M:%S')}</p>
        </div>
        
        {project_info_html}
        
        <div class="summary">
            <div class="summary-card total">
                <div class="label">전체 취약점</div>
                <div class="number">{summary.get('total_vulnerabilities', 0)}</div>
            </div>
            <div class="summary-card critical">
                <div class="label">Critical</div>
                <div class="number">{summary.get('critical', 0)}</div>
            </div>
            <div class="summary-card high">
                <div class="label">High</div>
                <div class="number">{summary.get('high', 0)}</div>
            </div>
            <div class="summary-card medium">
                <div class="label">Medium</div>
                <div class="number">{summary.get('medium', 0)}</div>
            </div>
            <div class="summary-card low">
                <div class="label">Low</div>
                <div class="number">{summary.get('low', 0)}</div>
            </div>
        </div>
        
        <div class="assessment">
            <h2>📊 종합 평가</h2>
            <p>{assessment}</p>
        </div>
        
        <div class="content">
            <h2 style="margin-bottom: 20px; color: #667eea;">🔍 발견된 취약점</h2>
            {vulnerabilities_html if vulnerabilities_html else '<p>발견된 취약점이 없습니다.</p>'}
        </div>
        
        <div class="footer">
            <p>이 보고서는 Claude API를 사용하여 자동 생성되었습니다.</p>
            <p>Powered by Anthropic Claude</p>
        </div>
    </div>
</body>
</html>
        """
        
        # HTML 파일 저장
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_template)
        
        print(f"✓ HTML 보고서 생성 완료: {output_path}")
        return output_path


def main():
    """
    메인 실행 함수
    """
    # ==========================================
    # 여기에 Anthropic API 키를 입력하세요
    # ==========================================
    ANTHROPIC_API_KEY = "YOUR_API_KEY"  # 이 부분을 실제 API 키로 변경하세요
    # ==========================================
    
    print("=" * 60)
    print("🔒 보안 취약점 분석 시스템")
    print("=" * 60)
    
    # API 키 확인
    if ANTHROPIC_API_KEY == "your-api-key-here":
        print("\n❌ API 키를 설정해주세요!")
        print("security_analyzer.py 파일을 열어서")
        print("ANTHROPIC_API_KEY 변수에 실제 API 키를 입력하세요.")
        print("\n예시:")
        print('ANTHROPIC_API_KEY = "sk-ant-api03-xxxxx"')
        return 1
    
    # 분석할 폴더 입력 받기
    print("\n📁 분석할 프로젝트 폴더 경로를 입력하세요:")
    print("예시: /home/user/my-project 또는 ./my-app")
    directory = input("> ").strip()
    
    if not directory:
        print("\n❌ 폴더 경로를 입력해주세요.")
        return 1
    
    # 디렉토리 확인
    if not os.path.exists(directory):
        print(f"\n❌ 디렉토리를 찾을 수 없습니다: {directory}")
        return 1
    
    # 출력 파일명 입력 (선택사항)
    print("\n📄 보고서 파일명을 입력하세요 (Enter = security_report.html):")
    output_file = input("> ").strip()
    if not output_file:
        output_file = "security_report.html"
    
    # 분석기 초기화
    try:
        analyzer = SecurityAnalyzer(ANTHROPIC_API_KEY)
    except Exception as e:
        print(f"\n❌ 분석기 초기화 실패: {e}")
        return 1
    
    # 디렉토리 스캔
    code_files_paths = analyzer.scan_directory(directory)
    
    if not code_files_paths:
        print("\n❌ 분석할 코드 파일을 찾을 수 없습니다.")
        return 1
    
    # 파일 분류
    categorized = analyzer.categorize_files(code_files_paths)
    
    # 파일 읽기
    print(f"\n📖 파일 읽기 중...")
    code_files = analyzer.read_code_files(code_files_paths)
    
    if not code_files:
        print("\n❌ 읽을 수 있는 파일이 없습니다.")
        return 1
    
    # 배치 크기 설정 (파일 개수에 따라 자동 조절)
    total_files = len(code_files)
    if total_files <= 10:
        batch_size = total_files
    elif total_files <= 50:
        batch_size = 10
    else:
        batch_size = 15
    
    print(f"\n💡 총 {total_files}개 파일을 {batch_size}개씩 배치로 분석합니다.")
    
    # 보안 분석 (배치 처리)
    all_vulnerabilities = analyzer.analyze_security_batch(code_files, batch_size)
    
    # 요약 통계 생성
    summary = {
        'total_vulnerabilities': len(all_vulnerabilities),
        'critical': sum(1 for v in all_vulnerabilities if v.get('severity') == 'Critical'),
        'high': sum(1 for v in all_vulnerabilities if v.get('severity') == 'High'),
        'medium': sum(1 for v in all_vulnerabilities if v.get('severity') == 'Medium'),
        'low': sum(1 for v in all_vulnerabilities if v.get('severity') == 'Low'),
    }
    
    # 전체 평가 생성
    project_name = Path(directory).name
    overall_assessment = f"""
    프로젝트 '{project_name}'에 대한 보안 분석이 완료되었습니다.
    
    - 분석된 파일: {len(code_files)}개
    - 프론트엔드 파일: {len(categorized['frontend'])}개
    - 백엔드 파일: {len(categorized['backend'])}개
    - 설정 파일: {len(categorized['config'])}개
    
    총 {len(all_vulnerabilities)}개의 보안 취약점이 발견되었습니다.
    심각도가 높은 취약점부터 우선적으로 수정하시기 바랍니다.
    """
    
    # 분석 데이터 구성
    analysis_data = {
        'vulnerabilities': all_vulnerabilities,
        'summary': summary,
        'overall_assessment': overall_assessment,
        'project_info': {
            'name': project_name,
            'path': directory,
            'total_files': len(code_files),
            'frontend_files': len(categorized['frontend']),
            'backend_files': len(categorized['backend']),
            'config_files': len(categorized['config'])
        }
    }
    
    # HTML 보고서 생성
    print(f"\n📄 HTML 보고서 생성 중...")
    analyzer.generate_html_report(analysis_data, output_file)
    
    print("\n" + "=" * 60)
    print("✅ 분석 완료!")
    print(f"📊 총 {summary['total_vulnerabilities']}개의 취약점 발견")
    print(f"   - Critical: {summary['critical']}개")
    print(f"   - High: {summary['high']}개")
    print(f"   - Medium: {summary['medium']}개")
    print(f"   - Low: {summary['low']}개")
    print(f"📁 보고서: {output_file}")
    print("=" * 60)
    
    return 0


if __name__ == "__main__":
    exit(main())