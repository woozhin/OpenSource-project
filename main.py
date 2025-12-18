import anthropic
import os
import sys
import json
import html
import io
import logging
import subprocess
import tempfile
import shutil
from datetime import datetime
from pathlib import Path

# Bandit imports (pip로 설치된 버전 사용)
from bandit.core import config as b_config
from bandit.core import manager as b_manager
from bandit.core import constants as b_constants
from bandit.formatters import json as json_formatter


class UnclosableStringIO(io.StringIO):
    """StringIO wrapper that prevents closing (for Bandit formatter compatibility)"""
    def close(self):
        # Prevent closing so we can read the value after formatter finishes
        pass
    
    def real_close(self):
        # Call the real close when we're done
        super().close()


class IntegratedSecurityAnalyzer:
    def __init__(self, api_key):
        """
        Bandit + LLM을 사용한 통합 보안 취약점 분석기 초기화
        
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
        
        # 분석 결과 저장
        self.bandit_results = None
        self.semgrep_results = None
    
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
            'config': [],
            'python': []  # Python 파일 별도 추적
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
                if ext == '.py':
                    categories['python'].append(file_path)
            elif ext in config_exts:
                categories['config'].append(file_path)
        
        print(f"\n📊 파일 분류:")
        print(f"  - 프론트엔드: {len(categories['frontend'])}개")
        print(f"  - 백엔드: {len(categories['backend'])}개")
        print(f"  - Python 파일: {len(categories['python'])}개")
        print(f"  - 설정 파일: {len(categories['config'])}개")
        
        return categories
    
    def run_semgrep_analysis(self, target_path):
        """
        Semgrep을 사용하여 다양한 언어의 코드 분석 (OWASP Top 10 포함)
        
        Args:
            target_path: 분석할 디렉토리 또는 파일 경로
            
        Returns:
            Semgrep 분석 결과 (JSON 형식)
        """
        print(f"\n🔍 Semgrep으로 보안 분석 중 (OWASP Top 10 포함)...")
        
        # Semgrep 실행 파일 찾기
        semgrep_exe = None
        
        # 방법 1: PATH에서 semgrep 찾기 (shutil.which)
        semgrep_exe = shutil.which('semgrep')
        
        # 방법 2: Python Scripts 폴더에서 직접 찾기
        if not semgrep_exe:
            scripts_dir = os.path.join(os.path.dirname(sys.executable), 'Scripts')
            possible_path = os.path.join(scripts_dir, 'semgrep.exe')
            if os.path.exists(possible_path):
                semgrep_exe = possible_path
        
        # 방법 3: Python 모듈로 실행 (fallback)
        if not semgrep_exe:
            print(f"  ℹ️ Semgrep 실행 파일을 찾지 못해 python -m semgrep 사용")
            semgrep_cmd = [sys.executable, '-m', 'semgrep']
        else:
            print(f"  ✓ Semgrep 실행 파일: {semgrep_exe}")
            semgrep_cmd = [semgrep_exe]
        
        try:
            # UTF-8 인코딩 강제 설정 (Windows cp949 문제 해결)
            env = os.environ.copy()
            env['PYTHONUTF8'] = '1'
            env['PYTHONIOENCODING'] = 'utf-8'
            env['LANG'] = 'en_US.UTF-8'
            
            # 버전 확인
            version_result = subprocess.run(
                semgrep_cmd + ['--version'],
                capture_output=True,
                text=True,
                timeout=10,
                encoding='utf-8',
                errors='ignore',
                env=env
            )
            
            if version_result.returncode == 0:
                # 버전 정보 출력 (경고 메시지 제외)
                for line in version_result.stdout.split('\n'):
                    if line and not line.startswith('Using') and not line.startswith('  '):
                        print(f"  ✓ Semgrep 버전: {line.strip()}")
                        break
            
            # Semgrep 실행
            print(f"  ⏳ 분석 시작... (최대 10분 소요)")
            
            # 규칙 선택 로직
            script_dir = os.path.dirname(os.path.abspath(__file__))
            downloaded_rules_dir = os.path.join(script_dir, 'semgrep-rules')
            
            # 1순위: 다운로드된 규칙 (semgrep-rules 폴더)
            if os.path.exists(downloaded_rules_dir):
                print(f"  ✓ 다운로드된 Semgrep 규칙 사용")
                
                # 주요 보안 규칙 경로들
                security_paths = [
                    os.path.join(downloaded_rules_dir, 'python', 'django', 'security'),
                    os.path.join(downloaded_rules_dir, 'python', 'flask', 'security'),
                    os.path.join(downloaded_rules_dir, 'python', 'lang', 'security'),
                    os.path.join(downloaded_rules_dir, 'javascript', 'express', 'security'),
                    os.path.join(downloaded_rules_dir, 'javascript', 'react', 'security'),
                    os.path.join(downloaded_rules_dir, 'javascript', 'lang', 'security'),
                    os.path.join(downloaded_rules_dir, 'generic', 'secrets'),
                    os.path.join(downloaded_rules_dir, 'generic', 'security'),
                ]
                
                # 존재하는 경로만 추가
                config_args = []
                for path in security_paths:
                    if os.path.exists(path):
                        config_args.extend(['--config', path])
                
                if not config_args:
                    # 폴더는 있지만 규칙이 없으면 전체 폴더 사용
                    config_args = ['--config', downloaded_rules_dir]
                
                cmd = semgrep_cmd + config_args + [
                    '--json',
                    '--no-git-ignore',
                    '--metrics', 'off',
                    '--max-target-bytes', '5000000',
                    '--timeout', '60',
                    target_path
                ]
                
            # 2순위: Semgrep 레지스트리 (p/...)
            else:
                print(f"  ℹ️ Semgrep 레지스트리 규칙 사용")
                print(f"  💡 더 많은 규칙을 사용하려면: python download_semgrep_rules.py")
                
                cmd = semgrep_cmd + [
                    '--config', 'p/owasp-top-ten',
                    '--config', 'p/security-audit',
                    '--config', 'p/python',
                    '--json',
                    '--no-git-ignore',
                    '--metrics', 'off',
                    '--verbose',
                    '--max-target-bytes', '5000000',
                    '--timeout', '60',
                    target_path
                ]
            
            # env는 이미 위에서 정의됨 (UTF-8 설정 포함)
            result = subprocess.run(
                cmd,
                capture_output=True,  # stdout, stderr 자동 캡처
                text=True,
                timeout=600,  # 10분 타임아웃
                encoding='utf-8',
                errors='ignore',  # 인코딩 에러 무시
                env=env  # UTF-8 환경 변수 전달
            )
            
            # stderr 출력 확인 (디버그용)
            if result.stderr:
                stderr_lines = result.stderr.strip().split('\n')
                for line in stderr_lines[:5]:  # 처음 5줄만 출력
                    if line and not line.startswith('Scanning'):
                        print(f"  ℹ️ {line}")
            
            # Semgrep은 발견이 있으면 exit code 1을 반환
            # returncode 0 또는 1은 정상 (2 이상이 실제 오류)
            if result.returncode >= 2:
                print(f"  ✗ Semgrep 실행 실패 (Return Code: {result.returncode})")
                print(f"  ℹ️ Stderr: {result.stderr}")
                return None
            
            # JSON 파싱
            if not result.stdout or not result.stdout.strip():
                print(f"  ⚠ Semgrep 출력이 비어있습니다.")
                print(f"  ℹ️ Stderr 전체: {result.stderr}")
                return None
            
            try:
                semgrep_data = json.loads(result.stdout)
            except json.JSONDecodeError as e:
                print(f"  ✗ JSON 파싱 실패: {e}")
                print(f"  ℹ️ 출력 미리보기: {result.stdout[:200]}")
                return None
            
            # 통계 출력
            results = semgrep_data.get('results', [])
            errors = semgrep_data.get('errors', [])
            paths = semgrep_data.get('paths', {})
            
            # 스캔된 파일 정보
            scanned_files = paths.get('scanned', []) if paths else []
            skipped_files = paths.get('skipped', []) if paths else []
            
            print(f"  📁 스캔 정보:")
            print(f"    - 스캔된 파일: {len(scanned_files)}개")
            if skipped_files:
                print(f"    - 건너뛴 파일: {len(skipped_files)}개")
            
            # 심각도별 통계
            severity_count = {
                'ERROR': 0,
                'WARNING': 0,
                'INFO': 0
            }
            
            for finding in results:
                severity = finding.get('extra', {}).get('severity', 'INFO').upper()
                if severity in severity_count:
                    severity_count[severity] += 1
            
            print(f"  ✓ Semgrep 분석 완료")
            print(f"    - 발견된 이슈: {len(results)}개")
            print(f"    - ERROR: {severity_count['ERROR']}개")
            print(f"    - WARNING: {severity_count['WARNING']}개")
            print(f"    - INFO: {severity_count['INFO']}개")
            
            if errors:
                print(f"    - 분석 오류: {len(errors)}개")
                for err in errors[:3]:  # 처음 3개만 표시
                    print(f"      ⚠ {err.get('message', 'Unknown error')}")
            
            self.semgrep_results = semgrep_data
            return semgrep_data
            
        except subprocess.TimeoutExpired as e:
            print(f"  ✗ Semgrep 실행 타임아웃 (10분 초과)")
            print(f"  💡 분석 대상이 너무 큽니다. 작은 폴더로 시도하거나 Semgrep을 건너뛰세요.")
            return None
        except FileNotFoundError as e:
            print(f"  ✗ Semgrep을 찾을 수 없습니다: {e}")
            print(f"  💡 설치 방법: pip install semgrep")
            return None
        except json.JSONDecodeError as e:
            print(f"  ✗ Semgrep 결과 파싱 실패: {e}")
            return None
        except PermissionError as e:
            print(f"  ✗ 권한 오류: {e}")
            print(f"  💡 관리자 권한으로 실행하거나 다른 폴더를 시도하세요.")
            return None
        except Exception as e:
            print(f"  ✗ Semgrep 분석 중 예상치 못한 오류: {type(e).__name__}: {e}")
            print(f"  💡 상세 정보:")
            import traceback
            traceback.print_exc()
            return None
    
    def run_bandit_analysis(self, target_path):
        """
        Bandit을 사용하여 Python 코드 분석
        
        Args:
            target_path: 분석할 디렉토리 또는 파일 경로
            
        Returns:
            Bandit 분석 결과 (JSON 형식)
        """
        print(f"\n🔍 Bandit으로 Python 코드 분석 중...")
        
        try:
            # Bandit 설정 초기화
            b_conf = b_config.BanditConfig()
            
            # BanditManager 초기화
            b_mgr = b_manager.BanditManager(
                b_conf,
                'file',
                debug=False,
                verbose=False,
                quiet=True,
                ignore_nosec=False
            )
            
            # 파일 검색
            b_mgr.discover_files([target_path], True, None)
            
            if not b_mgr.files_list:
                print("  ⚠ 분석할 Python 파일이 없습니다.")
                return None
            
            print(f"  📁 {len(b_mgr.files_list)}개의 Python 파일 발견")
            
            # 테스트 실행
            b_mgr.run_tests()
            
            # 결과를 JSON으로 변환
            output = UnclosableStringIO()
            output.name = '<string>'  # StringIO에 name 속성 추가 (Bandit formatter 호환)
            json_formatter.report(
                b_mgr,
                output,
                b_constants.LOW,
                b_constants.LOW,
                lines=-1
            )
            
            json_output = output.getvalue()
            bandit_data = json.loads(json_output)
            output.real_close()  # 이제 실제로 닫기
            
            # 통계 출력
            results_count = len(bandit_data.get('results', []))
            metrics = bandit_data.get('metrics', {}).get('_totals', {})
            
            print(f"  ✓ Bandit 분석 완료")
            print(f"    - 발견된 이슈: {results_count}개")
            print(f"    - HIGH 심각도: {metrics.get('SEVERITY.HIGH', 0)}개")
            print(f"    - MEDIUM 심각도: {metrics.get('SEVERITY.MEDIUM', 0)}개")
            print(f"    - LOW 심각도: {metrics.get('SEVERITY.LOW', 0)}개")
            
            self.bandit_results = bandit_data
            return bandit_data
            
        except Exception as e:
            print(f"  ✗ Bandit 분석 중 오류 발생: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def format_semgrep_results_for_llm(self, semgrep_data):
        """
        Semgrep 결과를 LLM이 이해하기 쉬운 형식으로 변환
        
        Args:
            semgrep_data: Semgrep JSON 결과
            
        Returns:
            포맷된 텍스트
        """
        if not semgrep_data or not semgrep_data.get('results'):
            return "Semgrep 분석 결과: 발견된 이슈가 없습니다."
        
        formatted = "=" * 70 + "\n"
        formatted += "🔍 SEMGREP 정적 분석 결과 (OWASP Top 10 포함)\n"
        formatted += "=" * 70 + "\n\n"
        
        results = semgrep_data.get('results', [])
        
        for idx, finding in enumerate(results, 1):
            extra = finding.get('extra', {})
            metadata = extra.get('metadata', {})
            
            formatted += f"\n[이슈 #{idx}]\n"
            formatted += f"파일: {finding.get('path', 'N/A')}\n"
            formatted += f"라인: {finding.get('start', {}).get('line', 'N/A')}\n"
            formatted += f"규칙 ID: {finding.get('check_id', 'N/A')}\n"
            formatted += f"심각도: {extra.get('severity', 'INFO')}\n"
            
            # OWASP 태그
            if metadata.get('owasp'):
                formatted += f"OWASP: {', '.join(metadata['owasp'])}\n"
            
            # CWE
            if metadata.get('cwe'):
                formatted += f"CWE: {', '.join(metadata['cwe'])}\n"
            
            formatted += f"설명: {extra.get('message', 'N/A')}\n"
            
            # 코드
            if extra.get('lines'):
                formatted += f"코드:\n{extra['lines']}\n"
            
            formatted += "-" * 70 + "\n"
        
        # 통계 요약
        severity_count = {'ERROR': 0, 'WARNING': 0, 'INFO': 0}
        for finding in results:
            severity = finding.get('extra', {}).get('severity', 'INFO').upper()
            if severity in severity_count:
                severity_count[severity] += 1
        
        formatted += f"\n통계 요약:\n"
        formatted += f"  - 총 이슈: {len(results)}개\n"
        formatted += f"  - ERROR: {severity_count['ERROR']}개\n"
        formatted += f"  - WARNING: {severity_count['WARNING']}개\n"
        formatted += f"  - INFO: {severity_count['INFO']}개\n"
        formatted += "=" * 70 + "\n"
        
        return formatted
    
    def format_bandit_results_for_llm(self, bandit_data):
        """
        Bandit 결과를 LLM이 이해하기 쉬운 형식으로 변환
        
        Args:
            bandit_data: Bandit JSON 결과
            
        Returns:
            포맷된 텍스트
        """
        if not bandit_data or not bandit_data.get('results'):
            return "Bandit 분석 결과: 발견된 이슈가 없습니다."
        
        formatted = "=" * 70 + "\n"
        formatted += "🔍 BANDIT 정적 분석 결과 (Python 코드)\n"
        formatted += "=" * 70 + "\n\n"
        
        results = bandit_data.get('results', [])
        
        for idx, issue in enumerate(results, 1):
            formatted += f"\n[이슈 #{idx}]\n"
            formatted += f"파일: {issue.get('filename', 'N/A')}\n"
            formatted += f"라인: {issue.get('line_number', 'N/A')}\n"
            formatted += f"테스트 ID: {issue.get('test_id', 'N/A')}\n"
            formatted += f"심각도: {issue.get('issue_severity', 'N/A')}\n"
            formatted += f"신뢰도: {issue.get('issue_confidence', 'N/A')}\n"
            
            if issue.get('issue_cwe'):
                cwe = issue['issue_cwe']
                formatted += f"CWE: CWE-{cwe.get('id', 'N/A')} ({cwe.get('link', 'N/A')})\n"
            
            formatted += f"설명: {issue.get('issue_text', 'N/A').strip()}\n"
            
            if issue.get('code'):
                formatted += f"코드:\n{issue['code']}\n"
            
            formatted += "-" * 70 + "\n"
        
        # 통계 요약
        metrics = bandit_data.get('metrics', {}).get('_totals', {})
        formatted += f"\n통계 요약:\n"
        formatted += f"  - 총 이슈: {len(results)}개\n"
        formatted += f"  - HIGH: {metrics.get('SEVERITY.HIGH', 0)}개\n"
        formatted += f"  - MEDIUM: {metrics.get('SEVERITY.MEDIUM', 0)}개\n"
        formatted += f"  - LOW: {metrics.get('SEVERITY.LOW', 0)}개\n"
        formatted += "=" * 70 + "\n"
        
        return formatted
    
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
                skipped_files.append(f"{file_path} (오류: {str(e)})")
        
        if skipped_files:
            print(f"\n⚠ 건너뛴 파일 ({len(skipped_files)}개):")
            for skipped in skipped_files[:5]:  # 최대 5개만 표시
                print(f"  - {skipped}")
            if len(skipped_files) > 5:
                print(f"  ... 외 {len(skipped_files) - 5}개")
        
        print(f"\n✓ {len(code_files)}개 파일 읽기 완료")
        return code_files
    
    def convert_semgrep_to_vulnerabilities(self, semgrep_results):
        """
        Semgrep 결과를 취약점 리스트로 변환
        
        Args:
            semgrep_results: Semgrep JSON 결과
            
        Returns:
            취약점 딕셔너리 리스트
        """
        vulnerabilities = []
        
        if not semgrep_results or not semgrep_results.get('results'):
            return vulnerabilities
        
        # 심각도 매핑
        severity_map = {
            'ERROR': 'High',
            'WARNING': 'Medium',
            'INFO': 'Low'
        }
        
        for finding in semgrep_results.get('results', []):
            extra = finding.get('extra', {})
            
            # 카테고리 추출 (OWASP 등)
            metadata = extra.get('metadata', {})
            owasp_tags = [tag for tag in metadata.get('owasp', [])] if metadata.get('owasp') else []
            category = metadata.get('category', 'Security')
            
            # CWE 추출
            cwe_list = metadata.get('cwe', [])
            cwe_id = f"CWE-{cwe_list[0].split('-')[1]}" if cwe_list else ''
            
            vuln = {
                'severity': severity_map.get(extra.get('severity', 'INFO').upper(), 'Medium'),
                'category': f"{category} ({', '.join(owasp_tags[:2])})" if owasp_tags else category,
                'title': f"{extra.get('message', 'Security Issue')}",
                'description': extra.get('message', '') + '\n' + metadata.get('description', ''),
                'location': f"{Path(finding.get('path', '')).name}:{finding.get('start', {}).get('line', 'N/A')}",
                'code_snippet': finding.get('extra', {}).get('lines', '').strip(),
                'impact': f"심각도: {extra.get('severity', 'INFO')}, 신뢰도: High",
                'recommendation': metadata.get('fix', metadata.get('references', ['코드를 검토하고 보안 모범 사례를 따르세요.'])[0] if metadata.get('references') else '코드를 검토하고 보안 모범 사례를 따르세요.'),
                'cwe_id': cwe_id,
                'source': 'Semgrep'
            }
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def convert_bandit_to_vulnerabilities(self, bandit_results):
        """
        Bandit 결과를 취약점 리스트로 변환
        
        Args:
            bandit_results: Bandit JSON 결과
            
        Returns:
            취약점 딕셔너리 리스트
        """
        vulnerabilities = []
        
        if not bandit_results or not bandit_results.get('results'):
            return vulnerabilities
        
        # 심각도 매핑
        severity_map = {
            'HIGH': 'High',
            'MEDIUM': 'Medium',
            'LOW': 'Low'
        }
        
        for issue in bandit_results.get('results', []):
            vuln = {
                'severity': severity_map.get(issue.get('issue_severity', 'MEDIUM'), 'Medium'),
                'category': 'Python 보안',
                'title': f"{issue.get('test_name', 'Security Issue')} - {issue.get('test_id', '')}",
                'description': issue.get('issue_text', '').strip(),
                'location': f"{Path(issue.get('filename', '')).name}:{issue.get('line_number', 'N/A')}",
                'code_snippet': issue.get('code', '').strip(),
                'impact': f"심각도: {issue.get('issue_severity', 'N/A')}, 신뢰도: {issue.get('issue_confidence', 'N/A')}",
                'recommendation': '코드를 검토하고 보안 모범 사례를 따르세요.',
                'cwe_id': f"CWE-{issue['issue_cwe']['id']}" if issue.get('issue_cwe') else '',
                'source': 'Bandit'
            }
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def analyze_security_with_tools(self, code_files, semgrep_results, bandit_results):
        """
        Semgrep + Bandit 결과를 포함하여 LLM으로 보안 분석
        
        Args:
            code_files: 파일명과 코드 내용을 담은 딕셔너리
            semgrep_results: Semgrep 분석 결과
            bandit_results: Bandit 분석 결과
            
        Returns:
            분석 결과 텍스트
        """
        # Semgrep 결과를 취약점으로 변환
        semgrep_vulnerabilities = self.convert_semgrep_to_vulnerabilities(semgrep_results)
        
        # Bandit 결과를 취약점으로 변환
        bandit_vulnerabilities = self.convert_bandit_to_vulnerabilities(bandit_results)
        
        # 두 도구의 취약점을 합침
        all_tool_vulnerabilities = semgrep_vulnerabilities + bandit_vulnerabilities
        
        # 코드 파일들을 프롬프트에 포함할 형식으로 변환
        code_context = []
        for file_path, content in code_files.items():
            # 파일명만 표시 (경로가 너무 길면)
            rel_path = Path(file_path).name if len(file_path) > 60 else file_path
            # 파일 크기 제한 (너무 큰 파일은 일부만)
            if len(content) > 10000:
                content = content[:10000] + "\n\n... (파일이 너무 커서 일부만 표시)"
            code_context.append(f"\n## 파일: {rel_path}\n```\n{content}\n```")
        
        code_text = "\n".join(code_context)
        
        # Semgrep 결과 포맷팅
        semgrep_text = ""
        if semgrep_results:
            semgrep_text = self.format_semgrep_results_for_llm(semgrep_results)
        
        # Bandit 결과 포맷팅
        bandit_text = ""
        if bandit_results:
            bandit_text = self.format_bandit_results_for_llm(bandit_results)
        
        # 도구별 취약점 개수
        semgrep_count = len(semgrep_vulnerabilities)
        bandit_count = len(bandit_vulnerabilities)
        total_tool_count = semgrep_count + bandit_count
        
        # 보안 분석 프롬프트
        prompt = f"""당신은 경험이 풍부한 보안 전문가입니다. 다음 코드들을 철저히 분석하여 모든 보안 취약점을 찾아주세요.

⚠️ **중요: 모든 응답은 반드시 한글로 작성해주세요!**

{"=" * 70}
🔍 SEMGREP 정적 분석 결과 (OWASP Top 10 포함 - 모든 언어)
{"=" * 70}
{semgrep_text if semgrep_text else "Semgrep 분석 결과가 없습니다."}

{"=" * 70}
🔍 BANDIT 정적 분석 결과 (Python 특화)
{"=" * 70}
{bandit_text if bandit_text else "Python 파일이 없거나 Bandit 분석 결과가 없습니다."}

{"=" * 70}
📄 분석할 전체 코드베이스
{"=" * 70}
{code_text}

{"=" * 70}
⚠️ 중요 지시사항
{"=" * 70}

1. **정적 분석 도구가 발견한 {total_tool_count}개의 취약점을 반드시 JSON에 포함하세요**
   - Semgrep 발견: {semgrep_count}개 → "source": "Semgrep"
   - Bandit 발견: {bandit_count}개 → "source": "Bandit"
   - 각 도구의 결과를 그대로 유지하면서 더 자세한 설명 추가

2. **추가로 다음 항목들을 철저히 분석하세요:**
   
   **프론트엔드 보안 (JavaScript, HTML 등):**
   - XSS (innerHTML, eval 등)
   - 클라이언트 측 비밀정보 저장
   - 안전하지 않은 HTTP 사용
   - CORS 문제
   
   **백엔드 보안 (Python, API 등):**
   - SQL Injection (parameterized query 미사용)
   - Command Injection (os.system, subprocess)
   - 인증/권한 검증 누락
   - Rate limiting 부재
   - IDOR (Insecure Direct Object Reference)
   - 민감한 에러 정보 노출
   
   **공통 보안:**
   - 하드코딩된 비밀번호/API 키/토큰
   - 약한 암호화 (MD5, SHA1, DES)
   - 위험한 함수 (eval, exec, pickle)
   - 파일 권한 문제
   - JWT 검증 없음
   - Debug mode 활성화

3. **각 취약점마다:**
   - 정확한 파일명과 라인 번호
   - 실제 문제 코드 스니펫
   - 구체적인 수정 방법
   - "source": "LLM Analysis" 표시

{"=" * 70}
📝 응답 형식 (반드시 JSON만 출력, 모든 내용은 한글로!)
{"=" * 70}

{{
  "vulnerabilities": [
    {{
      "severity": "Critical|High|Medium|Low",
      "category": "SQL Injection|XSS|인증 우회|민감정보 노출|등등 (한글로!)",
      "title": "명확한 취약점 제목 (한글로!)",
      "description": "상세한 설명 (한글로!)",
      "location": "파일명:라인번호",
      "code_snippet": "실제 문제 코드",
      "impact": "구체적인 보안 영향 (한글로!)",
      "recommendation": "실행 가능한 수정 방안 (한글로!)",
      "cwe_id": "CWE-XXX (있는 경우)",
      "source": "Semgrep|Bandit|LLM Analysis"
    }}
  ],
  "summary": {{
    "total_vulnerabilities": {total_tool_count} + 추가발견,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "semgrep_issues": {semgrep_count},
    "bandit_issues": {bandit_count},
    "llm_found_issues": 추가발견수
  }},
  "overall_assessment": "종합 평가 (한글로!)"
}}

⚠️ **모든 텍스트 필드(title, description, category, impact, recommendation, overall_assessment)는 반드시 한글로 작성!**
⚠️ 반드시 순수 JSON만 출력하세요. 설명이나 마크다운 없이 JSON만!
⚠️ Semgrep {semgrep_count}개 + Bandit {bandit_count}개 + 추가 발견 취약점 모두 포함!
⚠️ 모든 파일(프론트엔드/백엔드/설정)을 빠짐없이 검사!"""

        print("\n🤖 Claude API를 통한 보안 분석 시작...")
        print(f"   📊 정적 분석 도구 발견:")
        print(f"      - Semgrep: {semgrep_count}개")
        print(f"      - Bandit: {bandit_count}개")
        print(f"   🔍 LLM 추가 취약점 탐지 중...")
        
        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=16000,
                system="당신은 한국어로 소통하는 보안 전문가입니다. 모든 응답은 반드시 한글로 작성해야 합니다.",
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            result = message.content[0].text
            print("✓ LLM 분석 완료")
            
            # LLM 응답에 도구 취약점이 누락되었을 경우를 대비해 병합
            return self.merge_tools_and_llm_results(result, all_tool_vulnerabilities)
            
        except Exception as e:
            print(f"✗ 분석 중 오류 발생: {e}")
            # 오류 발생 시에도 도구 결과는 반환
            if all_tool_vulnerabilities:
                return self.create_tools_only_result(all_tool_vulnerabilities, semgrep_count, bandit_count)
            return None
    
    def merge_tools_and_llm_results(self, llm_result, tool_vulnerabilities):
        """
        LLM 결과와 정적 분석 도구 취약점을 병합
        
        Args:
            llm_result: LLM 분석 결과 텍스트
            tool_vulnerabilities: 정적 분석 도구 취약점 리스트 (Semgrep + Bandit)
            
        Returns:
            병합된 결과 텍스트
        """
        # LLM 결과 파싱 시도
        parsed = self.parse_analysis_result(llm_result)
        
        # LLM이 발견한 취약점
        llm_vulnerabilities = parsed.get('vulnerabilities', [])
        
        # 도구 취약점이 LLM 결과에 포함되었는지 확인
        semgrep_in_llm = sum(1 for v in llm_vulnerabilities if v.get('source') == 'Semgrep')
        bandit_in_llm = sum(1 for v in llm_vulnerabilities if v.get('source') == 'Bandit')
        tools_in_llm = semgrep_in_llm + bandit_in_llm
        
        # 도구 취약점이 누락되었거나 적으면 직접 추가
        if tools_in_llm < len(tool_vulnerabilities):
            missing = len(tool_vulnerabilities) - tools_in_llm
            print(f"   ℹ️ 정적 분석 도구 취약점 {missing}개를 결과에 추가합니다")
            
            # 중복 제거를 위해 이미 포함된 것은 제외
            existing_locations = {v.get('location', '') for v in llm_vulnerabilities if v.get('source') in ['Semgrep', 'Bandit']}
            
            for tool_vuln in tool_vulnerabilities:
                if tool_vuln['location'] not in existing_locations:
                    llm_vulnerabilities.insert(0, tool_vuln)  # 맨 앞에 추가
            
            # 통계 재계산
            summary = {
                'total_vulnerabilities': len(llm_vulnerabilities),
                'critical': sum(1 for v in llm_vulnerabilities if v.get('severity') == 'Critical'),
                'high': sum(1 for v in llm_vulnerabilities if v.get('severity') == 'High'),
                'medium': sum(1 for v in llm_vulnerabilities if v.get('severity') == 'Medium'),
                'low': sum(1 for v in llm_vulnerabilities if v.get('severity') == 'Low'),
                'semgrep_issues': sum(1 for v in llm_vulnerabilities if v.get('source') == 'Semgrep'),
                'bandit_issues': sum(1 for v in llm_vulnerabilities if v.get('source') == 'Bandit'),
                'llm_found_issues': sum(1 for v in llm_vulnerabilities if v.get('source') == 'LLM Analysis'),
            }
            
            # 새로운 JSON 생성
            merged_result = {
                'vulnerabilities': llm_vulnerabilities,
                'summary': summary,
                'overall_assessment': parsed.get('overall_assessment', '보안 분석 완료')
            }
            
            return json.dumps(merged_result, ensure_ascii=False, indent=2)
        
        return llm_result
    
    def create_tools_only_result(self, tool_vulnerabilities, semgrep_count, bandit_count):
        """
        정적 분석 도구 결과만으로 JSON 생성 (LLM 실패 시)
        
        Args:
            tool_vulnerabilities: 도구 취약점 리스트
            semgrep_count: Semgrep 발견 수
            bandit_count: Bandit 발견 수
            
        Returns:
            JSON 문자열
        """
        summary = {
            'total_vulnerabilities': len(tool_vulnerabilities),
            'critical': sum(1 for v in tool_vulnerabilities if v.get('severity') == 'Critical'),
            'high': sum(1 for v in tool_vulnerabilities if v.get('severity') == 'High'),
            'medium': sum(1 for v in tool_vulnerabilities if v.get('severity') == 'Medium'),
            'low': sum(1 for v in tool_vulnerabilities if v.get('severity') == 'Low'),
            'semgrep_issues': semgrep_count,
            'bandit_issues': bandit_count,
            'llm_found_issues': 0,
        }
        
        result = {
            'vulnerabilities': tool_vulnerabilities,
            'summary': summary,
            'overall_assessment': f'정적 분석 도구만 완료 (Semgrep: {semgrep_count}개, Bandit: {bandit_count}개) - LLM 분석 실패'
        }
        
        return json.dumps(result, ensure_ascii=False, indent=2)
    
    def parse_analysis_result(self, analysis_text):
        """
        LLM의 분석 결과에서 JSON 데이터 추출
        
        Args:
            analysis_text: LLM의 분석 결과 텍스트
            
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
    
    def generate_html_report(self, analysis_data, semgrep_data, bandit_data, output_path="security_report.html"):
        """
        분석 결과를 HTML 보고서로 생성
        
        Args:
            analysis_data: 파싱된 LLM 분석 결과 딕셔너리
            semgrep_data: Semgrep 분석 결과
            bandit_data: Bandit 분석 결과
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
        
        # Semgrep 요약 HTML
        semgrep_summary_html = ""
        if semgrep_data:
            semgrep_results = semgrep_data.get('results', [])
            semgrep_issues_count = len(semgrep_results)
            
            # 심각도별 통계
            severity_count = {'ERROR': 0, 'WARNING': 0, 'INFO': 0}
            for finding in semgrep_results:
                severity = finding.get('extra', {}).get('severity', 'INFO').upper()
                if severity in severity_count:
                    severity_count[severity] += 1
            
            semgrep_summary_html = f"""
            <div class="semgrep-summary">
                <h2>🔍 Semgrep 정적 분석 요약 (OWASP Top 10)</h2>
                <div class="tool-stats">
                    <div class="stat-item">
                        <span class="stat-label">발견된 이슈</span>
                        <span class="stat-value">{semgrep_issues_count}개</span>
                    </div>
                    <div class="stat-item error">
                        <span class="stat-label">ERROR</span>
                        <span class="stat-value">{severity_count['ERROR']}개</span>
                    </div>
                    <div class="stat-item warning">
                        <span class="stat-label">WARNING</span>
                        <span class="stat-value">{severity_count['WARNING']}개</span>
                    </div>
                    <div class="stat-item info">
                        <span class="stat-label">INFO</span>
                        <span class="stat-value">{severity_count['INFO']}개</span>
                    </div>
                </div>
            </div>
            """
        
        # Bandit 요약 HTML
        bandit_summary_html = ""
        if bandit_data:
            bandit_metrics = bandit_data.get('metrics', {}).get('_totals', {})
            bandit_issues_count = len(bandit_data.get('results', []))
            
            bandit_summary_html = f"""
            <div class="bandit-summary">
                <h2>🔍 Bandit 정적 분석 요약 (Python)</h2>
                <div class="tool-stats">
                    <div class="stat-item">
                        <span class="stat-label">발견된 이슈</span>
                        <span class="stat-value">{bandit_issues_count}개</span>
                    </div>
                    <div class="stat-item high">
                        <span class="stat-label">HIGH</span>
                        <span class="stat-value">{bandit_metrics.get('SEVERITY.HIGH', 0)}개</span>
                    </div>
                    <div class="stat-item medium">
                        <span class="stat-label">MEDIUM</span>
                        <span class="stat-value">{bandit_metrics.get('SEVERITY.MEDIUM', 0)}개</span>
                    </div>
                    <div class="stat-item low">
                        <span class="stat-label">LOW</span>
                        <span class="stat-value">{bandit_metrics.get('SEVERITY.LOW', 0)}개</span>
                    </div>
                </div>
            </div>
            """
        
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
                        <span class="info-label">Python 파일:</span>
                        <span class="info-value">{project_info.get('python_files', 0)}개</span>
                    </div>
                </div>
            </div>
            """
        
        # 취약점 HTML 생성
        vulnerabilities_html = ""
        for idx, vuln in enumerate(vulnerabilities, 1):
            severity = vuln.get("severity", "Medium")
            color = severity_colors.get(severity, "#6c757d")
            source = vuln.get("source", "LLM Analysis")
            
            # 소스 뱃지 색상
            source_badge_colors = {
                "Semgrep": "#00d4ff",
                "Bandit": "#ff4785",
                "LLM Analysis": "#6f42c1"
            }
            source_badge_color = source_badge_colors.get(source, "#6c757d")
            
            # 코드 스니펫 HTML 이스케이프 처리
            code_snippet = html.escape(vuln.get('code_snippet', 'N/A'))
            
            vulnerabilities_html += f"""
            <div class="vulnerability-card">
                <div class="vulnerability-header">
                    <div>
                        <h3>#{idx} {html.escape(vuln.get('title', 'Unknown'))}</h3>
                        <span class="source-badge" style="background-color: {source_badge_color};">
                            {source}
                        </span>
                    </div>
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
    <title>통합 보안 취약점 분석 보고서</title>
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
        
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
            margin-bottom: 10px;
        }}
        
        .header .date {{
            opacity: 0.9;
            font-size: 0.9em;
        }}
        
        .semgrep-summary {{
            padding: 30px;
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
            color: white;
        }}
        
        .semgrep-summary h2 {{
            margin-bottom: 20px;
            font-size: 1.5em;
        }}
        
        .bandit-summary {{
            padding: 30px;
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
        }}
        
        .bandit-summary h2 {{
            margin-bottom: 20px;
            font-size: 1.5em;
        }}
        
        .tool-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
        }}
        
        .stat-item {{
            background: rgba(255, 255, 255, 0.2);
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            backdrop-filter: blur(10px);
        }}
        
        .stat-label {{
            display: block;
            font-size: 0.9em;
            margin-bottom: 5px;
            opacity: 0.9;
        }}
        
        .stat-value {{
            display: block;
            font-size: 1.8em;
            font-weight: bold;
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
            margin-bottom: 8px;
        }}
        
        .severity-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            font-size: 0.9em;
        }}
        
        .source-badge {{
            padding: 3px 10px;
            border-radius: 12px;
            color: white;
            font-size: 0.75em;
            font-weight: bold;
            display: inline-block;
            margin-left: 10px;
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
            <h1>🔒 통합 보안 취약점 분석 보고서</h1>
            <p class="subtitle">Semgrep + Bandit + Claude AI 통합 분석</p>
            <p class="date">생성 일시: {datetime.now().strftime('%Y년 %m월 %d일 %H:%M:%S')}</p>
        </div>
        
        {semgrep_summary_html}
        
        {bandit_summary_html}
        
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
            <p><strong>이 보고서는 Semgrep, Bandit 정적 분석 도구와 Claude AI를 사용하여 자동 생성되었습니다.</strong></p>
            <p>Powered by Semgrep + Bandit + Anthropic Claude</p>
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
    # API 키 설정 - 아래 두 방법 중 하나를 선택하세요:
    # 
    # 방법 1 (권장): 환경 변수 설정
    #   Windows PowerShell: $env:ANTHROPIC_API_KEY="sk-ant-api03-xxxxx"
    #   Windows CMD: set ANTHROPIC_API_KEY=sk-ant-api03-xxxxx
    #   Linux/Mac: export ANTHROPIC_API_KEY="sk-ant-api03-xxxxx"
    #
    # 방법 2: 아래 줄의 "YOUR_API_KEY"를 실제 API 키로 변경
    # ==========================================
    ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "YOUR_API_KEY")
    # ==========================================
    
    print("=" * 70)
    print("🔒 통합 보안 취약점 분석 시스템 (Semgrep + Bandit + Claude AI)")
    print("=" * 70)
    
    # Semgrep 규칙 확인
    script_dir = os.path.dirname(os.path.abspath(__file__))
    rules_dir = os.path.join(script_dir, 'semgrep-rules')
    
    if not os.path.exists(rules_dir):
        print("\n⚠️ Semgrep 규칙이 다운로드되지 않았습니다.")
        print("💡 더 정확한 분석을 위해 규칙을 다운로드하시겠습니까? (Y/N)")
        choice = input("> ").strip().upper()
        
        if choice == 'Y':
            print("\n📥 Semgrep 규칙 다운로드 중...")
            try:
                result = subprocess.run(
                    [sys.executable, "download_semgrep_rules.py"],
                    timeout=300
                )
                if result.returncode == 0:
                    print("✅ 규칙 다운로드 완료!")
                else:
                    print("⚠️ 규칙 다운로드 실패 - 레지스트리 규칙을 사용합니다.")
            except Exception as e:
                print(f"⚠️ 규칙 다운로드 중 오류: {e}")
                print("ℹ️ 레지스트리 규칙을 사용합니다.")
        else:
            print("ℹ️ 레지스트리 규칙을 사용합니다 (나중에 'python download_semgrep_rules.py' 실행)")
    else:
        print(f"\n✅ Semgrep 규칙: {rules_dir}")
    
    # API 키 확인
    if ANTHROPIC_API_KEY == "YOUR_API_KEY":
        print("\n❌ API 키를 설정해주세요!")
        print("환경변수 ANTHROPIC_API_KEY를 설정하거나")
        print("main.py 파일의 ANTHROPIC_API_KEY를 수정하세요.")
        print("\n예시:")
        print('ANTHROPIC_API_KEY = "sk-ant-api03-xxxxx"')
        return 1
    
    # 분석할 폴더 입력 받기
    print("\n📁 분석할 프로젝트 폴더 경로를 입력하세요:")
    print("예시: C:\\Users\\user\\project 또는 ./my-app")
    directory = input("> ").strip()
    
    if not directory:
        print("\n❌ 폴더 경로를 입력해주세요.")
        return 1
    
    # 디렉토리 확인
    if not os.path.exists(directory):
        print(f"\n❌ 디렉토리를 찾을 수 없습니다: {directory}")
        return 1
    
    # 출력 파일명 입력 (선택사항)
    print("\n📄 보고서 파일명을 입력하세요 (Enter = integrated_security_report.html):")
    output_file = input("> ").strip()
    if not output_file:
        output_file = "integrated_security_report.html"
    
    # 분석기 초기화
    try:
        analyzer = IntegratedSecurityAnalyzer(ANTHROPIC_API_KEY)
    except Exception as e:
        print(f"\n❌ 분석기 초기화 실패: {e}")
        return 1
    
    # 1단계: 디렉토리 스캔
    code_files_paths = analyzer.scan_directory(directory)
    
    if not code_files_paths:
        print("\n❌ 분석할 코드 파일을 찾을 수 없습니다.")
        return 1
    
    # 2단계: 파일 분류
    categorized = analyzer.categorize_files(code_files_paths)
    
    # 3단계: Semgrep으로 먼저 전체 분석 (OWASP Top 10 포함)
    print(f"\n🎯 정적 분석 도구 실행 중...")
    semgrep_results = analyzer.run_semgrep_analysis(directory)
    
    # 4단계: Python 파일이 있으면 Bandit으로 추가 분석
    bandit_results = None
    if categorized['python']:
        print(f"\n📝 {len(categorized['python'])}개의 Python 파일 발견")
        bandit_results = analyzer.run_bandit_analysis(directory)
    else:
        print("\n⚠ Python 파일이 없습니다. Bandit 분석을 건너뜁니다.")
    
    # 5단계: 파일 읽기
    print(f"\n📖 파일 읽기 중...")
    code_files = analyzer.read_code_files(code_files_paths)
    
    if not code_files:
        print("\n❌ 읽을 수 있는 파일이 없습니다.")
        return 1
    
    # 6단계: LLM 보안 분석 (Semgrep + Bandit 결과 포함)
    print(f"\n🔍 통합 보안 분석 시작...")
    analysis_result = analyzer.analyze_security_with_tools(code_files, semgrep_results, bandit_results)
    
    if not analysis_result:
        print("\n❌ 분석 실패")
        return 1
    
    # 7단계: 결과 파싱
    parsed_result = analyzer.parse_analysis_result(analysis_result)
    
    # 요약 통계 생성
    vulnerabilities = parsed_result.get('vulnerabilities', [])
    summary = {
        'total_vulnerabilities': len(vulnerabilities),
        'critical': sum(1 for v in vulnerabilities if v.get('severity') == 'Critical'),
        'high': sum(1 for v in vulnerabilities if v.get('severity') == 'High'),
        'medium': sum(1 for v in vulnerabilities if v.get('severity') == 'Medium'),
        'low': sum(1 for v in vulnerabilities if v.get('severity') == 'Low'),
        'semgrep_issues': sum(1 for v in vulnerabilities if v.get('source') == 'Semgrep'),
        'bandit_issues': sum(1 for v in vulnerabilities if v.get('source') == 'Bandit'),
        'llm_found_issues': sum(1 for v in vulnerabilities if v.get('source') == 'LLM Analysis'),
    }
    
    # 전체 평가 생성
    project_name = Path(directory).name
    overall_assessment = f"""
프로젝트 '{project_name}'에 대한 통합 보안 분석이 완료되었습니다.

【분석된 파일】
- 전체 파일: {len(code_files)}개
- 프론트엔드: {len(categorized['frontend'])}개
- 백엔드: {len(categorized['backend'])}개
- Python: {len(categorized['python'])}개
- 설정 파일: {len(categorized['config'])}개

【분석 방법】
1. Semgrep 정적 분석 (OWASP Top 10): {len(semgrep_results.get('results', [])) if semgrep_results else 0}개 이슈 발견
2. Bandit 정적 분석 (Python): {len(bandit_results.get('results', [])) if bandit_results else 0}개 이슈 발견
3. Claude AI 분석: 추가 취약점 탐지

【발견된 취약점】
- 총 {len(vulnerabilities)}개의 보안 취약점 발견
- Critical: {summary['critical']}개
- High: {summary['high']}개
- Medium: {summary['medium']}개
- Low: {summary['low']}개

심각도가 높은 취약점부터 우선적으로 수정하시기 바랍니다.
"""
    
    # 분석 데이터 구성
    analysis_data = {
        'vulnerabilities': vulnerabilities,
        'summary': summary,
        'overall_assessment': overall_assessment,
        'project_info': {
            'name': project_name,
            'path': directory,
            'total_files': len(code_files),
            'frontend_files': len(categorized['frontend']),
            'backend_files': len(categorized['backend']),
            'python_files': len(categorized['python']),
            'config_files': len(categorized['config'])
        }
    }
    
    # 8단계: HTML 보고서 생성
    print(f"\n📄 HTML 보고서 생성 중...")
    analyzer.generate_html_report(analysis_data, semgrep_results, bandit_results, output_file)
    
    print("\n" + "=" * 70)
    print("✅ 분석 완료!")
    print(f"📊 총 {summary['total_vulnerabilities']}개의 취약점 발견")
    print(f"   【정적 분석 도구】")
    print(f"   - Semgrep: {summary['semgrep_issues']}개")
    print(f"   - Bandit: {summary['bandit_issues']}개")
    print(f"   【LLM 추가 발견】")
    print(f"   - LLM Analysis: {summary['llm_found_issues']}개")
    print(f"\n   【심각도별】")
    print(f"   - Critical: {summary['critical']}개")
    print(f"   - High: {summary['high']}개")
    print(f"   - Medium: {summary['medium']}개")
    print(f"   - Low: {summary['low']}개")
    print(f"\n📁 보고서: {output_file}")
    print("=" * 70)
    
    return 0


if __name__ == "__main__":
    exit(main())

