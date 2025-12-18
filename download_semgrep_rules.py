"""
Semgrep 규칙을 GitHub에서 다운로드하는 스크립트
"""
import os
import subprocess
import sys
from pathlib import Path

def download_semgrep_rules():
    """
    Semgrep 공식 규칙 레포지토리를 다운로드
    """
    rules_dir = Path("semgrep-rules")
    
    print("🔍 Semgrep 규칙 다운로드 중...")
    print(f"📁 대상 디렉토리: {rules_dir.absolute()}")
    
    # 이미 규칙이 있으면 업데이트
    if rules_dir.exists():
        print("  ℹ️ 기존 규칙 발견 - 업데이트 중...")
        try:
            result = subprocess.run(
                ["git", "-C", str(rules_dir), "pull"],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                print("  ✓ 규칙 업데이트 완료!")
                return True
            else:
                print(f"  ⚠ 업데이트 실패: {result.stderr}")
                print("  ℹ️ 기존 규칙 삭제 후 재다운로드합니다...")
                import shutil
                shutil.rmtree(rules_dir)
        except FileNotFoundError:
            print("  ⚠ Git이 설치되어 있지 않습니다.")
            print("  💡 Git 설치 후 다시 시도하거나, 수동으로 다운로드하세요:")
            print("     https://github.com/returntocorp/semgrep-rules")
            return False
        except Exception as e:
            print(f"  ✗ 오류: {e}")
            return False
    
    # 새로 다운로드
    print("  📥 Semgrep 규칙 레포지토리 클론 중... (약 1~3분 소요)")
    try:
        result = subprocess.run(
            [
                "git", "clone",
                "--depth", "1",  # 최신 버전만 다운로드 (속도 향상)
                "https://github.com/returntocorp/semgrep-rules.git",
                str(rules_dir)
            ],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode == 0:
            print("  ✓ 규칙 다운로드 완료!")
            
            # 다운로드된 규칙 개수 확인
            yaml_files = list(rules_dir.rglob("*.yaml")) + list(rules_dir.rglob("*.yml"))
            print(f"  📊 다운로드된 규칙 파일: {len(yaml_files)}개")
            
            return True
        else:
            print(f"  ✗ 다운로드 실패: {result.stderr}")
            return False
            
    except FileNotFoundError:
        print("  ✗ Git이 설치되어 있지 않습니다!")
        print("  💡 해결 방법:")
        print("     1. Git 설치: https://git-scm.com/download/win")
        print("     2. 또는 수동 다운로드:")
        print("        https://github.com/returntocorp/semgrep-rules/archive/refs/heads/develop.zip")
        print("        압축 해제 후 'semgrep-rules' 폴더로 이름 변경")
        return False
    except subprocess.TimeoutExpired:
        print("  ✗ 다운로드 타임아웃 (네트워크 문제)")
        return False
    except Exception as e:
        print(f"  ✗ 예상치 못한 오류: {e}")
        return False

def get_recommended_rule_paths():
    """
    추천 규칙 경로 반환
    """
    rules_dir = Path("semgrep-rules")
    
    if not rules_dir.exists():
        return []
    
    recommended = []
    
    # OWASP Top 10 관련
    owasp_paths = [
        "python/django/security",
        "python/flask/security",
        "python/lang/security",
        "javascript/express/security",
        "javascript/react/security",
        "generic/secrets",
    ]
    
    for path in owasp_paths:
        full_path = rules_dir / path
        if full_path.exists():
            recommended.append(str(full_path))
    
    return recommended

if __name__ == "__main__":
    success = download_semgrep_rules()
    
    if success:
        print("\n✅ 규칙 다운로드 성공!")
        print("\n📁 다운로드된 주요 규칙 폴더:")
        
        rules_dir = Path("semgrep-rules")
        important_dirs = [
            "python/django/security",
            "python/flask/security", 
            "python/lang/security",
            "javascript/express/security",
            "javascript/react/security",
            "generic/secrets",
        ]
        
        for dir_path in important_dirs:
            full_path = rules_dir / dir_path
            if full_path.exists():
                yaml_count = len(list(full_path.glob("*.yaml"))) + len(list(full_path.glob("*.yml")))
                print(f"  ✓ {dir_path} ({yaml_count}개 규칙)")
        
        print("\n🚀 이제 main.py를 실행하세요!")
        sys.exit(0)
    else:
        print("\n❌ 규칙 다운로드 실패")
        print("💡 수동 다운로드 방법:")
        print("   1. https://github.com/returntocorp/semgrep-rules/archive/refs/heads/develop.zip")
        print("   2. 압축 해제")
        print("   3. 'semgrep-rules' 폴더로 이름 변경")
        sys.exit(1)


