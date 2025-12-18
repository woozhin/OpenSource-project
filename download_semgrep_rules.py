"""
Semgrep 규칙을 GitHub에서 다운로드하는 스크립트
"""
import os
import subprocess
import sys
import shutil
import stat
from pathlib import Path

def remove_readonly(func, path, excinfo):
    """
    Windows에서 읽기 전용 파일 삭제를 위한 오류 핸들러
    """
    os.chmod(path, stat.S_IWRITE)
    func(path)

def safe_rmtree(path):
    """
    Windows 호환 폴더 삭제 (읽기 전용 파일 포함)
    """
    try:
        shutil.rmtree(path, onerror=remove_readonly)
    except Exception as e:
        print(f"  ⚠️ 폴더 삭제 중 오류: {e}")
        print(f"  💡 수동으로 삭제해주세요: {path}")
        return False
    return True

def download_semgrep_rules():
    """
    Semgrep 공식 규칙 레포지토리를 다운로드
    """
    rules_dir = Path("semgrep-rules")
    
    print("🔍 Semgrep 규칙 다운로드 중...")
    print(f"📁 대상 디렉토리: {rules_dir.absolute()}")
    
    # 이미 규칙이 있으면 검증 후 업데이트
    if rules_dir.exists():
        print("  ℹ️ 기존 규칙 발견 - 검증 중...")
        
        # 먼저 규칙 파일 개수 확인
        yaml_files = list(rules_dir.rglob("*.yaml")) + list(rules_dir.rglob("*.yml"))
        print(f"  📊 현재 규칙 파일: {len(yaml_files)}개")
        
        # 규칙이 너무 적으면 폴더 삭제하고 재다운로드
        if len(yaml_files) < 100:
            print("  ⚠️ 규칙이 너무 적습니다 (정상: 2000개 이상)")
            print("  ℹ️ 기존 폴더를 삭제하고 재다운로드합니다...")
            if not safe_rmtree(rules_dir):
                return False
        else:
            # 규칙이 충분하면 업데이트 시도
            print("  ✓ 규칙이 충분합니다. 업데이트 중...")
            try:
                result = subprocess.run(
                    ["git", "-C", str(rules_dir), "pull"],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                if result.returncode == 0:
                    # 업데이트 후 다시 개수 확인
                    yaml_files = list(rules_dir.rglob("*.yaml")) + list(rules_dir.rglob("*.yml"))
                    print(f"  ✓ 규칙 업데이트 완료! (총 {len(yaml_files)}개)")
                    return True
                else:
                    print(f"  ⚠ 업데이트 실패: {result.stderr}")
                    print("  ℹ️ 기존 규칙 삭제 후 재다운로드합니다...")
                    if not safe_rmtree(rules_dir):
                        return False
            except FileNotFoundError:
                print("  ⚠ Git이 설치되어 있지 않습니다.")
                print("  💡 Git 설치 후 다시 시도하거나, 수동으로 다운로드하세요:")
                print("     https://github.com/returntocorp/semgrep-rules")
                return False
            except Exception as e:
                print(f"  ✗ 오류: {e}")
                print("  ℹ️ 기존 규칙 삭제 후 재다운로드합니다...")
                if not safe_rmtree(rules_dir):
                    return False
                # 재다운로드를 위해 계속 진행
    
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
        
        found_rules = 0
        for dir_path in important_dirs:
            full_path = rules_dir / dir_path
            if full_path.exists():
                yaml_count = len(list(full_path.glob("*.yaml"))) + len(list(full_path.glob("*.yml")))
                if yaml_count > 0:
                    print(f"  ✓ {dir_path} ({yaml_count}개 규칙)")
                    found_rules += yaml_count
                else:
                    print(f"  ⚠ {dir_path} (규칙 없음)")
            else:
                print(f"  ✗ {dir_path} (폴더 없음)")
        
        # 전체 규칙 개수 확인
        all_yaml_files = list(rules_dir.rglob("*.yaml")) + list(rules_dir.rglob("*.yml"))
        print(f"\n📊 전체 규칙 파일: {len(all_yaml_files)}개")
        
        if len(all_yaml_files) < 100:
            print("\n⚠️ 경고: 규칙 파일이 너무 적습니다!")
            print("💡 다시 다운로드하려면:")
            print("   1. semgrep-rules 폴더 삭제")
            print("   2. python download_semgrep_rules.py 재실행")
        else:
            print("\n🚀 이제 main.py를 실행하세요!")
        
        sys.exit(0)
    else:
        print("\n❌ 규칙 다운로드 실패")
        print("💡 수동 다운로드 방법:")
        print("   1. https://github.com/returntocorp/semgrep-rules/archive/refs/heads/develop.zip")
        print("   2. 압축 해제")
        print("   3. 'semgrep-rules' 폴더로 이름 변경")
        sys.exit(1)


