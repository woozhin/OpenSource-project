"""
파일 권한 및 Race Condition 취약점 예시
Bandit이 감지할 수 있는 취약점
"""
import os
import tempfile
import shutil

# ❌ 취약점 1: 과도하게 개방된 파일 권한 (777)
def create_world_writable_file(filename):
    """누구나 읽고 쓸 수 있는 파일"""
    with open(filename, 'w') as f:
        f.write("sensitive data")
    os.chmod(filename, 0o777)  # Bandit: B103

# ❌ 취약점 2: 과도하게 개방된 디렉토리 권한
def create_public_directory(dirname):
    """모든 권한 개방"""
    os.mkdir(dirname)
    os.chmod(dirname, 0o777)  # Bandit: B103

# ❌ 취약점 3: 안전하지 않은 임시 파일 생성
def unsafe_temp_file():
    """예측 가능한 임시 파일명"""
    temp_file = "/tmp/myapp_temp_file.txt"  # Bandit: B108
    with open(temp_file, 'w') as f:
        f.write("sensitive data")
    return temp_file

# ❌ 취약점 4: mktemp() 사용 (Race Condition)
def use_mktemp():
    """파일 생성과 사용 사이에 Race Condition"""
    temp_filename = tempfile.mktemp()  # Bandit: B306
    with open(temp_filename, 'w') as f:
        f.write("data")
    return temp_filename

# ❌ 취약점 5: 심볼릭 링크 공격 취약
def unsafe_file_write(filename):
    """TOCTOU (Time-of-Check-Time-of-Use) 취약"""
    # 체크
    if not os.path.exists(filename):
        # 사용 (이 사이에 공격자가 심볼릭 링크 생성 가능)
        with open(filename, 'w') as f:
            f.write("important data")

# ❌ 취약점 6: /tmp 디렉토리 직접 사용
def write_to_tmp():
    """공유 디렉토리 사용"""
    filepath = "/tmp/user_data.txt"
    with open(filepath, 'w') as f:
        f.write("user credentials")

# ❌ 취약점 7: 파일 삭제 전 권한 확인 없음
def unsafe_delete(filepath):
    """권한 확인 없이 삭제"""
    os.remove(filepath)

# ❌ 취약점 8: 하드링크 공격 취약
def unsafe_copy(src, dst):
    """파일 복사 시 검증 없음"""
    shutil.copy(src, dst)
    os.chmod(dst, 0o666)  # Bandit: B103

# ❌ 취약점 9: 예측 가능한 파일명
import time
def create_backup():
    """타임스탬프로 파일명 생성"""
    timestamp = int(time.time())
    backup_file = f"/tmp/backup_{timestamp}.db"
    # 공격자가 파일명 예측 가능
    return backup_file

# ❌ 취약점 10: 민감한 파일을 전체 읽기 권한으로 생성
def save_private_key(key_data):
    """개인키 파일 권한 문제"""
    key_file = "/home/user/.ssh/id_rsa"
    with open(key_file, 'w') as f:
        f.write(key_data)
    # 권한 설정 없음 - 기본 umask로 생성됨

# ❌ 취약점 11: Race Condition - 파일 존재 확인 후 생성
def create_lock_file(lockfile):
    """TOCTOU 취약점"""
    if not os.path.exists(lockfile):
        # 이 사이에 다른 프로세스가 파일 생성 가능
        with open(lockfile, 'w') as f:
            f.write(str(os.getpid()))

# ❌ 취약점 12: 안전하지 않은 파일 이동
def unsafe_move(old_path, new_path):
    """심볼릭 링크 검증 없음"""
    os.rename(old_path, new_path)

# ❌ 취약점 13: umask 설정 없이 민감한 파일 생성
def create_config_file():
    """기본 파일 권한으로 생성"""
    with open('config.ini', 'w') as f:
        f.write("[database]\n")
        f.write("password=secret123\n")
    # 다른 사용자가 읽을 수 있음!

# ❌ 취약점 14: 디렉토리 순회 취약점
def list_user_files(user_dir):
    """입력 검증 없이 디렉토리 접근"""
    files = []
    for root, dirs, filenames in os.walk(user_dir):
        files.extend(filenames)
    return files

# ❌ 취약점 15: 안전하지 않은 파일 압축 해제
import zipfile
def unsafe_extract_zip(zip_path, extract_to):
    """Path Traversal 취약"""
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        # ../../../etc/passwd 같은 경로 가능
        zip_ref.extractall(extract_to)

# ✅ 안전한 방법 (비교용)
def safe_temp_file():
    """✅ 안전한 임시 파일 생성"""
    # NamedTemporaryFile은 안전하게 생성됨
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("sensitive data")
        return f.name

def safe_create_file(filename):
    """✅ 안전한 파일 생성"""
    # 먼저 안전한 권한 설정
    fd = os.open(filename, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write("sensitive data")

def safe_create_private_key(key_data):
    """✅ 개인키 안전하게 저장"""
    key_file = os.path.expanduser("~/.ssh/id_rsa")
    # 먼저 파일 생성 시 권한 설정
    fd = os.open(key_file, os.O_CREAT | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(key_data)

def safe_extract_zip(zip_path, extract_to):
    """✅ 안전한 압축 해제"""
    import os.path
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for member in zip_ref.namelist():
            # Path Traversal 방지
            member_path = os.path.join(extract_to, member)
            if not member_path.startswith(os.path.abspath(extract_to)):
                raise Exception("Path Traversal detected")
            zip_ref.extract(member, extract_to)

def safe_atomic_write(filename, data):
    """✅ Atomic 파일 쓰기"""
    # 임시 파일에 먼저 쓰고 rename으로 atomic 하게 교체
    temp_fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(filename))
    try:
        with os.fdopen(temp_fd, 'w') as f:
            f.write(data)
        os.chmod(temp_path, 0o600)
        os.rename(temp_path, filename)
    except:
        os.unlink(temp_path)
        raise

if __name__ == "__main__":
    # 위험한 예시
    create_world_writable_file("/tmp/test.txt")
    print("Created insecure file with 777 permissions")


