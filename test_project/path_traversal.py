"""
Path Traversal 및 Insecure Deserialization 취약점 예시
"""
import pickle
import yaml
import os
import json

def unsafe_file_read(filename):
    """❌ Path Traversal 취약 - 경로 검증 없음"""
    # 취약점 1: 사용자 입력으로 파일 경로 생성
    filepath = f"/var/www/uploads/{filename}"
    with open(filepath, 'r') as f:
        return f.read()

def unsafe_file_download(user_id, filename):
    """❌ Path Traversal 취약"""
    # 취약점 2: 문자열 연결로 경로 생성
    base_path = "/home/users/"
    file_path = base_path + user_id + "/" + filename
    
    if os.path.exists(file_path):
        with open(file_path, 'rb') as f:
            return f.read()
    return None

def unsafe_deserialize_pickle(data):
    """❌ Insecure Deserialization - pickle"""
    # 취약점 3: pickle.loads는 임의 코드 실행 가능
    obj = pickle.loads(data)  # Bandit: B301
    return obj

def unsafe_yaml_load(yaml_string):
    """❌ Insecure Deserialization - yaml"""
    # 취약점 4: yaml.load는 임의 코드 실행 가능
    data = yaml.load(yaml_string)  # Bandit: B506
    return data

def unsafe_eval_json(user_input):
    """❌ Arbitrary Code Execution - eval"""
    # 취약점 5: eval 사용
    result = eval(user_input)  # Bandit: B307
    return result

def unsafe_exec_code(code_string):
    """❌ Arbitrary Code Execution - exec"""
    # 취약점 6: exec 사용
    exec(code_string)  # Bandit: B102

def unsafe_file_open(filename):
    """❌ Path Traversal - open"""
    # 취약점 7: 직접 open 사용
    with open(filename, 'r') as f:
        return f.read()

def unsafe_compile(expression):
    """❌ Code Injection - compile"""
    # 취약점 8: compile 사용
    code = compile(expression, '<string>', 'eval')  # Bandit: B307
    return eval(code)

# ✅ 안전한 방법 (비교용)
def safe_file_read(filename):
    """✅ 경로 검증 및 정규화"""
    import os.path
    
    # 안전: 경로 정규화 및 검증
    base_dir = "/var/www/uploads/"
    filepath = os.path.join(base_dir, filename)
    filepath = os.path.normpath(filepath)
    
    # 베이스 디렉토리 벗어나는지 확인
    if not filepath.startswith(base_dir):
        raise ValueError("Path traversal detected")
    
    with open(filepath, 'r') as f:
        return f.read()

def safe_deserialize_json(json_string):
    """✅ JSON 사용 (안전)"""
    # 안전: JSON은 데이터만 역직렬화
    data = json.loads(json_string)
    return data

def safe_yaml_load(yaml_string):
    """✅ yaml.safe_load 사용"""
    # 안전: yaml.safe_load는 안전한 데이터만 로드
    data = yaml.safe_load(yaml_string)
    return data

if __name__ == "__main__":
    # 공격 예시
    malicious_path = "../../etc/passwd"
    unsafe_file_read(malicious_path)
    
    # Pickle 공격 예시
    import pickle
    import os
    
    class MaliciousClass:
        def __reduce__(self):
            return (os.system, ('ls -la',))
    
    dangerous_pickle = pickle.dumps(MaliciousClass())
    # unsafe_deserialize_pickle(dangerous_pickle)  # 실행하면 위험!


