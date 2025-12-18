"""
Command Injection 취약점 예시
Semgrep과 Bandit이 모두 감지할 수 있는 취약점
"""
import os
import subprocess
import platform

def unsafe_ping(host):
    """❌ Command Injection 취약 - os.system 사용"""
    # 취약점 1: os.system with user input
    command = f"ping -c 4 {host}"
    os.system(command)  # Bandit: B605, B607

def unsafe_backup(filename):
    """❌ Command Injection 취약 - shell=True"""
    # 취약점 2: subprocess with shell=True
    command = f"tar -czf backup.tar.gz {filename}"
    subprocess.call(command, shell=True)  # Bandit: B602, B607

def unsafe_file_viewer(filepath):
    """❌ Command Injection 취약 - popen"""
    # 취약점 3: os.popen with user input
    cmd = f"cat {filepath}"
    result = os.popen(cmd).read()  # Bandit: B605
    return result

def unsafe_dns_lookup(domain):
    """❌ Command Injection 취약 - subprocess.Popen"""
    # 취약점 4: subprocess.Popen with shell=True
    cmd = f"nslookup {domain}"
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    output, _ = process.communicate()
    return output.decode()

def unsafe_compress(directory):
    """❌ Command Injection 취약 - os.popen"""
    # 취약점 5: 여러 명령어 실행 가능
    os.popen(f"cd {directory} && ls -la")

def unsafe_kill_process(pid):
    """❌ Command Injection 취약"""
    # 취약점 6: 문자열 연결
    os.system("kill -9 " + pid)

def unsafe_network_scan(ip_range):
    """❌ Command Injection 취약"""
    # 취약점 7: 복잡한 명령어
    command = f"nmap -sP {ip_range} | grep 'Host is up'"
    subprocess.run(command, shell=True, capture_output=True)

# ✅ 안전한 방법 (비교용)
def safe_ping(host):
    """✅ shell=False 사용 및 입력 검증"""
    # 입력 검증
    if not host.replace('.', '').replace('-', '').isalnum():
        raise ValueError("Invalid host")
    
    # 안전: 리스트 형태 + shell=False
    if platform.system() == "Windows":
        command = ["ping", "-n", "4", host]
    else:
        command = ["ping", "-c", "4", host]
    
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout

def safe_file_list(directory):
    """✅ os.listdir 사용"""
    # 안전: 직접 파일시스템 API 사용
    import os
    return os.listdir(directory)

if __name__ == "__main__":
    # 공격 예시
    malicious_host = "google.com; cat /etc/passwd"
    unsafe_ping(malicious_host)
    
    malicious_file = "test.txt; rm -rf /"
    unsafe_backup(malicious_file)


