import os
import hashlib
import json
import time
import random
import string
import sys
import getpass

# 配置
APP_FILES_DIR = './Unit2/app'  # 关键文件目录
ROOT_HASH_FILE = './Unit2/root_hash.txt'  # 存储根哈希和盐值的文件
CHECK_INTERVAL = 10  # 实时校验的时间间隔（秒）
SENSITIVE_PASSWORD = 'securepassword'  # 敏感操作的密码（在实际应用中应安全存储）

def generate_salt(length=16):
    """生成随机盐值"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def hash_file(filepath):
    """计算文件的SHA-256哈希值"""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            data = f.read(65536)  # 64KB
            if not data:
                break
            sha256.update(data)
    return sha256.hexdigest()

def build_hash_tree(files_hashes):
    """构建哈希树并返回根哈希"""
    hashes = list(files_hashes.values())
    while len(hashes) > 1:
        temp_hashes = []
        for i in range(0, len(hashes), 2):
            if i + 1 < len(hashes):
                combined = hashes[i] + hashes[i+1]
            else:
                combined = hashes[i] + hashes[i]
            temp_hash = hashlib.sha256(combined.encode()).hexdigest()
            temp_hashes.append(temp_hash)
        hashes = temp_hashes
    return hashes[0] if hashes else None

def generate_root_hash():
    """生成根哈希并存储盐值"""
    if not os.path.exists(APP_FILES_DIR):
        print(f"关键文件目录 '{APP_FILES_DIR}' 不存在。")
        sys.exit(1)
    
    # 读取所有关键文件并计算哈希
    files_hashes = {}
    for root, dirs, files in os.walk(APP_FILES_DIR):
        for file in files:
            filepath = os.path.join(root, file)
            relative_path = os.path.relpath(filepath, APP_FILES_DIR)
            files_hashes[relative_path] = hash_file(filepath)
    
    # 构建哈希树
    hash_tree_root = build_hash_tree(files_hashes)
    if not hash_tree_root:
        print("未找到任何文件来生成哈希树。")
        sys.exit(1)
    
    # 生成盐值并计算最终根哈希
    salt = generate_salt()
    final_root_hash = hashlib.sha256((hash_tree_root + salt).encode()).hexdigest()
    
    # 存储根哈希和盐值
    with open(ROOT_HASH_FILE, 'w') as f:
        json.dump({'root_hash': final_root_hash, 'salt': salt}, f)
    
    print(f"根哈希已生成并存储在 '{ROOT_HASH_FILE}'。")
    print(f"根哈希: {final_root_hash}")
    print(f"盐值: {salt}")

def load_root_hash():
    """加载存储的根哈希和盐值"""
    if not os.path.exists(ROOT_HASH_FILE):
        print(f"根哈希文件 '{ROOT_HASH_FILE}' 不存在。请先生成根哈希。")
        sys.exit(1)
    
    with open(ROOT_HASH_FILE, 'r') as f:
        data = json.load(f)
    return data['root_hash'], data['salt']

def verify_integrity(root_hash, salt):
    """验证当前文件的完整性是否与存储的根哈希一致"""
    files_hashes = {}
    for root, dirs, files in os.walk(APP_FILES_DIR):
        for file in files:
            filepath = os.path.join(root, file)
            relative_path = os.path.relpath(filepath, APP_FILES_DIR)
            if not os.path.exists(filepath):
                print(f"文件缺失: {relative_path}")
                return False
            files_hashes[relative_path] = hash_file(filepath)
    
    current_hash_tree_root = build_hash_tree(files_hashes)
    if not current_hash_tree_root:
        print("未找到任何文件来验证哈希树。")
        return False
    
    current_final_root_hash = hashlib.sha256((current_hash_tree_root + salt).encode()).hexdigest()
    return current_final_root_hash == root_hash

def monitor_integrity(root_hash, salt):
    """实时监控文件完整性"""
    print("开始实时完整性监控...")
    try:
        while True:
            if verify_integrity(root_hash, salt):
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 完整性校验通过。")
            else:
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 完整性校验失败！文件可能被篡改。采取安全措施。")
                # 采取响应措施，例如退出程序
                sys.exit(1)
            time.sleep(CHECK_INTERVAL)
    except KeyboardInterrupt:
        print("完整性监控已停止。")

def simulate_tampering(file_relative_path, new_content):
    """模拟文件篡改"""
    target_file = os.path.join(APP_FILES_DIR, file_relative_path)
    if not os.path.exists(target_file):
        print(f"目标文件 '{file_relative_path}' 不存在，无法篡改。")
        return
    with open(target_file, 'w') as f:
        f.write(new_content)
    print(f"文件 '{file_relative_path}' 已被篡改。")

def perform_sensitive_operation(root_hash, salt):
    """执行敏感操作前进行完整性校验和密码验证"""
    print("准备执行敏感操作，正在进行完整性校验...")
    if not verify_integrity(root_hash, salt):
        print("完整性校验失败！文件可能被篡改。采取安全措施。")
        # 采取响应措施，例如报警、退出程序等
        sys.exit(1)
    print("完整性校验通过。")
    
    # 完整性校验通过后，提示用户输入密码
    print("请输入密码以执行敏感操作。")
    password = getpass.getpass("密码：")
    
    if password != SENSITIVE_PASSWORD:
        print("密码错误！拒绝执行敏感操作。")
        # 可以选择记录日志、报警等
        return
    
    print("密码正确，执行敏感操作。")
    # 模拟敏感操作
    print("敏感操作已成功执行。")

def main():
    print("完整性校验模拟脚本")
    print("1. 生成根哈希")
    print("2. 监控完整性")
    print("3. 模拟篡改")
    print("4. 执行敏感操作")
    print("5. 退出")
    
    while True:
        choice = input("请选择操作（1-5）：")
        if choice == '1':
            generate_root_hash()
        elif choice == '2':
            root_hash, salt = load_root_hash()
            monitor_integrity(root_hash, salt)
        elif choice == '3':
            file_path = input("请输入要篡改的文件相对路径（相对于 'app_files/'）：")
            new_content = input("请输入新的文件内容：")
            simulate_tampering(file_path, new_content)
        elif choice == '4':
            root_hash, salt = load_root_hash()
            perform_sensitive_operation(root_hash, salt)
        elif choice == '5':
            print("退出程序。")
            break
        else:
            print("无效的选择，请重新输入。")

if __name__ == "__main__":
    main()
