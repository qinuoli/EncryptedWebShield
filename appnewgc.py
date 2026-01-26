from flask import Flask, request, render_template_string, redirect, url_for, send_file, session
import os
import time
import sys
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import io

# ========== 路径配置 ==========
# config.py路径
sys.path.append('./')
# de.py和en.py路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
# de.py的DATA_DIR
DATA_DIR = "./data"

# 新增：私钥保存目录
PRIVATE_KEY_DIR = "saved_private_keys"
if not os.path.exists(PRIVATE_KEY_DIR):
    os.makedirs(PRIVATE_KEY_DIR)

try:
    import config
    from en import DBE_Encryptor
    # 导入de.py的核心函数
    from de import decrypt, load_hdr, load_original_K, safe_gt, reconstruct_private_key
except ImportError as e:
    raise ImportError(f"""
    ❌ 导入失败：{e}
    请确保：
    1. config.py已生成
    2. de.py/en.py与app.py在同一目录
    3. DATA_DIR路径正确：{DATA_DIR}
    """)

# 创建Flask应用
app = Flask(__name__)
# 配置session密钥（用于记录已保存的私钥信息）
app.secret_key = get_random_bytes(16).hex()

# 配置：文章保存的文件夹
ARTICLE_FOLDER = "articles"
if not os.path.exists(ARTICLE_FOLDER):
    os.makedirs(ARTICLE_FOLDER)

# ---------------------- 核心工具函数 ----------------------
def generate_dbe_key_and_hdr(revoked_users=[1,4]):
    """调用en.py生成K和Hdr（固定总用户数6）"""
    try:
        encryptor = DBE_Encryptor(total_users=6)
        encryptor.set_revoked_users(revoked_users)
        Hdr, K = encryptor.encrypt()
        
        # 序列化
        C1, C2 = Hdr
        serialized_C1 = encryptor.group.serialize(C1).decode('utf-8')
        serialized_C2 = encryptor.group.serialize(C2).decode('utf-8')
        serialized_K = encryptor.group.serialize(K).decode('utf-8')
        
        # AES密钥转换
        aes_key = serialized_K.encode('utf-8')[:32]
        if len(aes_key) < 32:
            aes_key = aes_key.ljust(32, b'\0')
        
        # 保存
        encryptor.save_encryption_results(Hdr, K)
        encryptor.save_separate_files(Hdr, K)
        
        return {
            "aes_key": aes_key,
            "serialized_K": serialized_K,
            "serialized_Hdr": {"C1": serialized_C1, "C2": serialized_C2},
            "status": "success"
        }
    except Exception as e:
        return {
            "aes_key": b'',
            "serialized_K": "",
            "serialized_Hdr": {"C1":"", "C2":""},
            "status": f"生成K/Hdr失败：{str(e)}"
        }

def encrypt_text_with_dbe_k(plaintext: str, aes_key: bytes):
    """AES加密"""
    if not plaintext:
        return "", "", "明文内容为空"
    if len(aes_key) != 32:
        return "", "", f"AES密钥长度异常（需32字节，实际{len(aes_key)}字节）"
    
    try:
        cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        encrypted_data = cipher.nonce + tag + ciphertext
        encrypted_hex = encrypted_data.hex()
        return encrypted_hex, cipher.nonce.hex(), "加密成功"
    except Exception as e:
        return "", "", f"AES加密失败：{str(e)}"

def decrypt_text_with_recovered_k(encrypted_hex: str, nonce_hex: str, recovered_K_serialized: str):
    """使用de.py恢复的K解密明文"""
    if not encrypted_hex or not nonce_hex or not recovered_K_serialized:
        return "", "密文/Nonce/恢复的K为空"
    
    # 转换为AES密钥
    aes_key = recovered_K_serialized.encode('utf-8')[:32]
    if len(aes_key) < 32:
        aes_key = aes_key.ljust(32, b'\0')
    
    try:
        encrypted_data = bytes.fromhex(encrypted_hex)
        nonce = bytes.fromhex(nonce_hex)
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8'), "解密成功"
    except ValueError as e:
        return "", f"解密失败（数据篡改或密钥错误）：{str(e)}"
    except Exception as e:
        return "", f"解密异常：{str(e)}"

# ---------------------- 私钥保存/读取函数 ----------------------
def save_private_key(private_key_file, revoked_set):
    """
    保存上传的私钥文件到本地，并记录撤销集合（仅保存，不解密）
    :param private_key_file: 上传的私钥文件对象
    :param revoked_set: 撤销用户集合
    :return: 保存的文件名、保存状态
    """
    try:
        # 生成安全的文件名（用户ID+时间戳）
        filename = private_key_file.filename
        user_id = None
        if "user_" in filename and "_private_key.json" in filename:
            user_id = int(filename.split("user_")[1].split("_private_key.json")[0])
        timestamp = str(int(time.time()))
        save_filename = f"saved_key_{user_id or 'unknown'}_{timestamp}.json"
        save_path = os.path.join(PRIVATE_KEY_DIR, save_filename)
        
        # 保存私钥文件
        private_key_file.seek(0)
        with open(save_path, 'wb') as f:
            f.write(private_key_file.read())
        
        # 保存撤销集合配置
        config_filename = f"key_config_{user_id or 'unknown'}_{timestamp}.json"
        config_path = os.path.join(PRIVATE_KEY_DIR, config_filename)
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump({
                "revoked_set": list(revoked_set),
                "save_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                "user_id": user_id,
                "key_filename": save_filename
            }, f, ensure_ascii=False, indent=4)
        
        # 更新session记录当前激活的私钥（仅保存，不标记解密状态）
        session['active_private_key'] = {
            "key_path": save_path,
            "config_path": config_path,
            "user_id": user_id,
            "revoked_set": list(revoked_set),
            "decrypt_triggered": False  # 新增：标记是否触发了解密
        }
        
        # 重置表单显示状态为隐藏
        session['show_private_key_form'] = False
        
        return save_filename, f"私钥已保存：{save_filename}，撤销集合：{sorted(revoked_set)}"
    except Exception as e:
        return "", f"私钥保存失败：{str(e)}"

def get_saved_private_key():
    """
    获取首页保存的私钥信息
    :return: 私钥文件路径、配置信息、状态
    """
    active_key = session.get('active_private_key', {})
    if not active_key or not os.path.exists(active_key.get('key_path', '')):
        return None, None, "未找到已保存的私钥，请先在首页上传并保存"
    
    # 读取配置文件
    config_path = active_key.get('config_path')
    if not os.path.exists(config_path):
        return None, None, "私钥配置文件丢失"
    
    with open(config_path, 'r', encoding='utf-8') as f:
        config_data = json.load(f)
    
    return active_key['key_path'], config_data, "获取已保存私钥成功"

# ---------------------- 文章操作函数 ----------------------
def save_article(title, original_text, encrypted_text, nonce, encrypt_status, dbe_result):
    """保存加密文章（含Hdr/K信息）"""
    timestamp = str(int(time.time()))
    safe_title = title.replace(" ", "_").replace("/", "-").replace("\\", "-")
    filename = f"{timestamp}_{safe_title}.txt"
    filepath = os.path.join(ARTICLE_FOLDER, filename)
    
    hdr_str = f"C1: {dbe_result['serialized_Hdr']['C1']}\nC2: {dbe_result['serialized_Hdr']['C2']}"
    k_str = dbe_result['serialized_K']
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"标题：{title}\n")
        f.write(f"原始明文：{original_text}\n")
        f.write(f"AES加密后文本（16进制）：{encrypted_text}\n")
        f.write(f"加密Nonce（16进制）：{nonce}\n")
        f.write(f"加密状态：{encrypt_status}\n")
        f.write(f"DBE_K（序列化）：{k_str}\n")
        f.write(f"DBE_Hdr（序列化）：\n{hdr_str}\n")
        f.write(f"DBE生成状态：{dbe_result['status']}\n")
    return filename

def save_plain_article(title, original_text):
    """保存纯文本文章（不加密）"""
    timestamp = str(int(time.time()))
    safe_title = title.replace(" ", "_").replace("/", "-").replace("\\", "-")
    filename = f"{timestamp}_{safe_title}_plain.txt"  # 标记为纯文本
    filepath = os.path.join(ARTICLE_FOLDER, filename)
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"标题：{title}\n")
        f.write(f"原始明文：{original_text}\n")
        f.write(f"AES加密后文本（16进制）：\n")  # 空值保持格式统一
        f.write(f"加密Nonce（16进制）：\n")
        f.write(f"加密状态：未加密\n")
        f.write(f"DBE_K（序列化）：\n")
        f.write(f"DBE_Hdr（序列化）：\n")
        f.write(f"DBE生成状态：未生成\n")
    return filename

def decrypt_article_content(article_data):
    """
    解密单篇文章内容
    :param article_data: 文章基础数据
    :return: 解密后的内容、解密状态
    """
    # 检查是否触发了解密
    active_key = session.get('active_private_key', {})
    if not active_key.get('decrypt_triggered', False):
        return article_data['encrypted_text'], "未触发解密"
    
    # 如果是非加密文章，直接返回原文
    if article_data['encrypt_status'] == "未加密":
        return article_data['original_text'], "未加密"
    
    # 获取保存的私钥
    key_path, config_data, key_status = get_saved_private_key()
    if not key_path:
        return article_data['encrypted_text'], f"解密失败：{key_status}"
    
    try:
        # 1. 恢复K值
        revoked_set = set(config_data.get('revoked_set', [1,4]))
        recovered_k, decrypt_k_status, decrypt_k_verify = decrypt_with_private_key(
            key_path, revoked_set, article_data['hdr_dict']
        )
        
        if not recovered_k:
            return article_data['encrypted_text'], f"K恢复失败：{decrypt_k_status}"
        
        # 2. 解密明文
        plaintext, decrypt_status = decrypt_text_with_recovered_k(
            article_data['encrypted_text'],
            article_data['nonce'],
            recovered_k
        )
        
        if "成功" in decrypt_status:
            return plaintext, "解密成功"
        else:
            return article_data['encrypted_text'], decrypt_status
    except Exception as e:
        return article_data['encrypted_text'], f"解密异常：{str(e)}"

def get_all_articles(with_auto_decrypt=True):
    """
    获取所有文章（兼容加密/非加密，仅在触发解密后自动解密）
    :param with_auto_decrypt: 是否自动解密加密文章
    :return: 文章列表（含解密状态）
    """
    articles = []
    if os.path.exists(ARTICLE_FOLDER):
        for filename in os.listdir(ARTICLE_FOLDER):
            if filename.endswith(".txt"):
                filepath = os.path.join(ARTICLE_FOLDER, filename)
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read().split("\n")
                
                # 基础信息提取
                title = content[0].replace("标题：", "") if len(content)>=1 else "无标题"
                original_text = content[1].replace("原始明文：", "") if len(content)>=2 else ""
                encrypted_text = content[2].replace("AES加密后文本（16进制）：", "") if len(content)>=3 else ""
                nonce = content[3].replace("加密Nonce（16进制）：", "") if len(content)>=4 else ""
                encrypt_status = content[4].replace("加密状态：", "") if len(content)>=5 else "未知"
                
                # 解析Hdr（用于解密）
                hdr_dict = {}
                hdr_lines = []
                hdr_start = False
                for line in content:
                    if line.startswith("DBE_Hdr（序列化）："):
                        hdr_start = True
                        continue
                    if hdr_start:
                        if line.startswith("C1:") or line.startswith("C2:"):
                            hdr_lines.append(line)
                        else:
                            break
                for line in hdr_lines:
                    if line.startswith("C1:"):
                        hdr_dict["C1"] = line.split(":", 1)[1].strip()
                    elif line.startswith("C2:"):
                        hdr_dict["C2"] = line.split(":", 1)[1].strip()
                
                # 构建文章基础数据
                article_data = {
                    "filename": filename,
                    "title": title,
                    "original_text": original_text,
                    "encrypted_text": encrypted_text,
                    "nonce": nonce,
                    "encrypt_status": encrypt_status,
                    "hdr_dict": hdr_dict,
                    "url": f"/article/{filename}"
                }
                
                # 自动解密逻辑（仅当触发解密且有保存的私钥时）
                display_content = original_text
                decrypt_status = ""
                active_key = session.get('active_private_key', {})
                if with_auto_decrypt and encrypt_status != "未加密" and active_key.get('decrypt_triggered', False):
                    display_content, decrypt_status = decrypt_article_content(article_data)
                elif encrypt_status == "未加密":
                    display_content = original_text
                    decrypt_status = "未加密"
                else:
                    display_content = encrypted_text
                    decrypt_status = "未解密（未触发解密）"
                
                # 最终文章数据
                articles.append({
                    "filename": filename,
                    "title": title,
                    "display_content": display_content,
                    "decrypt_status": decrypt_status,
                    "encrypt_status": encrypt_status,
                    "url": f"/article/{filename}"
                })
    return articles

def read_article(filename):
    """读取文章详情（解析Hdr/K，兼容非加密）"""
    filepath = os.path.join(ARTICLE_FOLDER, filename)
    if not os.path.exists(filepath):
        return None
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read().split("\n")
    
    # 提取基础信息
    title = content[0].replace("标题：", "") if len(content)>=1 else ""
    original_text = content[1].replace("原始明文：", "") if len(content)>=2 else ""
    encrypted_text = content[2].replace("AES加密后文本（16进制）：", "") if len(content)>=3 else ""
    nonce = content[3].replace("加密Nonce（16进制）：", "") if len(content)>=4 else ""
    encrypt_status = content[4].replace("加密状态：", "") if len(content)>=5 else ""
    serialized_K = content[5].replace("DBE_K（序列化）：", "") if len(content)>=6 else ""
    
    # 解析Hdr
    hdr_lines = []
    hdr_start = False
    dbe_status = ""
    for line in content:
        if line.startswith("DBE_Hdr（序列化）："):
            hdr_start = True
            continue
        if hdr_start:
            if line.startswith("C1:") or line.startswith("C2:"):
                hdr_lines.append(line)
            elif line.startswith("DBE生成状态："):
                dbe_status = line.replace("DBE生成状态：", "")
                break
    
    # 重构Hdr字典
    hdr_dict = {}
    for line in hdr_lines:
        if line.startswith("C1:"):
            hdr_dict["C1"] = line.split(":", 1)[1].strip()
        elif line.startswith("C2:"):
            hdr_dict["C2"] = line.split(":", 1)[1].strip()
    
    return {
        "title": title,
        "original_text": original_text,
        "encrypted_text": encrypted_text,
        "nonce": nonce,
        "encrypt_status": encrypt_status,
        "serialized_K": serialized_K,
        "hdr_dict": hdr_dict,
        "dbe_status": dbe_status,
        "filename": filename
    }

def export_all_articles():
    """导出所有文章信息为JSON格式（过滤加密文章的原文和K）"""
    export_data = {
        "export_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "total_articles": 0,
        "articles": []
    }
    
    if os.path.exists(ARTICLE_FOLDER):
        articles = []
        for filename in os.listdir(ARTICLE_FOLDER):
            if filename.endswith(".txt"):
                article = read_article(filename)
                if article:
                    # 构造单篇文章的导出信息（区分加密/非加密）
                    article_info = {
                        "filename": filename,
                        "title": article["title"],
                        "encrypt_status": article["encrypt_status"],
                        "display_content": article["original_text"] if article["encrypt_status"] == "未加密" else article["encrypted_text"],
                        "nonce": article["nonce"],
                        "dbe_Hdr": article["hdr_dict"],
                        "dbe_status": article["dbe_status"]
                    }
                    # 仅非加密文章保留原始明文（加密文章不导出original_text）
                    if article["encrypt_status"] == "未加密":
                        article_info["original_text"] = article["original_text"]
                    # 加密文章不导出dbe_K，非加密文章本身dbe_K为空，无需处理
                    
                    articles.append(article_info)
        
        export_data["total_articles"] = len(articles)
        export_data["articles"] = articles
    
    # 将数据转换为JSON（确保中文正常显示）
    json_data = json.dumps(export_data, ensure_ascii=False, indent=4)
    # 生成字节流（用于下载）
    byte_io = io.BytesIO()
    byte_io.write(json_data.encode('utf-8'))
    byte_io.seek(0)
    
    # 生成带时间戳的文件名
    timestamp = str(int(time.time()))
    filename = f"article_export_{timestamp}.json"
    
    return send_file(
        byte_io,
        as_attachment=True,
        download_name=filename,
        mimetype='application/json; charset=utf-8'
    )

# ---------------------- 解密核心逻辑（集成de.py） ----------------------
def decrypt_with_private_key(private_key_file, revoked_set, article_hdr_dict):
    """
    调用de.py解密恢复K
    :param private_key_file: 上传的私钥JSON文件/本地文件对象
    :param revoked_set: 撤销用户集合（需与加密时一致）
    :param article_hdr_dict: 文章保存的Hdr（C1/C2序列化字符串）
    :return: 恢复的K（序列化字符串）、解密状态、K一致性验证结果
    """
    try:
        # ========== 关键修复：在函数内重新导入PairingGroup ==========
        from charm.toolbox.pairinggroup import PairingGroup, G1, G2, GT, ZR, pair
        
        # 1. 初始化群
        group = PairingGroup('SS512')
        
        # 2. 解析私钥文件（兼容上传文件/本地文件）
        if isinstance(private_key_file, str):  # 本地文件路径
            with open(private_key_file, 'r', encoding='utf-8') as f:
                sk_data = json.load(f)
            # 从文件名提取用户ID
            filename = os.path.basename(private_key_file)
        else:  # 上传的文件对象
            sk_data = json.load(private_key_file)
            filename = private_key_file.filename
        
        user_id = None
        if "user_" in filename and "_private_key.json" in filename:
            user_id = int(filename.split("user_")[1].split("_private_key.json")[0])
        elif "saved_key_" in filename:
            user_id = filename.split("saved_key_")[1].split("_")[0]
            if user_id.isdigit():
                user_id = int(user_id)
        
        if user_id is None:
            return "", "无法从文件名提取用户ID（需符合：user_0_private_key.json）", ""
        
        # 3. 重构私钥
        d0 = group.deserialize(sk_data['d0'].encode('utf-8'))
        d0_ = group.deserialize(sk_data['d0_'].encode('utf-8'))
        d = []
        for s in sk_data['d']:
            if s is None:
                d.append(None)
            else:
                d.append(group.deserialize(s.encode('utf-8')))
        sk = {'d0': d0, 'd0_': d0_, 'd': d}
        
        # 4. 加载文章的Hdr（优先使用文章保存的，而非DATA_DIR）
        C1 = group.deserialize(article_hdr_dict['C1'].encode('utf-8'))
        C2 = group.deserialize(article_hdr_dict['C2'].encode('utf-8'))
        Hdr = (C1, C2)
        
        # 5. 加载原始K（加密时保存的）
        # 复用de.py的load_original_K函数（需确保其内部也有PairingGroup）
        K_original = load_original_K(group)
        
        # 6. 执行de.py的解密逻辑
        prod_d = sk['d0']
        for r in revoked_set:
            if r == user_id or sk['d'][r] is None:
                continue
            prod_d *= sk['d'][r]
        
        # 配对计算恢复K
        num = pair(C1, prod_d)
        den = pair(C2, sk['d0_'])
        K_recovered = num / den
        
        # 7. 序列化恢复的K
        K_recovered_serialized = group.serialize(K_recovered).decode('utf-8')
        
        # 8. 验证K一致性
        is_k_match = K_recovered == K_original
        verify_msg = f"用户{user_id}恢复的K与原始K{'一致' if is_k_match else '不一致'}"
        if user_id in revoked_set:
            verify_msg += f"（用户{user_id}已被撤销，不一致属于正常现象）"
        
        # 9. 保存解密结果（同de.py）
        out_file = f"{DATA_DIR}/K_decrypted_user_{user_id}.txt"
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(f"# 用户 {user_id} 解密结果（来自app.py）\n")
            f.write(f"# 撤销集合: {sorted(revoked_set)}\n")
            f.write(f"K_recovered = {K_recovered_serialized}\n")
        
        status = f"用户{user_id}解密K成功，结果已保存至{out_file}"
        return K_recovered_serialized, status, verify_msg
    
    except Exception as e:
        error_msg = f"解密K失败：{str(e)}"
        return "", error_msg, ""

# ---------------------- 网页路由 ----------------------
@app.route('/', methods=['GET', 'POST'])
def index():
    """首页：上传私钥仅保存，点击显示内容按钮才解密"""
    upload_status = ""  # 清空状态提示
    save_status = ""
    has_saved_key = 'active_private_key' in session  # 是否已保存私钥
    show_form = session.get('show_private_key_form', False)  # 控制表单显示
    
    # 处理“显示内容”按钮点击
    if request.method == 'POST' and 'show_form_btn' in request.form:
        if has_saved_key:
            # 如果已有保存的私钥，触发解密
            session['active_private_key']['decrypt_triggered'] = True
            # 保持表单隐藏状态
            session['show_private_key_form'] = False
        else:
            # 如果没有保存的私钥，显示上传表单
            session['show_private_key_form'] = True
        return redirect(url_for('index'))
    
    # 处理私钥上传和保存请求（仅保存，不解密）
    if request.method == 'POST' and 'private_key_file' in request.files:
        private_key_file = request.files['private_key_file']
        if private_key_file and private_key_file.filename.endswith('.json'):
            # 解析撤销用户集合
            revoked_users_str = request.form.get('revoked_users', '1,4').strip()
            revoked_set = set([int(x.strip()) for x in revoked_users_str.split(',') if x.strip().isdigit()])
            
            # 保存私钥（仅保存，不触发解密）
            save_private_key(private_key_file, revoked_set)
            # 清空状态提示，不显示任何上传成功信息
            upload_status = ""
            # 强制回到只显示"显示内容"按钮的状态
            session['show_private_key_form'] = False
    
    # 获取文章列表（仅在触发解密后才解密）
    articles = get_all_articles(with_auto_decrypt=True)
    
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {max-width: 1000px; margin: 20px auto; padding: 0 20px; font-family: Arial;}
            .form-area {border: 1px solid #ccc; padding: 20px; border-radius: 8px; margin-bottom: 30px;}
            .article-list {border: 1px solid #2196F3; padding: 20px; border-radius: 8px; margin-bottom: 20px; margin-top: 80px;}
            textarea {width: 100%; height: 120px; padding: 10px; margin: 10px 0; box-sizing: border-box;}
            button {padding: 8px 20px; border: none; border-radius: 4px; cursor: pointer; color: white; margin-right: 10px;}
            .submit-btn {background: #2196F3;}
            .plain-btn {background: #4CAF50;}  /* 绿色按钮区分纯文本保存 */
            .export-btn {background: #9C27B0;}  /* 紫色按钮区分导出功能 */
            .article-item {
                margin: 15px 0; 
                padding: 20px; 
                background: #f5f9ff; 
                border-radius: 8px; 
                display: flex; 
                flex-direction: column;  /* 改为纵向布局 */
                gap: 10px;
            }
            .article-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                border-bottom: 1px solid #e0e0e0;
                padding-bottom: 8px;
                margin-bottom: 8px;
            }
            .article-title {
                font-size: 16px;
                font-weight: bold;
            }
            .article-content {
                width: 95%;
                max-height: 200px;  /* 限制高度，避免页面过长 */
                overflow-y: auto;    /* 溢出滚动 */
                padding: 10px;
                border-radius: 4px;
                background: #ffffff;
                word-wrap: break-word;
                white-space: pre-wrap;
                line-height: 1.5;
            }
            .content-plain {color: #333;}  /* 非加密/解密成功内容样式 */
            .content-encrypted {color: #666; font-family: monospace;}  /* 密文样式（等宽字体） */
            .status-success {color: #4CAF50; font-weight: bold;}
            .status-error {color: #f44336; font-weight: bold;}
            .status-plain {color: #FF9800; font-weight: bold;}  /* 橙色标记未加密 */
            .status-decrypted {color: #1976D2; font-weight: bold;} /* 蓝色标记已解密 */
            .dbe-config {margin: 10px 0; padding: 10px; background: #f0f8ff; border-radius: 4px;}
            .btn-group {margin-top: 15px;}
            .export-group {margin: 20px 0; text-align: right;}
            
            /* 新增：右上角私钥上传样式 */
            .private-key-upload {
                position: absolute;
                top: 20px;
                right: 20px;
                width: 250px;
                padding: 15px;
                border: 1px solid #2196F3;
                border-radius: 8px;
                background: #f0f8ff;
                z-index: 999;
                box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            }
            .key-upload-title {
                font-size: 15px;
                font-weight: bold;
                color: #1976D2;
                margin-bottom: 12px;
                border-bottom: 1px solid #e3f2fd;
                padding-bottom: 8px;
            }
            .upload-form label {
                font-size: 12px;
                color: #555;
                display: block;
                margin-bottom: 4px;
            }
            .upload-form input[type="text"],
            .upload-form input[type="file"] {
                width: 100%;
                padding: 6px;
                margin-bottom: 10px;
                font-size: 12px;
                border: 1px solid #ddd;
                border-radius: 4px;
                box-sizing: border-box;
            }
            .save-key-btn {
                background: #1976D2;
                padding: 7px 15px;
                font-size: 12px;
                width: 100%;
                margin-top: 5px;
            }
            .show-content-btn {
                background: #1976D2;
                padding: 7px 15px;
                font-size: 12px;
                width: 100%;
            }
            /* 隐藏所有状态提示 */
            .upload-status {
                display: none;
            }
            .has-key-tip {
                display: none;
            }
            .decrypt-status-tag {
                font-size: 12px;
                padding: 2px 6px;
                border-radius: 3px;
                margin-left: 8px;
            }
            .tag-success {background: #e8f5e9; color: #2e7d32;}
            .tag-error {background: #ffebee; color: #c62828;}
            .tag-plain {background: #fff8e1; color: #ff8f00;}
        </style>
    </head>
    <body>
        <!-- 新增：右上角私钥上传保存区域 -->
        <div class="private-key-upload">
            <!-- 第一步：显示“显示内容”按钮 或 第二步：显示上传表单 -->
            {% if not show_form %}
                <form method="POST">
                    <button type="submit" name="show_form_btn" class="show-content-btn">显示内容</button>
                </form>
            {% else %}
                <!-- 第二步：显示私钥选择和撤销列表表单 -->
                <form method="POST" enctype="multipart/form-data" class="upload-form">
                    <label>撤销用户列表：</label>
                    <input type="text" name="revoked_users" placeholder="例如：1,4" value="1,4" required>
                    
                    <label>选择用户私钥文件（JSON）：</label>
                    <input type="file" name="private_key_file" accept=".json" required>
                    
                    <button type="submit" class="save-key-btn">上传并保存私钥</button>
                </form>
            {% endif %}
            
            <!-- 完全隐藏上传状态提示 -->
            {% if upload_status %}
                <div class="upload-status" style="display: none;">
                    {{ upload_status }}
                </div>
            {% endif %}
        </div>

        <!-- 加密结果列表 -->
        <div class="article-list">
            <h3>文章列表</h3>
            {% if articles %}
                {% for article in articles %}
                    <div class="article-item">
                        <div class="article-header">
                            <div class="article-title">
                                <a href="{{ article.url }}">{{ article.title }}</a>
                                <!-- 解密状态标签 -->
                            </div>
                        </div>
                        <!-- 展示解密后的内容（或密文） -->
                        <div class="article-content {% if article.decrypt_status == '解密成功' or article.decrypt_status == '未加密' %}content-plain{% else %}content-encrypted{% endif %}">
                            {{ article.display_content or '无内容' }}
                        </div>
                    </div>
                {% endfor %}
            {% else %}
                <p>暂无文章，快去提交第一篇吧！</p>
            {% endif %}
        </div>
    </body>
    </html>
    '''
    return render_template_string(html, 
                                  articles=articles,
                                  upload_status=upload_status,
                                  has_saved_key=has_saved_key,
                                  show_form=show_form)

@app.route('/save', methods=['POST'])
def save():
    """保存处理：区分加密/非加密"""
    # 1. 获取基础参数
    title = request.form.get('title', '无标题').strip()
    original_text = request.form.get('input_text', '')
    action = request.form.get('action', 'encrypt')  # 默认加密
    
    # 2. 分支处理：直接保存原文
    if action == 'plain':
        save_plain_article(title, original_text)
        return redirect(url_for('index'))
    
    # 3. 原有加密保存逻辑
    # 解析撤销用户
    revoked_users_str = request.form.get('revoked_users', '1,4').strip()
    revoked_users = [int(x.strip()) for x in revoked_users_str.split(',') if x.strip().isdigit()]
    revoked_users = [x for x in revoked_users if 0 <= x <= 5]
    
    # 生成K+Hdr
    dbe_result = generate_dbe_key_and_hdr(revoked_users)
    
    # AES加密
    if dbe_result['status'] == "success" and dbe_result['aes_key']:
        encrypted_text, nonce, encrypt_status = encrypt_text_with_dbe_k(
            original_text, dbe_result['aes_key']
        )
    else:
        encrypted_text = ""
        nonce = ""
        encrypt_status = f"DBE生成失败：{dbe_result['status']}"
    
    # 保存加密文章
    save_article(title, original_text, encrypted_text, nonce, encrypt_status, dbe_result)
    
    return redirect(url_for('index'))

@app.route('/article/<filename>', methods=['GET'])
def view_article(filename):
    """详情页：访问时自动执行解密操作（移除POST请求依赖）"""
    article = read_article(filename)
    if not article:
        return redirect(url_for('index'))
    
    # 初始化解密相关变量
    decrypt_k_status = ""
    decrypt_k_verify = ""
    recovered_k = ""
    plaintext = ""
    decrypt_text_status = ""
    display_text = article['original_text'] if article['encrypt_status'] == "未加密" else article['encrypted_text']
    
    # 核心修改：仅在触发解密后才执行解密
    active_key = session.get('active_private_key', {})
    if article['encrypt_status'] != "未加密" and active_key.get('decrypt_triggered', False):
        # 获取首页保存的私钥
        key_path, config_data, key_status = get_saved_private_key()
        
        if not key_path:
            decrypt_text_status = f"自动解密失败：{key_status}"
        else:
            # 使用保存的私钥解密
            revoked_set = set(config_data.get('revoked_set', [1,4]))
            recovered_k, decrypt_k_status, decrypt_k_verify = decrypt_with_private_key(
                key_path, revoked_set, article['hdr_dict']
            )
            
            # 用恢复的K解密明文
            if recovered_k:
                plaintext, decrypt_text_status = decrypt_text_with_recovered_k(
                    article['encrypted_text'],
                    article['nonce'],
                    recovered_k
                )
                # 解密成功则替换展示文本
                if "成功" in decrypt_text_status:
                    display_text = plaintext
                    decrypt_text_status = f"✅ 自动解密成功：{decrypt_text_status}"
            else:
                decrypt_text_status = f"自动解密失败：{decrypt_k_status}"
    elif article['encrypt_status'] != "未加密":
        decrypt_text_status = "未触发解密"
    
    # 详情页HTML（移除解密按钮，保留状态提示）
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>{{ article.title }} - 文章详情</title>
        <style>
            body {max-width: 800px; margin: 20px auto; padding: 0 20px; font-family: Arial;}
            .content {margin: 20px 0; padding: 20px; border: 1px solid #ccc; border-radius: 8px;}
            .decrypt-status-area {margin: 20px 0; padding: 15px; border: 1px dashed #2196F3; border-radius: 8px;}
            .result-box {margin: 15px 0; padding: 10px; background: #f5f9ff; border-radius: 4px; white-space: pre-wrap;}
            .btn {padding: 8px 20px; border: none; border-radius: 4px; cursor: pointer; color: white; margin-right: 10px;}
            .back-btn {background: #2196F3;}
            .status-success {color: #4CAF50; font-weight: bold;}
            .status-error {color: #f44336; font-weight: bold;}
            .status-plain {color: #FF9800; font-weight: bold;}
            .long-text {
                word-wrap: break-word;
                white-space: pre-wrap;
                line-height: 1.5;
            }
            .display-tip {font-size: 12px; color: #666; margin-top: 5px;}
            .decrypt-status {
                margin: 15px 0;
                padding: 10px;
                border-radius: 4px;
                font-size: 12px;
            }
            .success-tip {background: #e8f5e9; color: #2e7d32;}
            .error-tip {background: #ffebee; color: #c62828;}
            .auto-decrypt-tip {
                font-size: 12px;
                color: #777;
                margin-top: 10px;
                padding: 8px;
                background: #f8f8f8;
                border-radius: 4px;
            }
        </style>
    </head>
    <body>
        <h1>{{ article.title }}</h1>

        <!-- 文章内容展示（兼容加密/非加密） -->
        <div class="content">
            <h3>文章内容</h3>
            <p><strong>文章标题：</strong>{{ article.title }}</p>
            </span></p>
            <p><strong>正文：</strong><span class="long-text">{{ display_text }}</span></p>
        </div>

        <!-- 操作按钮：仅保留返回按钮 -->
        <button class="btn back-btn" onclick="location.href='/'">返回列表</button>
    </body>
    </html>
    '''
    return render_template_string(html, 
                                  article=article,
                                  display_text=display_text,
                                  decrypt_text_status=decrypt_text_status,
                                  decrypt_k_verify=decrypt_k_verify)

@app.route('/export_all')
def export_all():
    """导出所有文章信息"""
    return export_all_articles()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)