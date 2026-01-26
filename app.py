from flask import Flask, request, render_template_string, redirect, url_for, send_file
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

def get_all_articles():
    """获取所有文章（兼容加密/非加密）"""
    articles = []
    if os.path.exists(ARTICLE_FOLDER):
        for filename in os.listdir(ARTICLE_FOLDER):
            if filename.endswith(".txt"):
                filepath = os.path.join(ARTICLE_FOLDER, filename)
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read().split("\n")
                title = content[0].replace("标题：", "") if len(content)>=1 else "无标题"
                encrypted_text = content[2].replace("AES加密后文本（16进制）：", "") if len(content)>=3 else ""
                encrypt_status = content[4].replace("加密状态：", "") if len(content)>=5 else "未知"
                
                articles.append({
                    "filename": filename,
                    "title": title,
                    "encrypted_text": encrypted_text,
                    "encrypt_status": encrypt_status,
                    "url": f"/article/{filename}",
                    "delete_url": f"/delete/{filename}"
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
        "hdr_dict": hdr_dict,  # 序列化的C1/C2
        "dbe_status": dbe_status,
        "delete_url": f"/delete/{filename}",
        "filename": filename
    }

def delete_article(filename):
    """删除文章"""
    filepath = os.path.join(ARTICLE_FOLDER, filename)
    if os.path.exists(filepath):
        os.remove(filepath)
    return redirect(url_for('index'))

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
    :param private_key_file: 上传的私钥JSON文件
    :param revoked_set: 撤销用户集合（需与加密时一致）
    :param article_hdr_dict: 文章保存的Hdr（C1/C2序列化字符串）
    :return: 恢复的K（序列化字符串）、解密状态、K一致性验证结果
    """
    try:
        # ========== 关键修复：在函数内重新导入PairingGroup ==========
        from charm.toolbox.pairinggroup import PairingGroup, G1, G2, GT, ZR, pair
        
        # 1. 初始化群
        group = PairingGroup('SS512')
        
        # 2. 解析上传的私钥文件
        sk_data = json.load(private_key_file)
        user_id = None
        # 从文件名提取用户ID（格式：user_0_private_key.json）
        filename = private_key_file.filename
        if "user_" in filename and "_private_key.json" in filename:
            user_id = int(filename.split("user_")[1].split("_private_key.json")[0])
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
@app.route('/')
def index():
    """首页：新增直接保存原文按钮 + 导出所有信息按钮"""
    articles = get_all_articles()
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>DBE+AES加密论坛（预初始化版）</title>
        <style>
            body {max-width: 800px; margin: 20px auto; padding: 0 20px; font-family: Arial;}
            .form-area {border: 1px solid #ccc; padding: 20px; border-radius: 8px; margin-bottom: 30px;}
            .article-list {border: 1px solid #2196F3; padding: 20px; border-radius: 8px; margin-bottom: 20px;}
            textarea {width: 100%; height: 120px; padding: 10px; margin: 10px 0; box-sizing: border-box;}
            button {padding: 8px 20px; border: none; border-radius: 4px; cursor: pointer; color: white; margin-right: 10px;}
            .submit-btn {background: #2196F3;}
            .plain-btn {background: #4CAF50;}  /* 绿色按钮区分纯文本保存 */
            .export-btn {background: #9C27B0;}  /* 紫色按钮区分导出功能 */
            .delete-btn {background: #f44336; margin-left: 10px;}
            .article-item {margin: 10px 0; padding: 15px; background: #f5f9ff; border-radius: 4px; display: flex; justify-content: space-between; align-items: center;}
            .encrypted-text {color: #666; margin-top: 8px; font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;}
            .status-success {color: #4CAF50; font-weight: bold;}
            .status-error {color: #f44336; font-weight: bold;}
            .status-plain {color: #FF9800; font-weight: bold;}  /* 橙色标记未加密 */
            .dbe-config {margin: 10px 0; padding: 10px; background: #f0f8ff; border-radius: 4px;}
            .btn-group {margin-top: 15px;}
            .export-group {margin: 20px 0; text-align: right;}
        </style>
    </head>
    <body>
        <h1>DBE+AES-256加密论坛（预初始化6用户）</h1>
        <div style="color: #4CAF50; font-weight: bold; margin: 10px 0;">
            ✅ 已加载预生成公共参数
        </div>
        
        <div class="form-area">
            <h3>文本操作</h3>
            <form method="POST" action="/save" enctype="multipart/form-data">
                <!-- 文章标题 -->
                <label>文章标题：</label>
                <input type="text" name="title" placeholder="输入文章标题" required style="width: 100%; padding: 8px; margin: 5px 0;">
                
                <!-- DBE配置（仅加密时生效） -->
                <div class="dbe-config">
                    <label>撤销用户列表（逗号分隔，如1,4，索引0-5）：</label>
                    <input type="text" name="revoked_users" placeholder="1,4" value="1,4" style="width: 100%; padding: 8px; margin: 5px 0;">
                    <p style="color: #999; font-size: 12px;">注：仅加密保存时生效，总用户数固定为6（预初始化）</p>
                </div>
                
                <!-- 待处理文本 -->
                <label>文本内容：</label>
                <textarea name="input_text" placeholder="输入要加密或直接保存的文本" required></textarea>
                
                <!-- 按钮组：加密保存 + 直接保存原文 -->
                <div class="btn-group">
                    <button type="submit" name="action" value="encrypt" class="submit-btn">生成K+Hdr并加密保存</button>
                    <button type="submit" name="action" value="plain" class="plain-btn">直接保存原文（不加密）</button>
                </div>
            </form>
        </div>
        
        <!-- 加密结果列表 -->
        <div class="article-list">
            <!-- 导出按钮 -->
            <div class="export-group">
                <a href="/export_all" class="export-btn" style="padding: 8px 20px; border-radius: 4px; color: white; text-decoration: none; background: #9C27B0;">
                    📤 导出所有文章信息（JSON格式）
                </a>
            </div>
            
            <h3>文章列表</h3>
            {% if articles %}
                {% for article in articles %}
                    <div class="article-item">
                        <div style="max-width: 70%;">
                            <a href="{{ article.url }}">{{ article.title }}</a>
                            {% if article.encrypt_status == "未加密" %}
                                <span class="status-plain">[未加密]</span>
                            {% else %}
                                <span class="status-success">[已加密]</span>
                            {% endif %}
                        </div>
                        <a href="{{ article.delete_url }}" class="delete-btn" onclick="return confirm('确定删除？')">删除</a>
                    </div>
                {% endfor %}
            {% else %}
                <p>暂无文章，快去提交第一篇吧！</p>
            {% endif %}
        </div>
    </body>
    </html>
    '''
    return render_template_string(html, articles=articles)

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

@app.route('/article/<filename>', methods=['GET', 'POST'])
def view_article(filename):
    """详情页：兼容加密/非加密文章"""
    article = read_article(filename)
    if not article:
        return redirect(url_for('index'))
    
    # 初始化解密相关变量
    decrypt_k_status = ""
    decrypt_k_verify = ""
    recovered_k = ""
    plaintext = ""
    decrypt_text_status = ""
    revoked_set = set()
    
    # 核心：定义展示文本，优先用解密后的明文，否则用加密正文/原文
    if article['encrypt_status'] == "未加密":
        display_text = article['original_text']  # 非加密文章直接展示原文
    else:
        display_text = article['encrypted_text']  # 加密文章默认展示密文
    
    # 处理POST请求（仅加密文章需要解密）
    if request.method == 'POST' and article['encrypt_status'] != "未加密":
        # 1. 获取撤销用户集合（需与加密时一致）
        revoked_users_str = request.form.get('revoked_users', '1,4').strip()
        revoked_set = set([int(x.strip()) for x in revoked_users_str.split(',') if x.strip().isdigit()])
        
        # 2. 上传私钥文件
        private_key_file = request.files.get('private_key_file')
        if private_key_file and private_key_file.filename.endswith('.json'):
            # 3. 调用de.py解密恢复K
            recovered_k, decrypt_k_status, decrypt_k_verify = decrypt_with_private_key(
                private_key_file, revoked_set, article['hdr_dict']
            )
            
            # 4. 用恢复的K解密明文
            if recovered_k:
                plaintext, decrypt_text_status = decrypt_text_with_recovered_k(
                    article['encrypted_text'],
                    article['nonce'],
                    recovered_k
                )
                # 解密成功则替换展示文本为明文
                if "成功" in decrypt_text_status:
                    display_text = plaintext
    
    # 详情页HTML
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>{{ article.title }} - 文章详情</title>
        <style>
            body {max-width: 800px; margin: 20px auto; padding: 0 20px; font-family: Arial;}
            .content {margin: 20px 0; padding: 20px; border: 1px solid #ccc; border-radius: 8px;}
            .upload-area {margin: 20px 0; padding: 15px; border: 1px dashed #2196F3; border-radius: 8px; display: {% if article.encrypt_status == "未加密" %}none{% else %}block{% endif %};}
            .result-box {margin: 15px 0; padding: 10px; background: #f5f9ff; border-radius: 4px; white-space: pre-wrap;}
            .btn {padding: 8px 20px; border: none; border-radius: 4px; cursor: pointer; color: white; margin-right: 10px;}
            .back-btn {background: #2196F3;}
            .delete-btn {background: #f44336;}
            .action-btn {background: #4CAF50; margin-top: 10px;}
            .status-success {color: #4CAF50; font-weight: bold;}
            .status-error {color: #f44336; font-weight: bold;}
            .status-plain {color: #FF9800; font-weight: bold;}
            .long-text {
                word-wrap: break-word;
                white-space: pre-wrap;
                line-height: 1.5;
            }
            .dbe-info {margin: 10px 0; padding: 10px; background: #f0f8ff; border-radius: 4px;}
            .display-tip {font-size: 12px; color: #666; margin-top: 5px;}
        </style>
    </head>
    <body>
        <h1>{{ article.title }} - 文章详情</h1>

        <!-- 文章内容展示（兼容加密/非加密） -->
        <div class="content">
            <h3>文章内容</h3>
            <p><strong>文章标题：</strong>{{ article.title }}</p>
            <p><strong>加密状态：</strong><span class="{% if article.encrypt_status == '未加密' %}status-plain{% else %}status-success{% endif %}">
                {{ article.encrypt_status }}
            </span></p>
            <p><strong>正文：</strong><span class="long-text">{{ display_text }}</span></p>
            {% if plaintext and "成功" in decrypt_text_status %}
                <div class="display-tip">✅ 已自动替换为解密后的明文</div>
            {% elif article.encrypt_status == "未加密" %}
                <div class="display-tip">ℹ️ 该文章为纯文本，未进行加密</div>
            {% endif %}
        </div>

        <!-- 解密区域（仅加密文章显示） -->
        <div class="upload-area">
            <h3>上传私钥解密（仅加密文章有效）</h3>
            <form method="POST" enctype="multipart/form-data">
                <label>撤销用户列表（需与加密时一致，如1,4）：</label>
                <input type="text" name="revoked_users" placeholder="1,4" value="1,4" style="width: 100%; padding: 8px; margin: 5px 0;">
                
                <label>选择用户私钥文件：</label>
                <input type="file" name="private_key_file" accept=".json" required style="margin: 10px 0;">
                
                <button type="submit" class="btn action-btn">解密K并恢复明文</button>
            </form>
        </div>

        <!-- 明文解密结果（保留原有展示，仅作为补充） -->
        {% if decrypt_text_status %}
            <div style="margin: 20px 0;">
                <p style="color: #999; font-size: 12px;">注：解密结果仅临时展示，未保存到文件</p>
            </div>
        {% endif %}

        <!-- 操作按钮 -->
        <button class="btn back-btn" onclick="location.href='/'">返回列表</button>
        <button class="btn delete-btn" onclick="if(confirm('确定删除？')){location.href='{{ article.delete_url }}'}">删除文章</button>
    </body>
    </html>
    '''
    return render_template_string(html, 
                                  article=article,
                                  decrypt_k_status=decrypt_k_status,
                                  decrypt_k_verify=decrypt_k_verify,
                                  recovered_k=recovered_k,
                                  plaintext=plaintext,
                                  decrypt_text_status=decrypt_text_status,
                                  display_text=display_text)

@app.route('/delete/<filename>')
def delete(filename):
    """删除文章"""
    return delete_article(filename)

@app.route('/export_all')
def export_all():
    """导出所有文章信息"""
    return export_all_articles()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)