# decrypt_with_full_print.py
import os
import json
from charm.toolbox.pairinggroup import PairingGroup, G1, G2, GT, ZR, pair

DATA_DIR = "./data"

# ==================== 安全打印 GT 元素（关键！避免 segfault） ====================
def safe_gt(group, elem, label="GT element"):
    if elem is None:
        return "None"
    ser = group.serialize(elem).decode('utf-8')
    return f"{label}: {ser[:80]}{'...' if len(ser) > 80 else ''}"

# ==================== 加载原始 K（加密端生成） ====================
def load_original_K(group):
    k_file = f"{DATA_DIR}/K.txt"
    print(f"\n[0] 加载加密端生成的原始会话密钥 ← {k_file}")
    with open(k_file, "r", encoding="utf-8") as f:
        line = f.read().strip()
    K_str = line.split(":", 1)[1].strip()
    K_orig = group.deserialize(K_str.encode('utf-8'))
    print(f"    原始 K 加载成功")
    print(f"    {safe_gt(group, K_orig, '原始 K')}")
    return K_orig

# ==================== 加载 Hdr ====================
def load_hdr(group):
    hdr_file = f"{DATA_DIR}/Hdr.txt"
    print(f"\n[1] 加载广播头 Hdr ← {hdr_file}")
    with open(hdr_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    C1_str = lines[0].split(":", 1)[1].strip()
    C2_str = lines[1].split(":", 1)[1].strip()

    C1 = group.deserialize(C1_str.encode('utf-8'))
    C2 = group.deserialize(C2_str.encode('utf-8'))

    print(f"    C1 = g^k      = {C1}")
    print(f"    C2 = M^k      = {C2}")
    return (C1, C2)

# ==================== 加载用户私钥（.json） ====================
def reconstruct_private_key(group, user_id):
    sk_file = f"{DATA_DIR}/user_{user_id}_private_key.json"
    print(f"\n[2] 加载用户 {user_id} 的私钥 ← {sk_file}")

    with open(sk_file, "r", encoding="utf-8") as f:
        sk_data = json.load(f)

    print(f"    私钥文件解析成功，包含字段: {list(sk_data.keys())}")

    d0  = group.deserialize(sk_data['d0'].encode('utf-8'))
    d0_ = group.deserialize(sk_data['d0_'].encode('utf-8'))
    print(f"    d0      = {d0}")
    print(f"    d0_     = {d0_}")

    d = []
    print(f"    d[] 分量（共 {len(sk_data['d'])} 个）:")
    for i, s in enumerate(sk_data['d']):
        if s is None:
            d.append(None)
            print(f"      d[{i}] = None")
        else:
            elem = group.deserialize(s.encode('utf-8'))
            d.append(elem)
            status = "（用户自身）" if i == user_id else ""
            print(f"      d[{i}] = {elem} {status}")
    d[user_id] = None
    print(f"    已强制设置 d[{user_id}] = None")

    return {'d0': d0, 'd0_': d0_, 'd': d}

# ==================== 主解密函数 ====================
def decrypt(user_id, revoked_set):
    print("="*90)
    print(f"开始为用户 {user_id} 执行 Malluhi 2020 解密 + 完整验证")
    print(f"撤销用户集合 R = {sorted(revoked_set)}")
    print("="*90)

    group = PairingGroup('SS512')

    # 1. 加载原始 K
    K_original = load_original_K(group)

    # 2. 加载 Hdr
    C1, C2 = load_hdr(group)

    # 3. 加载用户私钥
    sk = reconstruct_private_key(group, user_id)

    # 4. 执行解密算法
    print(f"\n[3] 执行解密计算：K = e(C1, d0 · ∏_{{r∈R}} d_r) / e(C2, d0_)")

    prod_d = sk['d0']
    print(f"    初始 prod_d = d0")

    used_count = 0
    for r in revoked_set:
        if r == user_id:
            print(f"    跳过 r={r}（用户自身）")
            continue
        if sk['d'][r] is not None:
            print(f"    × d[{r}]")
            prod_d *= sk['d'][r]
            used_count += 1
        else:
            print(f"    d[{r}] 为 None，跳过")

    print(f"    共使用了 {used_count} 个 d_r 分量")
    print(f"    最终 prod_d = {prod_d}")

    if user_id in revoked_set:
        print(f"\n[Warning] 用户 {user_id} 已被撤销，理论上无法恢复 K")

    # 配对计算
    print(f"\n[4] 开始配对计算...")
    num = pair(C1, prod_d)
    den = pair(C2, sk['d0_'])
    K_recovered = num / den

    print(f"    e(C1, prod_d)    = {safe_gt(group, num, '分子')}")
    print(f"    e(C2, d0_)       = {safe_gt(group, den, '分母')}")
    print(f"    K_recovered      = {safe_gt(group, K_recovered, '恢复的 K')}")

    # 5. 保存结果
    out_file = f"{DATA_DIR}/K_decrypted_user_{user_id}.txt"
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(f"# 用户 {user_id} 解密结果\n")
        f.write(f"# 撤销集合: {sorted(revoked_set)}\n")
        f.write(f"K_recovered = {group.serialize(K_recovered).decode('utf-8')}\n")
    print(f"\n[Success] 解密完成！结果已保存 → {out_file}")

    # 6. 最终验证
    print("\n" + "="*70)
    print("【最终一致性验证】".center(70))
    print("="*70)

    if K_recovered == K_original:
        print(f"用户 {user_id} 解密成功！会话密钥完全一致")
        verdict = "成功"
    else:
        print(f"用户 {user_id} 解密失败！会话密钥不一致")
        if user_id in revoked_set:
            print("   （用户已被撤销，属于正常现象）")
        else:
            print("   （未被撤销但 K 不一致，说明实现有误！）")
        verdict = "失败"

    print(f"原始 K       : {safe_gt(group, K_original, '原始 K')}")
    print(f"恢复 K       : {safe_gt(group, K_recovered, '恢复 K')}")
    print(f"是否相等     : {K_recovered == K_original}")
    print(f"最终结论     : 解密{verdict}")
    print("="*70)

    return K_recovered, K_original

# ============================== 运行入口 ==============================
if __name__ == "__main__":
    USER_ID     = 0          # ← 改成你要测试的用户
    REVOKED_SET = {1, 4}     # ← 必须和加密时完全一致

    try:
        K_rec, K_orig = decrypt(USER_ID, REVOKED_SET)
    except Exception as e:
        print(f"\n[Error] 解密失败: {e}")
        import traceback
        traceback.print_exc()