# -*- coding: utf-8 -*-
# encrypt_from_config.py
import os
from charm.toolbox.pairinggroup import PairingGroup, G1, G2, GT, ZR, pair

# ==================== 关键：直接从 config.py 导入真实对象 ====================
try:
    from config import PK, group
    print("成功从 config.py 导入公共参数 PK 和 group！")
    print("公共参数已准备就绪，无需任何反序列化")
except ImportError as e:
    print("错误：无法找到 ./data/config.py")
    print("请先运行一次 Setup 程序生成 config.py")
    raise e


class DBE_Encryptor:
    def __init__(self, total_users=6):
        self.N = total_users
        # 直接使用导入的 group 和 PK，无需任何初始化或反序列化
        self.group = group
        self.PK = PK
        self.revoked_set = set()

        print(f"【初始化】使用曲线 SS512，总用户数 N = {self.N}")
        print("【成功】公共参数已直接加载（来自 config.py）")

    def safe_gt(self, elem):
        """安全打印 GT 元素，避免 segfault"""
        if elem is None:
            return "None"
        ser = self.group.serialize(elem).decode('utf-8')
        return ser[:80] + "..." if len(ser) > 80 else ser

    def set_revoked_users(self, revoked_list):
        self.revoked_set = set(revoked_list)
        print(f"\n【撤销设置】撤销用户集合 R = {sorted(self.revoked_set)} (索引从 0 开始)")

    def encrypt(self):
        print("\n" + "="*80)
        print("开始执行 Malluhi 2020 广播加密")
        print("="*80)

        k = self.group.random(ZR)
        print(f"随机选择会话密钥指数 k ∈ ZR → k = {int(k)}")

        C1 = self.PK['g'] ** k
        print(f"C1 = g^k = {C1}")

        print(f"\n计算 M = g^β × ∏_{{r∈R}} u_r")
        M = self.PK['g_beta']
        print(f"  初始 M = g^β = {M}")
        for r in self.revoked_set:
            print(f"  × u[{r}] = {self.PK['u'][r]}")
            M *= self.PK['u'][r]
        print(f"  最终 M = {M}")

        C2 = M ** k
        print(f"\nC2 = M^k = {C2}")

        K = self.PK['e_alpha'] ** k
        print(f"\n会话密钥 K = e(g,g̃)^{{αk}}")
        print(f"  K = {self.safe_gt(K)}")

        Hdr = (C1, C2)
        print(f"\n加密完成！")
        print(f"  Hdr = (C1, C2)")
        print(f"  会话密钥 K = {self.safe_gt(K)}")
        print("="*80)

        return Hdr, K#注意这里的K，使用这个K进行加密

    def save_separate_files(self, Hdr, K, base_path="./data"):
        os.makedirs(base_path, exist_ok=True)
        C1, C2 = Hdr

        def ser(elem):
            return self.group.serialize(elem).decode('utf-8')

        hdr_file = os.path.join(base_path, "Hdr.txt")
        with open(hdr_file, 'w', encoding='utf-8') as f:
            f.write(f"C1: {ser(C1)}\n")
            f.write(f"C2: {ser(C2)}\n")
        print(f"Hdr 已保存（serialize 格式）→ {hdr_file}")

        k_file = os.path.join(base_path, "K.txt")
        with open(k_file, 'w', encoding='utf-8') as f:
            f.write(f"K: {ser(K)}\n")
        print(f"K 已保存（serialize 格式）→ {k_file}")

        readable_file = os.path.join(base_path, "Hdr_and_K_readable.txt")
        with open(readable_file, 'w', encoding='utf-8') as f:
            f.write(f"C1 (可读): {str(C1)}\n")
            f.write(f"C2 (可读): {str(C2)}\n")
            f.write(f"K  (可读): {str(K)}\n")
        print(f"可读版本已保存 → {readable_file}")

    def save_encryption_results(self, Hdr, K, file_path="./data/encryption_results.txt"):
        C1, C2 = Hdr
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        def ser(elem):
            return self.group.serialize(elem).decode('utf-8')

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(f"Hdr_C1: {ser(C1)}\n")
            f.write(f"Hdr_C2: {ser(C2)}\n")
            f.write(f"K: {ser(K)}\n")
        print(f"加密结果已保存（serialize 格式）→ {file_path}")


# ============================== 主程序 ==============================
def main():
    print("=" * 80)
    print("    Malluhi 2020 DBE 广播加密 - 加密端（config.py 直读版）")
    print("=" * 80)

    encryptor = DBE_Encryptor(total_users=6)

    encryptor.set_revoked_users([1, 4])  # ← 随意修改撤销用户

    Hdr, K = encryptor.encrypt()

    encryptor.save_encryption_results(Hdr, K)
    encryptor.save_separate_files(Hdr, K)

    print("\n全部完成！")
    print("  Hdr 和 K 已保存到 ./data/")
    print("  你现在可以运行解密程序进行验证了！")


if __name__ == "__main__":
    main()