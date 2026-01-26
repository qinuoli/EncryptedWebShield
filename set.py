# -*- coding: utf-8 -*-
import os
import json
from charm.toolbox.pairinggroup import PairingGroup, G1, G2, GT, ZR, pair


class DBE_Malluhi2020:
    def __init__(self, n_key_users=6, total_users=6, curve='SS512'):
        self.n = n_key_users
        self.N = total_users
        self.group = PairingGroup(curve)

        self.g  = self.group.random(G1)
        self.gt = self.group.random(G2)

        self.PK = None
        self.users = {}

        self.master_alpha = None
        self.master_beta  = None
        self.master_r     = None

        self.s = [[self.group.random(ZR) for _ in range(self.N)] for _ in range(self.N)]

        print(f"[初始化] 曲线: {curve}, 用户总数 N = {self.N}")

    def Setup(self):
        print("\n" + "="*80)
        print("开始执行 Malluhi 2020 多权威 Setup")
        print("="*80)

        alpha = [self.group.random(ZR) for _ in range(self.N)]
        beta  = [self.group.random(ZR) for _ in range(self.N)]
        r     = [[self.group.random(ZR) for _ in range(self.N)] for _ in range(self.N)]

        self.master_alpha = alpha
        self.master_beta  = beta
        self.master_r     = r

        e_alpha = self.group.init(GT, 1)
        beta_0  = self.group.init(ZR, 0)
        u  = [self.group.init(G1, 1) for _ in range(self.N)]
        ut = [self.group.init(G2, 1) for _ in range(self.N)]

        for i in range(self.N):
            e_alpha *= pair(self.g, self.gt ** alpha[i])
            beta_0  += beta[i]
            for j in range(self.N):
                u[j]  *= self.g  ** r[i][j]
                ut[j] *= self.gt ** r[i][j]

        g_beta  = self.g  ** beta_0
        gt_beta = self.gt ** beta_0

        self.PK = {
            'g': self.g, 'gt': self.gt,
            'e_alpha': e_alpha, 'g_beta': g_beta, 'gt_beta': gt_beta,
            'u': u, 'ut': ut, 'beta_0': beta_0
        }

        print("公共参数计算完成")
        print("\n公共参数概览（安全打印）")
        print(f"  g         = {self.PK['g']}")
        print(f"  g̃         = {self.PK['gt']}")
        print(f"  e(g,g̃)^α  = {self.safe_gt(self.PK['e_alpha'])}")
        print(f"  g^β       = {self.PK['g_beta']}")
        print(f"  g̃^β       = {self.PK['gt_beta']}")
        print(f"  beta_0    = {int(self.PK['beta_0'])}")
        for i in range(self.N):
            print(f"  u[{i:<2}]    = {self.PK['u'][i]}")
            print(f"  ũ[{i:<2}]    = {self.PK['ut'][i]}")

        self.save_public_key()
        self.save_s_parameters()

        print("\n开始为每个用户生成私钥...")
        for uid in range(self.N):
            self._extract_user(uid, alpha, beta, r)

        print("\n" + "="*80)
        print("Setup 全部完成！共生成以下内容：")
        print("="*80)

    def safe_gt(self, elem):
        """安全打印 GT 元素（避免 segfault）"""
        if elem is None:
            return "None"
        ser = self.group.serialize(elem).decode('utf-8')
        return ser[:80] + "..." if len(ser) > 80 else ser

    def _extract_user(self, j, alpha_list, beta_list, r_matrix):
        d0  = self.group.init(G2, 1)
        d0_ = self.group.init(G2, 1)
        d   = [self.group.init(G2, 1) for _ in range(self.N)]

        for i in range(self.N):
            s_ij = self.s[i][j]
            d0  *= ( (self.gt ** self.PK['beta_0']) ** s_ij ) * (self.gt ** alpha_list[i])
            d0_ *= self.gt ** s_ij
            for k in range(self.N):
                d[k] *= self.PK['ut'][k] ** s_ij

        d[j] = None
        self.users[j] = {'d0': d0, 'd0_': d0_, 'd': d}

        # 打印该用户私钥（安全方式）
        print(f"\n用户 {j} 私钥（共 {self.N} 个分量）")
        print(f"  d0      = {d0}")
        print(f"  d0_     = {d0_}")
        print(f"  d[]     = [", end="")
        for i in range(self.N):
            if i == j:
                print(" None", end="")
            elif d[i] is None:
                print(" None", end="")
            else:
                print(f" {i}:{str(d[i])[:30]}...", end="")
        print(" ]")

        # 保存为 .json（标准 serialize 格式）
        directory = './data'
        os.makedirs(directory, exist_ok=True)
        sk_file = f"{directory}/user_{j}_private_key.json"
        sk_data = {
            'd0':  self.group.serialize(d0).decode('utf-8'),
            'd0_': self.group.serialize(d0_).decode('utf-8'),
            'd':   [self.group.serialize(dk).decode('utf-8') if dk is not None else None for dk in d]
        }
        with open(sk_file, 'w', encoding='utf-8') as f:
            json.dump(sk_data, f, indent=2)
        print(f"  用户 {j} 私钥已保存 → {sk_file}")

        # 删除旧的 .txt 文件（避免混淆）
        old_file = f"{directory}/user_{j}_private_key.txt"
        if os.path.exists(old_file):
            os.remove(old_file)
            print(f"  已删除旧版私钥文件: {old_file}")

    def save_public_key(self):
        """生成 config.py —— 所有元素都用 group.init() 重构，确保是真实对象"""
        directory = './'
        os.makedirs(directory, exist_ok=True)
        config_path = f"{directory}/config.py"

        with open(config_path, 'w', encoding='utf-8') as f:
            f.write("# -*- coding: utf-8 -*-\n")
            f.write("# 自动生成的公共参数模块 - 所有元素均为真实 Charm 对象！\n")
            f.write("from charm.toolbox.pairinggroup import PairingGroup\n")
            f.write("\n")
            f.write("group = PairingGroup('SS512')\n\n")

            # 关键：所有元素都用 group.init() + serialize 再反序列化，确保是真实对象
            def export_elem(name, elem):
                if elem is None:
                    return f"{name} = None\n"
                ser = self.group.serialize(elem).decode('utf-8')
                return f"{name} = group.deserialize('{ser}'.encode('utf-8'))\n"

            def export_list(name, elem_list):
                lines = [f"{name} = ["]
                for i, elem in enumerate(elem_list):
                    if elem is None:
                        lines.append("    None,")
                    else:
                        ser = self.group.serialize(elem).decode('utf-8')
                        lines.append(f"    group.deserialize('{ser}'.encode('utf-8')),")
                lines.append("]\n")
                return "\n".join(lines)

            f.write("# === 基础生成元 ===\n")
            f.write(export_elem("g", self.PK['g']))
            f.write(export_elem("gt", self.PK['gt']))
            f.write("\n")

            f.write("# === 公共参数 ===\n")
            f.write(export_elem("e_alpha", self.PK['e_alpha']))
            f.write(export_elem("g_beta", self.PK['g_beta']))
            f.write(export_elem("gt_beta", self.PK['gt_beta']))
            f.write(f"beta_0 = {int(self.PK['beta_0'])}\n")
            f.write("\n")

            f.write("# === 用户相关向量 ===\n")
            f.write(export_list("u", self.PK['u']))
            f.write(export_list("ut", self.PK['ut']))
            f.write("\n")

            f.write("PK = {\n")
            f.write("    'g': g, 'gt': gt,\n")
            f.write("    'e_alpha': e_alpha,\n")
            f.write("    'g_beta': g_beta,\n")
            f.write("    'gt_beta': gt_beta,\n")
            f.write("    'beta_0': beta_0,\n")
            f.write("    'u': u,\n")
            f.write("    'ut': ut,\n")
            f.write("}\n\n")
            f.write("print('config.py 加载成功！所有公共参数均为真实 Charm 对象')\n")

        print(f"公共参数已成功导出 → {config_path}")
        print("   所有元素均为真实群元素，可直接参与运算！")

    def save_s_parameters(self):
        directory = './data'
        os.makedirs(directory, exist_ok=True)
        s_dict = {f"s_{i}_{j}": str(int(self.s[i][j])) for i in range(self.N) for j in range(self.N)}
        s_file = f"{directory}/s_parameters.json"
        with open(s_file, 'w', encoding='utf-8') as f:
            json.dump(s_dict, f, indent=2)
        print(f"公共随机因子 s_ij 已保存      → {s_file}")


# ============================== 运行入口 ==============================
if __name__ == "__main__":
    print("=" * 80)
    print(" Malluhi 2020 DBE 多权威广播加密 - 参数生成 + 详细打印版")
    print("=" * 80)

    dbe = DBE_Malluhi2020(n_key_users=6, total_users=6, curve='SS512')
    dbe.Setup()

    print("\n所有文件已生成在：./data/")
    print("  - public_key.json")
    print("  - user_0_private_key.json ~ user_5_private_key.json")
    print("  - s_parameters.json")
    print("\n现在可以直接运行加密程序了！")