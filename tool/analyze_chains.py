#!/usr/bin/env python3
"""
证书链扫描结果分析器 v0.1
输入：data/chains_top1000/summary.json（或任意扫描输出）
输出：中国 Top N TLS 证书链量子脆弱性统计（方向一论文图表的直接输入）
"""
import json, sys, re
from collections import Counter
from datetime import datetime

# X.509 公钥算法 → Shor 威胁
SHOR_VULN_ALGOS = {"rsaEncryption", "id-ecPublicKey"}
# 签名算法 → Shor 威胁（RSA/ECDSA 签名全部可被 Shor 破）
SHOR_SIG_MARKERS = ["rsa", "ecdsa", "ec", "sm2", "rsassa"]

def classify_pk(algo):
    a = algo.lower()
    if "rsa" in a:
        return "RSA"
    if "ec" in a or "dsa" in a:
        return "ECC"
    if "ed25519" in a or "ed448" in a:
        return "EdDSA"
    if "ml-dsa" in a or "slh" in a or "dilithium" in a or "sphincs" in a:
        return "PQC"
    return "other"

def classify_sig(sig):
    s = sig.lower()
    if "ml-dsa" in s or "slh" in s or "dilithium" in s or "sphincs" in s:
        return "PQC"
    if "rsa" in s or "rsassa" in s:
        return "RSA-sig"
    if "ecdsa" in s or "ec" in s:
        return "ECC-sig"
    if "ed25519" in s or "ed448" in s:
        return "EdDSA-sig"
    if "sm3" in s or "sm2" in s:
        return "SM2-sig"
    return "other"

def main():
    if len(sys.argv) < 2:
        print("usage: analyze_chains.py summary.json [--print-all]")
        return
    path = sys.argv[1]
    s = json.load(open(path))

    total = s["total"]
    ok = s.get("ok", 0)
    chains = s.get("chain_stats", [])

    print(f"=== 扫描汇总 ===")
    print(f"总目标: {total} | 成功: {ok} ({ok/total*100:.1f}%) | 失败: {total-ok}")
    print()

    # 1. 链长分布
    lens = Counter(c["chain_length"] for c in chains)
    print("=== 证书链长度分布 ===")
    for l in sorted(lens):
        print(f"  链长 {l}: {lens[l]} 站 ({lens[l]/max(ok,1)*100:.1f}%)")

    # 2. 每个位置的算法分布
    print()
    print("=== 各链位置的公钥算法分布 ===")
    pos_pk = {}
    for c in chains:
        for cert in c["cert_subjects"]:
            idx = cert["idx"]
            if idx not in pos_pk:
                pos_pk[idx] = Counter()
            pos_pk[idx][classify_pk(cert["pk_algo"])] += 1
    for idx in sorted(pos_pk):
        print(f"  位置 {idx} (0=叶子): {dict(pos_pk[idx])}")

    # 3. 签名算法分布
    print()
    print("=== 签名算法分布（全部证书） ===")
    sig_dist = Counter()
    for c in chains:
        for cert in c["cert_subjects"]:
            sig_dist[classify_sig(cert["sig_algo"])] += 1
    for k, v in sig_dist.most_common():
        print(f"  {k}: {v}")

    # 4. 整链 Shor 脆弱性（串联模型：任一环 RSA/ECC → 整链脆弱）
    print()
    print("=== 整链 Shor 脆弱性（串联：最弱环主导） ===")
    shor_ok = 0
    for c in chains:
        vuln = any(classify_pk(cert["pk_algo"]) in ("RSA", "ECC") for cert in c["cert_subjects"])
        if vuln:
            shor_ok += 1
    print(f"  整链含 RSA/ECC（Shor 脆弱）: {shor_ok}/{len(chains)} ({shor_ok/max(len(chains),1)*100:.1f}%)")
    pqc_ok = sum(1 for c in chains if any(classify_pk(cert["pk_algo"]) == "PQC" for cert in c["cert_subjects"]))
    print(f"  链中含 PQC 算法: {pqc_ok}/{len(chains)}")

    # 5. 签发者分析（中国 CA 份额）
    print()
    print("=== 叶子证书签发者（Top 15） ===")
    issuers = Counter()
    for c in chains:
        if c["cert_subjects"]:
            leaf = c["cert_subjects"][0]
            issuers[leaf["issuer"][:60]] += 1
    for k, v in issuers.most_common(15):
        print(f"  {k}: {v}")

    # 6. 验证状态
    print()
    print("=== 验证状态 ===")
    v = Counter(t["verify"] for t in s["targets"])
    for k, cnt in v.most_common(5):
        print(f"  {k}: {cnt}")

if __name__ == "__main__":
    main()
