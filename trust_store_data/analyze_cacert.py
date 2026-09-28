#!/usr/bin/env python3
"""Parse Mozilla cacert.pem: extract alg, key_size, sig_alg, validity, issuer."""
import subprocess, re, sys
from pathlib import Path
from datetime import datetime

CACERT = Path(__file__).parent / "cacert.pem"
OUT = Path(__file__).parent / "cacert_stats.md"

def parse_pem(pem_path):
    """Split PEM file into individual certs."""
    with open(pem_path) as f:
        data = f.read()
    certs = []
    for block in data.split("-----BEGIN CERTIFICATE-----"):
        if "-----END CERTIFICATE-----" not in block:
            continue
        pem = "-----BEGIN CERTIFICATE-----" + block.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----"
        certs.append(pem.strip())
    return certs

def get_cert_info(pem):
    """Use openssl to extract cert fields."""
    try:
        r = subprocess.run(
            ["openssl", "x509", "-text", "-noout"],
            input=pem, capture_output=True, text=True, timeout=5
        )
        if r.returncode != 0:
            return None
        text = r.stdout
    except:
        return None

    info = {}

    # Subject
    m = re.search(r"Subject:\s*(.+)", text)
    info["subject"] = m.group(1).strip() if m else "?"

    # Issuer
    m = re.search(r"Issuer:\s*(.+)", text)
    info["issuer"] = m.group(1).strip() if m else "?"

    # Validity
    m = re.search(r"Not Before:\s*(.+?)\n", text)
    info["not_before"] = m.group(1).strip() if m else "?"
    m = re.search(r"Not After\s*:\s*(.+?)\n", text)
    info["not_after"] = m.group(1).strip() if m else "?"

    # Public key algorithm + size
    m = re.search(r"Public Key Algorithm:\s*(.+?)\n", text)
    raw_algo = m.group(1).strip() if m else "?"
    info["pk_algo_raw"] = raw_algo
    
    # Determine pk_algo and key_size
    m_rsa = re.search(r"RSA Public-Key:\s*\((\d+) bit\)", text)
    m_pk = re.search(r"Public-Key:\s*\((\d+) bit\)", text)
    
    if m_pk:
        info["key_size"] = int(m_pk.group(1))
        if "rsa" in raw_algo.lower():
            info["pk_algo"] = "RSA"
        elif "ec" in raw_algo.lower() or "dsa" in raw_algo.lower():
            info["pk_algo"] = "ECC"
        else:
            info["pk_algo"] = raw_algo
    else:
        info["key_size"] = 0
        info["pk_algo"] = raw_algo

    # Signature algorithm
    m = re.search(r"Signature Algorithm:\s*(.+?)\n", text)
    info["sig_algo"] = m.group(1).strip() if m else "?"

    # Parse validity dates for year calc
    for field in ["not_before", "not_after"]:
        date_str = info[field]
        try:
            dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
            info[field + "_year"] = dt.year
        except:
            try:
                dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y GMT")
                info[field + "_year"] = dt.year
            except:
                info[field + "_year"] = 0

    # Check if this is a Chinese CA (CN/O contains China-related keywords)
    subj = info["subject"]
    cn_keywords = ["China", "CFCA", "CNNIC", "WoSign", "TrustAsia", "BJCA",
                   "北京", "中国", "上海", "浙江", "广东", "网银", "国密",
                   "CHINANET", "CHINATELECOM", "Chinanet", "ChinaNet"]
    info["is_china"] = any(kw.lower() in subj.lower() for kw in cn_keywords)

    return info

# Main
certs = parse_pem(CACERT)
print(f"Total certs: {len(certs)}")

results = []
china_results = []
for i, pem in enumerate(certs):
    info = get_cert_info(pem)
    if info:
        results.append(info)
        if info["is_china"]:
            china_results.append(info)
    if (i+1) % 20 == 0:
        print(f"  Parsed {i+1}/{len(certs)}...")

# Statistics
total = len(results)
china_total = len(china_results)
non_china = total - china_total

def count(seq, key, val):
    return sum(1 for x in seq if x.get(key) == val)

# Algorithm distribution
rsa_total = count(results, "pk_algo", "RSA")
ecc_total = count(results, "pk_algo", "ECC")
china_rsa = count(china_results, "pk_algo", "RSA")
china_ecc = count(china_results, "pk_algo", "ECC")

# NIST timeline mapping
def nist_zone(year):
    if year == 0:
        return "unknown"
    if year <= 2030:
        return "<=2030 (高风险)"
    elif year <= 2035:
        return "2030-2035 (过渡期)"
    else:
        return ">2035 (越线)"

nist_all = {}
nist_china = {}
nist_non_china = {}
for r in results:
    zone = nist_zone(r["not_after_year"])
    nist_all[zone] = nist_all.get(zone, 0) + 1
    if r["is_china"]:
        nist_china[zone] = nist_china.get(zone, 0) + 1
    else:
        nist_non_china[zone] = nist_non_china.get(zone, 0) + 1

# Key size distribution
key_dist = {}
for r in results:
    ks = r["key_size"]
    label = f"{ks}bit" if ks else "unknown"
    key_dist[label] = key_dist.get(label, 0) + 1

# Signature algorithm distribution
sig_dist = {}
for r in results:
    sa = r["sig_algo"]
    sig_dist[sa] = sig_dist.get(sa, 0) + 1

# Generate report
lines = [
    "# Mozilla 根证书商店 PQC 就绪度快照",
    "",
    f"> 数据来源: curl.se/ca/cacert.pem (Mozilla NSS 信任库)",
    f"> 快照时间: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
    f"> 根证书总数: {total}",
    "",
    "---",
    "",
    "## 1. 算法分布",
    "",
    "### 全部根证书",
    f"| 算法 | 数量 | 占比 |",
    f"|------|------|------|",
    f"| RSA | {rsa_total} | {rsa_total/total*100:.1f}% |",
    f"| ECC | {ecc_total} | {ecc_total/total*100:.1f}% |",
    f"| **合计** | **{total}** | **100%** |",
    "",
    "### 中国 CA 根证书",
    f"| 算法 | 数量 | 占比 |",
    f"|------|------|------|",
    f"| RSA | {china_rsa} | {china_rsa/china_total*100:.1f}% |" if china_total else "| RSA | 0 | N/A |",
    f"| ECC | {china_ecc} | {china_ecc/china_total*100:.1f}% |" if china_total else "| ECC | 0 | N/A |",
    f"| **合计** | **{china_total}** | **100%** |" if china_total else "| **合计** | **0** | **N/A** |",
    "",
    "### 非中国根证书",
    f"| 算法 | 数量 | 占比 |",
    f"|------|------|------|",
    f"| RSA | {count(results, 'pk_algo', 'RSA') - china_rsa} | {(non_china and (non_china - count(results, 'pk_algo', 'ECC')))/non_china*100:.1f}% |",
    f"| ECC | {count(results, 'pk_algo', 'ECC') - china_ecc} | {ecc_total/non_china*100:.1f}% |",
    f"| **合计** | **{non_china}** | **100%** |",
    "",
    "## 2. 密钥长度分布",
    "",
    "| 密钥长度 | 数量 | 占比 |",
    "|----------|------|------|",
]
for label in sorted(key_dist.keys()):
    lines.append(f"| {label} | {key_dist[label]} | {key_dist[label]/total*100:.1f}% |")

lines += [
    "",
    "## 3. 签名算法分布（Top 10）",
    "",
    "| 签名算法 | 数量 | 占比 |",
    "|----------|------|------|",
]
sorted_sig = sorted(sig_dist.items(), key=lambda x: -x[1])
for sa, cnt in sorted_sig[:10]:
    lines.append(f"| {sa} | {cnt} | {cnt/total*100:.1f}% |")

lines += [
    "",
    "## 4. NIST IR 8547 迁移时间线映射",
    "",
    "根证书到期年份 → NIST 迁移阶段:",
    "",
    "### 全部根证书",
    "| NIST 阶段 | 数量 | 占比 |",
    "|-----------|------|------|",
]
for zone in ["<=2030 (高风险)", "2030-2035 (过渡期)", ">2035 (越线)", "unknown"]:
    cnt = nist_all.get(zone, 0)
    lines.append(f"| {zone} | {cnt} | {cnt/total*100:.1f}% |")

lines += [
    "",
    "### 中国 CA 根证书",
    "| NIST 阶段 | 数量 | 占比 |",
    "|-----------|------|------|",
]
for zone in ["<=2030 (高风险)", "2030-2035 (过渡期)", ">2035 (越线)", "unknown"]:
    cnt = nist_china.get(zone, 0)
    pct = cnt/china_total*100 if china_total else 0
    lines.append(f"| {zone} | {cnt} | {pct:.1f}% |")

lines += [
    "",
    "### 非中国根证书",
    "| NIST 阶段 | 数量 | 占比 |",
    "|-----------|------|------|",
]
for zone in ["<=2030 (高风险)", "2030-2035 (过渡期)", ">2035 (越线)", "unknown"]:
    cnt = nist_non_china.get(zone, 0)
    pct = cnt/non_china*100 if non_china else 0
    lines.append(f"| {zone} | {cnt} | {pct:.1f}% |")

lines += [
    "",
    "## 5. 中国 CA 根证书清单",
    "",
    "| 序号 | Subject | 算法 | 密钥长度 | 签名算法 | 到期年份 |",
    "|------|---------|------|----------|----------|----------|",
]
for i, r in enumerate(china_results, 1):
    lines.append(f"| {i} | {r['subject'][:60]} | {r['pk_algo']} | {r['key_size']}bit | {r['sig_algo'][:30]} | {r['not_after_year']} |")

lines += ["", "---", "", "## 6. 关键发现", ""]

# Shor vulnerability
shor_vuln = rsa_total + ecc_total  # RSA and ECC are both Shor-vulnerable
china_shor = china_rsa + china_ecc

lines.append(f"- **全部 121 个 Mozilla 根证书中，{shor_vuln} 个（{shor_vuln/total*100:.1f}%）使用 RSA 或 ECC 算法，均受 Shor 算法威胁。**")
lines.append(f"- 中国 CA 根证书 {china_total} 个，其中 {china_shor} 个（{china_shor/china_total*100:.1f}%）使用量子脆弱算法。" if china_total else "- 未检测到中国 CA 根证书（关键词匹配可能不完整）。")
lines.append(f"- NIST 2030 高风险期（<= 2030 年到期）根证书: {nist_all.get('<=2030 (高风险)', 0)} 个。")
lines.append(f"- NIST 2035 截止线后仍有效的根证书（>2035 年到期）: {nist_all.get('>2035 (越线)', 0)} 个——这些根不会自然轮换，需主动迁移。")
lines.append("")
lines.append("### 对中国 CA 生态的观察")
lines.append("")

# Find some Chinese CA details
for r in china_results[:5]:
    lines.append(f"- {r['subject'][:50]}: {r['pk_algo']} {r.get('key_size',0)}bit, 到期 {r['not_after_year']}")

lines += [
    "",
    "---",
    "",
    "## 7. 数据质量说明",
    "",
    "- 使用 Mozilla NSS 信任库（curl.se/ca/cacert.pem），包含 121 个根证书",
    "- 中国 CA 检测基于 Subject 字段关键词匹配（CFCA/CNNIC/WoSign/TrustAsia/BJCA 及中文关键词）",
    "- 此快照仅覆盖 Mozilla 信任库中的根证书，不包括：",
    "  - 中国特有浏览器（360/QQ）的自有信任库",
    "  - 国密 SM2 证书链（部分不在 Mozilla 商店中）",
    "  - 政府/金融行业的专有根",
    "- 完整普查需要结合 CCADB V5 CSV、Chrome root_store、中国特有信任库",
]

Path(OUT).write_text("\n".join(lines))
print(f"\nDone! Report saved to {OUT}")
print(f"Total: {total} roots | China: {china_total} | RSA: {rsa_total} | ECC: {ecc_total}")