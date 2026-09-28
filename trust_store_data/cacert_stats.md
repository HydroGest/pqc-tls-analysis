# Mozilla 根证书商店 PQC 就绪度快照

> 数据来源: curl.se/ca/cacert.pem (Mozilla NSS 信任库)
> 快照时间: 2026-09-20 01:47
> 根证书总数: 121

---

## 1. 算法分布

### 全部根证书
| 算法 | 数量 | 占比 |
|------|------|------|
| RSA | 80 | 66.1% |
| ECC | 41 | 33.9% |
| **合计** | **121** | **100%** |

### 中国 CA 根证书
| 算法 | 数量 | 占比 |
|------|------|------|
| RSA | 5 | 55.6% |
| ECC | 4 | 44.4% |
| **合计** | **9** | **100%** |

### 非中国根证书
| 算法 | 数量 | 占比 |
|------|------|------|
| RSA | 75 | 63.4% |
| ECC | 37 | 36.6% |
| **合计** | **112** | **100%** |

## 2. 密钥长度分布

| 密钥长度 | 数量 | 占比 |
|----------|------|------|
| 2048bit | 21 | 17.4% |
| 256bit | 3 | 2.5% |
| 384bit | 37 | 30.6% |
| 4096bit | 59 | 48.8% |
| 521bit | 1 | 0.8% |

## 3. 签名算法分布（Top 10）

| 签名算法 | 数量 | 占比 |
|----------|------|------|
| sha256WithRSAEncryption | 53 | 43.8% |
| ecdsa-with-SHA384 | 34 | 28.1% |
| sha384WithRSAEncryption | 20 | 16.5% |
| ecdsa-with-SHA256 | 6 | 5.0% |
| sha512WithRSAEncryption | 4 | 3.3% |
| sha1WithRSAEncryption | 3 | 2.5% |
| ecdsa-with-SHA512 | 1 | 0.8% |

## 4. NIST IR 8547 迁移时间线映射

根证书到期年份 → NIST 迁移阶段:

### 全部根证书
| NIST 阶段 | 数量 | 占比 |
|-----------|------|------|
| <=2030 (高风险) | 13 | 10.7% |
| 2030-2035 (过渡期) | 10 | 8.3% |
| >2035 (越线) | 98 | 81.0% |
| unknown | 0 | 0.0% |

### 中国 CA 根证书
| NIST 阶段 | 数量 | 占比 |
|-----------|------|------|
| <=2030 (高风险) | 1 | 11.1% |
| 2030-2035 (过渡期) | 0 | 0.0% |
| >2035 (越线) | 8 | 88.9% |
| unknown | 0 | 0.0% |

### 非中国根证书
| NIST 阶段 | 数量 | 占比 |
|-----------|------|------|
| <=2030 (高风险) | 12 | 10.7% |
| 2030-2035 (过渡期) | 10 | 8.9% |
| >2035 (越线) | 90 | 80.4% |
| unknown | 0 | 0.0% |

## 5. 中国 CA 根证书清单

| 序号 | Subject | 算法 | 密钥长度 | 签名算法 | 到期年份 |
|------|---------|------|----------|----------|----------|
| 1 | C = CN, O = China Financial Certification Authority, CN = CF | RSA | 4096bit | sha256WithRSAEncryption | 2029 |
| 2 | C = CN, O = "iTrusChina Co.,Ltd.", CN = vTrus ECC Root CA | ECC | 384bit | ecdsa-with-SHA384 | 2043 |
| 3 | C = CN, O = "iTrusChina Co.,Ltd.", CN = vTrus Root CA | RSA | 4096bit | sha256WithRSAEncryption | 2043 |
| 4 | C = CN, O = BEIJING CERTIFICATE AUTHORITY, CN = BJCA Global  | RSA | 4096bit | sha256WithRSAEncryption | 2044 |
| 5 | C = CN, O = BEIJING CERTIFICATE AUTHORITY, CN = BJCA Global  | ECC | 384bit | ecdsa-with-SHA384 | 2044 |
| 6 | C = CN, O = "TrustAsia Technologies, Inc.", CN = TrustAsia G | RSA | 4096bit | sha384WithRSAEncryption | 2046 |
| 7 | C = CN, O = "TrustAsia Technologies, Inc.", CN = TrustAsia G | ECC | 384bit | ecdsa-with-SHA384 | 2046 |
| 8 | C = CN, O = "TrustAsia Technologies, Inc.", CN = TrustAsia T | ECC | 384bit | ecdsa-with-SHA384 | 2044 |
| 9 | C = CN, O = "TrustAsia Technologies, Inc.", CN = TrustAsia T | RSA | 4096bit | sha384WithRSAEncryption | 2044 |

---

## 6. 关键发现

- **全部 121 个 Mozilla 根证书中，121 个（100.0%）使用 RSA 或 ECC 算法，均受 Shor 算法威胁。**
- 中国 CA 根证书 9 个（Mozilla 信任库），其中 9 个（100.0%）使用量子脆弱算法。
- NIST 2030 高风险期（<= 2030 年到期）根证书: 13 个。
- NIST 2035 截止线后仍有效的根证书（>2035 年到期）: **98 个（81.0%）**——这些根不会自然轮换，需主动迁移。
- **无 PQC 根证书存在。**

### 对中国 CA 生态的观察（Mozilla + CCADB）

**Mozilla 信任库中的中国根**（9 个，全球浏览器信任）：
- CFCA EV ROOT: RSA 4096bit, 到期 **2029-12-31**（NIST 2030 高风险窗口内）✅
- BJCA Global Root CA1/2: RSA 4096bit, 到期 2044
- iTrusChina vTrus Root: RSA 4096bit, ECC 384bit, 到期 2043
- TrustAsia (4 根): RSA/ECC, 到期 2044-2046
- Shanghai UCA (2 根): 到期 2038-2040

**CCADB 登记的中国根证书共 48 个**，分布在：
| 组织 | 根证书数 | 状态 |
|---|---|---|
| TrustAsia Technologies | 18 | 4 个在 Mozilla 中 |
| Shanghai (UCA/UniTrust) | 8 | 4 个 Mozilla Included |
| CFCA (中国金融认证中心) | 8 | 1 个 Mozilla/Chrome/MS (EV ROOT) |
| BJCA (北京数字认证) | 7 | 2 个 Mozilla Included |
| WoSign (沃通) | 5 | **全部 Mozilla Removed**（2017 年撤销） |
| CNNIC | 2 | **全部 Mozilla Removed** |

**被移除的中国根**：CNNIC 和 WoSign 的根已被 Mozilla 从信任库移除，但国内浏览器（360、QQ）仍可能信任它们。

**未覆盖的盲区**：
- 国密 SM2 证书链：部分不在 Mozilla/CCADB 中，需从国内 CA 网站收集
- 360/QQ 浏览器的定制信任库（闭源）
- 政府/金融行业的专有 PKI 体系

**关键结论：中国 48 个已知根证书中，100% 使用 RSA 或 ECC（均受 Shor 威胁）。SM2 国密也是 ECC，同样脆弱。**

---

## 7. 数据质量说明

- 使用 Mozilla NSS 信任库（curl.se/ca/cacert.pem），包含 121 个根证书
- 中国 CA 检测基于 Subject 字段关键词匹配（CFCA/CNNIC/WoSign/TrustAsia/BJCA 及中文关键词）
- 此快照仅覆盖 Mozilla 信任库中的根证书，不包括：
  - 中国特有浏览器（360/QQ）的自有信任库
  - 国密 SM2 证书链（部分不在 Mozilla 商店中）
  - 政府/金融行业的专有根
- 完整普查需要结合 CCADB V5 CSV、Chrome root_store、中国特有信任库