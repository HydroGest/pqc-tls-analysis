# 中国特有浏览器/应用信任库根证书调研报告

> 调研日期: 2026-09-20
> 项目: 中国根证书商店 PQC 就绪度普查（大创）
> 方法: 直接抓取各 CA 官网 / 浏览器官网 / CCADB 数据库，交叉验证
> 数据目录: `trust_store_data/china/`（已下载证书）、`trust_store_data/cacert.pem`（Mozilla）、`trust_store_data/ccadb_v5.csv`（CCADB V5）

---

## 1. 调研结论总表

| 来源 | 是否找到 | 公开根证书吗 | URL 来源 | 获取难度 |
|------|---------|-------------|----------|---------|
| **360 安全浏览器** | 部分 | ❌ 未公开独立根列表（基于 Chromium 132 内核） | https://browser.360.cn/ 、https://browser.360.cn/se/help/ | 高（闭源，需安装后从安装目录提取） |
| **QQ 浏览器** | 部分 | ❌ 未公开独立根列表（基于 Chromium/双核） | https://browser.qq.com/ | 高（闭源，需安装后提取） |
| **CFCA 国密根（国家信任源）** | ✅ 找到 | ✅ 公开下载（RAR/ZIP，含 SM2 与 RSA） | https://www.cfca.com.cn/ （"证书链下载"区） | 低（直接下载） |
| **CFCA 生产证书链（SM2/RSA）** | ✅ 找到 | ✅ 公开下载（ZIP，2026-01-08 版） | https://www.cfca.com.cn/upload/生产证书链SM2（20260108）.zip | 低（直接下载） |
| **沃通 WoTrus 国密根** | ✅ 找到 | ✅ 公开下载（SM2 根 + 各省政务 SM2 中间根） | https://www.wotrus.com/ca/chain.html | 低（直接下载） |
| **沃通 WoSign 老根** | ⚠️ 部分 | 官网仅提供 Sectigo 代理根；自有根已被 Mozilla 移除 | https://www.wosign.com/Support/root_crt.htm | 中（已废弃） |
| **BJCA 北京数字认证** | ⚠️ 部分 | 官网 403 无法访问；Mozilla/CCADB 有 BJCA Global Root | https://www.bjca.org.cn/ （403） | 高（网站反爬） |
| **上海 CA（SHECA/UCA）** | ⚠️ 部分 | 官网无根证书下载页；Mozilla 有 UCA 根，CCADB 有 UniTrust 根 | https://www.sheca.com/ | 中 |
| **CNNIC 根** | ✅ 找到（元数据） | 已被 Mozilla/Chrome/MS 移除或禁用 | CCADB V5 CSV | 中（证书可从 CCADB 取） |
| **国家密码管理局（OSCCA/NRCAC 国家根）** | ✅ 找到 | ✅ 通过 CFCA 国家信任源包公开（SM2 根 2042 到期、RSA 根已过期） | https://www.cfca.com.cn/file/gjzsl-sm2.rar | 低 |
| **政务各省 CA（湖南/广西/广东/福建/江西/陕西/贵州/新疆/河南/重庆）** | ✅ 找到 | ✅ 通过 WoTrus 证书体系页公开（SM2 政务根） | https://www.wotrus.com/ca/chain.html | 低 |
| **运营商 CA（中国移动/联通/电信）** | ⚠️ 未单独找到 | 中国联通 SSL 中间 CA 出现在 CCADB（SHECA 签发） | CCADB V5 CSV | 中 |

---

## 2. 已获取的根证书清单

### 2.1 CFCA 国家信任源（National Trust Source, 国家信任源）

**来源**: https://www.cfca.com.cn/ → "服务与支持 → 证书链下载"

| 文件 | 内容 | 提取日期 |
|------|------|---------|
| `cfca_gjzsl-sm2.rar` → `gjzsl-sm2/` | **国家根 SM2 信任链**：`cfca_gj_cs_sm2.p7b`（含 **ROOTCA/O=NRCAC 国家 SM2 根** + CFCA CS SM2 CA）、`oca1sm2.cer`、`oca11sm2.cer` | 2026-09-20 |
| `cfca_gjzsl.rar` → `gjzsl-rsa/` | **国家根 RSA 信任链**：`CFCA-RSA2048.p7b`（含 **ROOTCA/O=OSCCA 国家 RSA 根** + CFCA CS OCA11） | 2026-09-20 |
| `生产证书链SM2（20260108）.zip` | CFCA 生产 SM2 证书链（GT/EV/CS/Identity 各 CA 及 OCA） | 2026-09-20 |
| `生产证书链RSA（20260108）.zip` | CFCA 生产 RSA 证书链（ACS/CS/Identity） | 2026-09-20 |

### 2.2 沃通 WoTrus 国密 SM2 根证书（全部公开下载）

**来源**: https://www.wotrus.com/ca/chain.html

| 文件 | 证书名 | 算法 | 有效期 | 序列号 |
|------|--------|------|--------|--------|
| `wotrus_sm2_ca.cer` | WoTrus SM2 CA（issuer: ROOTCA） | SM2 | 2022-01-20 ~ 2033-07-23 | 1e607bb74148c1a0afd5e2c17decb4e4 |
| `wotrus_sm2_root.cer` | WoTrus SM2 Root | SM2 | 2024-10-09 ~ 2049-10-03 | 32b36203c5fdc53458db3b7cb61cc4f6 |
| `wotrus_gca.cer` | WoTrus GCA（issuer: WoTrus SM2 Root） | SM2 | 2024-10-09 ~ 2044-10-04 | 1995e235a56c8b2ac609d63784a1549a |
| `wotrus_sm2_global.crt` | 国密SM2根证书（国际信任体系） | SM2 | 2019-04-04 ~ 2044-04-04 | 0081c354bd60b92cbb5e8155a34238fad4 |
| `wotrus_sm2_ssl_v3.crt` | 国密SM2服务器根证书V3 | SM2 | 2019-04-04 ~ 2034-04-04 | 0b82eb32c6cc553c1729a08a80e93094 |
| `wotrus_sm2_tsa.crt` | 国密SM2时间戳根证书 | SM2 | 2019-04-04 ~ 2034-04-04 | 0e9a6913b7669ea641ee8b09af42642d |
| `hunan_sm2.crt` | 湖南电子政务国密SM2服务器根证书 | SM2 | 2019-04-04 ~ 2034-04-04 | 19f30dadeeb8c6c2aade8455ee968183 |
| `guangxi_sm2.crt` | 广西电子政务国密SM2服务器根证书 | SM2 | 2019-04-04 ~ 2034-04-04 | 00ab6d7415778e380aa131bc73c5d9fa7c |
| `guangdong_sm2.cer` | 广东电子政务国密SM2服务器根证书 | SM2 | 2019-11-12 ~ 2034-11-12 | 2f3e6a5091c97689bdff0afb7b704e00 |
| `cqcca_sm2.crt` | CQCCA国密SM2服务器根证书（重庆） | SM2 | 2019-04-29 ~ 2034-04-29 | 30c591e35058ea1ecb97ea33769a1e78 |
| `fujian_sm2.crt` | 福建省CA国密SM2服务器根证书 | SM2 | 2019-04-29 ~ 2034-04-29 | 1072663c1a3316220be959d126ddc652 |
| `henan_sm2.crt` | 河南省电子政务国密SM2服务器根证书 | SM2 | 2019-04-29 ~ 2034-04-29 | 48e0a01fa9b6b7057193a98826b4281e |
| `jiangxi_sm2.crt` | 江西CA国密SM2服务器根证书 | SM2 | 2019-04-29 ~ 2034-04-29 | 00bc5fe98f17b1a8125ffec60f4bd15550 |
| `xinjiang_sm2.crt` | 新疆数字证书认证中心（SM2） | SM2 | 2019-11-12 ~ 2034-11-12 | 3555fcf8dfce79bc6ab8825ededf7901 |
| `shanxi_sm2.cer` | 陕西CA国密SM2服务器根证书 | SM2 | 2019-11-12 ~ 2034-11-12 | 00f859c549ff16ecb7d39b908fc0f8515f |
| `guizhou_sm2.cer` | 贵州CA(GZCA)国密SM2服务器根证书 | SM2 | 2019-11-12 ~ 2034-11-12 | 1e4e483cff0eb534c612e97dc8057615 |

> 注：WoTrus 页面还有更多 SM2 根（国富安 CA、华测 CA、中国教育 eCard 等），可按需批量抓取：
> https://www.wotrus.com/root/wtsm2_guofuan.crt 、https://www.wotrus.com/root/wtsm2_huace2.crt 等。

### 2.3 CFCA SM2 根（生产证书链，本地已提取并解析）

| 文件（本地） | Subject | 有效期 | 签名算法 OID | 确认 |
|-------------|---------|--------|-------------|------|
| `extracted_sm2/nrcac_root_0.cer` | CN=ROOTCA, O=NRCAC, C=CN（**国家 SM2 根**） | 2012-07-14 ~ 2042-07-07 | 1.2.156.10197.1.501（SM3withSM2） | ✅ |
| `extracted_sm2/nrcac_rsa_root_0.cer` | CN=ROOTCA, O=OSCCA, C=CN（**国家 RSA 根**） | 2005-08-28 ~ **2025-08-23（已过期）** | 1.2.840.113549.1.1.5（sha1WithRSA） | ✅ |
| `extracted_sm2/CFCA_GT_SM2_CA.cer` | CN=CFCA GT SM2 CA | 2012-08-21 ~ 2042-08-21 | 1.2.156.10197.1.501 | ✅ |
| `extracted_sm2/CFCA_EV_SM2_ROOT.cer` | CN=CFCA EV SM2 ROOT | 2012-08-08 ~ 2029-12-31 | 1.2.156.10197.1.501 | ✅ |
| `extracted_sm2/CFCA_CS_SM2_CA.cer` | CN=CFCA CS SM2 CA | 2012-08-31 ~ 2042-08-24 | 1.2.156.10197.1.501 | ✅ |
| `extracted_sm2/CFCA_Identity_SM2_CA.cer` | CN=CFCA Identity SM2 CA | 2015-06-30 ~ 2040-06-30 | 1.2.156.10197.1.501 | ✅ |

---

## 3. SM2 国密根专项

### 3.1 关键结论

1. **国密 SM2 根证书是公开下载的**。CFCA 和 WoTrus 均在官网上直接提供 PEM/DER/P7B 格式的根证书与中间证书链下载，无需申请。
2. **算法确认**: 所有国密根使用 **SM2 椭圆曲线（OID 1.2.156.10197.1.301, sm2p256v1）** 与 **SM3withSM2 签名（OID 1.2.156.10197.1.501）**。Python `cryptography` 库不支持该曲线，属预期（openssl 3.x 需编译 `enable-sm2` 才能解析）。
3. **有效期普遍很长**（20~30 年）:
   - 国家 SM2 根 (NRCAC): 2012-2042（30 年）
   - CFCA GT/CS SM2 CA: 2042 年到期
   - WoTrus SM2 Root: 2049 年到期
   - 各省政务 SM2 根: 2034 年到期
   - **这些根在 NIST 2035 迁移截止线之后仍有效，属于"不会自然轮换"的高风险根。**
4. **国家 RSA 根 (OSCCA) 已于 2025-08-23 过期** —— 这是一个重要发现：若仍被旧版国产浏览器信任，构成风险。

### 3.2 SM2 根 vs 国际根体系（双层架构）

```
国家信任体系（国密）:
  国家根 ROOTCA (NRCAC, SM2, 2012-2042)
    └── CFCA CS SM2 CA / WoTrus SM2 CA（国密中间根）
         └── 各省政务/金融 SM2 根

国际信任体系:
  CFCA EV ROOT (RSA, 2012-2029) —— 唯一进入 Mozilla/Chrome/MS 的 CFCA 根
  WoTrus/沃通根 —— 2017 年因不透明事件被 Mozilla 移除
  CNNIC ROOT —— 被 Mozilla 移除、MS 禁用
```

---

## 4. 浏览器信任库方法论

### 4.1 国产浏览器信任库现状（调研结论）

- **360 安全浏览器**: 官网宣传基于 **Chromium 132 内核**（https://browser.360.cn/）。官方帮助中心（https://browser.360.cn/se/help/）无根证书列表文档。**未找到公开的 360 自有根证书列表**。360 的信任库 = Chromium 内置根 + 国密根（其"360安全浏览器"同时宣称支持国密 SSL，参考沃通国密 SSL 兼容性列表）。
- **QQ 浏览器**: 官网（https://browser.qq.com/）无信任库文档。基于 Chromium + 自有双核。**未找到公开根列表**。
- **结论**: 国产浏览器的"中国特有"部分不是一份公开清单，而是**内置国密根（国家根 NRCAC + 国内 CA 根）+ 可能保留已被国际移除的根（如 CNNIC、WoSign）**。严谨获取的唯一途径是**安装浏览器后从其安装目录提取**（见 4.2）。

### 4.2 可复现的提取方法（供后续工作）

| 方法 | 适用浏览器 | 操作 |
|------|-----------|------|
| 提取 cert8.db / cert9.db | Firefox/基于 NSS 的浏览器 | 用 `certutil -L -d sql:<profile>` 导出 |
| Chromium root_store | Chromium 系（360/QQ 均基于 Chromium） | 从 chromium.googlesource.com/chromium/src/+/main/net/data/ssl/root_store/ 获取；国产浏览器通常随版本 fork |
| 安装后目录抓包 | 360/QQ | 安装到 Windows/Linux 后搜索 *.db / *.store / cacert.pem / 国密根文件 |
| chrome://settings/certificates | 所有 Chromium 系 | 手动导出但不适合大批量 |

### 4.3 "中国特有信任库"的严谨定义（universe 定义）

本项目建议将 **"中国特有信任库"** 定义为以下并集（每项都可溯源）：

```
U_CN = U_national_root        # 国家根: NRCAC SM2 根 + OSCCA RSA 根（通过 CFCA 国家信任源包）
     ∪ U_cn_ca_roots          # 中国 CA 根（CCADB 登记的 48 个，含 7 个 CA Owner）
     ∪ U_sm2_roots            # 国密 SM2 根（CFCA 生产链 + WoTrus 全部 SM2 根 + 各省政务 SM2 根）
     ∪ U_cn_browser_extra     # 国产浏览器附加根（360/QQ 闭源，标注"未获取"，需提取）
     − U_international        # 已在 Mozilla/Chrome/MS 中的（如 CFCA EV ROOT、BJCA Global、vTrus、TrustAsia）
```

其中 **U_international 的补集**（中国特有 = U_CN 中不在 Mozilla/Chrome/MS 的根）是论文的核心分析对象。**CCADB V5 CSV 提供权威的"是否在 Mozilla/Chrome/MS"标注**（本报告第 1 节的 CA 状态均来自该 CSV）。

---

## 5. CCADB 中中国 CA 根证书全景（V5 快照）

数据源: `trust_store_data/ccadb_v5.csv`（2026-09-20 抓取，10270 条记录），按 CA Owner 统计：

| CA Owner | 记录数 | 根证书 | 国际信任状态要点 |
|----------|--------|--------|-----------------|
| TrustAsia Technologies, Inc. | 18 | 4 根（RSA+ECC） | 4 根在 Mozilla；其余不在 |
| China Financial Certification Authority (CFCA) | 22 | 9 根 | 仅 **CFCA EV ROOT** 进 Mozilla/Chrome/MS；CFCA Global RSA/ECC ROOT 均不在；CFCA GT CA 被 MS Disabled；CFCA Identity CA 仅 MS 信任 |
| China Internet Network Information Center (CNNIC) | 9 | 2 根 | **全部被 Mozilla Removed / MS Disabled** |
| Shanghai Electronic Certification Authority (SHECA/UCA) | 118 | 12 根 | UCA EV Root、UCA Global G2 进 Mozilla/Chrome/MS；UCA Root、UCA Global Root 被 MS Disabled；UniTrust Global 系列根均不在 |
| WoSign CA Limited | 48 | 5 根 | **全部被 Mozilla Removed / MS Disabled**（2017 年事件）；含 360 EV/OV Server CA 中间根（360 曾用沃通根） |
| iTrusChina Co., Ltd. | 25 | 2 根 | vTrus Root CA、vTrus ECC Root CA 进 Chrome + Mozilla |
| BEIJING CERTIFICATE AUTHORITY Co., Ltd. | 9 | 7 根 | BJCA Global Root CA1/2 进 Mozilla；其余 OCA 中间根 |

> 详细逐条状态已存于 /tmp/dsh-spill-1VerZa/session-d5704b5b0a59/0b7b81839284-bash.txt（可再跑脚本重现）。

---

## 6. 局限声明（未获取项）

| 项目 | 状态 | 说明 |
|------|------|------|
| 360 浏览器自有根证书列表 | **未获取** | 闭源，官网/帮助中心无公开文档；需安装浏览器后从安装目录提取（Windows 下可尝试 `%APPDATA%\360se6\User Data` 及安装目录） |
| QQ 浏览器自有根证书列表 | **未获取** | 闭源，官网无文档 |
| UC / 猎豹 / 搜狗 / 2345 浏览器信任库 | **未调研**（超出本次范围） | 同属 Chromium 系，推测同类处理 |
| BJCA 官网根证书下载页 | **未获取** | https://www.bjca.org.cn/ 返回 403（反爬）；其 SM2 根未在其官网找到，但 BJCA Global 根在 Mozilla/CCADB 有完整元数据 |
| SHECA 官网根证书下载页 | **未获取** | 官网无下载页；根在 Mozilla/CCADB 有元数据 |
| 运营商专有 PKI（中国移动/电信自建根） | **未找到** | 无公开证据表明运营商维护独立 TLS 根；联通 SSL 中间 CA 出现在 CCADB（由 SHECA 签发），可继续深挖 |
| 金融 IC 卡根（银联/网联） | **未获取** | CFCA 提供"金融IC卡根服务平台相关手册"（https://www.cfca.com.cn/upload/IC/金融IC卡根服务平台相关手册（20250423）.zip），但根证书本身未直接公开下载，需按手册流程申请 |
| WoSign 自有老根（CA 沃通根证书等） | 元数据已获取 | Mozilla 已移除；本地可从 CCADB 或互联网档案馆取回原始 PEM |
| 国家根 (NRCAC/OSCCA) 是否被 360/QQ 信任 | **无法从官网确认** | 间接证据：沃通国密 SSL 宣称兼容 360 浏览器 → 360 必然内置国家 SM2 根 |

---

## 7. 下一步建议

1. **批量抓取 WoTrus 全部 SM2 根**（含国富安/华测/教育 eCard 等剩余条目），生成 `wotrus_sm2_all.pem` 合并文件。
2. **用脚本从 CCADB 导出中国根证书本体**（CCADB 提供证书下载 URL 字段，需确认 V5 CSV 中字段），与 Mozilla 根做集合差集，得到"中国特有但不入国际信任库"的正式清单。
3. **在 Windows 沙箱中安装 360/QQ 浏览器**，提取其内置根数据库，与 Chromium root_store 做 diff，识别 360/QQ 的附加中国根（重点验证 CNNIC/WoSign/NRCAC 是否仍在）。
4. **将已获取的 SM2 根（约 25 个）批量解析**并纳入 PQC 普查：全部为 SM2（ECC，受 Shor 威胁），其中大部分有效期超过 NIST 2035 迁移截止线。
5. 尝试联系 CFCA/沃通商务渠道索取"国家根信任列表"官方清单（若论文需要权威背书）。

---

## 附录 A: 关键 URL 索引

- CFCA 证书链下载（国家信任源 RSA/SM2、生产链 RSA/SM2、测试链）: https://www.cfca.com.cn/ （服务与支持 → 证书链下载）
- 国家信任源 SM2 链: https://www.cfca.com.cn/file/gjzsl-sm2.rar
- 国家信任源 RSA 链: https://www.cfca.com.cn/file/gjzsl.rar
- 生产证书链 SM2 (20260108): https://www.cfca.com.cn/upload/生产证书链SM2（20260108）.zip
- WoTrus 证书体系（全部 SM2 根可下载）: https://www.wotrus.com/ca/chain.html
- 沃通官网: https://www.wosign.com/ 、根证书下载: https://www.wosign.com/Support/root_crt.htm
- 360 安全浏览器: https://browser.360.cn/ 、帮助中心: https://browser.360.cn/se/help/
- QQ 浏览器: https://browser.qq.com/
- BJCA（403）: https://www.bjca.org.cn/
- 上海 CA: https://www.sheca.com/
- CCADB V5 CSV: https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatV5
- Mozilla cacert.pem: https://curl.se/ca/cacert.pem
