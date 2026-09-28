# 中国 Top 1000 网站 TLS 证书链主动扫描：工具技术栈调研 + 合规/法律边界

> 项目：大创方向一「中国 Top 1000 网站 TLS 证书链主动扫描（量子脆弱性分析）」前期调研
> 执行环境：中山大学校园网/实验室，AMD Ryzen 7 7840HS（8C/16T），Ubuntu 24.04，16GB RAM
> 目标：确定扫描工具选型（技术栈）+ 明确中国境内主动扫描的合规边界
> 文档日期：2025-11（基于 GitHub 上游 master 源码核对）

---

## 0. 结论速览（TL;DR）

| 决策点 | 结论 |
|---|---|
| 主扫描器（方案 A） | **ZGrab2 TLS 模块**（配合域名列表直连，**不需要 ZMap/masscan**） |
| 保守替代（方案 B） | **openssl s_client 脚本化** 或 **Python asyncio + pyOpenSSL** |
| 深度校验（抽样） | **testssl.sh**（≤100 个抽样站点） |
| 端口预探测 | **不需要**——目标为已知 Top-1000 域名，直接 DNS 解析 + TCP 443 连接即可，避免 SYN 扫描面 |
| 证书链完整性 | ✅ ZGrab2/zcrypto 输出 `server_certificates.chain`（服务器实际下发的全部证书，含中间 CA）；AIA 缺失的中间 CA 可事后补链 |
| TLS 版本 | ✅ 支持 TLS 1.2/1.3；可用 `--min-version`/`--max-version` 固定 TLS 1.2（0x0303） |
| 国密 SM2 | ❌ **ZGrab2/zcrypto 不支持 SM2**（无 SM4/SM3 密码套件、无 SM2 公钥解析、无 SM2 曲线）——**本调研的关键负面结论**，见第 2 节 |
| 合规路径 | 以**被动数据（CT 日志 + CA 国密证书库）为主** + **主动扫描最小化样本**，扫描前向学校网络中心报备、速率 ≤300 conn/s、排除敏感目标 |

---

## 1. 技术栈决策表

### 1.1 候选工具对比

| 维度 | ZGrab2 | ZMap | masscan | openssl s_client | Python (ssl/asyncio) | testssl.sh |
|---|---|---|---|---|---|---|
| 定位 | L7 应用层握手扫描器（专为 TLS 设计） | L4 无状态单包扫描器 | L4 高速端口扫描器 | CLI 单次握手 | 自研并发握手 | 单主机深度 TLS 配置审计 |
| 吞吐量 | 数千–数万握手/秒（受带宽/RTT 限制） | ~140 万 pps（1Gbps 口），全网 <45 分钟 | ~1000 万 pps（声明上限） | ~10–50 握手/秒/进程，多进程并行可上百/秒 | asyncio 500–2000 并发，1000 conn/s 现实可行 | 极慢，单主机全量检查 1–3 分钟 |
| TLS 1.2/1.3 | ✅ 均支持（zcrypto，含 TLSv1.3 握手实现） | ❌ 不适用（仅 SYN/ICMP/DNS/UDP 探测） | ❌ 仅 banner 级 SSL 探测（非完整握手） | ✅ `-tls1_2`/`-tls1_3` | ✅ `ssl.TLSVersion.TLSv1_2/TLSv1_3` | ✅ 完整版本矩阵检测 |
| 证书链完整性 | ✅ 完整记录服务器下发的 `server_certificates.chain` + `raw` DER + 解析后字段 | ❌ | ❌（banner 太浅） | ✅ `-showcerts` 输出全部链 | ⚠️ 标准库不暴露对端链，需 pyOpenSSL `get_peer_cert_chain()` | ✅ 完整证书信息 |
| 国密 SM2 | ❌ 不支持（见 2.1） | ❌ | ❌ | ✅ 证书解析（OpenSSL ≥1.1.1 支持 SM2 证书/密钥），❌ 标准 OpenSSL 无 TLCP 套件 | ❌ 标准库/cryptography 不支持；pyOpenSSL 走 OpenSSL 后端可解析 SM2 证书 | ✅ 可检测 SM2（依赖 OpenSSL/GMSSL 后端） |
| 资源占用（16GB RAM） | 极低（Go 运行时 + 并发协程，1000 并发 <100MB） | 极低（<10MB） | 极低 | 每进程 ~10MB，16 并行 ~160MB | 低（注意 fd 上限 ulimit） | 低 |
| 部署难度 | 需 Go ≥1.23 + `make`，编译后单二进制，简单 | 需 root（raw socket）+ cmake 构建 | 需 root + `make` | 系统自带 | pip 安装，简单 | 免安装直接运行 |
| 输出格式 | JSONL（zcrypto 结构化 schema，含算法/密钥/有效期/指纹） | 纯 IP 列表 | XML/JSON/grepable | 文本（需解析） | 自定 | 彩色文本/CSV/JSON |
| 学术论文常用度 | ⭐⭐⭐⭐⭐（行业标准） | ⭐⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐（早期论文/补链） | ⭐⭐⭐ | ⭐⭐ |
| 合规友好度 | 高（标准握手、握手后即断开、不发送载荷） | 低（SYN 扫描特征明显，易触发告警） | 低（同 ZMap） | 高 | 高 | 高 |

### 1.2 学术论文标准工具链（引用依据）

- **ZMap 原始论文**：Durumeric, Wustrow, Halderman, "ZMap: Fast Internet-Wide Scanning and Its Security Applications", USENIX Security 2013 —— 提出 ZMap（L4）＋ ZGrab（L7 握手）流水线，并在文中专节讨论扫描伦理（速率、退出机制、USENIX 社区讨论）。
  来源：https://zmap.io/paper.pdf （ZMap README 引文页 https://github.com/zmap/zmap ）
- **TLS 证书生态系统测量**：Durumeric, Kasten, Bailey, Halderman, "Analysis of the HTTPS Certificate Ecosystem", **IMC 2013** —— 用 ZMap 扫 IPv4 全空间 443 端口，再以 ZGrab 抓 TLS 握手与完整证书链，是"证书链主动扫描"的奠基性论文（本项目方向一最直接对标论文）。
- **DH 安全测量**：Adrian et al., "Imperfect Forward Secrecy: How Diffie-Hellman Fails in Practice", CCS 2015 —— 同样 ZMap+ZGrab 全互联网 TLS 握手。
- **Censys**：Durumeric et al., "Censys: A Search Engine Backed by Internet-Wide Scanning", CCS 2015 —— 将 ZMap+ZGrab 流水线商业化/常态化（10Gbps 级），输出 scans.io 开放数据集。
- **Heartbleed**：Durumeric et al., "The Matter of Heartbleed", IMC 2014 —— ZMap+ZGrab 快速测量。
- **10Gbps 扫描**：Adrian et al., "Zippier ZMap: Internet-Wide Scanning at 10 Gbps", WOOT 2014。
- **十年回顾（含伦理演进）**："Ten Years of ZMap", arXiv:2406.15585（2024），https://arxiv.org/abs/2406.15585 —— 回顾扫描速率/退出机制/与 CERT 协调等社区规范演变。

> 结论：**2025 年 TLS 测量的论文标准工具链 = ZMap（L4，可选）＋ ZGrab2（L7）+ zcrypto 输出 schema**。testssl.sh 多用于"少数量、深配置"的研究；Python/openssl 脚本多用于纵向（longitudinal）小规模复扫。

### 1.3 推荐方案

#### 方案 A（主推）：ZGrab2 TLS 模块 + 域名列表直连

```bash
# 目标列表（Top-1000 域名 → CSV，每行一个域名）
# 安装
git clone https://github.com/zmap/zgrab2.git && cd zgrab2 && make   # 需 Go >= 1.23

# 第一遍：固定 TLS 1.2（兼容性最好的基线，中文站点老旧服务器多）
cat targets.csv | ./zgrab2 tls --min-version=0x0303 --max-version=0x0303 \
    --tls-handshake-timeout=10s --output-file=tls12.jsonl

# 第二遍（可选）：TLS 1.3 对比
cat targets.csv | ./zgrab2 tls --output-file=tls13.jsonl

# 后处理：解析 zcrypto JSON（certificate/chain 每环的 key_algorithm、rsa/ecdsa 长度、
# signature_algorithm、validity.start/end、fingerprint_sha256），做量子脆弱性判定
```

要点：
- **不需要 ZMap/masscan**：目标是已知 1000 个域名，无需全网端口探测。直接 DNS 解析 + TCP 443 连接即可，规避了 SYN 扫描的全部合规与误报风险。ZMap 仅在将来要扩展为"IP 空间发现"时才需要。
- **证书链完整性**：ZGrab2 的 TLS 模块记录 `handshake_log.server_certificates` = `{certificate（叶子）, chain（服务器下发的其余证书）, validation（信任链校验结果）}`（来源：zcrypto schema `tls/tls_handshake.go: ServerHandshake`，https://github.com/zmap/zcrypto/blob/master/zcrypto_schemas/zcrypto.py ）。每个证书含 `raw`（DER）与 `parsed`（算法/密钥/有效期等）。若服务器漏发中间 CA，可用 `parsed.extensions.authority_info_access.issuer_urls`（AIA，zcrypto 已解析输出）离线补链。
- **TLS 1.2 固定**：`--min-version/--max-version` 取值即 TLS 版本号（0x0303=TLS1.2），确认自 ZGrab2 源码 `tls.go`（https://github.com/zmap/zgrab2/blob/master/tls.go ）。另支持 `--cipher-suite`（限定套件）、`--client-hello`（注入自定义 base64 ClientHello）、`--no-sni`、`--sct`。
- **吞吐**：1000 目标在 100–300 conn/s 下几分钟内完成；单目标并发建议 ≤8，避免被 WAF 限流。
- **速率控制**：ZGrab2 本身按输入流速率消费（读一行扫一个），用 `pv`/`rate` 工具或分块输入控制速率即可。

#### 方案 B（保守替代）：openssl s_client 脚本化

```bash
# 每目标一次握手，-showcerts 输出全链，-tls1_2 固定版本，-servername 指定 SNI
# 16 并行 ≈ 100-300 conn/s
cat targets.txt | xargs -P 16 -I{} sh -c \
  'echo | timeout 10 openssl s_client -connect {}:443 -servername {} -tls1_2 -showcerts \
    2>/dev/null > out/{}.pem'
# 用 openssl x509 -text 逐环解析（支持 SM2 证书）
```

- 优点：零部署、行为最"像普通浏览器"、**OpenSSL 3.x 可解析 SM2 证书**（`-sm2`/SM2 OID 支持自 1.1.1 起），是 SM2 链离线解析的金标准。
- 缺点：每握手一次进程启动开销（~5–15ms），1000 目标量级可接受；输出文本需自写解析。

#### 方案 C（Python 自研）：仅作为方案 A 出问题时的兜底

- `asyncio` + `ssl`：并发高、可控性强；但标准库 **不暴露对端证书链**（`getpeercert(binary_form=True)` 只有叶子），需改用 **pyOpenSSL 的 `get_peer_cert_chain()`** 取完整链，再交给 `cryptography` 解析（`cryptography` 不支持 SM2 公钥解析，SM2 证书需回退 OpenSSL）。
- 注意 `ulimit -n`（默认 1024 不够），并发上千时需调大。

#### 方案 D（testssl.sh）：仅用于抽样深检

- 功能全（协议/套件/弱点/证书/时间戳），单主机全量检测 1–3 分钟，**不适合 1000 主机规模**；建议对主动扫描结果抽 50–100 个代表性站点做交叉验证（含 SM2 检测，依赖后端 OpenSSL/GMSSL 能力）。
- 来源：https://github.com/testssl/testssl.sh （仓库已由 drwetter 转移至 testssl org，README：https://raw.githubusercontent.com/testssl/testssl.sh/3.3dev/Readme.md ）

---

## 2. 国密 SM2 支持结论（关键）

### 2.1 ZGrab2 / zcrypto：**不支持 SM2**（源码级核实）

对上游源码逐项核实（master 分支）：

1. **无 SM2/SM4 密码套件**：`zcrypto/tls/tls_names.go` 的 `cipherSuiteNames` 表中**没有任何 SM2/SM4 套件**（如 `TLS_ECC_SM4_CBC_SM3` 0x00C2、`TLS_ECC_SM4_GCM_SM3` 0x00C3、GB/T 38636 TLCP 套件均不存在）。→ ZGrab2 的 ClientHello 不会通告国密套件，**纯国密（仅 TLCP）站点无法完成握手**。
   来源：https://github.com/zmap/zcrypto/blob/master/tls/tls_names.go
2. **无 SM2 公钥解析**：`zcrypto/x509/x509.go` 中 `keyAlgorithmNames = [unknown, RSA, DSA, ECDSA, Ed25519, X25519]`，`getPublicKeyAlgorithmFromOID` 不识别 SM2 OID（1.2.156.10197.1.301）→ 返回 `UnknownPublicKeyAlgorithm`；`namedCurveFromOID` 仅支持 P-224/256/384/521。
   来源：https://github.com/zmap/zcrypto/blob/master/x509/x509.go
3. **无 SM2 签名算法**：`signatureAlgorithmDetails` 表不含 SM2-SM3（OID 1.2.156.10197.1.501）→ `UnknownSignatureAlgorithm`。
4. **曲线表细节**：Python schema 文件里出现了 `41: "curveSM2"`（https://github.com/zmap/zcrypto/blob/master/zcrypto_schemas/zcrypto.py ），但 **Go 源码 `tls_names.go` 的 `curveNames` 映射并不含 41**，即当前代码连"SM2 曲线命名"都没有落地，schema 领先于实现。
5. **缓解**：即使 SM2 证书解析失败，ZGrab2 输出仍保留每张证书的 **`raw` DER** 与指纹字段 → 可**事后用 OpenSSL 3 重解析** SM2 链（OpenSSL 1.1.1+ 完整支持 SM2 证书/密钥/SM3 摘要）。方案：管道中增加"zcrypto 解析失败（unknown_algorithm）→ 调 openssl x509 重解析"的回退逻辑。

### 2.2 对中国 Top-1000 场景的推断

- 中国境内国密（SM2/SM4）HTTPS 主要部署在**政务、金融、央企内网/门户**，多采用**双栈**：标准 TLS 通道下发 RSA/ECDSA 链，国密通道（GB/T 38636 TLCP）才下发 SM2 链。
- 公开 Top-1000 站点（电商、社交、视频、新闻等）绝大多数用 RSA/ECDSA + 标准 TLS，**标准握手即可正常采集**。
- 因此：**主动扫描主要产出 RSA/ECDSA 链**；SM2 链的主动获取需要 TLCP 客户端（标准 OpenSSL **不含** TLCP 套件，需 GMSSL/Tongsuo 等国密分支），且对公网站点命中率低。
- **SM2 链分析建议走被动/离线数据**：CT 日志（叶子证书）＋ CA 官方证书库（本项目 `trust_store_data/china/` 已有 CFCA 生产证书链 RSA/SM2 数据）＋ 对少数已知国密站点（经批准）用 GMSSL 客户端小样本验证。

### 2.3 工具 SM2 能力一览

| 工具 | SM2 证书解析 | SM2/TLCP 握手 | 说明 |
|---|---|---|---|
| ZGrab2/zcrypto | ❌（raw DER 保留，可回退 OpenSSL） | ❌ | 无 SM4/SM3 套件、无 SM2 曲线 |
| openssl x509（1.1.1+/3.x） | ✅ | ❌（标准版无 TLCP 套件） | SM2 链解析金标准 |
| GMSSL / Tongsuo | ✅ | ✅ | 国密协议分支，仅小样本用 |
| Python cryptography | ❌ | ❌ | 尚无 SM2 支持 |
| testssl.sh | ✅（依赖后端） | ⚠️ | 检测能力视 OpenSSL/GMSSL 后端 |

---

## 3. 合规框架总结

> ⚠️ 以下法律条文为**调研时点**的公开文本整理，出处标注官方来源；因中国政府网改版，部分原始链接已失效，**带 ★ 的条目建议人工核对原文后再引用**。

### 3.1 法律层面

#### (1) 《中华人民共和国网络安全法》（2016-11-07 通过，2017-06-01 施行）

- **第 27 条**（对主动扫描最直接相关）：
  > "任何个人和组织不得从事**非法侵入他人网络、干扰他人网络正常功能、窃取网络数据**等危害网络安全的活动；不得提供专门用于从事侵入网络、干扰网络正常功能及防护措施、窃取网络数据等危害网络安全活动的程序、工具；明知他人从事危害网络安全的活动的，不得为其提供技术支持、广告推广、支付结算等帮助。"
- **第 44 条**：禁止窃取或以其他非法方式获取个人信息。
- **第 63 条**（罚则）：违反 27 条，由公安机关给予警告、罚款（个人最高 100 万元）、**拘留（≤15 日）**；构成犯罪依法追究刑事责任。
- 来源（★原链接已 404，建议人工核对）：
  - 中国政府网发布页（原）：https://www.gov.cn/xinwen/2016-11/07/content_5129471.htm （已失效）
  - 官方替代源：全国人大网 www.npc.gov.cn 法律库；《全国人民代表大会常务委员会公报》2016 年第 8 号。

#### (2) 《中华人民共和国刑法》（1997 年刑法，历经修正）

- **第 285 条第 1 款**（非法侵入计算机信息系统罪）：
  > "违反国家规定，侵入国家事务、国防建设、尖端科学技术领域的计算机信息系统的，处三年以下有期徒刑或者拘役。"
- **第 285 条第 2 款**（非法获取计算机信息系统数据罪 / 非法控制计算机信息系统罪，2009 年《刑法修正案（七）》增设）：
  > "违反国家规定，侵入前款规定以外的计算机信息系统或者**采用其他技术手段**，获取该计算机信息系统中存储、处理或者传输的数据，或者对该计算机信息系统实施非法控制，情节严重的，处三年以下有期徒刑或者拘役，并处或者单处罚金；情节特别严重的，处三年以上七年以下有期徒刑，并处罚金。"
- **第 286 条**（破坏计算机信息系统罪）：删除/修改/增加/干扰系统功能或数据、造成系统不能正常运行、后果严重的，追究刑事责任。
- **关键司法解释**：《最高人民法院、最高人民检察院关于办理危害计算机信息系统安全刑事案件应用法律若干问题的解释》（法释〔2011〕19 号）——明确"侵入"、"情节严重"的量化标准（如违法所得、经济损失、数据条数等）。（★来源：最高人民法院官网 www.court.gov.cn，建议人工核对）
- **边界分析**（本调研的核心论证）：
  - **"侵入"的构成要件** = 违反国家规定 + **未经授权进入**（绕过访问控制/认证）。标准的 TLS ClientHello→ServerHello→Certificate 握手是**服务器对任意客户端主动公开其证书**的正常协议行为，客户端未进入系统内部存储区、未绕过任何认证——通说认为**不构成"侵入"**。
  - **"非法获取数据"的争议点**：第 2 款"采用其他技术手段"措辞宽泛。但证书是服务器**面向全体客户端主动披露**的公开信息，学界通说认为此类"banner 抓取/握手探测"不属"非法获取"；若扫描者利用**异常报文/漏洞**诱导服务器泄露非公开配置，则边界模糊、风险陡增。
  - **实务观察**：中国境内因"单纯端口扫描/TLS 握手"被追究刑责的公开判例极少，被判刑的"扫描类"案件几乎都伴随**爆破、漏洞利用、植入控制、窃取非公开数据或造成服务瘫痪**等行为。**无先例 ≠ 无风险**：高速率/无授权/无报备的扫描一旦被 WAF 与网安部门认定为"网络攻击"，存在按 285/286 条解释的空间。

#### (3) 《中华人民共和国数据安全法》（2021-09-01 施行）

- 第 3 条界定"数据"；第 27 条要求数据处理者履行安全保护义务；第 45/46 条设法律责任。批量采集境内网站数据（虽为公开证书数据）属于"数据处理活动"，应遵守**合法、正当**原则；数据**不出境、仅境内学术使用**时风险显著降低。

#### (4) 《中华人民共和国个人信息保护法》（2021-11-01 施行）

- 证书/域名/DNS 记录一般不属个人信息；但若将 IP ↔ 个人用户关联并存储，可能触发 PIPL 的"合法、正当、必要、最小范围"要求。本项目**只存域名+证书，不做 IP→个人关联**，基本不触及 PIPL。

#### (5) 其他相关

- 《中华人民共和国治安管理处罚法》第 29 条：非法侵入计算机信息系统、干扰系统功能等，处 5–10 日拘留（行政处罚兜底，比刑法门槛低）。
- 《关键信息基础设施安全保护条例》（2021-09-01 施行）：对关键信息基础设施（CII）有专门保护要求；Top-1000 中的**政府、金融、能源类站点可能属于 CII 或重要信息系统**，扫描此类站点敏感性最高。
- 《计算机信息网络国际联网安全保护管理办法》（公安部令第 33 号）：校园网出口安全管理的框架文件。

### 3.2 伦理标准：Menlo Report

- **出处**：Kenneally, Bailey, Maughan, "The Menlo Report: Ethical Principles Guiding Information and Communication Technology Research", USENIX Security 2012。（★URL 建议人工核对：https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/kenneally ；CAIDA 专题页 https://www.caida.org/catalog/publications/papers/menlo/ ）
- **四大原则**（对应到本项目）：
  1. **尊重人（Respect for Persons）**：知情/退出机制——公开研究联系方式，目标管理员可要求停止扫描。
  2. **善行（Beneficence）**：收益最大化、伤害最小化——低速率、最小握手、不发送载荷、不存储多余数据。
  3. **公正（Justice）**：负担公平——不应让特定网络/机构承担不成比例的扫描负担（Top-1000 均匀低速率即符合）。
  4. **尊重法律与公共利益（Respect for Law and Public Interest）**：报备、透明、可问责。
- **学界实践**：ZMap 论文专节讨论扫描伦理（速率与退出机制）；"Ten Years of ZMap"（arXiv:2406.15585）总结了社区规范的演进（限速、随机化、opt-out、与 CERT 协调）。IMC/USENIX 等会议审稿已把**伦理声明**（扫描速率、范围、数据处置）作为测量论文的常规要求。

### 3.3 商业扫描器做法：Censys

- Censys（密歇根大学团队创立）将 ZMap+ZGrab 流水线常态化运行，公开发布数据集（scans.io），并有**研究伦理声明**（responsible scanning：限速、受控目标、数据脱敏与负责任披露）。
- ★URL 建议人工核对：https://censys.com/research-ethics/ （旧地址 about.censys.io/research-ethics 与 search.censys.io/ethics 已失效/403）；服务条款 https://censys.com/terms-of-service/ （原 censys.io/terms 已重定向）。
- **启示**：即便在美国，常态化大网扫描也依赖"专用基础设施 + 伦理声明 + 公开数据 + 可退出"。本项目在校园网内小规模、限时、报备后扫描，合规要求远低于 Censys 形态，但**报备 + 伦理声明**的做法值得完整借鉴。

### 3.4 合规实践：校园网与高校政策

- 中山大学网络与信息技术中心：★建议人工核对 https://inc.sysu.edu.cn （本环境无法访问），查询《校园网管理办法/用户守则/网络安全管理办法》，重点确认：**对外主动扫描是否需要报备、出口 IP 是否需要固定、是否有防火墙/WAF 会拦截或记录 TLS 流量**。
- 高校通行做法：以**科研用途**为名提交"网络使用/安全测试申请"至网络中心，说明目的、范围（域名清单）、速率、时段、出口 IP、数据处置方式，获批后实施；未报备的大流量/异常连接行为可能被出口设备自动封禁并通报院系。
- **ICP 备案**：扫描行为本身无需备案（备案针对托管服务）；若后续要发布扫描 API/公开数据集服务，才涉及备案与《数据安全法》数据出境评估。

### 3.5 结论建议（主动 vs 被动）

1. **数据主体建议用被动源**：CT 日志（crt.sh/Google CT）+ CA 官方证书库（本项目已有 CFCA RSA/SM2 链）+ Censys 证书索引，可覆盖 Top-1000 的叶子证书（算法/密钥/有效期）与 CA 链关系，**零扫描风险**。
2. **主动扫描作为补充验证**：对被动数据无法覆盖的站点（漏报/不一致/链缺失）做最小样本主动握手，速率 ≤300 conn/s、仅 TLS 握手、单目标并发 ≤8、限定时段。
3. **SM2 链**：被动优先（国密证书库+CT），主动仅对获批的少数国密站点用 GMSSL/TLCP 小样本验证。
4. **全流程**：报备 → 获批 → 限速执行 → 数据境内存储 → 论文伦理声明。

---

## 4. 风险矩阵（扫描行为 × 法律风险 × 缓解措施）

| # | 行为 | 风险等级 | 法律/规制依据 | 缓解措施 |
|---|---|---|---|---|
| 1 | 域名解析 + 单次 TCP 443 连接/目标 | 低 | 正常网络业务；不构成"侵入"（无认证绕过） | 目标清单固定为 Top-1000 合法域名；向网络中心报备出口 IP 与时段 |
| 2 | 标准 TLS 握手（ClientHello→证书获取后断开） | 低 | 服务器主动公开证书；网安法 27 条"侵入/干扰/窃取"均不适用 | 仅握手、不发送 HTTP 载荷、不请求敏感路径、不保存会话密钥之外的任何数据 |
| 3 | 批量 100–1000 conn/s 主动握手 | 中 | 理论上有"干扰网络正常功能"解释空间；实际风险是 WAF/IDS 告警 → 目标投诉 → 学校通报 | 速率 ≤300 conn/s（≈0.3 conn/s/目标，远低于正常流量）；随机化顺序；低峰时段；冷却重试；设目标退出渠道 |
| 4 | 全网 IP 空间 SYN 扫描（ZMap/masscan 形态） | 高 | 特征明显，易被认定为"网络攻击"；网安法 27 条/治安管理处罚法 29 条/刑法 285-286 条解释空间大 | **本项目不做**（目标已知，无需全网扫描） |
| 5 | 漏洞探测/爆破/渗透 | 极高 | 刑法 285/286 条直接适用；网安法 63 条 | 一律禁止 |
| 6 | 扫描数据公开/出境 | 中 | 数据安全法（分类分级、出境评估）；PIPL（若含个人关联） | 数据仅境内学术分析；只存域名+证书（不存 IP→个人映射）；论文脱敏 |
| 7 | 扫描政府/金融/关键信息基础设施站点 | 高 | CII 条例；主管部门敏感；网安法 CII 条款 | 目标清单提交导师/网络中心审查，敏感站点剔除或专项获批 |
| 8 | 长期/常驻扫描服务（实验室 7×24） | 中 | 校园网管理办法禁止未报备对外服务 | 限时窗口（建议每轮 ≤1 周）；明确起止；扫描后关闭 |

---

## 5. 给导师的确认清单

1. **范围确认**：方案是否限定为"Top-1000 域名、仅 TLS 证书链主动测量"，明确**排除**全网 IP 扫描（ZMap/masscan 形态）与任何漏洞探测？
2. **校园网报备**：是否同意/协助向中山大学网络与信息技术中心（inc.sysu.edu.cn）提交报备？报备需要哪些材料（目的说明、域名清单、速率、时段、出口 IP）？出口 IP 是否需要固定？
3. **目标清单审查**：Top-1000 中政府、金融、能源等敏感站点如何处理——剔除、仅被动数据覆盖，还是需专项授权？
4. **速率与时段**：≤300 conn/s、单目标并发 ≤8、低峰时段、每轮 ≤1 周——是否可接受？是否需要更低（如 ≤100 conn/s）？
5. **工具许可**：是否允许在实验室安装 ZGrab2（Go 编译）？还是仅允许 openssl/Python 轻量方案（方案 B）？
6. **数据处置**：扫描数据是否仅限课题组内使用？论文发表时域名是否需要脱敏（hash/匿名化）？数据是否可发布到公开数据集（涉及数据安全法评估）？
7. **伦理合规**：是否需要在论文/申报书中写"伦理与合规声明"（参照 Menlo Report 四原则）？是否需要课题组伦理审查流程？
8. **SM2 策略**：鉴于 ZGrab2 不支持 SM2 且公网 SM2 命中率低，是否同意"被动（CT+CA 证书库）为主、主动扫描为辅、SM2 用离线链分析"的技术路线？
9. **目标退出机制**：是否提供研究联系方式（如 `scan-optout@课题组邮箱`），供目标站点要求停止扫描？
10. **出口设备确认**：请网络中心确认校园网出口是否存在防火墙/WAF/威胁检测设备，其告警阈值是否会误报本项目流量（TLS 批量连接）？

---

## 6. 参考来源汇总

| 主题 | 来源 URL |
|---|---|
| ZGrab2 README（模块列表、安装、伦理声明） | https://github.com/zmap/zgrab2 ；raw README：https://raw.githubusercontent.com/zmap/zgrab2/master/README.md |
| ZGrab2 TLS 模块源码（flags：--min-version 等） | https://github.com/zmap/zgrab2/blob/master/tls.go ；模块注册 https://github.com/zmap/zgrab2/blob/master/modules/tls.go |
| zcrypto TLS schema（server_certificates.chain、TLS 版本、曲线表） | https://github.com/zmap/zcrypto/blob/master/zcrypto_schemas/zcrypto.py |
| zcrypto TLS 套件名表（无 SM2/SM4 套件） | https://github.com/zmap/zcrypto/blob/master/tls/tls_names.go |
| zcrypto x509 解析（无 SM2 公钥/签名支持） | https://github.com/zmap/zcrypto/blob/master/x509/x509.go |
| ZMap README（架构、速率、伦理警告、引用） | https://github.com/zmap/zmap ；论文 https://zmap.io/paper.pdf |
| masscan README | https://github.com/robertdavidgraham/masscan |
| testssl.sh（已迁移至 testssl org） | https://github.com/testssl/testssl.sh ；README https://raw.githubusercontent.com/testssl/testssl.sh/3.3dev/Readme.md |
| Ten Years of ZMap（伦理演进） | https://arxiv.org/abs/2406.15585 |
| 网络安全法（★人工核对原文） | 原发布页 https://www.gov.cn/xinwen/2016-11/07/content_5129471.htm 已失效；建议核对全国人大网 www.npc.gov.cn 法律库 |
| 刑法 285/286 条、法释〔2011〕19 号（★人工核对） | 最高人民法院官网 www.court.gov.cn ；最高检官网 www.spp.gov.cn |
| 数据安全法、个人信息保护法（★人工核对） | 全国人大网 www.npc.gov.cn |
| Menlo Report（★人工核对） | https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/kenneally ；CAIDA https://www.caida.org/catalog/publications/papers/menlo/ |
| Censys 研究伦理/条款（★人工核对） | https://censys.com/research-ethics/ ；https://censys.com/terms-of-service/ |
| 中山大学网络与信息技术中心（★人工核对） | https://inc.sysu.edu.cn |

> 说明：本文件全部技术结论基于 2025-11 时点 GitHub 上游 master 源码（zgrab2/zcrypto）逐文件核实；法律条文与政策页面凡标注 ★ 者，因政府网站改版/反爬限制未能在线复核原文，引用前请以官方现行文本为准。
