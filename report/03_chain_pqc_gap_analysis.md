# 证书链/CA 生态量子脆弱性测量 — 学术空白调研

调研日期:2026-09-20(会话环境日期)
方法:web_fetch 直抓 eprint.iacr.org 检索 + 论文摘要页、NIST IR 8547 PDF 全文、crt.sh CA 数据结构、CCADB、CABF。
注意:调研环境网络屏蔽 arxiv.org / export.arxiv.org / semanticscholar API / Google / DuckDuckGo(连接超时);Bing 可访问但结果退化(关键词词义化)。因此以下"未找到"主要指 eprint + 上述可达源,**arxiv/IMC/USENIX 侧结论需后续工作 后续补查**。

---

## 1. 检索过程与原始来源

### 1.1 eprint.iacr.org 检索(全部真实执行)

| 查询 | 结果数 | 最相关命中 |
|---|---|---|
| certificate chain quantum | 9 | 2026/866、2026/666、2026/779、2021/1447、2022/1556、2020/071 |
| CA ecosystem post quantum | 1 | 无关(CA-MCPQ, AI 代理协议) |
| root certificate RSA quantum | 0 | —(该词条在 eprint 不是检索热点) |
| post-quantum X.509 certificate | 11 | 2026/1703(SoK)、2026/1416、2026/1374、2025/1245、2025/1241、2018/063 |
| quantum migration PKI | 5 | 2017/460、2026/1467、2026/1262 |
| certificate ecosystem quantum | 4 | 2026/1703、2025/1245、2025/556、2022/483 |
| trust anchor quantum | 1 | 2026/1703 |
| hybrid certificate chain root intermediate | 0 | — |
| quantum vulnerability TLS ecosystem | 0 | — |
| internet scanning certificate algorithm | 2 | 2017/020(concerto)、2016/515(RSA 弱公钥) |
| China CA quantum | 0 | — |

### 1.2 抓取的论文全文摘要页(URL 均真实访问)

- https://eprint.iacr.org/2026/866 (Delgado, Observability for PQ TLS Readiness)
- https://eprint.iacr.org/2026/666 (Delgado, Signature Placement in PQ TLS Certificate Hierarchies)
- https://eprint.iacr.org/2026/779 (Scott/Adj/Rodríguez-Henríquez, And TLS lived happily ever after)
- https://eprint.iacr.org/2026/1703 (Roy, PQ TLS Migration SoK)
- https://eprint.iacr.org/2021/1447 (Paul et al., Mixed Certificate Chains; AsiaCCS 2022)
- https://eprint.iacr.org/2022/1556 (Sikeridis et al., ICA Suppression; CoNEXT'22)
- https://eprint.iacr.org/2017/460 (Bindel et al., Transitioning to a QR-PKI; PQCrypto 2017)

### 1.3 其他可达来源

- https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf (NIST IR 8547 IPD, 2024-11, 全文解析)
- https://crt.sh/ (CA 层级数据页:父/子 CA、证书、13 个信任列表来源)
- https://www.ccadb.org/ (Common CA Database, Linux Foundation)
- https://cabforum.org/ (CA/Browser Forum)
- 不可达(需后续): https://www.nccoe.nist.gov/pqc (403)、search.censys.io (403)、support.censys.io (522)、NIST SP 1800-38B 各 URL (404/403)

---

## 2. 核心发现

### A. 有没有已发表的"证书链级量子脆弱性"分析(非只看叶子)?

**设计/迁移侧:有大量"链级"研究,但都是"如何建 PQ 链",不是"测量现有链的脆弱性"。**

- **2021/1447 "Mixed Certificate Chains for the Transition to PQ Authentication in TLS 1.3"**(Paul/Kuzovkova/Lahr/Niederhagen, AsiaCCS 2022):明确提出在**同一证书链内混用算法**,并实测"哈希签名(SPHINCS+/XMSS)只放在根 CA 层"的混合链握手可行。这是"链分层"研究的最早代表之一。https://eprint.iacr.org/2021/1447
- **2026/666 "Signature Placement in Post-Quantum TLS Certificate Hierarchies"**(Delgado):核心结论 = **签名算法放在链的哪一层,重要性不亚于选哪个算法**;SLH-DSA 放叶证书会数量级恶化握手时延,放上层信任层、叶层用 ML-DSA 才是可行架构。直接支撑"根/中间 CA 算法决定整链脆弱性"的视角。https://eprint.iacr.org/2026/666
- **2026/779 "And TLS lived happily ever after"**(Scott 等, TII):融合(混合)签名用于 X.509 链的最小侵入方案。https://eprint.iacr.org/2026/779
- **2017/460 "Transitioning to a Quantum-Resistant PKI"**(Bindel 等, PQCrypto 2017):最早系统讨论 PKI/证书/邮件混合签名迁移,并实测软件对超大证书的兼容性。https://eprint.iacr.org/2017/460
- **2026/1703 "Post-Quantum TLS Migration: A Systematization…"**(Roy, SoK):把 trust-anchor/X.509 迁移、HSM、证书清单列为与 KEM 并列的迁移约束面;结论之一 = 部署就绪受"证书、信任库、HSM、中间盒"限制不亚于原语本身。https://eprint.iacr.org/2026/1703
- **2026/1416 "Beyond Size: Do Hybrid PQC Certificates Actually Enforce the Classical–PQC Binding?"**(Lee 等):对 Catalyst/Composite/Chameleon/签名组合器等混合证书策略的安全性(经典↔PQC 绑定)做检验,发现很多实现并不真正强制绑定。https://eprint.iacr.org/2026/1416

**测量侧:有一个非常接近的框架,但重点不在"链的算法盘点"。**

- **2026/866 "Observability for Post-Quantum TLS Readiness: A Multi-Surface Evidence Framework"**(Delgado):把 PQ 就绪度测量拆成会话/密钥交换/端点能力/认证/生命周期等"证据面",其中明确包含 **certificate-chain evidence**;并做了一个 1000 目标、2000 次探测的公网实测(1971 次握手完成、收集 1368 个链工件、310 个端点确认混合能力)。关键提示:**TLS 1.3 下链证据采集很难**(截断、恢复、碎片化、mTLS、活动证书抓取),被动视图会低估端点能力——这恰好是"只靠主动握手看链"的方法论陷阱。https://eprint.iacr.org/2026/866

**结论(A)**:已发表工作覆盖"链级迁移方案"(A1)和"链证据就绪度框架"(A2),但**没有找到一篇以"对现存公网证书链逐环(根/中间/叶)做算法盘点,并以 Shor 威胁为标准给整链打分/排序"为核心的实证测量论文**。eprint 检索 "root certificate RSA quantum" 零命中即是信号:根证书算法这个维度还没有进入该方向的学术主流。

### B. 现有 TLS 证书测量研究有没有单独分析根/中间 CA 算法?

**数据能力存在,但"专门以 PQ 视角分析根/中间 CA 算法分布"的公开论文未检索到。**

- **crt.sh**(Sectigo, 200 可达):CA 页面自带完整层级结构——父 CA、子 CA、证书列表、以及 13 个信任列表来源(360 浏览器、Apple、Microsoft、Mozilla、Chrome、Android、Gmail、Java、Cisco、EUTL、Adobe 等),每条信任条目还带上下文版本与过期状态。这意味着**"按 CA 枚举算法"在数据层已经现成**,但它是基础设施,不是研究论文。https://crt.sh/
- **CCADB**(Linux Foundation):根/中间 CA 注册、审计、策略数据的行业数据库,可支撑 CA 级统计。https://www.ccadb.org/
- **Censys**:证书数据集含链,是行业标准 TLS 测量源;但 search.censys.io 与 support 文档在本环境 403/522,**未能在本次会话核实其字段文档**,需后续确认(研究/学术访问通常可申请)。
- eprint 侧:2016/515(RSA 弱公钥,基于 4200 万把扫描公钥)与 2017/020(concerto,TLS 数据集可复现分析)是"证书/密钥测量方法论"的近邻,但都不是根/中间 CA 算法专题。https://eprint.iacr.org/2016/515 , https://eprint.iacr.org/2017/020

**结论(B)**:公开的经典 TLS 证书生态测量(Durumeric 等 IMC 2013 一脉)以叶证书为主;"根/中间 CA 的算法分布 → 量子脆弱性"没有成为已发表的测量专题。**这是数据成熟、分析缺位的典型空白形态。**

### C. 关于"根证书迁移 PQC"的讨论(NIST 迁移规划里 CA 是重点吗)?

**CA 被 NIST 明确列为迁移组件之一,但仅止于方向性指引,没有专门的根证书迁移路线图/度量标准。**

- **NIST IR 8547 "Transition to Post-Quantum Cryptography Standards"(2024-11 IPD)** 全文 2.2.4 节 "PKI and Other Infrastructure Components":CA/注册机构/密钥管理系统须"用 PQC 算法签发证书与吊销状态、更新签发流程与验证/吊销机制",并强调过渡期后向兼容与互操作。定位是**基础设施组件清单中的一项**,篇幅小、无"根先换还是叶先换"的顺序度量。https://doi.org/10.6028/NIST.IR.8547.ipd
- NIST FIPS 203/204/205(2024-08)给出 ML-KEM/ML-DSA/SLH-DSA 原语,但签名标准本身不涉及 CA 运营迁移。https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards
- **NIST SP 1800-38B "Implementing a Quantum-resistant Public Key Infrastructure"**(NCCoE 实践指南)存在,但本次调研其所有 URL 均 404/403,**无法核实当前状态**(可能仍为草稿/内部),建议后续工作 另行确认。
- 学术侧:**2026/1703 SoK** 把 trust-anchor 迁移列为四大结论之一("staged authentication and PKI migration");**2021/1447** 实测根层放哈希签名的混合链可行;这两者证明"根证书怎么迁"是公认难题,但**都没有给出现网根/中间 CA 的迁移优先级量化依据**。

**结论(C)**:CA 是 NIST 迁移规划中的明确组件,但"整链迁移的顺序、成本、度量"仍属开放问题——恰是实证测量的空间。

### D. 空白:整链分析 + 中国 CA 生态(CFCA/CNNIC 等)

- eprint 检索 "China CA quantum" **零命中**;可达来源中未见任何针对**中国 CA 生态(CFCA、CNNIC、沃通、BJCA 等)的 PQ 就绪度/链脆弱性测量**。
- 全球层面:未检索到"以整链为分析单位"的实证测量论文(见 A)。
- 交叉点(整链 × 中国生态)确认**空白**。中国场景还有独特数据难点:部分站点仅信任内置根/国密(SM2)链、CT 日志覆盖对 .cn 域相对完整但非全量、主动扫描出网受限——这既是难点也是差异化机会(需要把 crt.sh/信任库/主动探测三种源拼起来)。
- 注意:arxiv/IMC/USENIX 本次调研不可达,"中国 CA 生态"是否在中文期刊/会议(CJE、计算机学报等)或国内工作组已有工作,需后续工作 用可达渠道补查。

### E. 工作量评估:从公开数据能不能做?

**能做,可行性高,工作量中低。数据源与难点如下。**

可用数据源(本次调研已验证可达性):
1. **crt.sh**(免费,200):CA 层级(父/子/信任列表)+ 每张证书的算法字段;有 SQL/JSON API,可批量枚举中间证书。https://crt.sh/
2. **Mozilla certdata.txt / Chrome root_store.textproto**(免费):信任锚(根)的权威清单,可解析每根的公钥算法与有效期。https://hg.mozilla.org/mozilla-central/file/tip/security/nss/lib/ckfw/builtins/certdata.txt
3. **CCADB**:根/中间 CA 注册与审计数据(需按 usage terms 使用)。https://www.ccadb.org/
4. **Censys**(需研究申请):完整证书/链数据集,行业标准。
5. **主动探测**(自建):TLS 1.3 握手下发链 + 兼容模式抓叶与中间;根从信任库补齐。

核心方法(链条组装三件套):
- 叶证书 = 握手观察(或 CT)
- 中间证书 = crt.sh/CT(应对 TLS 1.3 intermediate suppression)
- 根证书 = certdata/CCADB(根不进握手,必须信任库补齐)
- 脆弱性评分 = 每环(公钥算法,密钥长度,签名算法,有效期)→ Shor 风险;整链评分可选"最弱环"或加权聚合;再叠加 HNDL 暴露窗口(证书剩余有效期、是否跨 PQ 时代)。

主要难点(均非不可逾越):
1. **TLS 1.3 中间证书抑制**:单靠握手链不完整 → 必须 CT/CA 库回填(2026/866 已实证 1368/2000 的链工件率,证明纯握手视图显著低估)。
2. **根证书不可见**:必须信任库补齐,且信任库(Chrome/Apple/Mozilla)之间有差异 → 结论需声明"按哪套信任库"。
3. **Censys 授权**与 **.cn 主动扫描受限**:中国站点主动握手覆盖面有限,需以 CT + 信任库为主、主动探测为补充。
4. 现状数据快照 + 时间序列:根证书 20+ 年有效期意味着"迁移窗口"必须按有效期/剩余寿命建模——这是比单点快照更有分量的产出。

**预估工作量**:数据管线(抓取 crt.sh/certdata + 解析 + 链组装)约 1–2 周;脆弱性评分模型 + 中国生态专题分析 1–2 周;可视化成稿另计。公开数据足以支撑,无需 Censys 付费也可出初版(用 crt.sh + certdata + 有限主动探测)。

---

## 3. 最新补充发现(第二轮检索)

### 3.1 2026/1174 "A Layered Risk Scoring Model for TLS Connections Against Quantum Threats" — 最接近的竞争论文

**来源**:Hyung/Jeong/Lim/Park/Cho/Kim/Kim/Seo (Hansung University, 韩国)  
**URL**: https://eprint.iacr.org/2026/1174  
**发表**: eprint Preprint, 2026-06

**贡献**:
- 提出 TLS 连接量子风险分层评分模型(0–100 分)
- 五层:L1 TLS 协议暴露;L2a 传统公钥脆弱性(RSA/ECDHE 等);L2b AES-128 Grover 弱化;L2c PQC Level-1 脆弱性;L3 证书过期紧迫性
- HNDL 全局乘子 M(数据机密性保留期)
- **实证**:502 个真实 TLS 会话,4 个行业
- 关键结果:韩国国内(domestic)平均风险 16.0 vs 全球平均 11.9;国内 legacy 密钥交换使用 77.4% vs 全球 53.5%;PQC 采用 22.6% vs 46.5%

**与我们的空白的关系(至关重要)**:
- ✅ 有"国家视角"的 TLS 量子风险测量(韩国)—这已被韩国团队做了
- ✅ L3 涉及证书,但仅限**有效期**
- ❌ **不是证书链级分析**:L2a 检查的是握手中的**密钥交换算法**(ECDHE/RSA KEX),不是证书链每环的签名算法
- ❌ **没有根/中间 CA 算法盘点**:整个模型基于会话层面,不解析每级证书
- ❌ 数据是 TLS 握手观察(502 会话),不是证书链拆解
- ✅ **但我们的项目中"中国视角"仍空白**:韩国团队做了韩国 vs 全球,没有中国数据
- ✅ **证书链算法维度仍空白**:他们没做链分析,我们做了就是差异化

**对我们的启示**:这个竞争论文实际上**突显了"证书链级别+中国生态"的空白**。他们的 502 会话握手-级分析已经显示"国内 legacy 比例高 → 风险更高"的趋势,但没能回答"这个高 34% 的风险中有多少是根/中间 CA 用 RSA 导致,多少是密钥交换导致"——这是证书链分析的增量价值。

### 3.2 2026/1467 "CARS: Crypto-Agility Readiness Score" — 组织就绪度评估

**来源**:Costa (Federal Rural University of the Amazon, 巴西)  
**URL**: https://eprint.iacr.org/2026/1467  
**投稿**:IEEE TDSC

**贡献**:五维加权综合指数(Inventory, Algorithm Compliance, Architectural Decoupling, Toolchain, Governance & Compliance),用于评估 PKI/TLS/HSM 的 PQC 迁移就绪度。43 个开源仓库实证,平均 CARS = 34.1/100。

**关系**:这是"组织/系统就绪度"而非"现网脆弱性测量",与我们的链分析互补而非竞争。

### 3.3 IETF LAMPS WG PQC 复合证书标准化(2024–2026 活跃)

**来源**:IETF Datatracker(本环境可达)  
**URL**: https://datatracker.ietf.org/ 搜索 pq-composite

**关键草案**:
- `draft-ietf-lamps-pq-composite-sigs` (Composite ML-DSA for Internet PKI) — 接近 RFC
- `draft-ietf-lamps-pq-composite-kem` (Composite KEM) — IETF Last Call
- `draft-ounsworth-pq-composite-keys` (Composite Public/Private Keys)
- `draft-ounsworth-pq-composite-encryption`

**意义**:说明互联网 PKI(CA)的 PQC 标准化已进入工程阶段,标准化的方向是"复合证书"(一个证书同时持古典+PQC 公钥)。这提供了"未来 CA 证书会长什么样"的标准上下文,但**不发生任何现网测量**。

### 3.4 2023/1921 "Automated Issuance of PQ Certificates" — ACME PQ 证书签发挑战

**来源**:Giron 等(UTFPR/IFRS/TII)  
**URL**: https://eprint.iacr.org/2023/1921  
**发表**:ACNS 2024

**贡献**:评估 ACME 协议迁移到 PQ 的挑战;提出新 challenge 方法(比 HTTP-01 快 4.22×)。

**关系**:侧重"签发效率",与现网链测量正交。

### 3.5 crt.sh 中国 CA 数据可行性实测

- **crt.sh JSON API**可访问: `https://crt.sh/?q=%CNNIC%&output=json` 返回 81 条证书;可通过 `?Identity=XX` 或 `?q=` 按组织/域名查询
- **CA 层级页面**已验证:含父 CA、子 CA、证书列表、13 个信任列表来源(360/Apple/MS/Mozilla/Chrome/Android/Gmail/Java/Cisco/EUTL/Adobe 等,带版本与过期状态)
- **中国 CA 如 CNNIC、CFCA**通过 crt.sh 可查到签发的中间/叶证书及其公钥算法字段
- ⚠️ 根证书不进 CT 日志,需要从 Mozilla certdata.txt / Chrome root_store.textproto 等信任库补齐

### 3.6 NIST SP 1800-38B 状态

- 本次调研所有 URL 变体均 404/403,包括:
  - `csrc.nist.gov/pubs/sp/1800/38b/final`
  - `csrc.nist.gov/pubs/sp/1800/38b/upd1/final`
  - `nccoe.nist.gov/pqc` (403)
- NIST 公开搜索无匹配 URL
- **推断**:该文档可能仍处于 NCCoE 内部草稿阶段,尚未公开 final,或者已更名为其他编号。需后续工作 从 NIST 渠道核实。

---

## 4. 修订后的空白定位(考虑 2026/1174 竞争后)

```
                    现有 TLS 量子风险/就绪度测量
                         │
                         ├── 会话/连接级评分 ─── 2026/1174 (韩国,502 sessions)
                         │                     2026/866 (全球,1000 targets)
                         │
                         ├── 组织就绪度评分 ─── 2026/1467 (CARS,43 repos)
                         │
                         ├── 迁移/设计研究 ─── 2021/1447, 2026/666, 2017/460...
                         │
                         └── ??? 证书链级逐环算法盘点 + Shor 脆弱性评分 ???
                                                    ↑
                                                  ⚠️ 空白
```

**现有研究都没做的**:
1. 拆解每张证书(根→中间→叶)的(公钥算法/密钥长度/签名算法/有效期),而非只看握手的密钥交换算法
2. 给整条链的"最弱环"脆弱性评分(如果根是 RSA-4096,中间是 RSA-2048,叶用 ML-DSA,那整条链仍受 Shor 威胁——因为根/中间可伪造证书)
3. 国家/地域视角聚焦中国 CA 生态

**2026/1174 做的是会话级,我们做链级,两者互补。实际上 2026/1174 的 L3(过期)是链属性的一个简单代理,但他们没意识到链每环的签名算法才是脆弱性的根本来源。**

## 5. 一句话结论

**空白成立且可做**:迁移侧论文已有(PQC 链该长什么样),测量侧只有"会话/KEM 就绪度"框架([2026/866](https://eprint.iacr.org/2026/866))和"会话级风险评分"([2026/1174](https://eprint.iacr.org/2026/1174),韩国团队做了韩国 vs 全球),**"现网整链逐环算法盘点 + Shor 脆弱性评分 + 中国 CA 生态(CFCA/CNNIC)专门分析"无已发表实证研究**;数据(crt.sh/信任库/CCADB/CT)公开可达,工作量中低,建议方向一按此切入。2026/1174 只做会话级、只有韩国/全球数据——链级 + 中国视角是我们相对既有工作的双重复合增量。

---

## 6. 第三轮:PDF 全文证据 + crt.sh 中国 CA 实证

### 6.1 🔴 决定性证据:竞争论文 2026/1174 自己把"整链分析"列为未来工作

下载并解析了 https://eprint.iacr.org/2026/1174.pdf 全文(1350 行文本)。

**Future Work #3(第 1282–1285 行,原文)**:
> "Full certificate chain tracking. Currently, L3 reflects only the expiration status of the server certificate. Since RSA keys remaining in intermediate CA certificates are also targets of quantum threats, extending L3 to incorporate the algorithms and expiration status of the entire chain is necessary."

**Future Work #5(第 1291–1302 行,原文)**:
> "Extension to other domains... applying the same framework to the entire PKI infrastructure (CA hierarchy, root trust chains)... In particular, evaluating quantum vulnerability by signature algorithm and key length of intermediate CA certificates in PKI environments can directly lead to further research, making it a promising future direction."

→ **最接近的竞争论文明确承认:① 当前 L3 只看叶证书过期,未覆盖中间 CA 的 RSA 密钥威胁;② 按签名算法+密钥长度评估中间 CA 证书的量子脆弱性是"有前景的未来方向"。这为我们的项目提供了第一手空白背书。**

### 6.2 crt.sh 中国 CA 数据实证(本次调研实测)

| CA | crt.sh 证书数 | 层级结构(issuer) | 算法确认 |
|---|---|---|---|
| CFCA | 125 | CFCA EV ROOT → CFCA Global RSA ROOT G2;CFCA Glo/EV/OV/OCA/GT CA | CFCA EV ROOT 详情页:**rsaEncryption, RSA 4096, sha256WithRSAEncryption, 至 2029-12-31**(纯 RSA,无 PQC) |
| TrustAsia(沃通后继) | 5248 | RSA DV SSL Server(1716)、OV TLS Pro CA G3(988)、ECC OV TLS Pro CA G3(282)、EV TLS RSA CA 2024 V2、宝塔 TLS ECC/RSA CA 2025 等;上层挂 Sectigo/COMODO/GeoTrust | 中间 CA 同时存在 RSA 与 ECC 体系 |
| BJCA(北京 CA) | 43 | BJCA Global Root C... | — |
| 上海 CA / 中国金融认证 | 各 10K–27K 字节 | — | — |

**管线已验证**:`https://crt.sh/?q=<org>&output=json`(获证书 ID)→ `https://crt.sh/?id=<ID>`(详情页含 Key Algorithm / RSA Public-Key (bits) / Signature Algorithm)。根证书不进 CT,需 certdata/信任库补齐。

### 6.3 IETF 复合证书标准状态(已核实)

- **RFC 9629**:Composite ML-KEM in CMS — 已发布(但针对 CMS,非 X.509 证书格式)
- **RFC 9631**:**不是**复合签名(实为 IPv6 Compact Routing Header)——复合签名标准尚未 RFC 化
- **draft-ietf-lamps-pq-composite-sigs**(Composite ML-DSA for Internet PKI):rev 19,IETF stream,接近 RFC 但未发布
- → LAMPS WG 正在把 PQ 复合证书写入标准,但**现网 CA 算法分布测量仍是空白**,且标准尚未落地,测量具有前瞻价值。

### 6.4 2026/1174 引用的可补查来源(arxiv 本环境不可达)

- Baseri, Chouhan, Ghorbani, Chow: "Evaluation framework for quantum security risk assessment" — arXiv:2404.08231 (2024)
- Blanco-Romero et al.: "On the practical feasibility of harvest-now, decrypt-later attacks" — arXiv:2603.01091 (2026)

### 6.5 项目定位建议(三层递进)

1. **基线**:对 2026/1174 的会话级风险评分,补充"整链证书算法盘点"维度(L3 扩展)——直接回应其 Future Work #3
2. **创新**:整链脆弱性评分模型(每环公钥算法/密钥长度/签名算法/有效期→Shor 风险,取最弱环或加权聚合)+ 根/中间 CA 剩余有效期 vs PQ 迁移窗口(HNDL 暴露)建模
3. **差异化**:中国 CA 生态(CFCA/CNNIC/BJCA/TrustAsia 等)专门分析——2026/1174 只有韩国/全球,中国视角空白
