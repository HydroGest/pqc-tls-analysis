# 时间感知的后量子迁移风险评估模型 — 文献现状与空白分析

> 调研日期：2026-09。检索范围：IACR ePrint 全文搜索（标题/摘要/关键词）、相关论文逐篇深读。arXiv 与 Google Scholar 抓取失败（网络/反爬），但 ePrint 已覆盖本方向的核心文献。
> 注意：本领域论文均为 2026 年 ePrint 预印本，无会议/期刊评审版本，引用时需注明。

---

## 0. 核心发现速览（TL;DR）

| 论文 | 评分对象 | 时间怎么建模 | 0–100 吗 | 概率模型 | 证书有效期 |
|---|---|---|---|---|---|
| [2026/1174](https://eprint.iacr.org/2026/1174) Hyoung et al. | TLS 连接 | **单一全局 HNDL 乘数 M=1.50** + L3"证书过期紧迫度" | ✅ | ❌ 无 | 仅作为离散层 |
| [2026/1467](https://eprint.iacr.org/2026/1467) Costa | 组织/软件仓库 | **完全不建模时间**（静态快照） | ✅ | ❌ 无 | ❌ 无 |
| [2026/790](https://eprint.iacr.org/2026/790) Chammas et al. | 遗留系统 | **只提框架不实现**（立场论文） | ❌ | ❌ 无 | ❌ 无 |
| [2026/866](https://eprint.iacr.org/2026/866) Delgado | TLS 可观测性 | 有"lifecycle/temporal drift"测量平面，但不量化风险 | ❌ | ❌ 无 | 作为证据面 |
| [2026/1703](https://eprint.iacr.org/2026/1703) Roy | TLS 迁移（SoK） | 概念性"优先 HNDL 敏感数据"，无量化 | ❌ | ❌ 无 | 作为约束 |

**结论**：你的项目方向（证书有效期 × NIST 时间线 × HNDL 的**概率化**时间感知模型）在 ePrint 上**没有任何直接竞争者**。现有模型要么用单一乘数近似时间（1174），要么完全忽略时间（1467），要么只是概念框架（790）。以下详述。

---

## 1. 逐篇深读

### 1.1 Hyoung et al. 2026 — [A Layered Risk Scoring Model for TLS Connections Against Quantum Threats](https://eprint.iacr.org/2026/1174)（韩国汉城大学，8 位作者）

**评分结构（0–100 分）**，五层：
- **L1**：TLS 协议暴露度（协议版本、握手类型等）
- **L2a**：遗留公钥算法脆弱性（RSA/ECDHE 等 Shor 可破算法）
- **L2b**：AES-128 Grover 削弱
- **L2c**：PQC Level-1 脆弱性（已部署 PQC 但强度只到 NIST Level-1 的情况）
- **L3**：证书过期紧迫度

**HNDL 乘数 M**：全局标量，论文实验取值 **M = 1.50**，语义是"数据保密性留存期"的放大系数。**关键点：M 是全局统一乘数，不是逐连接、也不是时间函数**——论文没有把 M 写成依赖证书剩余有效期或 CRQC 到达时间的函数。

**实测**：502 条真实 TLS 会话 × 4 个行业。韩国平均风险分 16.0，全球平均 11.9（高约 34%）；韩国遗留密钥交换占比 77.4% vs 全球 53.5%；PQC 采用率 22.6% vs 46.5%。

**局限**：
- M 是拍脑袋取的常数（1.50 没有推导来源）
- 时间只以离散层（L3）进入评分，没有连续时间积分
- 没有把 NIST 迁移里程碑（如 2024 FIPS 203/204、各机构 2030/2035 目标）作为时间锚点
- 没有 CRQC 到达的概率建模——威胁是二元存在/不存在

### 1.2 Costa 2026 — [Quantum-Safe Cryptography: A Migration Framework...Crypto-Agility Readiness Score (CARS)](https://eprint.iacr.org/2026/1467)（巴西亚马逊联邦农村大学，IEEE TDSC 审稿中）

**CARS 结构（0–100 复合指数）**，五维：
1. 资产清点完备度（Inventory Completeness）
2. 算法合规度（Algorithm Compliance）
3. 架构解耦度（Architectural Decoupling）
4. 工具链就绪度（Toolchain Readiness）
5. 治理与合规对齐度（Governance & Compliance Alignment）

**权重**：12 位资深迁移工程师两轮 Delphi 法得出。

**实测**：43 个开源密码软件仓库。CARS 均值：遗留密码库 24.9±9.5、PKI/证书管理 25.8±8.2、HSM 39.7±15.2、TLS1.3 Hybrid 47.2±16.5、PQC Native 47.5±11.1，总 34.1±15.0。**亮点结论**：PQC 参考实现尽管算法合规度 d2≥0.61，仍落在 At-Risk 区间，因为架构解耦度 d3≈0——"算法在场 ≠ 组织迁移就绪"。统计显著性：Kruskal-Wallis H(4)=17.55, p=0.0015。

**局限**：
- **完全静态**：CARS 是某个时刻的组织就绪度快照，没有任何时间维度
- 无 HNDL、无 CRQC 时间线、无证书生命周期
- 度量对象是组织/仓库，不是逐 TLS 连接或逐证书

### 1.3 Chammas et al. 2026 — [Towards a Field-Informed Risk-Based Framework for PQC Migration in Legacy Systems](https://eprint.iacr.org/2026/790)（圣约瑟夫大学 / QuRISK）

- **立场论文**（非模型实现）：批评现有标准（NIST/ETSI）和文献五宗罪——只讲算法规范、指导抽象无操作深度、缺实证验证、风险建模不足、忽略遗留约束
- 提议三层框架：遗留系统约束诊断 → 定性风险评估 → ROI 量化评估；尚未实施
- 对你项目的意义：它论证了"风险建模不足"是公认空白，但没有给出任何可执行模型——你的工作正好填这个洞

### 1.4 Delgado 2026 — [Observability for Post-Quantum TLS Readiness: A Multi-Surface Evidence Framework](https://eprint.iacr.org/2026/866)

- 多层可观测性框架：被动会话证据、主动探测、证书链证据、注册表知识，映射到 7 个测量平面（含 lifecycle、temporal drift）
- 实测：29 个受控场景 + 1000 目标/2000 探测的公网扫描（1971 握手、1368 证书链、310 个确认混合能力）
- 局限：这是**测量基础设施**，不产出风险分数；时间只作为"漂移"被观测，不进入风险计算。可作为你项目的数据采集层参考

### 1.5 Roy 2026 — [Post-Quantum TLS Migration: A Systematization of Hybrid Handshakes, PSKs, KeyUpdate, and Certificate Strategies](https://eprint.iacr.org/2026/1703)

- SoK 系统化论文：机密性迁移与认证迁移是**两个不同的安全程序**；混合 ECDHE-ML-KEM 是过渡架构首选；部署就绪受证书/信任库/HSM/中间盒约束
- 结论里"prioritizes HNDL-sensitive data"只是定性排序建议，无数值模型
- 对你项目的意义：它正式承认"HNDL 敏感数据优先级排序"是迁移决策的核心，但没有给出排序算法——这是你模型的用武之地

### 1.6 附带发现（搜索过程中）
- [2026/1374](https://eprint.iacr.org/2026/1374) Das & Chattopadhyay — S/MIME 消息级 PQ 安全保障（SMIME-PQCheck），聚焦邮件不是 TLS 评分
- 若干 2023–2025 证书/量子主题论文均为具体协议构造（如 PQCMC 隐式证书、everlasting security），与风险评估无关

---

## 2. A. 现有时间感知风险模型的共同点（"时间"怎么被建模的）

1. **单一全局乘数近似**（1174）：时间 = 一个常数 M（1.50）。所有连接一视同仁，与数据类型、证书剩余期、CRQC 到达时间无关。这是目前唯一把 HNDL 写进公式的模型。
2. **时间作为离散分层**（1174 的 L3）：证书过期紧迫度是评分的一部分，但作为离散分类（如"快过期/正常/刚签发"），不是连续函数。
3. **时间被完全忽略**（1467）：CARS 是静态快照，只测"此刻就绪度"。
4. **时间只作为观测维度**（866）：temporal drift 被测量和报告，但不参与风险量化。
5. **时间只作为定性原则**（790、1703）："尽早迁移""优先 HNDL 敏感数据"，无数值。
6. **威胁时间线全部是二元/确定性的**：所有论文都把"量子计算机存在与否"当 0/1，没有一篇把 CRQC 到达时间建模成概率分布。

**总结**：本领域对"时间"的处理停留在**近似、离散、静态、定性**四个层次，没有任何连续概率化时间模型。

---

## 3. B. 现有模型的缺点/局限清单

1. **HNDL 乘数是拍脑袋常数**：1174 的 M=1.50 无来源、无敏感性分析、无分布。
2. **无概率模型**：没有把 CRQC 到达时间当随机变量（没有对数正态/威布尔/专家先验分布，没有 Mosca 式 1/7/14 年概率估计的运用）。
3. **无证书剩余有效期分布**：没有人把"证书还剩下多久有效"作为**连续风险暴露窗口**来积分；1174 的 L3 只是离散紧迫度。
4. **无 NIST 时间线锚点**：FIPS 203/204（2024-08）、各机构 2030/2035 迁移截止、NIST 混合模式建议——没有论文把这些日期作为模型参数。
5. **无数据敏感期参数化**：HNDL 风险本质是"数据必须保密多久 vs CRQC 何时到达"的比赛（Mosca 不等式），现有模型没有显式建模数据保密期（session key 秒级 vs 归档数据十年级）。
6. **评分对象粒度混乱**：1174 逐连接、1467 逐组织、866 逐目标——没有统一到"证书→站点→组织"的分层。
7. **无风险公式**：没有论文给出类似 Mosca 不等式 1/7/14 的概率化形式（P(数据在 CRQC 到达前被保护失效)），全是启发式加权。
8. **实证规模小**：1174 只有 502 条会话；没有用 Censys/Shodan 级别的证书全量数据测过剩余有效期分布。
9. **没有"风险衰减/紧迫度上升"的动态模型**：风险应随时间推移单调上升（剩余有效期缩短 + CRQC 概率累积），现有模型都是点估计。

---

## 4. C. 还没有人做的空白（可突破点）

1. **CRQC 到达时间的概率分布建模**：把量子计算机到达建模为对数正态/威布尔分布（参数来自专家调查、NIST 路线图、量子计算社区预测），得到 P(CRQC ≤ t)。
2. **证书剩余有效期 → 连续风险暴露积分**：对每张证书，风险 ∝ ∫₀^τ P(CRQC 在证书有效期内到达) × 数据敏感度 dt，τ=剩余有效期。
3. **Mosca 不等式的概率化形式**：风险 = P(迁移完成时间 > CRQC 到达时间 - 数据保密期) 的显式分布计算，而非不等式判据。
4. **NIST 时间线作为校准锚点**：把 NIST 迁移里程碑（2024 标准化、混合推荐、2030/2035 目标）作为风险曲线的再校准点。
5. **互联网级证书剩余有效期分布测量**：Censys/Shodan/主动扫描的百万级证书数据，测 notBefore/notAfter 分布、各行业、各签名算法。
6. **逐证书/逐站点的时间感知风险分数**：把 1174 的全局 M 替换为逐连接的概率化时间积分，输出 0–100 且随日期自动重算。
7. **迁移紧迫度排序算法**：基于风险分数的组织/证书优先级排序（对应 1703 里"prioritize HNDL-sensitive data"的定性号召）。
8. **敏感性分析框架**：对 CRQC 分布参数、数据敏感期、NIST 截止日做敏感性分析，回答"如果 CRQC 提前/延后 5 年，风险排名怎么变"。

---

## 5. D. 结论：突破性贡献与工作量评估

### 推荐定位
做一个 **"概率化时间感知量子脆弱性评分"（Probabilistic Time-Aware Quantum Vulnerability Score, PTA-QVS）**，核心公式形如：

```
Risk(cert, t) = Sensitivity(data) × ∫₀^{τ(cert)} P_CRQC(s) × Vuln(algo) ds
```

- τ(cert) = 证书剩余有效期（连续积分窗口）
- P_CRQC(s) = CRQC 到达时间的累积概率密度（概率分布）
- Vuln(algo) = 算法 Shor/Grover 脆弱度（可复用 1174 的 L2 层思想）
- Sensitivity = 数据保密期（对应 1174 的 M，但变成逐数据类别的分布而非全局常数）

**相对现有工作的差异化**：
- vs 1174：全局常数 M → 逐连接概率积分；离散 L3 → 连续窗口；加 NIST 时间线锚点
- vs 1467：静态组织就绪度 → 动态时间风险；加 HNDL/证书生命周期
- vs 790：概念框架 → 可运行模型 + 实证
- vs 866：可观测性基础设施 → 风险决策输出

### 工作量估算（单人全职）
| 阶段 | 时间 | 说明 |
|---|---|---|
| 模型形式化 + 文献闭环 | 3–4 周 | 含 CRQC 概率分布参数来源调研 |
| CRQC 到达分布校准 | 2–3 周 | 专家调查/公开路线图数据 → 拟合分布 |
| 证书数据采集 | 1–2 周 | Censys/Shodan/主动扫描，测剩余有效期分布 |
| 原型实现 + 评分 | 3–4 周 | Python/Go 工具，输出 0–100 + 排序 |
| 对照验证 | 2–3 周 | 对 1174 的 502 会话思路 + 更大规模重跑 |
| 论文写作 | 3–4 周 | 目标：ePrint + 安全会议（USENIX/WWW/CCS 应用轨） |

**总计约 4–6 个月**可产出一篇有实证、有概率模型、填补明确空白的论文。风险点：CRQC 到达分布参数缺乏共识（需要用专家先验+敏感性分析兜底）；数据敏感度难以从公开数据获取（可用代理指标如站点类型/行业）。

---

## 6. 附录：PDF 全文深层挖掘（公式级细节）

> 通过 curl 下载 PDF + pdftotext 提取全文，确认了以下精确公式。这是对第 1–5 节摘要级分析的重要补充。

### 6.1 Hyoung 2026/1174 — 完整评分公式

**最终分**（式 1–2）：
```
Final Score = (L1 + L2a + L2b + L2c + L3) × M
Normalized  = (Final Score / 118) × 100  ∈ [0,100]  （超 100 时截断）
```
归一化常数 118 = 最坏场景上界（TLS 1.0 + RSA + AES-128 + 过期证书，h=20 → M=2.0）。

**各层公式**（T=威胁等级 1–5，E=暴露值，e=网络暴露系数，m=环境乘数 0.6–1.5）：
```
L1  = T × E × m          （协议层；TLS 1.3 纯 PQC = 0）
L2a = T × E × e × m      （RSA: E=5.0；ECDHE/DHE: E=3.0；e: 本地 0.25/内网 0.5/公网 443 为 1.0）
L2b = T × E × m          （AES-128 Grover：T=4.0 固定，E=0.5 固定）
L2c = T × E × m          （PQC Level-1 保守模式：T=3.0，E=2.0，需三条件同时满足）
L3  = 5.0（已过期）｜ 5.0 × (30−d)/30（0≤d<30 天）｜ 0（d≥30 天）
```

**HNDL 乘数 M（式 8）——论文的时间建模核心**：
```
M = 1.0 + h/20.0,  M ∈ [1.0, 2.0],  h = 数据保密期（年）
h=0→M=1.00, h=5→1.25, h=10→1.50, h=20→2.00
```

**L3 的关键弱点（实证证据）**：论文自己报告 L3 均值 domestic=0.15、global=0.09——因为 L3 只在"30 天窗口"内才线性上升，而大多数证书剩余期 >30 天 → L3≈0。**证书剩余有效期对 95%+ 的连接完全没有贡献**。

**HNDL 敏感性分析（表 12）**：h=5→(13.3, 10.0)；h=10→(16.0, 11.9)；h=20→(21.2, 15.9)。注意这是线性乘数放大，不是概率重算。

**论文自认的 5 个 future work**（第 5 节）：
1. m 自动化（当前外部不可观测、固定 1.0）
2. JA4 指纹集成（按 ClientHello 逐客户端差异化评分）
3. **完整证书链跟踪**——"L3 目前只反映服务器证书过期状态，中间 CA 证书里的 RSA 密钥同样是量子攻击目标"（这正是你的空白之一！）
4. 大规模验证 + OID fallback 频率测量 + 扩展到 QUIC
5. 扩展到 PKI/DB 传输加密

### 6.2 Costa 2026/1467 — CARS 完整公式与**作者自认的空白**

**CARS 公式（式 7）**：
```
CARS(S) = 100 × Σᵢ wᵢ·dᵢ(S),  Σwᵢ = 1
权重 w = (0.20, 0.25, 0.25, 0.15, 0.15)  ← 12 名工程师两轮 Delphi
d1=资产清点, d2=算法合规, d3=架构解耦, d4=工具链, d5=治理合规
分级：≤30 Critical ｜ 31–75 At-Risk/Transitional ｜ ≥76 Ready
```

**⚡ 最重要的发现——CARS 作者自己在 Future Work 中承认的空白（正文 3–4 页）**：
> "Future iterations of CARS could incorporate a **data-longevity weight** into d3: assets protecting data with confidentiality periods exceeding the estimated CRQC horizon (e.g., >10 years) would receive amplified weighting, reflecting elevated HNDL exposure. Formally, `d′₃(S) = d₃(S) × (1 + α·max(0, T_conf − T_CRQC))` where T_conf is the required confidentiality period, **T_CRQC the estimated CRQC arrival**, and α a tuning parameter."

**这正是你的项目的目标空白，且有两个决定性弱点**：
1. T_CRQC 是**确定性点估计**（单个"预计 CRQC 到达年"），不是概率分布——没有 P(CRQC ≤ t)
2. 公式只是对 d3 的线性放大，**没有证书剩余有效期、没有积分、没有 NIST 时间线里程碑、没有实现（仅 future work 提案）**

另外 CARS 的时间处理只有：Fig.9 迁移时长 vs CARS 分数投影（Delphi 估计）+ CNSA 2.0 2030 截止映射——都是组织层面，非逐证书。

### 6.3 其他论文的补充确认

- **Roy 1703**（SoK）：迁移框架第 2 步 "Identify HNDL-sensitive information. Prioritize information whose confidentiality must survive for years or decades"——**定性号召，无数值排序算法**（你的空白 7 的直接证据）。
- **Delgado 866**：7 个测量平面含 lifecycle/temporal drift，但**不产出任何风险分数**——可作你的数据采集层参考。
- **Chammas 790**：立场论文，批评标准/文献"风险建模不足"，提议三层框架（诊断+定性风险+ROI）——**无实现**。

### 6.4 文献侧翼（1174/1467 引用的相关来源，值得跟进）
- Kagai et al., *Harvest-now, decrypt-later: A temporal cybersecurity risk in the quantum transition*, Telecom 6(4), 100 (2025) — HNDL 时间风险的直接文献
- Mosca & Piani, *2023 Quantum Threat Timeline Report*, Global Risk Institute — h=10 的参数来源
- Baseri et al., *Evaluation framework for quantum security risk assessment*, arXiv:2404.08231 (2024) — 三阶段迁移 STRIDE 框架
- Krelina et al., *SQOUT*, arXiv:2510.23462 (2025) — QKD 威胁框架（T/E/m 结构的灵感来源）
- NIST IR 8547 ipd — RSA/ECDH/DSA 2030 弃用、2035 禁用的时间锚点

---

### 引用清单（全部 URL）
- Hyoung et al., *A Layered Risk Scoring Model for TLS Connections Against Quantum Threats*, ePrint 2026/1174 — https://eprint.iacr.org/2026/1174
- Costa, *Quantum-Safe Cryptography: A Migration Framework...Crypto-Agility Readiness Score*, ePrint 2026/1467 — https://eprint.iacr.org/2026/1467
- Chammas et al., *Towards a Field-Informed Risk-Based Framework for PQC Migration in Legacy Systems*, ePrint 2026/790 — https://eprint.iacr.org/2026/790
- Delgado, *Observability for Post-Quantum TLS Readiness*, ePrint 2026/866 — https://eprint.iacr.org/2026/866
- Roy, *Post-Quantum TLS Migration: A Systematization...*, ePrint 2026/1703 — https://eprint.iacr.org/2026/1703
- Das & Chattopadhyay, *Analysing the Post-Quantum Security of S/MIME*, ePrint 2026/1374 — https://eprint.iacr.org/2026/1374
- Kagai et al., *HNDL: A temporal cybersecurity risk in the quantum transition*, Telecom 6(4):100 (2025) — https://doi.org/10.3390/telecom6040100
- Mosca & Piani, *2023 Quantum Threat Timeline Report*, GRI — https://globalriskinstitute.org
- Baseri et al., *Evaluation framework for quantum security risk assessment*, arXiv:2404.08231 (2024) — https://arxiv.org/abs/2404.08231
