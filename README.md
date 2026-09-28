# pqc-tls-analysis

**中国 Top N 网站 TLS 证书链的量子脆弱性测量与分析** —— 从测量方法学、风险模型到判定工具与基准的全套研究。

> 目标：回答"中国的 TLS 证书链在后量子时代有多脆弱、何时必须迁移、迁移的优先级怎么排"。
> 产出：4 份研究报告（方法学 / 文献综述 / 学术空白 / 评分模型）+ C 语言威胁判定引擎 + TLS 证书链扫描管线 + SPHINCS+ 基准 + 可视化 Web 应用。

## 四份报告

| # | 报告 | 内容 |
|---|---|---|
| 01 | [TLS 证书链量子脆弱性测量方法论](report/01_tls_quantum_vulnerability_methodology.md) | 中国 Top N 网站 TLS 证书链量子脆弱性测量的结构化方法学：测量维度、威胁判定、数据源（Mozilla NSS / CCADB / crt.sh）、偏差控制 |
| 02 | [时间感知 PQC 迁移风险模型：文献现状与空白](report/02_time_aware_pqc_risk_review.md) | IACR ePrint 为主的文献综述（Hyoung 2026/1174、Costa 2026/1467、Chammas 2026/790 等），梳理"时间感知"风险建模的现状与空白 |
| 03 | [证书链/CA 生态量子脆弱性：学术空白调研](report/03_chain_pqc_gap_analysis.md) | 该方向学术空白检索：NIST IR 8547、SP 1800-38B、crt.sh 中国 CA 实证、CABF/CCADB 生态现状 |
| 04 | [概率化时间感知量子风险评分（PTA-QVS）建模方法论](report/04_pta_qvs_modeling.md) | 模型参数怎么来：每个参数绑定可复现依据来源、按证据强度分层、禁止拍脑袋常数 |

## 代码与工具

| 模块 | 说明 |
|---|---|
| `tool/` | **pqc-judge**：C 语言抗量子威胁判定引擎（OID / 算法名 / 证书文件 → Shor / Grover 威胁等级，退出码 0–5），112 项单元测试；配套 `scan_tls_chains.py`（批量扫描）、`analyze_chains.py`（链分析）、`pareto_analysis.py`（帕累托/操作点分析） |
| `benchmark/` | SPHINCS+（SLH-DSA）8 个参数变体的编译-运行基准（`run_all.sh` + 完整日志），含参考实现源码 `sphincs-ref/` |
| `data/` | 扫描结果：`chains_test/`（小样本）、`chains_top1000/`（Top 1000 网站证书链，json/ + pem/ + summary.json） |
| `trust_store_data/` | Mozilla NSS 根证书（121 roots）+ 中国 SM2/GM 根证书 + Top1000 榜单构建方法学与结果（`ccadb_v5.csv` 因体积不随仓库发布，见下） |
| `web/` | 可视化 Web 应用（Flask 单文件：证书续费 PQC 升级指南 / 信任库查询 / 状态页） |
| `research/` | 公共标准文本（RFC 8446/5280/8391/8554、FIPS 205 SLH-DSA）作为报告引用依据 |

## 快速开始

```bash
# 1) 编译威胁判定引擎
cd tool && make && make check   # 112 项单元测试

# 2) 扫描一个域名的证书链
python3 tool/scan_tls_chains.py example.com

# 3) 复跑 SPHINCS+ 基准（需 gcc，约 30 分钟）
cd benchmark && ./run_all.sh && cat logs/sphincs-sha2-128f.log

# 4) 启动可视化 Web 应用
cd web && pip install flask && python3 app.py
# 打开 http://localhost:5000（域名 → 证书链 PQC 升级建议）
```

## 数据说明

- **证书链数据**（`data/`）为公开 X.509 证书的聚合扫描结果，可随时用 `scan_tls_chains.py` 重新生成。
- **`ccadb_v5.csv`**（CCADB V5，约 1.5 万条记录，11 MB）为公开数据，未随仓库发布；需要完整 CA 库时从 [CCADB](https://www.ccadb.org/) 下载并放入 `trust_store_data/`，Web 应用会自动加载（缺失时自动降级）。
- **RFC/FIPS 文本**（`research/`）来自 IETF 与 NIST 公开文档。

## 主要结论速览

- **威胁判定**：RSA / ECC / SM2 / DSA / EdDSA / DH 全部落入 Shor 威胁类；AES-128 落入 Grover 类；ML-KEM / ML-DSA / SLH-DSA / XMSS / LMS 量子安全——中国大量存量证书（RSA、SM2）均在 Shor 威胁范围内。
- **时间维度**：证书到期年 × NIST 2030/2035 迁移时间线构成风险主变量；多数存量证书在量子威胁窗口内仍需续期，**续期决策本身即迁移决策**（见 `web/` 的"续费 PQC 升级指南"）。
- **测量**：证书链量子脆弱性的测量维度 = 算法威胁等级 + 密钥强度 + 有效期 + 签发链深度 + 信任存储含 PQC 根与否；Top 1000 扫描的统计见 `data/chains_top1000/summary.json`。

## License

MIT（代码部分）；报告与文档保留署名。
