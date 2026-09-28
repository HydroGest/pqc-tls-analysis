# 研究报告索引

本项目共四份研究报告，按阅读顺序排列：

| # | 文件 | 主题 |
|---|---|---|
| 01 | [01_tls_quantum_vulnerability_methodology.md](01_tls_quantum_vulnerability_methodology.md) | **测量方法论**：中国 Top N 网站 TLS 证书链量子脆弱性如何测（维度、判定、数据源、偏差控制） |
| 02 | [02_time_aware_pqc_risk_review.md](02_time_aware_pqc_risk_review.md) | **文献综述**：时间感知的 PQC 迁移风险模型现状与空白（IACR ePrint 核心文献） |
| 03 | [03_chain_pqc_gap_analysis.md](03_chain_pqc_gap_analysis.md) | **学术空白调研**：证书链/CA 生态量子脆弱性方向尚未被系统研究的空白点（NIST 标准、CA 生态实证） |
| 04 | [04_pta_qvs_modeling.md](04_pta_qvs_modeling.md) | **建模方法论**：PTA-QVS 评分模型每个参数的"依据来源"（可复现、按证据强度分层） |

## 阅读建议

- 想了解**项目全貌与结论**：01 → 04 → 顶层 README 的"主要结论速览"。
- 想找**研究空白（选题）**：02 与 03 的"空白分析"章节。
- 想复现**评分模型**：04 的每个参数都有对应的依据来源编号（指向 `research/` 中的标准文本或公开论文）。

## 信息边界

- 各报告标注了调研环境与可达性限制（部分渠道如 arXiv / Google Scholar 在调研时不可达），凡"未找到"均指在可达渠道内的未找到，不做绝对断言。
- 下载的论文全文（`papers/`）与中间研究产物（`research/` 中除标准文本外的部分）不随仓库发布；引用依据均在报告中注明出处（ePrint 编号 / DOI / 标准号）。
