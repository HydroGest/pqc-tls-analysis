# 中国特有信任库数据目录说明

## 数据来源与抓取日期
- 抓取日期: 2026-09-20
- 全部证书来自公开官网，无编造。

## 目录内容
- `extracted_sm2/` — CFCA 国家信任源 + 生产 SM2 根（从官网 RAR/ZIP 解包）
- `wotrus_sm2/` — 沃通 WoTrus 国密 SM2 根（国家信任体系 + 国际信任体系 + 各省政务根）
- `gjzsl-sm2/`, `gjzsl-rsa/` — CFCA 国家信任源 RAR 解包原始文件
- `生产证书链SM2/`, `生产证书链RSA/` — CFCA 生产证书链 ZIP 解包
- `cfca_*.rar`, `cfca_*.zip` — 原始下载包（可复现）
- `china_sm2_roots_combined.pem` — 全部已获取 SM2 根的合并 PEM（25 个证书）

## 关键文件 URL（原始来源）
见 ../china_trust_stores.md 附录 A。

## 解析注意事项
- SM2 曲线 OID: 1.2.156.10197.1.301（sm2p256v1），cryptography/openssl 默认不支持，需 SM2 支持编译或使用国密工具链（gmssl）。
- 国家 RSA 根（OSCCA）已于 2025-08-23 过期。
