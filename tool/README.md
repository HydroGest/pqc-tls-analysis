# pqc-judge — 抗量子威胁判定引擎

## 概述

`pqc-judge` 是"抗量子密码算法的应用与部署关键技术研究"（方向一）配套的 C 语言威胁判定工具。
它输入 算法标识（OID / 算法名 / 证书文件），输出 Shor / Grover 量子威胁等级，供批量扫描管线和
单站诊断调用。

## 威胁模型

| 威胁类型 | 适用算法 | 说明 |
|----------|----------|------|
| **THREAT_NONE** (0) | ML-KEM, ML-DSA, SLH-DSA, XMSS, LMS, AES-192/256, ChaCha20 | 量子安全（当前无已知量子威胁） |
| **THREAT_GROVER** (1) | AES-128（降至 ~64 位安全） | Grover 搜索加速，新部署建议 AES-256 |
| **THREAT_SHOR** (2) | RSA, ECC/ECDSA, SM2, DSA, EdDSA, DH | Shor 算法多项式时间破解整数分解/ECDLP/DLP |
| **THREAT_CRITICAL** (3) | RSA < 2048, SHA-1/MD5 签名, 过期/自签名证书, DES/3DES | 经典+量子皆存高危缺陷 |

## 编译

```bash
cd tool
make          # 编译 pqc-judge + test_judge
make check    # 编译 + 运行单元测试
```

### 依赖

- **gcc / clang**（C99 标准）
- **openssl CLI**（证书解析模式 a 需要；模式 b DER 自解析不依赖）
- **无 openssl 开发库依赖**（使用 openssl CLI + 自建 DER 解析器）

## 用法

```bash
# 按算法名判定
./pqc-judge -a RSA-2048       # Shor 威胁
./pqc-judge -a AES-128        # Grover 威胁
./pqc-judge -a ML-DSA-65      # 量子安全

# 按 OID 判定
./pqc-judge -o 1.2.840.113549.1.1.1       # rsaEncryption → Shor
./pqc-judge -o 2.16.840.1.101.3.4.3.17     # ML-DSA-44 → 安全

# 解析证书判定（模式 a：openssl CLI，自动回退 DER）
./pqc-judge -c cert.pem
# 强制 DER 解析（不依赖 openssl）
./pqc-judge -c cert.pem -m der

# 查看已知 OID 表
./pqc-judge --list
```

### 支持的输入格式（-a）

- **算法名**：`RSA-2048`, `RSA 4096`, `AES-128`, `AES-256`, `DES`, `3DES`
- **PQC**：`ML-KEM-768`, `mlkem`, `ML-DSA-65`, `mldsa44`, `slhdsa_sha2_128s`
- **EC**：`secp256r1`, `prime256v1`, `x25519`, `sm2`, `ed25519`
- **TLS 签名方案（name）**：`rsa_pkcs1_sha256`, `mldsa44`, `ed25519`
- **TLS 签名方案（hex）**：`0x0401` (rsa_pkcs1_sha256), `0x0904` (mldsa44)
- **SSH**：`ssh-rsa`, `ssh-ed25519`, `ecdsa-sha2-nistp256`

## 项目结构

```
tool/
├── Makefile               # 编译脚本
├── CMakeLists.txt          # CMake 备选
├── README.md
├── src/
│   ├── main.c              # CLI 入口（-a/-o/-c/--list）
│   ├── threat_judge.c/h    # 核心判定逻辑
│   ├── oid_db.c/h          # OID 特征库（硬编码静态表）
│   └── cert_parser.c/h     # 证书解析（openssl CLI + 自含 DER）
└── test/
    ├── test_judge.c        # 单元测试（112 项）
    └── certs/
        ├── test_rsa.pem      # RSA-2048 自签名 CA
        ├── test_sm2.pem      # SM2 自签名 CA
        ├── test_ec.pem       # ECDSA prime256v1 自签名
        ├── test_selfsigned.pem # RSA-2048 SHA-256 自签名
        └── test_expired.pem   # 已过期 RSA 自签名
```

## OID 特征库覆盖

特征库硬编码于 `src/oid_db.c`，来源包括：

- `research/算法特征识别库.json` v1.0 —— RSA、EC、DSA、EdDSA 等经典算法 OID
- IETF draft-ietf-lamps-kyber-certificates-05 → ML-KEM
- IETF draft-ietf-lamps-dilithium-certificates-10 → ML-DSA
- IETF draft-ietf-lamps-sphincs-plus-certificates → SLH-DSA
- RFC 8410（X25519/X448/EdDSA）、RFC 8708（LMS/HSS）
- 国密 GM/T 0009（SM2 公钥/签名 OID）

## 退出码

| 码 | 含义 | 典型场景 |
|----|------|----------|
| 0  | 量子安全 | PQC、AES-192/256 |
| 1  | Grover 威胁 | AES-128 |
| 2  | Shor 威胁 | RSA、ECC、SM2、DSA、EdDSA、DH |
| 3  | 致命 | RSA<2048、SHA-1/MD5、过期、自签名 |
| 4  | 未知/解析失败 | 未知 OID、证书解析失败 |
| 5  | 用法错误 | 参数不完整 |

## 单元测试

```bash
make check
```

运行 112 项测试：算法判定、OID 查找、算法名解析、签名算法判定、证书解析（双模式）。

## 后续扩展

- [ ] CRL/OCSP 吊销检查 → THREAT_CRITICAL
- [ ] 时间感知评分（证书到期年 × NIST 2030/2035 时间线）
- [ ] 批量扫描命令行支持（输入域名列表 → CSV 输出）
- [ ] Python ctypes 绑定 / JSON 输出模式