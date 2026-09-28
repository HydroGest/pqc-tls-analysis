/*
 * oid_db.c — OID 特征库（硬编码静态查找表）
 *
 * 数据来源：
 *   1) research/算法特征识别库.json v1.0 —— x509_key_oids（RSA/EC/DSA/DH/EdDSA）
 *   2) IETF draft-ietf-lamps-kyber-certificates-05    → ML-KEM OID 2.16.840.1.101.3.4.4.{1,2,3}
 *   3) IETF draft-ietf-lamps-dilithium-certificates-10 → ML-DSA OID 2.16.840.1.101.3.4.3.{17,18,19}
 *   4) IETF draft-ietf-lamps-sphincs-plus-certificates → SLH-DSA OID 2.16.840.1.101.3.4.3.{20..31}
 *   5) RFC 8410（X25519/X448/EdDSA）、RFC 8708（LMS/HSS）、draft-ietf-lamps-xmss-certificates（XMSS）
 *   6) 国密 GM/T 0009（SM2 公钥/签名 OID）
 *
 * 表为只读静态数组，工具运行不依赖外部 JSON 文件。
 */
#include "oid_db.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>

static const oid_entry_t oid_table[] = {
    /* ================= X.509 公钥算法 OID（特征库 x509_key_oids） ================= */
    {"1.2.840.113549.1.1.1",   "rsaEncryption",        ALGO_RSA,     2048, 0,
     "Shor 可直接分解 RSA 模数；<2048 位经典侧亦不安全"},
    {"1.2.840.10045.2.1",      "id-ecPublicKey",       ALGO_ECC,     0,    0,
     "通用 EC 公钥（曲线在 parameters 中），Shor 破 ECDLP"},
    {"1.2.840.10040.4.1",      "id-dsa",               ALGO_DSA,     0,    0,
     "Shor 破离散对数 DLP"},
    {"1.2.840.10046.2.1",      "dhpublicnumber",       ALGO_DH,      0,    0,
     "有限域 DH，Shor 破 DLP"},
    {"1.3.101.112",            "id-Ed25519",           ALGO_ED25519, 256,  0,
     "Ed25519 基于 ECDLP，同样被 Shor 破"},
    {"1.3.101.113",            "id-Ed448",             ALGO_ED448,   456,  0,
     "Ed448 基于 ECDLP，同样被 Shor 破"},

    /* ================= 国密 SM2 ================= */
    {"1.2.156.10197.1.301",    "id-sm2",               ALGO_SM2,     256,  0,
     "国密 SM2（ECDLP 基），Shor 可破；注意与 EC 参数区分"},
    {"1.2.156.10197.1.501",    "SM3withSM2",           ALGO_SM2,     256,  0,
     "SM2 签名（SM3 哈希），Shor 破 SM2 公钥体系"},

    /* ================= EC 命名曲线（SPKI parameters 中的 OID） ================= */
    {"1.2.840.10045.3.1.7",    "prime256v1",           ALGO_ECC,     256,  0, "NIST P-256，Shor 破"},
    {"1.3.132.0.34",           "secp384r1",            ALGO_ECC,     384,  0, "NIST P-384，Shor 破"},
    {"1.3.132.0.35",           "secp521r1",            ALGO_ECC,     521,  0, "NIST P-521，Shor 破"},
    {"1.2.840.10045.3.1.1",    "prime192v1",           ALGO_ECC,     192,  0, "P-192，经典+量子均不安全"},
    {"1.3.101.110",            "id-X25519",            ALGO_ECC,     256,  0, "X25519 ECDH，Shor 破"},
    {"1.3.101.111",            "id-X448",              ALGO_ECC,     448,  0, "X448 ECDH，Shor 破"},

    /* ================= RSA 签名算法 OID ================= */
    {"1.2.840.113549.1.1.4",   "md5WithRSAEncryption", ALGO_RSA,     2048, 0,
     "MD5 已完全破解（碰撞），签名不可信 → 致命"},
    {"1.2.840.113549.1.1.5",   "sha1WithRSAEncryption",ALGO_RSA,     2048, 0,
     "SHA-1 碰撞已实现（SHAttered），CA 已停止签发 → 致命"},
    {"1.2.840.113549.1.1.14",  "sha224WithRSAEncryption", ALGO_RSA,  2048, 0, "Shor 破 RSA"},
    {"1.2.840.113549.1.1.11",  "sha256WithRSAEncryption", ALGO_RSA,  2048, 0, "Shor 破 RSA"},
    {"1.2.840.113549.1.1.12",  "sha384WithRSAEncryption", ALGO_RSA,  2048, 0, "Shor 破 RSA"},
    {"1.2.840.113549.1.1.13",  "sha512WithRSAEncryption", ALGO_RSA,  2048, 0, "Shor 破 RSA"},
    {"1.2.840.113549.1.1.10",  "rsassaPss",            ALGO_RSA,     2048, 0, "RSA-PSS，Shor 破"},

    /* ================= ECDSA 签名算法 OID ================= */
    {"1.2.840.10045.4.1",      "ecdsa-with-SHA1",      ALGO_ECC,     256,  0, "SHA-1 + ECDSA，双重致命"},
    {"1.2.840.10045.4.3.2",    "ecdsa-with-SHA256",    ALGO_ECC,     256,  0, "Shor 破 ECDSA"},
    {"1.2.840.10045.4.3.3",    "ecdsa-with-SHA384",    ALGO_ECC,     384,  0, "Shor 破 ECDSA"},
    {"1.2.840.10045.4.3.4",    "ecdsa-with-SHA512",    ALGO_ECC,     521,  0, "Shor 破 ECDSA"},

    /* ================= DSA 签名算法 OID ================= */
    {"1.2.840.10040.4.3",      "dsa-with-sha1",        ALGO_DSA,     0,    0, "SHA-1 + DSA，致命"},
    {"2.16.840.1.101.3.4.3.2", "dsa-with-sha256",      ALGO_DSA,     0,    0, "Shor 破 DSA"},
    {"2.16.840.1.101.3.4.3.3", "dsa-with-sha384",      ALGO_DSA,     0,    0, "Shor 破 DSA"},
    {"2.16.840.1.101.3.4.3.4", "dsa-with-sha512",      ALGO_DSA,     0,    0, "Shor 破 DSA"},

    /* ================= PQC：ML-KEM（NIST FIPS 203） ================= */
    {"2.16.840.1.101.3.4.4.1", "id-alg-ml-kem-512",    ALGO_MLKEM,   0,    1, "NIST 类别 1，抗量子 KEM"},
    {"2.16.840.1.101.3.4.4.2", "id-alg-ml-kem-768",    ALGO_MLKEM,   0,    3, "NIST 类别 3，抗量子 KEM"},
    {"2.16.840.1.101.3.4.4.3", "id-alg-ml-kem-1024",   ALGO_MLKEM,   0,    5, "NIST 类别 5，抗量子 KEM"},

    /* ================= PQC：ML-DSA（NIST FIPS 204） ================= */
    {"2.16.840.1.101.3.4.3.17", "id-ml-dsa-44",        ALGO_MLDSA,   0,    2, "NIST 类别 2，抗量子签名"},
    {"2.16.840.1.101.3.4.3.18", "id-ml-dsa-65",        ALGO_MLDSA,   0,    3, "NIST 类别 3，抗量子签名"},
    {"2.16.840.1.101.3.4.3.19", "id-ml-dsa-87",        ALGO_MLDSA,   0,    5, "NIST 类别 5，抗量子签名"},

    /* ================= PQC：SLH-DSA（NIST FIPS 205） ================= */
    {"2.16.840.1.101.3.4.3.20", "id-alg-slh-dsa-sha2-128s",  ALGO_SLHDSA, 0, 1, "类别 1，哈希签名"},
    {"2.16.840.1.101.3.4.3.21", "id-alg-slh-dsa-sha2-128f",  ALGO_SLHDSA, 0, 1, "类别 1，哈希签名"},
    {"2.16.840.1.101.3.4.3.22", "id-alg-slh-dsa-sha2-192s",  ALGO_SLHDSA, 0, 3, "类别 3，哈希签名"},
    {"2.16.840.1.101.3.4.3.23", "id-alg-slh-dsa-sha2-192f",  ALGO_SLHDSA, 0, 3, "类别 3，哈希签名"},
    {"2.16.840.1.101.3.4.3.24", "id-alg-slh-dsa-sha2-256s",  ALGO_SLHDSA, 0, 5, "类别 5，哈希签名"},
    {"2.16.840.1.101.3.4.3.25", "id-alg-slh-dsa-sha2-256f",  ALGO_SLHDSA, 0, 5, "类别 5，哈希签名"},
    {"2.16.840.1.101.3.4.3.26", "id-alg-slh-dsa-shake-128s", ALGO_SLHDSA, 0, 1, "类别 1，SHAKE"},
    {"2.16.840.1.101.3.4.3.27", "id-alg-slh-dsa-shake-128f", ALGO_SLHDSA, 0, 1, "类别 1，SHAKE"},
    {"2.16.840.1.101.3.4.3.28", "id-alg-slh-dsa-shake-192s", ALGO_SLHDSA, 0, 3, "类别 3，SHAKE"},
    {"2.16.840.1.101.3.4.3.29", "id-alg-slh-dsa-shake-192f", ALGO_SLHDSA, 0, 3, "类别 3，SHAKE"},
    {"2.16.840.1.101.3.4.3.30", "id-alg-slh-dsa-shake-256s", ALGO_SLHDSA, 0, 5, "类别 5，SHAKE"},
    {"2.16.840.1.101.3.4.3.31", "id-alg-slh-dsa-shake-256f", ALGO_SLHDSA, 0, 5, "类别 5，SHAKE"},

    /* ================= PQC：XMSS / LMS（哈希签名） ================= */
    {"0.4.0.127.0.15.1.1.13.0", "id-alg-xmss",         ALGO_XMSS,    0,    0, "XMSS 状态型哈希签名"},
    {"0.4.0.127.0.15.1.1.14.0", "id-alg-xmssmt",       ALGO_XMSS,    0,    0, "XMSS^MT 多树哈希签名"},
    {"1.2.840.113549.1.9.16.3.17", "id-alg-hss-lms-hashsig", ALGO_LMS, 0,  0, "LMS/HSS（RFC 8708）哈希签名"},
};

#define OID_TABLE_LEN (sizeof(oid_table) / sizeof(oid_table[0]))

/* 前缀匹配：oid 以 prefix 开头，且后一个字符必须是 '.' 或结束 */
static int oid_has_prefix(const char *oid, const char *prefix)
{
    size_t plen = strlen(prefix);
    if (strncmp(oid, prefix, plen) != 0)
        return 0;
    return oid[plen] == '\0' || oid[plen] == '.';
}

/* 前缀回退条目：覆盖未知变体 OID */
typedef struct {
    const char *prefix;
    algo_type_t algo;
    const char *name;
    const char *note;
} oid_prefix_rule_t;

static const oid_prefix_rule_t oid_prefix_rules[] = {
    {"0.4.0.127.0.15.1.1.13", ALGO_XMSS,   "XMSS (变体)",   "XMSS 状态型哈希签名"},
    {"0.4.0.127.0.15.1.1.14", ALGO_XMSS,   "XMSS^MT (变体)","XMSS^MT 多树哈希签名"},
    {"1.2.840.113549.1.9.16.3.17", ALGO_LMS, "LMS/HSS",     "RFC 8708 哈希签名"},
    {"2.16.840.1.101.3.4.4",   ALGO_MLKEM, "ML-KEM (变体)", "抗量子 KEM"},
    {"1.2.156.10197",          ALGO_SM2,   "SM 国密 (变体)", "国密算法族，Shor 威胁"},
    {"1.2.840.10045",          ALGO_ECC,   "EC 算法族 (变体)", "ECDLP 基，Shor 威胁"},
    {"1.2.840.113549.1.1",     ALGO_RSA,   "RSA (变体)",    "PKCS#1 算法族，Shor 威胁"},
};

const oid_entry_t *oid_lookup(const char *oid_str)
{
    size_t i;
    if (!oid_str)
        return NULL;
    for (i = 0; i < OID_TABLE_LEN; i++)
        if (strcmp(oid_table[i].oid, oid_str) == 0)
            return &oid_table[i];
    /* 前缀回退：识别未知变体 */
    for (i = 0; i < sizeof(oid_prefix_rules) / sizeof(oid_prefix_rules[0]); i++) {
        const oid_prefix_rule_t *r = &oid_prefix_rules[i];
        if (oid_has_prefix(oid_str, r->prefix)) {
            static oid_entry_t fallback;
            fallback.oid = oid_str;
            fallback.name = r->name;
            fallback.algo = r->algo;
            fallback.key_size = 0;
            fallback.nist_category = 0;
            fallback.note = r->note;
            return &fallback;
        }
    }
    return NULL;
}

int oid_is_known(const char *oid_str)
{
    return oid_lookup(oid_str) != NULL;
}

int oid_entry_count(void)
{
    return (int)OID_TABLE_LEN;
}

const oid_entry_t *oid_entry_at(int i)
{
    if (i < 0 || i >= (int)OID_TABLE_LEN)
        return NULL;
    return &oid_table[i];
}

/* 按规范名查找：忽略大小写、'-' 与 '_' */
const oid_entry_t *oid_lookup_by_name(const char *name)
{
    char a[128], b[128];
    size_t i, j;
    if (!name)
        return NULL;
    j = 0;
    for (i = 0; name[i] && j + 1 < sizeof(a); i++) {
        char c = (char)tolower((unsigned char)name[i]);
        if (c == '-' || c == '_' || c == ' ')
            continue;
        a[j++] = c;
    }
    a[j] = '\0';
    for (i = 0; i < OID_TABLE_LEN; i++) {
        j = 0;
        for (size_t k = 0; oid_table[i].name[k] && j + 1 < sizeof(b); k++) {
            char c = (char)tolower((unsigned char)oid_table[i].name[k]);
            if (c == '-' || c == '_' || c == ' ')
                continue;
            b[j++] = c;
        }
        b[j] = '\0';
        if (strcmp(a, b) == 0)
            return &oid_table[i];
    }
    return NULL;
}
