/*
 * threat_judge.c — 抗量子威胁判定核心逻辑
 *
 * Shor 威胁：RSA/ECC/SM2/DSA/EdDSA/DH（整数分解 / ECDLP / DLP）
 * Grover 威胁：AES-128 降至 ~64 位安全；AES-192/256 仍安全
 * PQC：ML-KEM/ML-DSA/SLH-DSA/XMSS/LMS → 无已知量子威胁
 */
#include "threat_judge.h"
#include "oid_db.h"
#include "cert_parser.h"   /* for cert_info_t in time_judge_cert */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int contains_ci(const char *haystack, const char *needle);

/* ================================================================== */
/* 基础判定                                                           */
/* ================================================================== */

threat_level_t judge_algorithm(algo_type_t algo, int key_size)
{
    switch (algo) {
    case ALGO_RSA:
        /* RSA-1024 及以下：经典（GNFS/NFS）与量子（Shor）均可破 → 致命 */
        if (key_size > 0 && key_size < 2048)
            return THREAT_CRITICAL;
        return THREAT_SHOR;

    case ALGO_ECC:
    case ALGO_SM2:
    case ALGO_DSA:
    case ALGO_ED25519:
    case ALGO_ED448:
    case ALGO_DH:
        /* Shor 算法多项式时间解 ECDLP / DLP，密钥长度不影响结论 */
        return THREAT_SHOR;

    case ALGO_MLKEM:
    case ALGO_MLDSA:
    case ALGO_SLHDSA:
    case ALGO_XMSS:
    case ALGO_LMS:
        return THREAT_NONE;

    case ALGO_AES:
        if (key_size >= 192)
            return THREAT_NONE;            /* AES-192/256：Grover 后仍 >=96 位 */
        if (key_size == 128 || key_size == 0)
            return THREAT_GROVER;          /* AES-128：Grover → ~64 位（默认按 128 计） */
        if (key_size < 128)
            return THREAT_CRITICAL;        /* <128 位 AES（不存在，防御性） */
        return THREAT_GROVER;

    case ALGO_SYMMETRIC:
        if (key_size >= 256)
            return THREAT_NONE;            /* ChaCha20 等 256 位 */
        if (key_size >= 128)
            return THREAT_GROVER;
        if (key_size > 0)
            return THREAT_CRITICAL;        /* DES(56)/3DES(112) 等 */
        return THREAT_NONE;

    case ALGO_UNKNOWN:
    default:
        return THREAT_NONE;
    }
}

threat_level_t judge_oid(const char *oid_str)
{
    const oid_entry_t *e = oid_lookup(oid_str);
    if (!e)
        return THREAT_NONE;   /* 未知 OID：调用方须用 oid_is_known() 检测并提示复核 */
    /* SHA-1/MD5 签名 OID：哈希碰撞已实现，经典侧即可伪造 → 致命 */
    if (contains_ci(e->name, "sha1") || contains_ci(e->name, "md5"))
        return THREAT_CRITICAL;
    return judge_algorithm(e->algo, e->key_size);
}

/* ================================================================== */
/* 算法名解析（-a 输入）                                               */
/* ================================================================== */

typedef struct {
    const char *hex;    /* TLS 签名方案 / 命名组 16 进制值 */
    const char *name;   /* 规范名 */
    algo_type_t algo;   /* 算法分类 */
    int category;       /* NIST 类别（PQC），0 = 不适用 */
} tls_scheme_t;

/* 数据来自 research/算法特征识别库.json：tls_signature_schemes / tls_supported_groups */
static const tls_scheme_t tls_schemes[] = {
    /* ---- TLS 1.3 签名方案 ---- */
    {"0x0401", "rsa_pkcs1_sha256",         ALGO_RSA,    0},
    {"0x0403", "ecdsa_secp256r1_sha256",   ALGO_ECC,    0},
    {"0x0501", "rsa_pkcs1_sha384",         ALGO_RSA,    0},
    {"0x0503", "ecdsa_secp384r1_sha384",   ALGO_ECC,    0},
    {"0x0601", "rsa_pkcs1_sha512",         ALGO_RSA,    0},
    {"0x0603", "ecdsa_secp521r1_sha512",   ALGO_ECC,    0},
    {"0x0804", "rsa_pss_rsae_sha256",      ALGO_RSA,    0},
    {"0x0805", "rsa_pss_rsae_sha384",      ALGO_RSA,    0},
    {"0x0806", "rsa_pss_rsae_sha512",      ALGO_RSA,    0},
    {"0x0807", "ed25519",                  ALGO_ED25519, 0},
    {"0x0808", "ed448",                    ALGO_ED448,   0},
    {"0x0904", "mldsa44",                  ALGO_MLDSA,   2},
    {"0x0905", "mldsa65",                  ALGO_MLDSA,   3},
    {"0x0906", "mldsa87",                  ALGO_MLDSA,   5},
    {"0x0911", "slhdsa_sha2_128s",         ALGO_SLHDSA,  1},
    {"0x0912", "slhdsa_sha2_128f",         ALGO_SLHDSA,  1},
    {"0x0913", "slhdsa_sha2_192s",         ALGO_SLHDSA,  3},
    {"0x0914", "slhdsa_sha2_192f",         ALGO_SLHDSA,  3},
    {"0x0915", "slhdsa_sha2_256s",         ALGO_SLHDSA,  5},
    {"0x0916", "slhdsa_sha2_256f",         ALGO_SLHDSA,  5},
    /* ---- TLS 1.3 命名组 ---- */
    {"0x0017", "secp256r1",                ALGO_ECC,     0},
    {"0x0018", "secp384r1",                ALGO_ECC,     0},
    {"0x0019", "secp521r1",                ALGO_ECC,     0},
    {"0x001d", "x25519",                   ALGO_ECC,     0},
    {"0x001e", "x448",                     ALGO_ECC,     0},
    {"0x0100", "ffdhe2048",                ALGO_DH,      0},
    {"0x0101", "ffdhe3072",                ALGO_DH,      0},
    {"0x0102", "ffdhe4096",                ALGO_DH,      0},
    {"0x0103", "ffdhe6144",                ALGO_DH,      0},
    {"0x0104", "ffdhe8192",                ALGO_DH,      0},
    {"0x11eb", "x25519mlkem768",           ALGO_MLKEM,   1}, /* 混合：ML-KEM 抗量子 */
};

static const tls_scheme_t *tls_scheme_lookup(const char *s)
{
    char buf[32];
    size_t i;
    if (!s)
        return NULL;
    /* 先按 16 进制值匹配（不区分大小写） */
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        size_t n = strlen(s);
        if (n >= sizeof(buf))
            n = sizeof(buf) - 1;
        for (i = 0; i < n; i++)
            buf[i] = (char)tolower((unsigned char)s[i]);
        buf[n] = '\0';
        for (i = 0; i < sizeof(tls_schemes) / sizeof(tls_schemes[0]); i++)
            if (strcmp(buf, tls_schemes[i].hex) == 0)
                return &tls_schemes[i];
        return NULL;
    }
    /* 再按规范名匹配（忽略大小写） */
    {
        size_t n = strlen(s);
        if (n >= sizeof(buf))
            n = sizeof(buf) - 1;
        for (i = 0; i < n; i++)
            buf[i] = (char)tolower((unsigned char)s[i]);
        buf[n] = '\0';
        for (i = 0; i < sizeof(tls_schemes) / sizeof(tls_schemes[0]); i++)
            if (strcmp(buf, tls_schemes[i].name) == 0)
                return &tls_schemes[i];
    }
    return NULL;
}

/* 小写化 + 去除空白 */
static void normalize_str(char *dst, size_t sz, const char *src)
{
    size_t i = 0, j = 0;
    if (sz == 0)
        return;
    while (src[i] && j + 1 < sz) {
        if (!isspace((unsigned char)src[i]))
            dst[j++] = (char)tolower((unsigned char)src[i]);
        i++;
    }
    dst[j] = '\0';
}

/* 不区分大小写的子串匹配 */
static int contains_ci(const char *haystack, const char *needle)
{
    char h[128];
    size_t i;
    if (!haystack)
        return 0;
    for (i = 0; haystack[i] && i + 1 < sizeof(h); i++)
        h[i] = (char)tolower((unsigned char)haystack[i]);
    h[i] = '\0';
    return strstr(h, needle) != NULL;
}

/* 字符串中第一个十进制数 */
static int first_number(const char *s)
{
    while (*s) {
        if (isdigit((unsigned char)*s))
            return atoi(s);
        s++;
    }
    return 0;
}

/* 命名的 EC 曲线 → 密钥长度 */
static const struct { const char *name; int bits; } curve_bits[] = {
    {"secp256r1", 256}, {"secp384r1", 384}, {"secp521r1", 521},
    {"prime256v1", 256}, {"prime192v1", 192}, {"prime239v1", 239},
    {"sm2p256v1", 256}, {"x25519", 256}, {"x448", 448},
    {"curve25519", 256}, {"curve448", 448}, {"nistp256", 256},
    {"nistp384", 384}, {"nistp521", 521},
};

int parse_algo_and_size(const char *name, algo_type_t *algo_out, int *key_size_out)
{
    char s[128];
    algo_type_t algo = ALGO_UNKNOWN;
    int size = 0;
    size_t i;

    if (!name)
        return 0;
    normalize_str(s, sizeof(s), name);
    if (s[0] == '\0')
        return 0;

    /* 1) TLS 签名方案 / 命名组（含 0x 十六进制） */
    {
        const tls_scheme_t *t = tls_scheme_lookup(s);
        if (t) {
            *algo_out = t->algo;
            *key_size_out = 0;   /* 具体密钥长度由证书/命名组解析提供 */
            return 1;
        }
    }

    /* 2) PQC（先于 dsa/ec 等子串检查） */
    if (strstr(s, "ml-kem") || strstr(s, "mlkem") || strstr(s, "kyber"))
        algo = ALGO_MLKEM;
    else if (strstr(s, "ml-dsa") || strstr(s, "mldsa") || strstr(s, "dilithium"))
        algo = ALGO_MLDSA;
    else if (strstr(s, "slh-dsa") || strstr(s, "slhdsa") || strstr(s, "sphincs"))
        algo = ALGO_SLHDSA;
    else if (strstr(s, "xmss"))
        algo = ALGO_XMSS;
    else if (strstr(s, "hashsig") || strstr(s, "hss-lms") || strstr(s, "lms"))
        algo = ALGO_LMS;
    else if (strstr(s, "sm2"))
        algo = ALGO_SM2;
    else if (strstr(s, "ed25519")) {
        algo = ALGO_ED25519;
        size = 256;
    } else if (strstr(s, "ed448")) {
        algo = ALGO_ED448;
        size = 456;
    } else if (strstr(s, "ecdsa") || strstr(s, "ec") || strstr(s, "secp") ||
               strstr(s, "prime") || strstr(s, "x25519") || strstr(s, "x448") ||
               strstr(s, "curve25519") || strstr(s, "curve448") || strstr(s, "nistp"))
        algo = ALGO_ECC;
    else if (strstr(s, "dss") || strstr(s, "dsa"))
        algo = ALGO_DSA;
    else if (strstr(s, "ffdhe") || strstr(s, "diffie") || strstr(s, "dhpublic"))
        algo = ALGO_DH;
    else if (strstr(s, "rsa"))
        algo = ALGO_RSA;
    else if (strstr(s, "aes"))
        algo = ALGO_AES;
    else if (strstr(s, "3des")) {
        algo = ALGO_SYMMETRIC;
        size = 112;
    } else if (strstr(s, "des"))
        algo = ALGO_SYMMETRIC;
    else if (strstr(s, "chacha")) {
        algo = ALGO_SYMMETRIC;
        size = 256;
    } else
        return 0;

    /* 3) 密钥长度推断（带语境规则，避免把哈希后缀当密钥长度） */
    if (size == 0) {
        /* 命名曲线 */
        for (i = 0; i < sizeof(curve_bits) / sizeof(curve_bits[0]); i++)
            if (strstr(s, curve_bits[i].name)) {
                size = curve_bits[i].bits;
                break;
            }
    }
    if (size == 0) {
        if (algo == ALGO_RSA) {
            /* "rsa_pkcs1_sha256" / "rsa_pss_rsae_sha384" 等签名方案名不取数字 */
            if (!strstr(s, "sha") && !strstr(s, "pss"))
                size = first_number(s);
        } else if (algo == ALGO_AES) {
            size = first_number(s);
        } else if (algo == ALGO_MLDSA || algo == ALGO_MLKEM || algo == ALGO_SLHDSA ||
                   algo == ALGO_DSA || algo == ALGO_DH) {
            size = first_number(s);
        }
    }
    /* AES 裸名默认按 AES-128（最保守） */
    if (algo == ALGO_AES && size == 0)
        size = 128;
    /* DES 裸名默认 56 位 */
    if (algo == ALGO_SYMMETRIC && size == 0 && strstr(s, "des"))
        size = 56;

    *algo_out = algo;
    *key_size_out = size;
    return 1;
}

threat_level_t judge_name(const char *name)
{
    algo_type_t algo;
    int size;
    if (!name)
        return THREAT_NONE;
    if (parse_algo_and_size(name, &algo, &size))
        return judge_algorithm(algo, size);
    return THREAT_NONE;
}

/* ================================================================== */
/* 签名算法判定（SHA-1/MD5 → 致命；RSA/ECC/SM2 → Shor；PQC → 安全）    */
/* ================================================================== */

threat_level_t judge_signature_algo(const char *sig_name, const char *sig_oid)
{
    char n[128];
    algo_type_t algo;
    int size;

    /* 优先按 OID（DER 解析路径提供） */
    if (sig_oid && sig_oid[0]) {
        const oid_entry_t *e = oid_lookup(sig_oid);
        if (e) {
            if (contains_ci(e->name, "sha1") || contains_ci(e->name, "md5"))
                return THREAT_CRITICAL;    /* sha1WithRSA / ecdsa-with-SHA1 / md5WithRSA */
            return judge_algorithm(e->algo, e->key_size);
        }
    }

    if (!sig_name || !sig_name[0])
        return THREAT_NONE;

    normalize_str(n, sizeof(n), sig_name);

    /* 弱哈希签名：SHA-1 / MD5 碰撞已实现 → 致命 */
    if (strstr(n, "sha1") || strstr(n, "md5") || strstr(n, "sha-1"))
        return THREAT_CRITICAL;

    if (parse_algo_and_size(n, &algo, &size))
        return judge_algorithm(algo, size);

    return THREAT_NONE;
}

/* ================================================================== */
/* 人类可读输出                                                       */
/* ================================================================== */

const char *threat_level_str(threat_level_t level)
{
    switch (level) {
    case THREAT_NONE:     return "THREAT_NONE";
    case THREAT_GROVER:   return "THREAT_GROVER";
    case THREAT_SHOR:     return "THREAT_SHOR";
    case THREAT_CRITICAL: return "THREAT_CRITICAL";
    default:              return "THREAT_UNKNOWN";
    }
}

const char *threat_description(threat_level_t level)
{
    switch (level) {
    case THREAT_NONE:
        return "量子安全：当前无已知量子算法可显著降低其安全性（PQC 或对称 >=192 位）";
    case THREAT_GROVER:
        return "Grover 威胁：对称密钥搜索降至 2^(k/2)，如 AES-128 仅剩约 64 位量子安全强度";
    case THREAT_SHOR:
        return "Shor 威胁：基于整数分解 / ECDLP / DLP，规模化量子计算机可多项式时间破解";
    case THREAT_CRITICAL:
        return "致命：算法/密钥/证书状态存在经典侧或量子侧的高危缺陷（如 SHA-1 签名、RSA<2048、已过期、自签名）";
    default:
        return "未知威胁等级";
    }
}

const char *algo_name_str(algo_type_t algo)
{
    switch (algo) {
    case ALGO_RSA:      return "RSA";
    case ALGO_ECC:      return "ECC/ECDSA";
    case ALGO_SM2:      return "SM2";
    case ALGO_DSA:      return "DSA";
    case ALGO_ED25519:  return "Ed25519";
    case ALGO_ED448:    return "Ed448";
    case ALGO_DH:       return "DH/FFDHE";
    case ALGO_MLKEM:    return "ML-KEM";
    case ALGO_MLDSA:    return "ML-DSA";
    case ALGO_SLHDSA:   return "SLH-DSA";
    case ALGO_XMSS:     return "XMSS";
    case ALGO_LMS:      return "LMS/HSS";
    case ALGO_AES:      return "AES";
    case ALGO_SYMMETRIC:return "对称算法";
    default:            return "未知";
    }
}

const char *recommendation(threat_level_t level, algo_type_t algo)
{
    switch (level) {
    case THREAT_CRITICAL:
        if (algo == ALGO_RSA)
            return "立即处理：RSA 可被 Shor 算法多项式时间分解模数；若同时使用 SHA-1/MD5 签名则哈希碰撞已实现，须重新签发";
        return "立即处理：证书/密钥存在高危缺陷（过期、自签名、弱哈希、密钥过短），须人工复核并替换";
    case THREAT_SHOR:
        if (algo == ALGO_MLKEM || algo == ALGO_MLDSA || algo == ALGO_SLHDSA)
            return "PQC 方案当前无 Shor 威胁（该等级不适用）";
        return "列入迁移计划：NIST 建议 2030 年前完成向 ML-KEM/ML-DSA/SLH-DSA 的迁移（FIPS 203/204/205）";
    case THREAT_GROVER:
        return "可接受但需关注：AES-128 量子安全强度约 64 位，建议新部署采用 AES-256（NIST 类别 5）";
    case THREAT_NONE:
        return "无需迁移（按当前量子威胁模型）：若为 PQC 算法注意验证实现与密钥管理合规；若为 AES-256 可继续使用";
    default:
        return "人工复核";
    }
}

/* ================================================================== */
/* 时间感知评分（PTA-QVS v0.1 / NIST IR 8547）                       */
/* ================================================================== */

/*
 * NIST IR 8547 时间线阶段表 —— 论文可引用（L2 权威规范证据）
 *
 * 来源：
 *   - NIST IR 8547 (ipd) "Transition to Post-Quantum Cryptography Standards"
 *     doi:10.6028/NIST.IR.8547.ipd
 *   - CNSA 2.0（NSA）：国家安全系统 2030 年强制 ML-KEM-1024/ML-DSA-87
 *   - FIPS 203/204/205（2024-08 发布）：PQC 标准化完成
 *
 * 阶段权重 Z(zone) 为 v0.1 校准值（L5 敏感性分析兜底，见 PTA-QVS §3-C），
 * 公开可调，默认 1/3, 2/3, 1.0。
 */
static const nist_timeline_entry_t nist_timeline_table[] = {
    {0,    2030, NIST_ZONE_PRE2030,  TIME_RISK_LOW,    1.0/3.0,
     "2030 前到期",
     "证书在 NIST IR 8547 弃用线（2030）前自然到期：可随常规轮换迁移至 PQC，无需单独紧迫行动",
     "下次轮换时签发 PQC 证书（ML-KEM/ML-DSA），利用自然生命周期过渡，避免额外成本",
     "NIST IR 8547: RSA/ECDH/DSA 弃用于 2030；2030 前证书走完生命周期"},

    {2030,  2035, NIST_ZONE_2030_2035, TIME_RISK_MEDIUM, 2.0/3.0,
     "2030-2035 迁移窗口",
     "证书到期日落在 NIST 弃用（2030）与禁用（2035）之间：需主动制定迁移计划，无法仅靠自然轮换覆盖",
     "制定 PQC 迁移路线图（选择 ML-KEM/ML-DSA/SLH-DSA 等 FIPS 方案），在 2030 前完成高风险资产迁移",
     "NIST IR 8547: 2030 高风险优先迁移；跨弃用线证书需主动干预"},

    {2035,  10000, NIST_ZONE_POST2035, TIME_RISK_HIGH,  1.0,
     "2035 后到期",
     "证书有效期跨越 NIST IR 8547 的 2035 禁用线：RSA/ECC 将在 2035 年后不可用，该证书不会自然轮换覆盖",
     "必须立即迁移至 PQC，绝不能依赖该证书自然到期；同时缩短新证书有效期至 2035 前",
     "NIST IR 8547: RSA/ECC 2035 禁止使用；CNSA 2.0: 2030 强制 PQC"},

    {0, 0, NIST_ZONE_UNKNOWN, TIME_RISK_UNKNOWN, 0.0,
     "未知",
     "无法确定证书到期时间",
     "人工复核证书有效期，确认后重新评估",
     "-"},
};

const nist_timeline_entry_t *nist_timeline_get(int *count)
{
    if (count)
        *count = (int)(sizeof(nist_timeline_table) / sizeof(nist_timeline_table[0]));
    return nist_timeline_table;
}

/* 解析 notAfter 字符串 → 年份。支持两种格式：
 *   DER 模式："2031-05-01 12:00:00 UTC"   → 前 4 位即年份
 *   openssl 模式："May  1 12:00:00 2031 GMT" → 取最后一个四位数年份 */
int parse_notafter_year(const char *s)
{
    int y;
    if (!s || !*s) return 0;
    /* DER 格式：YYYY-... */
    if (s[0] >= '0' && s[0] <= '9' && s[1] >= '0' && s[1] <= '9' &&
        s[2] >= '0' && s[2] <= '9' && s[3] >= '0' && s[3] <= '9') {
        if (s[4] == '-' || s[4] == ' ' || s[4] == '\0') {
            y = atoi(s);
            if (y >= 1950 && y <= 2200) return y;
            return 0;
        }
    }
    /* openssl 格式：取最后一个四位数 */
    {
        const char *p = s;
        int last = 0, found = 0;
        while (*p) {
            if (isdigit((unsigned char)*p) &&
                isdigit((unsigned char)p[1]) &&
                isdigit((unsigned char)p[2]) &&
                isdigit((unsigned char)p[3]) &&
                (!isdigit((unsigned char)p[4]) || p[4] == 'Z' || p[4] == 'G' || p[4] == ' ' || p[4] == '\0')) {
                int v = atoi(p);
                if (v >= 1950 && v <= 2200) {
                    last = v;
                    found = 1;
                }
            }
            p++;
        }
        return found ? last : 0;
    }
}

nist_zone_t nist_zone_for_year(int year)
{
    if (year <= 0) return NIST_ZONE_UNKNOWN;
    if (year < PQC_NIST_YEAR_DEPRECATE) return NIST_ZONE_PRE2030;
    if (year < PQC_NIST_YEAR_PROHIBIT)  return NIST_ZONE_2030_2035;
    return NIST_ZONE_POST2035;
}

nist_zone_t nist_zone_for_notafter(const char *s)
{
    int y = parse_notafter_year(s);
    return nist_zone_for_year(y);
}

const char *nist_phase(int notafter_year)
{
    if (notafter_year <= 0)
        return "NIST阶段: UNKNOWN（无法解析有效期）";
    if (notafter_year < PQC_NIST_YEAR_DEPRECATE)
        return "NIST阶段: 2030前到期（低风险，可自然轮换）";
    if (notafter_year <= PQC_NIST_YEAR_PROHIBIT)
        return "NIST阶段: 2030-2035（中风险，建议主动迁移）";
    return "NIST阶段: 2035后到期（高风险，跨越NIST截止线）";
}

const char *nist_zone_str(nist_zone_t z)
{
    switch (z) {
    case NIST_ZONE_PRE2030:    return "PRE2030";
    case NIST_ZONE_2030_2035:  return "2030-2035";
    case NIST_ZONE_POST2035:   return "POST2035";
    default:                   return "UNKNOWN";
    }
}

const char *time_risk_str(time_risk_t r)
{
    switch (r) {
    case TIME_RISK_LOW:    return "LOW";
    case TIME_RISK_MEDIUM: return "MEDIUM";
    case TIME_RISK_HIGH:   return "HIGH";
    default:               return "UNKNOWN";
    }
}

const char *nist_zone_description(nist_zone_t z)
{
    int i, n;
    const nist_timeline_entry_t *t = nist_timeline_get(&n);
    for (i = 0; i < n; i++)
        if (t[i].zone == z)
            return t[i].description;
    return "未知阶段";
}

const char *nist_zone_action(nist_zone_t z)
{
    int i, n;
    const nist_timeline_entry_t *t = nist_timeline_get(&n);
    for (i = 0; i < n; i++)
        if (t[i].zone == z)
            return t[i].action;
    return "人工复核";
}

double nist_zone_weight(nist_zone_t z)
{
    int i, n;
    const nist_timeline_entry_t *t = nist_timeline_get(&n);
    for (i = 0; i < n; i++)
        if (t[i].zone == z)
            return t[i].zone_weight;
    return 0.0;
}

double hyoung_multiplier(double h)
{
    if (h < 0.0) h = 0.0;
    return 1.0 + h / 20.0;
}

double algo_vulnerability(algo_type_t algo, int key_size)
{
    switch (judge_algorithm(algo, key_size)) {
    case THREAT_SHOR:     return 1.0;
    case THREAT_CRITICAL: return 1.0;
    case THREAT_GROVER:   return 0.5;
    case THREAT_NONE:
    default:              return 0.0;
    }
}

int time_judge_components(algo_type_t algo, int key_size,
                          const char *not_after, double h,
                          time_judge_t *out)
{
    int i, n;
    memset(out, 0, sizeof(*out));
    out->not_after_year = parse_notafter_year(not_after);
    out->zone = nist_zone_for_year(out->not_after_year);
    out->vuln = algo_vulnerability(algo, key_size);
    out->m_factor = hyoung_multiplier(h);

    /* 查阶段表获取 risk / zone_weight */
    {
        const nist_timeline_entry_t *t = nist_timeline_get(&n);
        out->risk = TIME_RISK_UNKNOWN;
        out->zone_weight = 0.0;
        for (i = 0; i < n; i++) {
            if (t[i].zone == out->zone) {
                out->risk = t[i].risk;
                out->zone_weight = t[i].zone_weight;
                break;
            }
        }
    }

    out->time_score = 100.0 * out->vuln * out->zone_weight;
    out->time_score_adj = out->time_score * out->m_factor;
    if (out->time_score_adj > 100.0)
        out->time_score_adj = 100.0;

    /* 基础等级 */
    out->base_level = judge_algorithm(algo, key_size);

    /* 时间感知综合等级 */
    if (out->base_level == THREAT_CRITICAL) {
        out->level = THREAT_CRITICAL;
    } else if (out->zone == NIST_ZONE_POST2035 && out->base_level == THREAT_SHOR) {
        /* 跨越 NIST 2035 禁用线的 Shor 威胁算法 → 合规致命 */
        out->level = THREAT_CRITICAL;
    } else {
        out->level = out->base_level;
    }

    return 0;
}

int time_judge_cert(const struct cert_info *ci, double h, time_judge_t *out)
{
    if (!ci) return -1;
    /* 转型：struct cert_info 实际是包含 pk_algo / key_bits / not_after / is_expired
     * 的 cert_info_t。threat_judge.h 前向声明了 struct cert_info 标签。 */
    const cert_info_t *c = (const cert_info_t *)ci; /* NOLINT */
    time_judge_components(c->pk_algo, c->key_bits, c->not_after, h, out);

    /* 已过期 → 致命（覆盖其他等级） */
    if (c->is_expired) {
        out->level = THREAT_CRITICAL;
        out->time_score = 100.0;   /* 过期证书风险最高 */
        out->time_score_adj = 100.0;
    }
    return 0;
}
