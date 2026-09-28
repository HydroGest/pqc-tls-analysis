/*
 * cert_parser.c — 证书解析实现
 *
 * 模式 a（CERT_PARSE_OPENSSL）：popen 调用 `openssl x509 -noout -text`，正则提取字段
 * 模式 b（CERT_PARSE_DER）    ：自包含 ASN.1/DER TLV 解析，不依赖 openssl：
 *     - Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
 *     - SPKI 算法 OID、EC 曲线 OID（parameters）、RSA 模数长度（BIT STRING 内嵌 RSAPublicKey）
 *     - 签名算法 OID、有效期（UTCTime/GeneralizedTime）、自签名（subject/issuer 字节相等）
 *
 * 编译：gcc -std=c99 -D_GNU_SOURCE（timegm 需要）。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "cert_parser.h"
#include "oid_db.h"

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ================================================================== */
/* 小工具                                                             */
/* ================================================================== */

void cert_info_init(cert_info_t *ci)
{
    memset(ci, 0, sizeof(*ci));
    ci->pk_algo = ALGO_UNKNOWN;
}

const char *cert_parse_mode_name(cert_parse_mode_t m)
{
    return m == CERT_PARSE_DER ? "der" : "openssl";
}

static int read_file(const char *path, unsigned char **out, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    unsigned char *buf;
    long sz;
    size_t rd;
    if (!f)
        return -1;
    if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0 ||
        fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }
    buf = (unsigned char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return -1;
    }
    rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = '\0';
    *out = buf;
    *out_len = rd;
    return 0;
}

/* ---- Base64 解码 ---- */
static int b64_val(int c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static size_t base64_decode(const unsigned char *in, size_t in_len,
                            unsigned char *out, size_t out_cap)
{
    size_t i = 0, o = 0;
    int acc = 0, nbits = 0;
    while (i < in_len) {
        int c = in[i++];
        if (c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t')
            continue;
        int v = b64_val(c);
        if (v < 0)
            continue;
        acc = (acc << 6) | v;
        nbits += 6;
        if (nbits >= 8) {
            nbits -= 8;
            if (o < out_cap)
                out[o++] = (unsigned char)((acc >> nbits) & 0xff);
        }
    }
    return o;
}

/* PEM → DER：找到 BEGIN/END CERTIFICATE 块并 base64 解码。成功返回 0 */
static int pem_to_der(const unsigned char *pem, size_t pem_len,
                      unsigned char **der_out, size_t *der_len_out)
{
    static const char begin[] = "-----BEGIN CERTIFICATE-----";
    static const char end[] = "-----END CERTIFICATE-----";
    const unsigned char *b = NULL, *e = NULL;
    size_t i;
    unsigned char *der;
    size_t dlen;

    for (i = 0; i + sizeof(begin) - 1 <= pem_len; i++)
        if (memcmp(pem + i, begin, sizeof(begin) - 1) == 0) {
            b = pem + i + sizeof(begin) - 1;
            break;
        }
    if (!b)
        return -1;
    for (i = 0; i + sizeof(end) - 1 <= pem_len; i++)
        if (memcmp(pem + i, end, sizeof(end) - 1) == 0) {
            e = pem + i;
            break;
        }
    if (!e || e <= b)
        return -1;

    der = (unsigned char *)malloc((size_t)(e - b) + 1);
    if (!der)
        return -1;
    dlen = base64_decode(b, (size_t)(e - b), der, (size_t)(e - b) + 1);
    if (dlen == 0) {
        free(der);
        return -1;
    }
    *der_out = der;
    *der_len_out = dlen;
    return 0;
}

/* ================================================================== */
/* 模式 b：自包含 DER 解析                                            */
/* ================================================================== */

typedef struct {
    unsigned char tag;              /* TLV 标签 */
    const unsigned char *content;   /* 内容起始 */
    size_t len;                     /* 内容长度 */
    const unsigned char *start;     /* 整个 TLV 起始 */
    size_t total;                   /* 整个 TLV 长度（含 tag+len） */
} tlv_t;

/* 解析一个 TLV，*pp 前进到下一个 TLV。成功返回 1 */
static int tlv_read(const unsigned char **pp, const unsigned char *end, tlv_t *out)
{
    const unsigned char *p = *pp;
    size_t l = 0;
    if (p + 2 > end)
        return 0;
    out->start = p;
    out->tag = *p++;
    {
        unsigned char lb = *p++;
        if (lb & 0x80) {
            int n = lb & 0x7f;
            int i;
            if (n == 0 || n > 4 || (size_t)(end - p) < (size_t)n)
                return 0;
            for (i = 0; i < n; i++)
                l = (l << 8) | *p++;
        } else {
            l = lb;
        }
    }
    if ((size_t)(end - p) < l)
        return 0;
    out->content = p;
    out->len = l;
    out->total = (size_t)(p + l - out->start);
    *pp = p + l;
    return 1;
}

/* 取 SEQUENCE/SET 的第 idx 个子元素（0 基） */
static int tlv_child(const tlv_t *seq, size_t idx, tlv_t *out)
{
    const unsigned char *p = seq->content;
    const unsigned char *end = seq->content + seq->len;
    size_t i;
    for (i = 0; i <= idx; i++)
        if (!tlv_read(&p, end, out))
            return 0;
    return 1;
}

/* OID 内容 → 点分字符串 */
static int oid_bytes_to_str(const unsigned char *d, size_t n,
                            char *out, size_t outsz)
{
    size_t i = 0;
    size_t used = 0;
    unsigned long long first_sub = 0;
    int done = 0;
    int a1, a2;

    if (n < 1)
        return 0;
    /* 第一个子标识（40*a1+a2，可能多字节） */
    while (i < n) {
        unsigned char b = d[i++];
        first_sub = (first_sub << 7) | (b & 0x7f);
        if (!(b & 0x80)) {
            done = 1;
            break;
        }
    }
    if (!done)
        return 0;
    if (first_sub < 40) { a1 = 0; a2 = (int)first_sub; }
    else if (first_sub < 80) { a1 = 1; a2 = (int)(first_sub - 40); }
    else { a1 = 2; a2 = (int)(first_sub - 80); }

    used += (size_t)snprintf(out + used, outsz - used, "%d.%d", a1, a2);
    while (i < n) {
        unsigned long long sub = 0;
        int sub_done = 0;
        while (i < n) {
            unsigned char b = d[i++];
            sub = (sub << 7) | (b & 0x7f);
            if (!(b & 0x80)) {
                sub_done = 1;
                break;
            }
        }
        if (!sub_done)
            return 0;
        if (used + 24 >= outsz)
            return 0;
        used += (size_t)snprintf(out + used, outsz - used, ".%llu", sub);
    }
    return 1;
}

/* 公历日期 → 自 1970-01-01 的秒数（Howard Hinnant days_from_civil 算法） */
static time_t make_time(int y, int m, int d, int h, int mi, int s)
{
    long era, days;
    unsigned yoe, doy, doe;
    if (m <= 2)
        y -= 1;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = (unsigned)(y - era * 400);
    doy = (153u * (unsigned)(m + (m > 2 ? -3 : 9)) + 2) / 5 + (unsigned)d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    days = era * 146097 + (long)doe - 719468;
    return (time_t)days * 86400 + h * 3600 + mi * 60 + s;
}

/* ASN.1 UTCTime(17)/GeneralizedTime(18) → time_t。成功返回 1 */
static int parse_asn1_time(const tlv_t *t, time_t *out)
{
    size_t n = t->len;
    int y, mo, d, h, mi, s;
    if (t->tag == 0x17 && n == 13 && t->content[12] == 'Z') {
        y = 2000 + (t->content[0] - '0') * 10 + (t->content[1] - '0');
        if (y >= 2050)
            y -= 100;
        mo = (t->content[2] - '0') * 10 + (t->content[3] - '0');
        d  = (t->content[4] - '0') * 10 + (t->content[5] - '0');
        h  = (t->content[6] - '0') * 10 + (t->content[7] - '0');
        mi = (t->content[8] - '0') * 10 + (t->content[9] - '0');
        s  = (t->content[10] - '0') * 10 + (t->content[11] - '0');
        *out = make_time(y, mo, d, h, mi, s);
        return 1;
    }
    if (t->tag == 0x18 && n >= 15 && t->content[14] == 'Z') {
        y  = (t->content[0] - '0') * 1000 + (t->content[1] - '0') * 100 +
             (t->content[2] - '0') * 10 + (t->content[3] - '0');
        mo = (t->content[4] - '0') * 10 + (t->content[5] - '0');
        d  = (t->content[6] - '0') * 10 + (t->content[7] - '0');
        h  = (t->content[8] - '0') * 10 + (t->content[9] - '0');
        mi = (t->content[10] - '0') * 10 + (t->content[11] - '0');
        s  = (t->content[12] - '0') * 10 + (t->content[13] - '0');
        *out = make_time(y, mo, d, h, mi, s);
        return 1;
    }
    return 0;
}

/* 常见 DN 属性 OID → 缩写标签 */
static const char *dn_attr_label(const char *oid)
{
    if (strcmp(oid, "2.5.4.3") == 0) return "CN";
    if (strcmp(oid, "2.5.4.6") == 0) return "C";
    if (strcmp(oid, "2.5.4.7") == 0) return "L";
    if (strcmp(oid, "2.5.4.8") == 0) return "ST";
    if (strcmp(oid, "2.5.4.10") == 0) return "O";
    if (strcmp(oid, "2.5.4.11") == 0) return "OU";
    if (strcmp(oid, "2.5.4.5") == 0) return "serialNumber";
    if (strcmp(oid, "1.2.840.113549.1.9.1") == 0) return "emailAddress";
    if (strcmp(oid, "0.9.2342.19200300.100.1.25") == 0) return "DC";
    return oid;
}

/* Name ::= SEQUENCE OF RDN；RDN ::= SET OF AttributeTypeAndValue。
 * 输出 "C=CN, O=..., CN=..." 文本 */
static void der_name_to_str(const tlv_t *name, char *out, size_t outsz)
{
    const unsigned char *p = name->content;
    const unsigned char *end = name->content + name->len;
    tlv_t rdn;
    size_t used = 0;
    int first = 1;

    out[0] = '\0';
    while (used + 2 < outsz && tlv_read(&p, end, &rdn)) {
        const unsigned char *q = rdn.content;
        const unsigned char *qe = rdn.content + rdn.len;
        tlv_t atv;
        while (used + 2 < outsz && tlv_read(&q, qe, &atv)) {
            tlv_t type, val;
            char oidbuf[64];
            char vbuf[256];
            size_t vl;
            if (!tlv_child(&atv, 0, &type) || !tlv_child(&atv, 1, &val))
                continue;
            if (type.tag != 0x06)
                continue;
            if (!oid_bytes_to_str(type.content, type.len, oidbuf, sizeof(oidbuf)))
                continue;
            vbuf[0] = '\0';
            if (val.tag == 0x0c || val.tag == 0x13 || val.tag == 0x16 ||
                val.tag == 0x14 || val.tag == 0x1e || val.tag == 0x1c) {
                vl = val.len < sizeof(vbuf) - 1 ? val.len : sizeof(vbuf) - 1;
                memcpy(vbuf, val.content, vl);
                vbuf[vl] = '\0';
            }
            if (vbuf[0]) {
                int n = snprintf(out + used, outsz - used, "%s%s=%s",
                                 first ? "" : ", ", dn_attr_label(oidbuf), vbuf);
                if (n > 0)
                    used += (size_t)n;
                first = 0;
            }
        }
    }
}

/* 从 SPKI 的 BIT STRING 提取 RSA 模数位长 */
static int rsa_modulus_bits(const tlv_t *bitstr)
{
    const unsigned char *p;
    const unsigned char *end;
    tlv_t seq, mod;
    size_t mlen;

    if (bitstr->tag != 0x03 || bitstr->len < 2)
        return 0;
    p = bitstr->content + 1;          /* 跳过 unused bits 计数 */
    end = bitstr->content + bitstr->len;
    if (!tlv_read(&p, end, &seq) || seq.tag != 0x30)
        return 0;
    if (!tlv_child(&seq, 0, &mod) || mod.tag != 0x02)
        return 0;
    mlen = mod.len;
    if (mlen > 0 && mod.content[0] == 0x00)
        mlen--;                       /* 去掉前导 0（DER 正数填充） */
    return (int)(mlen * 8);
}

/* 从 EC 点（BIT STRING）长度估算曲线位长：点 = 0x04 || X || Y */
static int ec_point_bits(const tlv_t *bitstr)
{
    size_t n;
    if (bitstr->tag != 0x03 || bitstr->len < 3)
        return 0;
    n = bitstr->len - 1;              /* 去掉 unused bits 字节 */
    if (n < 3 || n % 2 == 0)          /* 1 + 2*coord */
        return 0;
    return (int)((n - 1) / 2 * 8);
}

/* 核心：DER 字节流解析 */
static int cert_parse_der_bytes(const unsigned char *der, size_t der_len,
                                cert_info_t *out)
{
    tlv_t root, tbs, sig_alg_outer, spki;
    tlv_t ver, serial, sig_tbs, issuer, validity, subject, pk_alg, pk_oid, params;
    tlv_t curve, bitstr, not_before, not_after;
    const unsigned char *p, *end;
    size_t nchildren;
    time_t nb = 0, na = 0, now = time(NULL);

    p = der;
    end = der + der_len;
    if (!tlv_read(&p, end, &root) || root.tag != 0x30)
        return -1;
    if (!tlv_child(&root, 0, &tbs) || tbs.tag != 0x30)
        return -1;

    /* TBS 子元素：version[可选] serial signature issuer validity subject spki ... */
    nchildren = 0;
    {
        const unsigned char *q = tbs.content;
        const unsigned char *qe = tbs.content + tbs.len;
        tlv_t t;
        while (tlv_read(&q, qe, &t))
            nchildren++;
    }
    if (nchildren < 6)
        return -1;

    /* version（可能 [0] EXPLICIT 或直接 INTEGER） */
    tlv_child(&tbs, 0, &ver);
    /* serialNumber */
    tlv_child(&tbs, 1, &serial);
    /* signature（TBS 内） */
    if (!tlv_child(&tbs, 2, &sig_tbs) || sig_tbs.tag != 0x30)
        return -1;
    if (tlv_child(&sig_tbs, 0, &pk_oid) && pk_oid.tag == 0x06)
        oid_bytes_to_str(pk_oid.content, pk_oid.len, out->sig_oid, sizeof(out->sig_oid));
    else
        tlv_child(&tbs, 2, &sig_tbs); /* 防御：个别实现结构差异 */

    /* issuer / subject（自签名 = DER 字节相等） */
    if (!tlv_child(&tbs, 3, &issuer) || !tlv_child(&tbs, 5, &subject))
        return -1;
    if (issuer.len == subject.len && memcmp(issuer.content, subject.content, issuer.len) == 0)
        out->is_self_signed = 1;
    der_name_to_str(&issuer, out->issuer, sizeof(out->issuer));
    der_name_to_str(&subject, out->subject, sizeof(out->subject));

    /* validity */
    if (!tlv_child(&tbs, 4, &validity) || validity.tag != 0x30)
        return -1;
    if (tlv_child(&validity, 0, &not_before) && parse_asn1_time(&not_before, &nb) &&
        tlv_child(&validity, 1, &not_after) && parse_asn1_time(&not_after, &na)) {
        struct tm tmv;
        time_t t1 = nb, t2 = na;
        gmtime_r(&t1, &tmv);
        strftime(out->not_before, sizeof(out->not_before), "%Y-%m-%d %H:%M:%S UTC", &tmv);
        gmtime_r(&t2, &tmv);
        strftime(out->not_after, sizeof(out->not_after), "%Y-%m-%d %H:%M:%S UTC", &tmv);
        if (now > na)
            out->is_expired = 1;
    }

    /* SubjectPublicKeyInfo */
    if (!tlv_child(&tbs, 6, &spki) || spki.tag != 0x30)
        return -1;
    if (!tlv_child(&spki, 0, &pk_alg) || pk_alg.tag != 0x30)
        return -1;
    if (!tlv_child(&pk_alg, 0, &pk_oid) || pk_oid.tag != 0x06)
        return -1;
    oid_bytes_to_str(pk_oid.content, pk_oid.len, out->pk_oid, sizeof(out->pk_oid));

    {
        const oid_entry_t *e = oid_lookup(out->pk_oid);
        out->pk_algo = e ? e->algo : ALGO_UNKNOWN;
    }

    /* EC 曲线：parameters 中的 OID */
    curve.tag = 0;
    if (tlv_child(&pk_alg, 1, &curve) && curve.tag == 0x06)
        oid_bytes_to_str(curve.content, curve.len, out->curve_oid, sizeof(out->curve_oid));

    /* subjectPublicKey BIT STRING */
    if (!tlv_child(&spki, 1, &bitstr))
        return -1;

    /* 密钥长度 */
    if (out->pk_algo == ALGO_RSA) {
        out->key_bits = rsa_modulus_bits(&bitstr);
    } else if (out->pk_algo == ALGO_ECC || out->pk_algo == ALGO_SM2) {
        const oid_entry_t *ce = out->curve_oid[0] ? oid_lookup(out->curve_oid) : NULL;
        if (ce && ce->key_size > 0)
            out->key_bits = ce->key_size;
        else
            out->key_bits = ec_point_bits(&bitstr);
        if (out->curve_oid[0] && strcmp(out->curve_oid, "1.2.156.10197.1.301") == 0)
            out->pk_algo = ALGO_SM2;   /* SM2 曲线 → SM2 算法 */
    } else if (out->pk_algo == ALGO_ED25519) {
        out->key_bits = 256;
    } else if (out->pk_algo == ALGO_ED448) {
        out->key_bits = 456;
    }

    /* 证书外层签名算法（signatureAlgorithm） */
    sig_alg_outer.tag = 0;
    if (tlv_child(&root, 1, &sig_alg_outer) && sig_alg_outer.tag == 0x30 &&
        tlv_child(&sig_alg_outer, 0, &pk_oid) && pk_oid.tag == 0x06) {
        char buf[64];
        if (oid_bytes_to_str(pk_oid.content, pk_oid.len, buf, sizeof(buf))) {
            if (out->sig_oid[0] == '\0')
                snprintf(out->sig_oid, sizeof(out->sig_oid), "%s", buf);
            else if (strcmp(out->sig_oid, buf) != 0) {
                /* TBS 与外层签名 OID 不同：记录外层（DER 结构签名），保留 TBS 摘要 */
            }
        }
    }

    /* 签名算法名：由 OID 表补全 */
    if (out->sig_oid[0]) {
        const oid_entry_t *se = oid_lookup(out->sig_oid);
        if (se && se->name)
            snprintf(out->sig_name, sizeof(out->sig_name), "%s", se->name);
        else
            snprintf(out->sig_name, sizeof(out->sig_name), "OID %s", out->sig_oid);
    }

    /* 参数占位清理 */
    (void)params;
    return 0;
}

/* ================================================================== */
/* 模式 a：openssl CLI 包装                                          */
/* ================================================================== */

static int contains(const char *haystack, const char *needle)
{
    return strstr(haystack, needle) != NULL;
}

/* 不区分大小写的子串匹配 */
static int contains_lower(const char *haystack, const char *needle)
{
    char h[256];
    size_t i;
    if (!haystack || !haystack[0])
        return 0;
    for (i = 0; haystack[i] && i + 1 < sizeof(h); i++)
        h[i] = (char)tolower((unsigned char)haystack[i]);
    h[i] = '\0';
    return strstr(h, needle) != NULL;
}

/* 文本算法名 → algo_type（openssl -text 输出） */
static algo_type_t algo_from_text(const char *s)
{
    char n[256];
    size_t i;
    if (!s || !s[0])
        return ALGO_UNKNOWN;
    for (i = 0; s[i] && i + 1 < sizeof(n); i++)
        n[i] = (char)tolower((unsigned char)s[i]);
    n[i] = '\0';
    if (contains(n, "ml-kem") || contains(n, "kyber")) return ALGO_MLKEM;
    if (contains(n, "ml-dsa") || contains(n, "dilithium")) return ALGO_MLDSA;
    if (contains(n, "slh-dsa") || contains(n, "sphincs")) return ALGO_SLHDSA;
    if (contains(n, "xmss")) return ALGO_XMSS;
    if (contains(n, "lms") || contains(n, "hashsig") || contains(n, "hss")) return ALGO_LMS;
    if (contains(n, "sm2")) return ALGO_SM2;
    if (contains(n, "ed25519")) return ALGO_ED25519;
    if (contains(n, "ed448")) return ALGO_ED448;
    if (contains(n, "ecdsa") || contains(n, "id-ecpublickey")) return ALGO_ECC;
    if (contains(n, "dsa") || contains(n, "dss")) return ALGO_DSA;
    if (contains(n, "dh")) return ALGO_DH;
    if (contains(n, "rsa")) return ALGO_RSA;
    return ALGO_UNKNOWN;
}

/* 曲线文本名（openssl "ASN1 OID: XXX"）→ OID 与算法 */
static void curve_text_to_oid(const char *text, char *oid_out, size_t oid_sz,
                              algo_type_t *algo_out)
{
    struct { const char *name; const char *oid; algo_type_t algo; } map[] = {
        {"sm2", "1.2.156.10197.1.301", ALGO_SM2},
        {"prime256v1", "1.2.840.10045.3.1.7", ALGO_ECC},
        {"secp384r1", "1.3.132.0.34", ALGO_ECC},
        {"secp521r1", "1.3.132.0.35", ALGO_ECC},
        {"prime192v1", "1.2.840.10045.3.1.1", ALGO_ECC},
        {"x25519", "1.3.101.110", ALGO_ECC},
        {"x448", "1.3.101.111", ALGO_ECC},
    };
    size_t i;
    oid_out[0] = '\0';
    *algo_out = ALGO_UNKNOWN;
    if (!text)
        return;
    for (i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
        if (contains(text, map[i].name) ||
            contains_lower(text, map[i].name)) {
            snprintf(oid_out, oid_sz, "%s", map[i].oid);
            *algo_out = map[i].algo;
            return;
        }
    }
}

/* 读取 openssl 输出中形如 "Keyword: value" 的首个匹配 */
static int grep_field(const char *text, const char *keyword, char *out, size_t outsz)
{
    const char *p = text;
    size_t klen = strlen(keyword);
    while ((p = strstr(p, keyword)) != NULL) {
        const char *v = p + klen;
        size_t n;
        /* 兼容 "Keyword: value" 与 "Keyword : value" 两种格式 */
        while (*v == ' ' || *v == '\t')
            v++;
        if (*v == ':')
            v++;
        while (*v == ' ' || *v == '\t')
            v++;
        n = 0;
        while (v[n] && v[n] != '\n' && n + 1 < outsz)
            n++;
        if (n > 0) {
            memcpy(out, v, n);
            out[n] = '\0';
            return 1;
        }
        p += klen;
    }
    return 0;
}

/* 取整数位长："Public-Key: (2048 bit)" */
static int grep_bits(const char *text, const char *keyword)
{
    const char *p = strstr(text, keyword);
    if (!p)
        return 0;
    p = strchr(p, '(');
    if (!p)
        return 0;
    return atoi(p + 1);
}

static int cert_parse_openssl(const char *path, cert_info_t *out)
{
    char cmdbuf[4096];
    FILE *fp;
    char *buf = NULL;
    size_t cap = 0, len = 0;
    char val[300];
    algo_type_t curve_algo = ALGO_UNKNOWN;
    int rc = -1;

    /* 使用 mkstemp 临时文件，避免路径中含空格/中文/特殊字符对 shell 的影响 */
    {
        int fd;
        unsigned char *fdata = NULL;
        size_t flen = 0;
        char tmpl[] = "/tmp/pqc-cert-XXXXXX.pem";
        size_t wr;

        fd = mkstemps(tmpl, 4);  /* ".pem" suffix */
        if (fd < 0)
            return -1;
        if (read_file(path, &fdata, &flen) != 0) {
            close(fd);
            unlink(tmpl);
            return -1;
        }
        wr = write(fd, fdata, flen);
        close(fd);
        free(fdata);
        if (wr != flen) {
            unlink(tmpl);
            return -1;
        }

        snprintf(cmdbuf, sizeof(cmdbuf),
                 "openssl x509 -in '%s' -noout -text 2>/dev/null", tmpl);
        fp = popen(cmdbuf, "r");
        if (!fp) {
            unlink(tmpl);
            return -1;
        }
        {
            char chunk[4096];
            size_t rd;
            while ((rd = fread(chunk, 1, sizeof(chunk), fp)) > 0) {
                if (len + rd + 1 > cap) {
                    cap = (cap ? cap * 2 : 16384);
                    buf = (char *)realloc(buf, cap);
                    if (!buf) {
                        pclose(fp);
                        unlink(tmpl);
                        return -1;
                    }
                }
                memcpy(buf + len, chunk, rd);
                len += rd;
            }
        }
        pclose(fp);
        unlink(tmpl);  /* 清理临时文件 */
    }

    if (!buf || len == 0) {
        free(buf);
        return -1;
    }
    buf[len] = '\0';

    /* 无法解析出 Public Key Algorithm → 失败 */
    if (grep_field(buf, "Public Key Algorithm", val, sizeof(val)))
        out->pk_algo = algo_from_text(val);
    if (out->pk_algo == ALGO_UNKNOWN) {
        free(buf);
        return -1;
    }

    out->key_bits = grep_bits(buf, "Public-Key");
    if (out->key_bits <= 0 && out->pk_algo == ALGO_ED25519)
        out->key_bits = 256;
    if (out->key_bits <= 0 && out->pk_algo == ALGO_ED448)
        out->key_bits = 456;

    if (grep_field(buf, "ASN1 OID", val, sizeof(val))) {
        curve_text_to_oid(val, out->curve_oid, sizeof(out->curve_oid), &curve_algo);
        if (curve_algo != ALGO_UNKNOWN)
            out->pk_algo = curve_algo;
    }

    /* 签名算法：取首个 "Signature Algorithm:"（TBS 段） */
    if (grep_field(buf, "Signature Algorithm", val, sizeof(val)))
        snprintf(out->sig_name, sizeof(out->sig_name), "%.127s", val);

    if (grep_field(buf, "Subject", val, sizeof(val)))
        snprintf(out->subject, sizeof(out->subject), "%.255s", val);
    if (grep_field(buf, "Issuer", val, sizeof(val)))
        snprintf(out->issuer, sizeof(out->issuer), "%.255s", val);

    /* 有效期（%b %d %H:%M:%S %Y GMT） */
    if (grep_field(buf, "Not Before", val, sizeof(val))) {
        snprintf(out->not_before, sizeof(out->not_before), "%.31s", val);
        {
            struct tm tmv;
            memset(&tmv, 0, sizeof(tmv));
            if (strptime(val, "%b %d %H:%M:%S %Y GMT", &tmv)) {
                /* 无需转换：仅展示 */
            }
        }
    }
    if (grep_field(buf, "Not After", val, sizeof(val))) {
        snprintf(out->not_after, sizeof(out->not_after), "%.31s", val);
        {
            struct tm tmv;
            time_t t;
            memset(&tmv, 0, sizeof(tmv));
            if (strptime(val, "%b %d %H:%M:%S %Y GMT", &tmv)) {
                t = timegm(&tmv);
                if (t > 0 && time(NULL) > t)
                    out->is_expired = 1;
            }
        }
    }

    /* 自签名：subject == issuer（字符串比较，忽略首尾空白差异） */
    if (out->subject[0] && out->issuer[0]) {
        char *s1 = out->subject;
        char *s2 = out->issuer;
        size_t l1 = strlen(s1), l2 = strlen(s2);
        while (l1 && isspace((unsigned char)s1[l1 - 1])) s1[--l1] = '\0';
        while (l2 && isspace((unsigned char)s2[l2 - 1])) s2[--l2] = '\0';
        if (strcmp(s1, s2) == 0)
            out->is_self_signed = 1;
    }

    /* 尽力提取 CRL DP / OCSP URL */
    extract_revoke_info(buf, out);

    cert_update_revoke_offline(out);

    rc = 0;
    free(buf);
    return rc;
}

/* ================================================================== */
/* 吊销检查（离线代理 + CRL DP 尽力提取）                             */
/* ================================================================== */

void extract_revoke_info(const char *text, cert_info_t *out)
{
    /* 从 openssl -text 输出中尽力提取 CRL Distribution Points 和 OCSP URL。
     * 不依赖 strict 结构解析，采用段逼近法 */
    const char *p, *seg_start, *seg_end;
    const char *uri, *uri_end;
    size_t n;

    if (!text || !text[0])
        return;

    /* --- CRL Distribution Points --- */
    p = strstr(text, "CRL Distribution Points");
    if (p) {
        seg_start = p;
        /* 段到第一个 "X509v3" 或空行或文件尾 */
        seg_end = strstr(seg_start + 5, "X509v3");
        if (!seg_end) {
            seg_end = strstr(seg_start + 5, "\n\n");
            if (!seg_end)
                seg_end = text + strlen(text);
        }
        /* 在段内找 "URI:" */
        p = seg_start;
        while (p < seg_end && (uri = strstr(p, "URI:")) != NULL && uri < seg_end) {
            uri += 4;
            while (*uri == ' ' || *uri == '\t') uri++;
            uri_end = uri;
            while (*uri_end && *uri_end != ' ' && *uri_end != '\t' &&
                   *uri_end != '\n' && *uri_end != '\r' && *uri_end != ';' && *uri_end != ')')
                uri_end++;
            n = (size_t)(uri_end - uri);
            if (n > 0 && n < sizeof(out->crl_dp) - 1) {
                memcpy(out->crl_dp, uri, n);
                out->crl_dp[n] = '\0';
                break;
            }
            p = uri_end;
        }
    }

    /* --- OCSP Responder URL (Authority Information Access) --- */
    p = strstr(text, "Authority Information Access");
    if (p) {
        seg_start = p;
        seg_end = strstr(seg_start + 5, "X509v3");
        if (!seg_end) {
            seg_end = strstr(seg_start + 5, "\n\n");
            if (!seg_end)
                seg_end = text + strlen(text);
        }
        /* 在段内找 "OCSP - URI:" */
        p = strstr(seg_start, "OCSP - URI:");
        if (p && p < seg_end) {
            uri = p + 10; /* after "OCSP - URI:" */
            while (*uri == ' ' || *uri == '\t') uri++;
            uri_end = uri;
            while (*uri_end && *uri_end != ' ' && *uri_end != '\t' &&
                   *uri_end != '\n' && *uri_end != '\r' && *uri_end != ';' && *uri_end != ')')
                uri_end++;
            n = (size_t)(uri_end - uri);
            if (n > 0 && n < sizeof(out->ocsp_url) - 1) {
                memcpy(out->ocsp_url, uri, n);
                out->ocsp_url[n] = '\0';
            }
        }
    }
}

void cert_update_revoke_offline(cert_info_t *ci)
{
    if (!ci) return;
    /* 优先级：已过期 > 自签名 > 未检查 */
    if (ci->is_expired)
        ci->revoke_status = REVOKE_EXPIRED;
    else if (ci->is_self_signed)
        ci->revoke_status = REVOKE_SELF_SIGNED;
    else
        ci->revoke_status = REVOKE_UNCHECKED;
}

const char *revoke_status_str(revoke_status_t s)
{
    switch (s) {
    case REVOKE_UNCHECKED:     return "未检查（离线模式）";
    case REVOKE_EXPIRED:       return "已过期（离线代理）";
    case REVOKE_SELF_SIGNED:   return "自签名（离线代理）";
    case REVOKE_ONLINE_OK:     return "在线检查：有效";
    case REVOKE_ONLINE_REVOKED:return "在线检查：确认吊销";
    case REVOKE_ONLINE_FAIL:   return "在线检查：失败";
    default:                   return "未知吊销状态";
    }
}

const char *cert_revoke_status_str(const cert_info_t *ci)
{
    return revoke_status_str(ci->revoke_status);
}

/* ================================================================== */
/* 入口                                                               */
/* ================================================================== */

int cert_parse_file(const char *path, cert_parse_mode_t mode, cert_info_t *out)
{
    unsigned char *file = NULL;
    size_t file_len = 0;
    unsigned char *der = NULL;
    size_t der_len = 0;
    int rc = -1;

    cert_info_init(out);

    if (mode == CERT_PARSE_OPENSSL) {
        /* openssl CLI 可解析 PEM 与 DER 输入 */
        rc = cert_parse_openssl(path, out);
        if (rc == 0)
            return 0;
        /* 失败则回退到 DER 自解析 */
    }

    if (read_file(path, &file, &file_len) != 0)
        return -1;

    /* 判断 PEM 还是 DER */
    if (file_len > 2 && file[0] == '-' && memcmp(file, "-----BEGIN", 10) == 0) {
        if (pem_to_der(file, file_len, &der, &der_len) != 0) {
            free(file);
            return -1;
        }
    } else {
        der = file;
        der_len = file_len;
    }

    rc = cert_parse_der_bytes(der, der_len, out);
    if (rc == 0)
        cert_update_revoke_offline(out);

    if (der != file)
        free(der);
    free(file);
    return rc;
}
