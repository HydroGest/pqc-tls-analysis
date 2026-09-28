/*
 * cert_parser.h — 证书解析接口
 *
 * 两种解析模式：
 *   CERT_PARSE_OPENSSL ：调用 openssl x509 CLI 解析（快速可用，依赖 openssl 命令）
 *   CERT_PARSE_DER     ：自包含 ASN.1/DER 解析（不依赖 openssl，可提取 OID/密钥长度/有效期）
 */
#ifndef PQC_CERT_PARSER_H
#define PQC_CERT_PARSER_H

#include "threat_judge.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============ 吊销检查状态（离线代理） ============ */
typedef enum {
    REVOKE_UNCHECKED = 0,         /* 未检查（离线模式），无吊销证据 */
    REVOKE_EXPIRED = 1,           /* 已过期（离线代理） */
    REVOKE_SELF_SIGNED = 2,       /* 自签名（离线代理） */
    REVOKE_ONLINE_OK = 3,         /* 在线检查：证书有效 */
    REVOKE_ONLINE_REVOKED = 4,    /* 在线检查：确认吊销 */
    REVOKE_ONLINE_FAIL = 5,       /* 在线检查失败 */
} revoke_status_t;

typedef enum {
    CERT_PARSE_OPENSSL = 0,   /* 模式 a：openssl CLI 包装 */
    CERT_PARSE_DER = 1,       /* 模式 b：直接 DER 解析 */
} cert_parse_mode_t;

/* tagged for forward declaration in threat_judge.h */
typedef struct cert_info {
    /* ---- 公钥 ---- */
    algo_type_t pk_algo;        /* 公钥算法分类 */
    char pk_oid[64];            /* 公钥算法 OID（DER 模式；openssl 模式可为空） */
    char curve_oid[64];         /* EC 曲线 OID（DER 模式；非 EC 为空） */
    int key_bits;               /* 密钥长度（bit） */
    /* ---- 签名 ---- */
    char sig_oid[64];           /* 签名算法 OID（DER 模式） */
    char sig_name[128];         /* 签名算法名（openssl 文本；DER 模式取规范名） */
    /* ---- 主体信息 ---- */
    char subject[256];
    char issuer[256];
    char not_before[32];        /* 人类可读 */
    char not_after[32];
    /* ---- 状态 ---- */
    int is_self_signed;         /* 1 = 自签名（subject == issuer） */
    int is_expired;             /* 1 = 已过期 */
    /* ---- 吊销检查（离线代理 / CRL 分发点） ---- */
    revoke_status_t revoke_status;  /* 吊销状态 */
    char crl_dp[512];               /* CRL Distribution Points URL（尽力提取，可为空） */
    char ocsp_url[512];             /* OCSP Responder URL（尽力提取，可为空） */
} cert_info_t;

void cert_info_init(cert_info_t *ci);

/*
 * 解析证书文件（PEM 或 DER 均可）。成功返回 0，失败返回 -1。
 * mode 指定解析方式；openssl 不可用时 DER 模式仍可工作。
 */
int cert_parse_file(const char *path, cert_parse_mode_t mode, cert_info_t *out);

const char *cert_parse_mode_name(cert_parse_mode_t m);

/* ============ 吊销检查 API ============ */

/* 根据 is_expired / is_self_signed 更新 revoke_status（离线代理） */
void cert_update_revoke_offline(cert_info_t *ci);

/* 吊销状态中文描述（"未检查（离线模式）" / "已过期" / "自签名" / ...） */
const char *revoke_status_str(revoke_status_t s);

/* 捷径：返回 cert 的吊销状态中文文本，优先处理过期 > 自签名 > 未知 */
const char *cert_revoke_status_str(const cert_info_t *ci);

/* 尽力提取 CRL DP / OCSP URL 的 openssl -text 辅助（在 cert_parse_openssl 内调用） */
void extract_revoke_info(const char *openssl_text, cert_info_t *out);

#ifdef __cplusplus
}
#endif

#endif /* PQC_CERT_PARSER_H */
