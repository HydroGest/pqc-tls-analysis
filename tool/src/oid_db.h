/*
 * oid_db.h — OID 特征库接口
 *
 * 数据来源：research/算法特征识别库.json（v1.0）的 x509_key_oids / tls_signature_schemes
 *           + IETF LAMPS PQC 证书草案（ML-KEM/ML-DSA/SLH-DSA OID）
 *           + RFC 8410（X25519/X448/EdDSA）+ RFC 8708（LMS/HSS）
 *
 * 为便于离线运行，本工具将 OID 硬编码为静态查找表（不依赖外部 JSON 文件）。
 */
#ifndef PQC_OID_DB_H
#define PQC_OID_DB_H

#include "threat_judge.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *oid;        /* 点分十进制 OID */
    const char *name;       /* 规范名（RFC / 国密 / NIST 名） */
    algo_type_t algo;       /* 算法分类 */
    int key_size;           /* 默认密钥长度（bit），0 = 不适用/随实例而定 */
    int nist_category;      /* NIST 后量子安全类别（1/3/5；0 = 无） */
    const char *note;       /* 威胁说明（中文） */
} oid_entry_t;

/* 精确查找 OID；未命中返回 NULL（含前缀规则回退，见实现） */
const oid_entry_t *oid_lookup(const char *oid_str);

/* 按规范名查找（忽略大小写与短横线/下划线差异的简易匹配） */
const oid_entry_t *oid_lookup_by_name(const char *name);

/* OID 是否已知（含前缀规则） */
int oid_is_known(const char *oid_str);

/* 遍历表 */
int oid_entry_count(void);
const oid_entry_t *oid_entry_at(int i);

#ifdef __cplusplus
}
#endif

#endif /* PQC_OID_DB_H */
