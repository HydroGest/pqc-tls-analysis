/*
 * test_judge.c — 单元测试
 *
 * 覆盖：
 *   - judge_algorithm：全部算法分类 × 关键密钥长度
 *   - judge_oid：特征库关键 OID（RSA/EC/SM2/Ed25519/PQC）
 *   - judge_name：算法名 / TLS 签名方案 / SSH 算法 / 对称算法
 *   - judge_signature_algo：SHA-1/MD5 致命判定
 *   - cert_parser：openssl 与 DER 双模式解析测试证书
 *
 * 用法：./test_judge [证书目录，默认 test/certs]
 * 返回 0 = 全部通过；非 0 = 存在失败。
 */
#include "cert_parser.h"
#include "oid_db.h"
#include "threat_judge.h"

#include <stdio.h>
#include <string.h>

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        if (cond) {                                                          \
            g_pass++;                                                        \
            printf("  PASS  %s\n", msg);                                     \
        } else {                                                             \
            g_fail++;                                                        \
            printf("  FAIL  %s  (%s:%d)\n", msg, __FILE__, __LINE__);        \
        }                                                                    \
    } while (0)

#define CHECK_EQ(actual, expect, msg)                                        \
    do {                                                                     \
        if ((actual) == (expect)) {                                          \
            g_pass++;                                                        \
            printf("  PASS  %s\n", msg);                                     \
        } else {                                                             \
            g_fail++;                                                        \
            printf("  FAIL  %s  (got %d, want %d)  (%s:%d)\n",               \
                   msg, (int)(actual), (int)(expect), __FILE__, __LINE__);   \
        }                                                                    \
    } while (0)

static void test_judge_algorithm(void)
{
    printf("[1] judge_algorithm\n");
    CHECK_EQ(judge_algorithm(ALGO_RSA, 2048), THREAT_SHOR, "RSA-2048 → SHOR");
    CHECK_EQ(judge_algorithm(ALGO_RSA, 3072), THREAT_SHOR, "RSA-3072 → SHOR");
    CHECK_EQ(judge_algorithm(ALGO_RSA, 4096), THREAT_SHOR, "RSA-4096 → SHOR");
    CHECK_EQ(judge_algorithm(ALGO_RSA, 1024), THREAT_CRITICAL, "RSA-1024 → CRITICAL");
    CHECK_EQ(judge_algorithm(ALGO_RSA, 512), THREAT_CRITICAL, "RSA-512 → CRITICAL");
    CHECK_EQ(judge_algorithm(ALGO_ECC, 256), THREAT_SHOR, "ECC-256 → SHOR");
    CHECK_EQ(judge_algorithm(ALGO_ECC, 384), THREAT_SHOR, "ECC-384 → SHOR");
    CHECK_EQ(judge_algorithm(ALGO_SM2, 256), THREAT_SHOR, "SM2-256 → SHOR");
    CHECK_EQ(judge_algorithm(ALGO_DSA, 2048), THREAT_SHOR, "DSA-2048 → SHOR");
    CHECK_EQ(judge_algorithm(ALGO_ED25519, 256), THREAT_SHOR, "Ed25519 → SHOR");
    CHECK_EQ(judge_algorithm(ALGO_ED448, 456), THREAT_SHOR, "Ed448 → SHOR");
    CHECK_EQ(judge_algorithm(ALGO_DH, 2048), THREAT_SHOR, "DH-2048 → SHOR");
    CHECK_EQ(judge_algorithm(ALGO_MLKEM, 0), THREAT_NONE, "ML-KEM → NONE");
    CHECK_EQ(judge_algorithm(ALGO_MLDSA, 0), THREAT_NONE, "ML-DSA → NONE");
    CHECK_EQ(judge_algorithm(ALGO_SLHDSA, 0), THREAT_NONE, "SLH-DSA → NONE");
    CHECK_EQ(judge_algorithm(ALGO_XMSS, 0), THREAT_NONE, "XMSS → NONE");
    CHECK_EQ(judge_algorithm(ALGO_LMS, 0), THREAT_NONE, "LMS → NONE");
    CHECK_EQ(judge_algorithm(ALGO_AES, 128), THREAT_GROVER, "AES-128 → GROVER");
    CHECK_EQ(judge_algorithm(ALGO_AES, 192), THREAT_NONE, "AES-192 → NONE");
    CHECK_EQ(judge_algorithm(ALGO_AES, 256), THREAT_NONE, "AES-256 → NONE");
    CHECK_EQ(judge_algorithm(ALGO_SYMMETRIC, 56), THREAT_CRITICAL, "DES-56 → CRITICAL");
    CHECK_EQ(judge_algorithm(ALGO_SYMMETRIC, 112), THREAT_CRITICAL, "3DES-112 → CRITICAL");
    CHECK_EQ(judge_algorithm(ALGO_SYMMETRIC, 256), THREAT_NONE, "ChaCha20-256 → NONE");
}

static void test_judge_oid(void)
{
    printf("[2] judge_oid / oid_db\n");
    CHECK_EQ(judge_oid("1.2.840.113549.1.1.1"), THREAT_SHOR, "rsaEncryption → SHOR");
    CHECK_EQ(judge_oid("1.2.840.10045.2.1"), THREAT_SHOR, "id-ecPublicKey → SHOR");
    CHECK_EQ(judge_oid("1.2.840.10040.4.1"), THREAT_SHOR, "id-dsa → SHOR");
    CHECK_EQ(judge_oid("1.2.840.10046.2.1"), THREAT_SHOR, "dhpublicnumber → SHOR");
    CHECK_EQ(judge_oid("1.3.101.112"), THREAT_SHOR, "id-Ed25519 → SHOR");
    CHECK_EQ(judge_oid("1.3.101.113"), THREAT_SHOR, "id-Ed448 → SHOR");
    CHECK_EQ(judge_oid("1.2.156.10197.1.301"), THREAT_SHOR, "SM2 → SHOR");
    CHECK_EQ(judge_oid("1.2.156.10197.1.501"), THREAT_SHOR, "SM3withSM2 → SHOR");
    CHECK_EQ(judge_oid("1.2.840.10045.3.1.7"), THREAT_SHOR, "prime256v1 → SHOR");
    CHECK_EQ(judge_oid("1.3.132.0.34"), THREAT_SHOR, "secp384r1 → SHOR");
    CHECK_EQ(judge_oid("1.2.840.113549.1.1.5"), THREAT_CRITICAL, "sha1WithRSA → CRITICAL");
    CHECK_EQ(judge_oid("1.2.840.113549.1.1.4"), THREAT_CRITICAL, "md5WithRSA → CRITICAL");
    CHECK_EQ(judge_oid("1.2.840.113549.1.1.11"), THREAT_SHOR, "sha256WithRSA → SHOR");
    CHECK_EQ(judge_oid("1.2.840.10045.4.3.2"), THREAT_SHOR, "ecdsa-with-SHA256 → SHOR");
    CHECK_EQ(judge_oid("2.16.840.1.101.3.4.4.1"), THREAT_NONE, "ML-KEM-512 → NONE");
    CHECK_EQ(judge_oid("2.16.840.1.101.3.4.4.2"), THREAT_NONE, "ML-KEM-768 → NONE");
    CHECK_EQ(judge_oid("2.16.840.1.101.3.4.4.3"), THREAT_NONE, "ML-KEM-1024 → NONE");
    CHECK_EQ(judge_oid("2.16.840.1.101.3.4.3.17"), THREAT_NONE, "ML-DSA-44 → NONE");
    CHECK_EQ(judge_oid("2.16.840.1.101.3.4.3.18"), THREAT_NONE, "ML-DSA-65 → NONE");
    CHECK_EQ(judge_oid("2.16.840.1.101.3.4.3.19"), THREAT_NONE, "ML-DSA-87 → NONE");
    CHECK_EQ(judge_oid("2.16.840.1.101.3.4.3.20"), THREAT_NONE, "SLH-DSA-128s → NONE");
    CHECK_EQ(judge_oid("2.16.840.1.101.3.4.3.31"), THREAT_NONE, "SLH-DSA-256f → NONE");
    CHECK_EQ(judge_oid("1.2.840.113549.1.9.16.3.17"), THREAT_NONE, "LMS/HSS (RFC8708) → NONE");
    CHECK_EQ(judge_oid("0.4.0.127.0.15.1.1.13.0"), THREAT_NONE, "XMSS → NONE");
    CHECK(oid_is_known("1.2.840.113549.1.1.1"), "已知 OID 识别");
    CHECK(!oid_is_known("1.2.3.4.5.6.7.8.9"), "未知 OID 识别");
    CHECK(oid_is_known("0.4.0.127.0.15.1.1.13.5"), "XMSS 变体前缀识别");
}

static void test_judge_name(void)
{
    printf("[3] judge_name / parse_algo_and_size\n");
    CHECK_EQ(judge_name("RSA-2048"), THREAT_SHOR, "RSA-2048 → SHOR");
    CHECK_EQ(judge_name("RSA-1024"), THREAT_CRITICAL, "RSA-1024 → CRITICAL");
    CHECK_EQ(judge_name("rsa 4096"), THREAT_SHOR, "rsa 4096 → SHOR");
    CHECK_EQ(judge_name("rsa4096"), THREAT_SHOR, "rsa4096 → SHOR");
    CHECK_EQ(judge_name("AES-128"), THREAT_GROVER, "AES-128 → GROVER");
    CHECK_EQ(judge_name("AES-192"), THREAT_NONE, "AES-192 → NONE");
    CHECK_EQ(judge_name("AES-256"), THREAT_NONE, "AES-256 → NONE");
    CHECK_EQ(judge_name("aes128"), THREAT_GROVER, "aes128 → GROVER");
    CHECK_EQ(judge_name("3DES"), THREAT_CRITICAL, "3DES → CRITICAL");
    CHECK_EQ(judge_name("DES"), THREAT_CRITICAL, "DES → CRITICAL");
    CHECK_EQ(judge_name("SM2"), THREAT_SHOR, "SM2 → SHOR");
    CHECK_EQ(judge_name("ed25519"), THREAT_SHOR, "ed25519 → SHOR");
    CHECK_EQ(judge_name("secp256r1"), THREAT_SHOR, "secp256r1 → SHOR");
    CHECK_EQ(judge_name("prime256v1"), THREAT_SHOR, "prime256v1 → SHOR");
    CHECK_EQ(judge_name("x25519"), THREAT_SHOR, "x25519 → SHOR");
    CHECK_EQ(judge_name("ML-DSA-65"), THREAT_NONE, "ML-DSA-65 → NONE");
    CHECK_EQ(judge_name("mldsa44"), THREAT_NONE, "mldsa44 → NONE");
    CHECK_EQ(judge_name("ML-KEM-768"), THREAT_NONE, "ML-KEM-768 → NONE");
    CHECK_EQ(judge_name("slhdsa_sha2_128s"), THREAT_NONE, "slhdsa_sha2_128s → NONE");
    CHECK_EQ(judge_name("0x0401"), THREAT_SHOR, "TLS rsa_pkcs1_sha256 (0x0401) → SHOR");
    CHECK_EQ(judge_name("0x0403"), THREAT_SHOR, "TLS ecdsa_secp256r1 (0x0403) → SHOR");
    CHECK_EQ(judge_name("0x0807"), THREAT_SHOR, "TLS ed25519 (0x0807) → SHOR");
    CHECK_EQ(judge_name("0x0904"), THREAT_NONE, "TLS mldsa44 (0x0904) → NONE");
    CHECK_EQ(judge_name("0x0915"), THREAT_NONE, "TLS slhdsa256s (0x0915) → NONE");
    CHECK_EQ(judge_name("rsa_pkcs1_sha256"), THREAT_SHOR, "rsa_pkcs1_sha256 → SHOR");
    CHECK_EQ(judge_name("ssh-ed25519"), THREAT_SHOR, "ssh-ed25519 → SHOR");
    CHECK_EQ(judge_name("ssh-rsa"), THREAT_SHOR, "ssh-rsa → SHOR");
    CHECK_EQ(judge_name("ecdsa-sha2-nistp256"), THREAT_SHOR, "ecdsa-sha2-nistp256 → SHOR");
    CHECK_EQ(judge_name("diffie-hellman-group14-sha256"), THREAT_SHOR, "DH-group14 → SHOR");
}

static void test_judge_signature(void)
{
    printf("[4] judge_signature_algo\n");
    CHECK_EQ(judge_signature_algo("sha1WithRSAEncryption", NULL), THREAT_CRITICAL,
             "sha1WithRSA → CRITICAL");
    CHECK_EQ(judge_signature_algo("md5WithRSAEncryption", NULL), THREAT_CRITICAL,
             "md5WithRSA → CRITICAL");
    CHECK_EQ(judge_signature_algo("ecdsa-with-SHA1", NULL), THREAT_CRITICAL,
             "ecdsa-with-SHA1 → CRITICAL");
    CHECK_EQ(judge_signature_algo("sha256WithRSAEncryption", NULL), THREAT_SHOR,
             "sha256WithRSA → SHOR");
    CHECK_EQ(judge_signature_algo("SM2-with-SM3", NULL), THREAT_SHOR, "SM2-with-SM3 → SHOR");
    CHECK_EQ(judge_signature_algo("ecdsa-with-SHA256", NULL), THREAT_SHOR,
             "ecdsa-with-SHA256 → SHOR");
    CHECK_EQ(judge_signature_algo("ml-dsa-65", NULL), THREAT_NONE, "ml-dsa-65 → NONE");
    CHECK_EQ(judge_signature_algo(NULL, "1.2.840.113549.1.1.5"), THREAT_CRITICAL,
             "OID sha1WithRSA → CRITICAL");
    CHECK_EQ(judge_signature_algo(NULL, "2.16.840.1.101.3.4.3.18"), THREAT_NONE,
             "OID ML-DSA-65 → NONE");
}

static void test_cert_parser(const char *dir)
{
    char p[512];
    cert_info_t ci;

    printf("[5] cert_parser（openssl 模式）\n");
    snprintf(p, sizeof(p), "%s/test_rsa.pem", dir);
    if (cert_parse_file(p, CERT_PARSE_OPENSSL, &ci) == 0) {
        CHECK(ci.pk_algo == ALGO_RSA, "RSA 证书：公钥分类 RSA");
        CHECK_EQ(ci.key_bits, 2048, "RSA 证书：密钥长度 2048");
        CHECK(strstr(ci.sig_name, "SHA1") || strstr(ci.sig_name, "sha1") ||
              strstr(ci.sig_name, "sha1WithRSA"), "RSA 证书：SHA-1 签名识别");
        CHECK_EQ(ci.is_self_signed, 1, "RSA 证书：自签名识别");
    } else {
        CHECK(0, "RSA 证书（openssl 模式）解析");
    }

    snprintf(p, sizeof(p), "%s/test_sm2.pem", dir);
    if (cert_parse_file(p, CERT_PARSE_OPENSSL, &ci) == 0) {
        CHECK(ci.pk_algo == ALGO_SM2, "SM2 证书：公钥分类 SM2");
        CHECK_EQ(ci.key_bits, 256, "SM2 证书：密钥长度 256");
    } else {
        CHECK(0, "SM2 证书（openssl 模式）解析");
    }

    snprintf(p, sizeof(p), "%s/test_ec.pem", dir);
    if (cert_parse_file(p, CERT_PARSE_OPENSSL, &ci) == 0) {
        CHECK(ci.pk_algo == ALGO_ECC, "EC 证书：公钥分类 ECC");
        CHECK_EQ(ci.key_bits, 256, "EC 证书：密钥长度 256");
        CHECK_EQ(ci.is_expired, 0, "EC 证书：未过期");
    } else {
        CHECK(0, "EC 证书（openssl 模式）解析");
    }

    snprintf(p, sizeof(p), "%s/test_expired.pem", dir);
    if (cert_parse_file(p, CERT_PARSE_OPENSSL, &ci) == 0) {
        CHECK_EQ(ci.is_expired, 1, "过期证书：is_expired=1");
        CHECK_EQ(ci.is_self_signed, 1, "过期证书：自签名");
    } else {
        CHECK(0, "过期证书（openssl 模式）解析");
    }

    printf("[6] cert_parser（DER 模式）\n");
    snprintf(p, sizeof(p), "%s/test_rsa.pem", dir);
    if (cert_parse_file(p, CERT_PARSE_DER, &ci) == 0) {
        CHECK(strcmp(ci.pk_oid, "1.2.840.113549.1.1.1") == 0, "DER：RSA 公钥 OID");
        CHECK_EQ(ci.key_bits, 2048, "DER：RSA 模数位长 2048");
        CHECK(strcmp(ci.sig_oid, "1.2.840.113549.1.1.5") == 0, "DER：SHA1WithRSA 签名 OID");
        CHECK_EQ(ci.is_self_signed, 1, "DER：自签名（字节级比较）");
        CHECK_EQ(ci.is_expired, 0, "DER：未过期");
        CHECK(ci.subject[0] != '\0' && strstr(ci.subject, "CFCA") != NULL, "DER：subject 解码");
    } else {
        CHECK(0, "RSA 证书（DER 模式）解析");
    }

    snprintf(p, sizeof(p), "%s/test_sm2.pem", dir);
    if (cert_parse_file(p, CERT_PARSE_DER, &ci) == 0) {
        CHECK(strcmp(ci.pk_oid, "1.2.840.10045.2.1") == 0, "DER：SM2 公钥 OID (id-ecPublicKey)");
        CHECK(strcmp(ci.curve_oid, "1.2.156.10197.1.301") == 0, "DER：SM2 曲线 OID");
        CHECK(ci.pk_algo == ALGO_SM2, "DER：SM2 算法识别");
        CHECK_EQ(ci.key_bits, 256, "DER：SM2 密钥长度 256");
        CHECK(strcmp(ci.sig_oid, "1.2.156.10197.1.501") == 0, "DER：SM3withSM2 签名 OID");
    } else {
        CHECK(0, "SM2 证书（DER 模式）解析");
    }

    snprintf(p, sizeof(p), "%s/test_expired.pem", dir);
    if (cert_parse_file(p, CERT_PARSE_DER, &ci) == 0) {
        CHECK_EQ(ci.is_expired, 1, "DER：过期识别");
        CHECK_EQ(ci.is_self_signed, 1, "DER：自签名识别");
    } else {
        CHECK(0, "过期证书（DER 模式）解析");
    }
}

int main(int argc, char **argv)
{
    const char *certdir = (argc > 1) ? argv[1] : "test/certs";

    printf("=== pqc-judge 单元测试 ===\n");
    test_judge_algorithm();
    test_judge_oid();
    test_judge_name();
    test_judge_signature();
    test_cert_parser(certdir);
    printf("\n结果：通过 %d，失败 %d\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
