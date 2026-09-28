/*
 * threat_judge.h — 抗量子威胁判定引擎核心接口（含时间感知评分）
 *
 * 项目：抗量子密码算法的应用与部署关键技术研究（方向一）
 * 功能：输入 算法标识（OID / 算法名 / 证书）→ 输出 Shor / Grover 威胁等级
 *        可选：时间感知评分（NIST IR 8547 时间线 × PTA-QVS 概率化模型 v0.1）
 *
 * 威胁模型：
 *   - Shor 算法  ：可多项式时间破解 RSA（整数分解）、ECC/ECDSA/SM2/EdDSA/DSA/DH（ECDLP/DLP）
 *   - Grover 算法：对称密钥搜索降至 2^(k/2)，AES-128 → ~64 位安全（威胁），
 *                  AES-192 → ~96 位，AES-256 → ~128 位（安全）
 *   - PQC 方案   ：ML-KEM / ML-DSA / SLH-DSA / XMSS / LMS 当前无已知量子威胁
 *
 * 数据来源：research/算法特征识别库.json（v1.0）+ IETF LAMPS PQC 证书草案 OID
 */
#ifndef PQC_THREAT_JUDGE_H
#define PQC_THREAT_JUDGE_H

/* 前向声明：cert_info_t 定义于 cert_parser.h（含其 typedef struct cert_info ...） */
struct cert_info;

#ifdef __cplusplus
extern "C" {
#endif

/* ============ 威胁等级 ============ */
typedef enum {
    THREAT_NONE = 0,     /* 量子安全（PQC / 对称 192~256 位等）            */
    THREAT_GROVER = 1,   /* Grover 威胁（AES-128 等对称密钥，降为 ~64 位） */
    THREAT_SHOR = 2,     /* Shor 威胁（RSA / ECC / SM2 / DSA / EdDSA 等）  */
    THREAT_CRITICAL = 3, /* 致命（弱算法/SHA-1/MD5 签名/已过期/自签名/密钥过短） */
} threat_level_t;

/* ============ 算法分类 ============ */
typedef enum {
    ALGO_RSA = 0,
    ALGO_ECC,        /* ECDSA / ECDH / 任意 EC 曲线 */
    ALGO_SM2,        /* 国密 SM2（ECDLP 基，同样被 Shor 破） */
    ALGO_DSA,
    ALGO_ED25519,
    ALGO_ED448,
    ALGO_DH,         /* 有限域 DH / FFDHE */
    ALGO_MLKEM,      /* ML-KEM (Kyber) */
    ALGO_MLDSA,      /* ML-DSA (Dilithium) */
    ALGO_SLHDSA,     /* SLH-DSA (SPHINCS+) */
    ALGO_XMSS,
    ALGO_LMS,
    ALGO_AES,        /* AES（Grover 关注对象） */
    ALGO_SYMMETRIC,  /* 其它对称算法（DES/3DES/ChaCha20...） */
    ALGO_UNKNOWN,
} algo_type_t;

/* ============ 核心判定 API ============ */

/*
 * 按算法类型 + 密钥长度判定威胁。
 * key_size 单位：位（bit）。0 表示未知/不适用。
 * 规则：
 *   RSA       < 2048 → CRITICAL（经典+量子皆不安全）；>= 2048 → SHOR
 *   ECC/SM2/DSA/Ed25519/Ed448/DH → SHOR（Shor 破 ECDLP/DLP）
 *   ML-KEM/ML-DSA/SLH-DSA/XMSS/LMS → NONE（PQC）
 *   AES-128 → GROVER；AES-192/256 → NONE
 *   SYMMETRIC <128 位 → CRITICAL；128~191 → GROVER；>=256 → NONE
 */
threat_level_t judge_algorithm(algo_type_t algo, int key_size);

/*
 * 按 OID 字符串判定（如 "1.2.840.113549.1.1.1"）。
 * 未知 OID 返回 THREAT_NONE —— 调用方必须先用 oid_is_known() 检测，
 * 未知 OID 应提示"需人工复核"，不可当作量子安全。
 */
threat_level_t judge_oid(const char *oid_str);

/* 按算法名判定（如 "RSA-2048"、"AES-128"、"mldsa44"、"secp256r1"、
 * "0x0401"（TLS 签名方案）、"ssh-ed25519" 等）。未知返回 THREAT_NONE。 */
threat_level_t judge_name(const char *name);

/* 签名算法判定：按名称或 OID。SHA-1/MD5 签名 → CRITICAL（经典已破）；
 * RSA/ECDSA/SM2/EdDSA → SHOR；PQC 签名 → NONE。 */
threat_level_t judge_signature_algo(const char *sig_name, const char *sig_oid);

/* ============ 输出辅助 ============ */

/* 威胁等级中文描述 */
const char *threat_description(threat_level_t level);

/* 威胁等级英文短名 */
const char *threat_level_str(threat_level_t level);

/* 算法类型中文名 */
const char *algo_name_str(algo_type_t algo);

/* 该等级 + 算法的迁移建议（中文） */
const char *recommendation(threat_level_t level, algo_type_t algo);

/* 解析 "RSA-2048" / "rsa 2048" / "mldsa44" / "secp256r1" 等。
 * 返回 1 表示识别成功（algo 与 key_size 有效），0 表示无法识别。 */
int parse_algo_and_size(const char *name, algo_type_t *algo, int *key_size);

/* ============ 时间感知评分（PTA-QVS v0.1 / NIST IR 8547） ============ */
/*
 * 设计依据：pta_qvs_modeling_methodology.md
 * - NIST IR 8547 (ipd) 迁移时间线 → 证书到期年映射三阶段（L2 权威规范证据）
 * - Hyoung 2026/1174 HNDL 乘数 M = 1.0 + h/20（L3 已发表文献证据）
 * - PTA-QVS §7 骨架公式：Risk = Vuln(algo) × ZoneWeight(zone) × M(h)
 * - Kagai 2025 R(t)=Pr{Ha(t)≥Ld} 概率形式（引用于 methodology §1.5）
 *
 * 分数规范：
 *   time_score = 100 × Vuln(algo) × Z(zone)   ∈ [0, 100]
 *   Vuln: NONE=0.0, GROVER=0.5, SHOR/CRITICAL=1.0
 *   Z:    PRE2030=1/3, 2030-2035=2/3, POST2035=1.0（v0.1 校准，L5 敏感性待后续）
 *   m_factor = 1.0 + h/20（默认 h=13 → 1.65, 来源 Mosca & Piani 2023）
 *   time_score_adj = min(100, time_score × m_factor)  [论文展示用]
 *
 * 威胁等级升级规则（时间感知）：
 *   - 已过期 / 基础 CRITICAL → CRITICAL
 *   - POST2035 + SHOR 威胁 → CRITICAL（跨越 NIST 2035 禁用线，合规致命）
 *   - 其它 → 基础等级
 */

/* NIST IR 8547 (ipd) 迁移里程碑（来源：doi:10.6028/NIST.IR.8547.ipd） */
#define PQC_NIST_YEAR_DEPRECATE 2030   /* RSA/ECDH/DSA 弃用（高风险优先迁移） */
#define PQC_NIST_YEAR_PROHIBIT  2035   /* RSA/ECC 禁止使用（移除前须完成迁移） */

/* 证书到期年 → NIST IR 8547 时间线阶段 */
typedef enum {
    NIST_ZONE_PRE2030 = 0,    /* notAfter < 2030：自然轮换来得及（时间风险低） */
    NIST_ZONE_2030_2035 = 1,  /* 2030 ≤ notAfter < 2035：需主动迁移计划（时间风险中） */
    NIST_ZONE_POST2035 = 2,   /* notAfter ≥ 2035：跨越 NIST 禁用线（时间风险高） */
    NIST_ZONE_UNKNOWN = 3,    /* 无法解析有效期 */
} nist_zone_t;

/* 时间风险等级 */
typedef enum {
    TIME_RISK_LOW = 0,
    TIME_RISK_MEDIUM = 1,
    TIME_RISK_HIGH = 2,
    TIME_RISK_UNKNOWN = 3,
} time_risk_t;

/* 论文可引用的 NIST 时间线阶段表条目
 * （对应 methodology §5 的 L2 证据锚点表） */
typedef struct {
    int year_from;             /* 含 */
    int year_to;               /* 不含 */
    nist_zone_t zone;
    time_risk_t risk;
    double zone_weight;        /* Z(zone)：时间风险权重 */
    const char *phase;         /* 阶段名（中文） */
    const char *description;   /* 阶段说明 */
    const char *action;        /* 建议动作 */
    const char *evidence;      /* 依据来源 */
} nist_timeline_entry_t;

/* 时间评分结果 */
typedef struct {
    int not_after_year;        /* 证书到期年（0=未知） */
    nist_zone_t zone;          /* NIST 阶段 */
    time_risk_t risk;          /* 时间风险等级 */
    double vuln;               /* 算法脆弱度 Vuln(algo) ∈ [0,1] */
    double zone_weight;        /* Z(zone) ∈ [1/3, 1.0] */
    double m_factor;           /* Hyoung HNDL 乘数 M=1.0+h/20 */
    double time_score;         /* 时间感知分 ∈ [0,100] = 100×vuln×zone_weight */
    double time_score_adj;     /* 调整后分数 = min(100, time_score×M) */
    threat_level_t base_level; /* 基础量子威胁（算法） */
    threat_level_t level;      /* 综合威胁等级（含时间） */
} time_judge_t;

/* ---------- 时间感知评分函数 ---------- */

/* 年份 → NIST 阶段（纯函数，线程安全） */
nist_zone_t nist_zone_for_year(int year);

/* 证书到期年 → NIST 时间线阶段中文行（-t 单行输出用，纯函数，线程安全）。
 * 返回完整输出行（含 "NIST阶段: " 前缀），无需再拼接：
 *   year < 2030          → "NIST阶段: 2030前到期（低风险，可自然轮换）"
 *   2030 <= year <= 2035 → "NIST阶段: 2030-2035（中风险，建议主动迁移）"
 *   year > 2035          → "NIST阶段: 2035后到期（高风险，跨越NIST截止线）"
 *   year <= 0（未知）    → "NIST阶段: UNKNOWN（无法解析有效期）"
 */
const char *nist_phase(int notafter_year);

/* notAfter 字符串（"2031-05-01 ..." 或 "May  1 12:00:00 2031 GMT"）→ NIST 阶段 */
nist_zone_t nist_zone_for_notafter(const char *not_after);

/* 解析 notAfter 字符串 → 年份（0=失败） */
int parse_notafter_year(const char *not_after);

/* NIST 阶段英文短名 */
const char *nist_zone_str(nist_zone_t z);

/* 时间风险英文短名 */
const char *time_risk_str(time_risk_t r);

/* NIST 阶段中文说明 */
const char *nist_zone_description(nist_zone_t z);

/* NIST 阶段建议动作（中文） */
const char *nist_zone_action(nist_zone_t z);

/* NIST 阶段权重 Z(zone) */
double nist_zone_weight(nist_zone_t z);

/* Hyoung HNDL 乘数 M = 1.0 + h/20（h 年；h<0 按 0 处理） */
double hyoung_multiplier(double h);

/* 算法脆弱度 Vuln(algo) ∈ [0,1]（Shor 威胁=1, PQC=0, Grover=0.5） */
double algo_vulnerability(algo_type_t algo, int key_size);

/* 时间感知判定核心：由算法 + 密钥长度 + notAfter 字符串 → 评分结果 */
int time_judge_components(algo_type_t algo, int key_size,
                          const char *not_after, double h,
                          time_judge_t *out);

/* 时间感知判定（证书）：包装 time_judge_components，额外处理 is_expired */
int time_judge_cert(const struct cert_info *ci, double h, time_judge_t *out);

/* 获取 NIST 时间线阶段表（论文引用用） */
const nist_timeline_entry_t *nist_timeline_get(int *count);

#ifdef __cplusplus
}
#endif

#endif /* PQC_THREAT_JUDGE_H */
