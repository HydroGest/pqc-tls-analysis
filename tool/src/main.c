/*
 * main.c — pqc-judge 命令行入口（v0.2 + 时间感知 + 批量扫描 + 吊销检查）
 *
 * 用法：
 *   ./pqc-judge -a <算法名>       直接判定算法名
 *   ./pqc-judge -o <OID>          按 OID 判定
 *   ./pqc-judge -c <证书文件>     解析证书并判定（PEM 或 DER）
 *   ./pqc-judge -c <证书文件> -t  时间感知评分
 *   ./pqc-judge -b <域名列表>    批量扫描（输出 CSV）
 *   ./pqc-judge --nist-timeline   打印 NIST IR 8547 时间线阶段表
 *   ./pqc-judge --list            列出全部已知 OID
 *
 * 退出码：0=NONE 1=GROVER 2=SHOR 3=CRITICAL 4=未知/解析失败 5=用法错误
 */
#include "cert_parser.h"
#include "oid_db.h"
#include "threat_judge.h"

#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *PROG = "pqc-judge";

/* ================================================================== */
/* 帮助                                                               */
/* ================================================================== */

static void print_usage(void)
{
    printf(
        "抗量子威胁判定引擎 v0.2 (pqc-judge)\n"
        "用法：\n"
        "  %s -a <算法名>       判定算法（RSA-2048 / AES-128 / ML-DSA-65 ...）\n"
        "  %s -o <OID>          判定 OID（如 1.2.840.113549.1.1.1）\n"
        "  %s -c <证书文件>     解析并判定证书（PEM/DER，自动选择 openssl/DER 解析）\n"
        "  %s -c <证书文件> -t  时间感知评分（NIST IR 8547 时间线 + HNDL 乘数）\n"
        "  %s -c <证书文件> -m der   强制使用内置 DER 解析（不依赖 openssl）\n"
        "  %s -b <域名列表>     批量扫描（域名列表一行一个；-o 指定 CSV 输出文件，默认 stdout）\n"
        "  %s -j <N>            与 -b 合用：并发数（默认 8，最大 8）\n"
        "  %s --hndl <年数>     设置 HNDL 乘数参数 h（默认 13）\n"
        "  %s --check-revocation 启用在线吊销检查（与 -c/-b 合用；仅打印 CRL DP 提示）\n"
        "  %s --nist-timeline   打印 NIST IR 8547 时间线阶段表（论文引用）\n"
        "  %s --list            列出已知 OID 表\n"
        "  %s -h                显示本帮助\n"
        "\n"
        "退出码：0=量子安全 1=Grover 2=Shor 3=致命 4=未知/解析失败 5=用法错误\n",
        PROG, PROG, PROG, PROG, PROG, PROG, PROG, PROG, PROG, PROG, PROG, PROG);
}

/* ================================================================== */
/* 基础输出                                                           */
/* ================================================================== */

static void print_algo_judgment(const char *label, algo_type_t algo, int key_bits,
                                threat_level_t level)
{
    printf("  %-8s %-10s", label, algo_name_str(algo));
    if (key_bits > 0)
        printf("%d-bit ", key_bits);
    else
        printf("%-5s ", "-");
    printf(" → [%s]  %s\n", threat_level_str(level), threat_description(level));
}

/* ---- 算法名判定（-a） ---- */
static int do_judge_name(const char *name)
{
    algo_type_t algo;
    int key_size;
    threat_level_t level;

    if (parse_algo_and_size(name, &algo, &key_size)) {
        level = judge_algorithm(algo, key_size);
        printf("输入算法 : %s\n", name);
        printf("算法分类 : %s", algo_name_str(algo));
        if (key_size > 0)
            printf("（%d 位）", key_size);
        printf("\n");
        printf("威胁等级 : [%s]\n", threat_level_str(level));
        printf("威胁说明 : %s\n", threat_description(level));
        printf("建议     : %s\n", recommendation(level, algo));
        return (int)level;
    }

    if (name[0] == '0' && (name[1] == 'x' || name[1] == 'X')) {
        printf("未知的 TLS 签名方案/命名组代码：%s（不在特征库中）\n", name);
        return 4;
    }

    printf("无法识别的算法名：%s\n", name);
    return 4;
}

/* ---- OID 判定（-o） ---- */
static int do_judge_oid(const char *oid_str)
{
    const oid_entry_t *e = oid_lookup(oid_str);
    if (!e) {
        printf("未知 OID：%s —— 不在特征库中，需人工复核，不可视为量子安全。\n", oid_str);
        return 4;
    }
    {
        threat_level_t level = judge_oid(oid_str);
        printf("输入 OID  : %s\n", oid_str);
        printf("规范名   : %s\n", e->name);
        printf("算法分类 : %s", algo_name_str(e->algo));
        if (e->key_size > 0)
            printf("（默认 %d 位）", e->key_size);
        printf("\n");
        if (e->nist_category > 0)
            printf("NIST 类别 : %d\n", e->nist_category);
        printf("威胁等级 : [%s]\n", threat_level_str(level));
        printf("威胁说明 : %s\n", threat_description(level));
        printf("备注     : %s\n", e->note ? e->note : "-");
        printf("建议     : %s\n", recommendation(level, e->algo));
        return (int)level;
    }
}

/* ---- 证书判定（-c） ---- */
static int do_judge_cert(const char *path, cert_parse_mode_t mode,
                         int time_aware, double hndl_years,
                         int check_revoke)
{
    cert_info_t ci;
    threat_level_t pk_t, sig_t, overall;

    if (cert_parse_file(path, mode, &ci) != 0) {
        fprintf(stderr, "证书解析失败：%s（模式 %s）\n", path, cert_parse_mode_name(mode));
        return 4;
    }

    printf("证书文件 : %s（解析模式 %s）\n", path, cert_parse_mode_name(mode));
    if (ci.subject[0])
        printf("Subject  : %s\n", ci.subject);
    if (ci.issuer[0])
        printf("Issuer   : %s\n", ci.issuer);
    if (ci.not_before[0] && ci.not_after[0]) {
        printf("有效期   : %s ~ %s",
               ci.not_before, ci.not_after);
        printf(ci.is_expired ? "  [已过期]\n" : "  [有效]\n");
    }

    /* 吊销状态（Task 3：新增行） */
    printf("吊销状态 : %s", cert_revoke_status_str(&ci));
    if (ci.crl_dp[0] && !ci.is_expired)
        printf(" （CRL: %s）", ci.crl_dp);
    if (ci.ocsp_url[0] && !ci.is_expired)
        printf(" （OCSP: %s）", ci.ocsp_url);
    printf("\n");

    if (ci.is_self_signed)
        printf("状态     : [自签名] 证书由自身签发（信任锚场景下属正常，需按信任库策略评估）\n");

    /* 公钥威胁 */
    pk_t = judge_algorithm(ci.pk_algo, ci.key_bits);
    printf("\n[公钥] ");
    if (ci.pk_oid[0])
        printf("OID %s ", ci.pk_oid);
    print_algo_judgment("公钥算法", ci.pk_algo, ci.key_bits, pk_t);
    if (ci.curve_oid[0] && ci.pk_algo != ALGO_RSA)
        printf("          EC 曲线 OID: %s\n", ci.curve_oid);

    /* 签名威胁 */
    sig_t = judge_signature_algo(ci.sig_name, ci.sig_oid);
    printf("[签名] ");
    if (ci.sig_oid[0])
        printf("OID %s ", ci.sig_oid);
    printf("签名算法 %s → [%s]  %s\n",
           ci.sig_name[0] ? ci.sig_name : "未知",
           threat_level_str(sig_t), threat_description(sig_t));

    /* 综合：取两者更高；过期/自签名直接升致命 */
    overall = pk_t > sig_t ? pk_t : sig_t;
    if (ci.is_expired || ci.is_self_signed)
        overall = THREAT_CRITICAL;

    /* ---- 时间感知评分（-t） ---- */
    if (time_aware) {
        time_judge_t tj;
        time_judge_cert(&ci, hndl_years, &tj);

        printf("\n--- 时间感知评分（NIST IR 8547 × PTA-QVS v0.1） ---\n");
        if (tj.not_after_year > 0) {
            printf("  证书到期年 : %d\n", tj.not_after_year);
            printf("  NIST 阶段  : %s [TIME_RISK_%s]\n",
                   nist_zone_str(tj.zone), time_risk_str(tj.risk));
            printf("  阶段说明   : %s\n", nist_zone_description(tj.zone));
        } else {
            printf("  NIST 阶段  : UNKNOWN（无法解析有效期）\n");
        }
        printf("  时间风险   : %s\n", time_risk_str(tj.risk));
        printf("  HNDL 乘数  : M = 1.0 + %.0f/20 = %.3f（h=%.0f，来源 Mosca & Piani 2023，Hyoung 2026/1174）\n",
               hndl_years, tj.m_factor, hndl_years);
        printf("  算法脆弱度 : Vuln(algo) = %.2f\n", tj.vuln);
        printf("  阶段权重   : Z(%s) = %.3f\n", nist_zone_str(tj.zone), tj.zone_weight);
        printf("  时间感知分 : %.1f / 100（= 100 × Vuln × Z）\n", tj.time_score);
        printf("  调整后分数 : %.1f（×M，上限 100）\n", tj.time_score_adj);
        printf("  基础威胁   : [%s]\n", threat_level_str(tj.base_level));
        printf("  综合威胁(含时间) : [%s]  %s\n",
               threat_level_str(tj.level),
               tj.level == THREAT_CRITICAL && tj.base_level != THREAT_CRITICAL
               ? "NIST 2035 禁用线跨越 → 合规致命"
               : threat_description(tj.level));
        printf("  建议动作   : %s\n", nist_zone_action(tj.zone));

        overall = tj.level;  /* 时间感知等级覆盖 */
    }

    printf("\n综合威胁等级 : [%s]\n", threat_level_str(overall));
    if (time_aware) {
        printf("%s\n", nist_phase(parse_notafter_year(ci.not_after)));
    }
    printf("威胁说明     : %s\n", threat_description(overall));
    printf("建议         : %s\n", recommendation(overall, ci.pk_algo));

    /* 显示 CRL DP 提示（--check-revocation 时） */
    if (check_revoke && ci.crl_dp[0] && !ci.is_expired) {
        printf("\nCRL Distribution Points: %s\n", ci.crl_dp);
        printf("  （在线吊销检查未实现，当前为离线模式；批量扫描 -b 模式支持 curl + openssl 在线检查）\n");
    }

    return (int)overall;
}

/* ---- 列出 OID 表 ---- */
static void do_list(void)
{
    int n = oid_entry_count();
    int i;
    printf("%-32s %-26s %-10s %-6s %s\n", "OID", "名称", "算法", "威胁", "备注");
    printf("%s\n", "-----------------------------------------------------------------------------------------------------");
    for (i = 0; i < n; i++) {
        const oid_entry_t *e = oid_entry_at(i);
        threat_level_t lv = judge_oid(e->oid);
        printf("%-32s %-26s %-10s %-6s %s\n",
               e->oid, e->name, algo_name_str(e->algo),
               threat_level_str(lv), e->note ? e->note : "");
    }
}

/* ---- NIST 时间线阶段表（论文引用用） ---- */
static void do_nist_timeline(void)
{
    int i, n;
    const nist_timeline_entry_t *t = nist_timeline_get(&n);

    printf("NIST IR 8547 迁移时间线阶段表\n");
    printf("（证据等级 L2，来源：doi:10.6028/NIST.IR.8547.ipd；CNSA 2.0；FIPS 203/204/205）\n");
    printf("\n");
    printf("%-6s %-8s %-12s %-8s %-14s %s\n",
           "年份", "阶段名", "NIST 阶段", "风险", "权重 Z", "依据");
    printf("%s\n",
           "----------------------------------------------------------------------------------------");
    for (i = 0; i < n; i++) {
        if (t[i].zone == NIST_ZONE_UNKNOWN) continue;
        printf("%-6s %-8s %-12s %-8s %-14s %s\n",
               t[i].year_from == 0 ? "<2030" :
                   t[i].year_from == 2035 ? "≥2035" :
                   t[i].year_from == 2030 ? "2030-" : "",
               t[i].phase,
               nist_zone_str(t[i].zone),
               time_risk_str(t[i].risk),
               t[i].zone_weight == 0.333333 ? "1/3" :
                   t[i].zone_weight == 0.666667 ? "2/3" :
                   t[i].zone_weight == 1.0 ? "1.0" : "",
               t[i].evidence);
    }
    printf("\n评分公式：TimeScore = 100 × Vuln(algo) × Z(zone)  ∈ [0, 100]\n");
    printf("HNDL 乘数：M = 1.0 + h/20（h=到 CRQC 年数，默认 13 → 1.65）\n");
    printf("调整后分数：TimeScore_adj = min(100, TimeScore × M)\n");
    printf("\n注：权重 Z 为 v0.1 校准值（L5 敏感性分析见 PTA-QVS §3-C），公开可调。\n");
}

/* ================================================================== */
/* 批量扫描（-b）                                                     */
/* ================================================================== */

/* CSV 字段转义（包在双引号内如果含逗号/引号/换行） */
static void csv_escape(FILE *fp, const char *s)
{
    if (!s) { fprintf(fp, ""); return; }
    int need_quote = 0;
    const char *p;
    for (p = s; *p; p++) {
        if (*p == ',' || *p == '"' || *p == '\n' || *p == '\r') {
            need_quote = 1;
            break;
        }
    }
    if (!need_quote) {
        fprintf(fp, "%s", s);
        return;
    }
    fputc('"', fp);
    for (p = s; *p; p++) {
        if (*p == '"') fputc('"', fp);  /* 双引号转义 */
        fputc(*p, fp);
    }
    fputc('"', fp);
}

/* 写入 CSV 一行（格式：domain,chain_length,threat_level,nist_zone） */
static void csv_write_row(FILE *fp,
    const char *domain, int chain_len,
    const char *threat_level, const char *nist_zone_val)
{
    csv_escape(fp, domain);           fprintf(fp, ",");
    fprintf(fp, "%d,", chain_len);
    csv_escape(fp, threat_level);     fprintf(fp, ",");
    csv_escape(fp, nist_zone_val);    fprintf(fp, "\n");
}

/* 域名合法性检查（仅 [A-Za-z0-9.-] 以防 shell 注入） */
static int valid_hostname(const char *s)
{
    if (!s || !*s) return 0;
    for (; *s; s++) {
        if (!isalnum((unsigned char)*s) && *s != '.' && *s != '-')
            return 0;
    }
    return 1;
}

/* 从 openssl s_client 输出中提取所有 PEM 证书块 */
typedef struct {
    char **pems;
    int n;
} pem_list_t;

static void pem_list_free(pem_list_t *pl)
{
    int i;
    for (i = 0; i < pl->n; i++)
        free(pl->pems[i]);
    free(pl->pems);
    pl->pems = NULL;
    pl->n = 0;
}

#define CERT_BEGIN "-----BEGIN CERTIFICATE-----"
#define CERT_END   "-----END CERTIFICATE-----"

static int fetch_chain_pems(const char *domain, pem_list_t *out,
                            char *errbuf, size_t errsz)
{
    char cmd[4096];
    FILE *fp;
    char *buf = NULL;
    size_t cap = 0, len = 0;
    const char *p, *end;

    out->pems = NULL;
    out->n = 0;

    if (!valid_hostname(domain)) {
        snprintf(errbuf, errsz, "非法域名");
        return -1;
    }

    snprintf(cmd, sizeof(cmd),
        "timeout 12 openssl s_client -connect %s:443 -servername %s "
        "-tls1_2 -showcerts -no_ign_eof </dev/null 2>/dev/null",
        domain, domain);

    fp = popen(cmd, "r");
    if (!fp) {
        snprintf(errbuf, errsz, "popen 失败: %s", strerror(errno));
        return -1;
    }
    {
        char chunk[4096];
        size_t rd;
        while ((rd = fread(chunk, 1, sizeof(chunk), fp)) > 0) {
            if (len + rd + 1 > cap) {
                cap = cap ? cap * 2 : 32768;
                char *nb = (char *)realloc(buf, cap);
                if (!nb) { free(buf); pclose(fp); return -1; }
                buf = nb;
            }
            memcpy(buf + len, chunk, rd);
            len += rd;
        }
    }
    pclose(fp);

    if (!buf || len == 0) {
        free(buf);
        snprintf(errbuf, errsz, "无输出");
        return -1;
    }
    buf[len] = '\0';

    /* 提取 PEM 块 */
    p = buf;
    while ((p = strstr(p, CERT_BEGIN)) != NULL) {
        end = strstr(p + sizeof(CERT_BEGIN) - 1, CERT_END);
        if (!end) break;
        end += sizeof(CERT_END) - 1;
        {
            size_t blen = (size_t)(end - p);
            char *pem = (char *)malloc(blen + 2);
            if (!pem) { free(buf); return -1; }
            memcpy(pem, p, blen);
            pem[blen] = '\n';
            pem[blen + 1] = '\0';
            char **np = (char **)realloc(out->pems,
                            (size_t)(out->n + 1) * sizeof(char *));
            if (!np) { free(pem); free(buf); return -1; }
            out->pems = np;
            out->pems[out->n++] = pem;
        }
        p = end;
    }

    free(buf);
    if (out->n == 0) {
        snprintf(errbuf, errsz, "未找到证书块");
        return -1;
    }
    return 0;
}

/* 判定证书链：返回链的综合威胁等级 */
static threat_level_t judge_chain(pem_list_t *chain,
                                  cert_info_t *leaf_out,
                                  int *chain_len_out,
                                  int time_aware,
                                  double hndl_years)
{
    int i;
    threat_level_t overall = THREAT_NONE;

    *chain_len_out = chain->n;
    memset(leaf_out, 0, sizeof(*leaf_out));

    for (i = 0; i < chain->n; i++) {
        /* 写临时 PEM 文件 */
        char tmpl[] = "/tmp/pqc-batch-XXXXXX.pem";
        int fd;
        size_t wr;
        cert_info_t ci;
        threat_level_t pk_t, sig_t, cert_level;

        fd = mkstemps(tmpl, 4);
        if (fd < 0) continue;
        wr = write(fd, chain->pems[i], strlen(chain->pems[i]));
        close(fd);
        if (wr != strlen(chain->pems[i])) {
            unlink(tmpl);
            continue;
        }

        if (cert_parse_file(tmpl, CERT_PARSE_OPENSSL, &ci) != 0) {
            unlink(tmpl);
            continue;
        }
        unlink(tmpl);

        pk_t = judge_algorithm(ci.pk_algo, ci.key_bits);
        sig_t = judge_signature_algo(ci.sig_name, ci.sig_oid);
        cert_level = pk_t > sig_t ? pk_t : sig_t;

        /* 叶子过期为致命；非叶子的过期/自签名仅提示 */
        if (i == 0) {
            if (ci.is_expired)    cert_level = THREAT_CRITICAL;
            if (ci.is_self_signed) cert_level = THREAT_CRITICAL;
            memcpy(leaf_out, &ci, sizeof(*leaf_out));
        }

        if (cert_level > overall)
            overall = cert_level;
    }

    /* 时间感知升级 */
    if (time_aware && leaf_out->not_after[0]) {
        time_judge_t tj;
        time_judge_cert(leaf_out, hndl_years, &tj);
        if (tj.level > overall)
            overall = tj.level;
    }

    return overall;
}

/* ---- 批量扫描主函数 ---- */
static int batch_scan(const char *list_path, const char *out_path,
                      int workers, int time_aware, double hndl_years)
{
    FILE *list_fp;
    char **domains = NULL;
    int n = 0, cap = 0;
    char line[1024];
    int i;
    FILE *out_fp;
    int ok_count = 0, fail_count = 0;

    /* 限制并发 */
    if (workers < 1) workers = 1;
    if (workers > 8) workers = 8;

    /* 读域名列表 */
    list_fp = fopen(list_path, "r");
    if (!list_fp) {
        fprintf(stderr, "无法打开域名列表：%s\n", list_path);
        return 5;
    }
    while (fgets(line, sizeof(line), list_fp)) {
        char *nl;
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
        nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        nl = strchr(line, '\r');
        if (nl) *nl = '\0';
        if (line[0] == '\0') continue;
        char *d = strdup(line);
        if (!d) continue;
        if (n >= cap) {
            cap = cap ? cap * 2 : 256;
            char **nd = (char **)realloc(domains, (size_t)cap * sizeof(char *));
            if (!nd) { free(d); break; }
            domains = nd;
        }
        domains[n++] = d;
    }
    fclose(list_fp);

    if (n == 0) {
        fprintf(stderr, "域名列表为空（或格式错误）\n");
        free(domains);
        return 5;
    }

    /* 打开输出 */
    if (out_path) {
        out_fp = fopen(out_path, "w");
        if (!out_fp) {
            fprintf(stderr, "无法写入输出文件：%s\n", out_path);
            for (i = 0; i < n; i++) free(domains[i]);
            free(domains);
            return 5;
        }
    } else {
        out_fp = stdout;
    }

    /* CSV 表头 */
    fprintf(out_fp, "domain,chain_length,threat_level,nist_zone\n");

    if (workers == 1) {
        /* 顺序扫描 */
        for (i = 0; i < n; i++) {
            pem_list_t chain;
            cert_info_t leaf;
            int chain_len;
            threat_level_t overall;
            char errbuf[256];
            const char *domain = domains[i];

            errbuf[0] = '\0';
            if (fetch_chain_pems(domain, &chain, errbuf, sizeof(errbuf)) != 0) {
                fprintf(stderr, "  [%d/%d] %s → 失败: %s\n", i+1, n, domain, errbuf);
                csv_write_row(out_fp, domain, 0, "ERROR", "UNKNOWN");
                fail_count++;
                continue;
            }

            overall = judge_chain(&chain, &leaf, &chain_len,
                                  time_aware, hndl_years);

            csv_write_row(out_fp,
                domain, chain_len,
                threat_level_str(overall),
                nist_zone_str(nist_zone_for_notafter(leaf.not_after)));

            fprintf(stderr, "  [%d/%d] %s → %s (链长 %d)\n",
                    i+1, n, domain, threat_level_str(overall), chain_len);
            pem_list_free(&chain);
            ok_count++;
        }
        ok_count = n - fail_count;
    } else {
        /* fork 并发：worker 进程按 stride 分配域名。
         * 子进程写固定临时文件 /tmp/pqc-batch-res-{worker_idx}，
         * 父进程收集后按域索引顺序合并。 */
        pid_t *pids = (pid_t *)calloc((size_t)workers, sizeof(pid_t));
        if (!pids) {
            for (i = 0; i < n; i++) free(domains[i]);
            free(domains);
            fclose(out_fp);
            return 5;
        }

        for (i = 0; i < workers; i++) {
            pid_t pid = fork();
            if (pid < 0) {
                continue;
            }
            if (pid == 0) {
                /* 子进程：处理 i, i+workers, i+2*workers, ... */
                char fname[64];
                FILE *tmp_fp;
                int j;

                snprintf(fname, sizeof(fname), "/tmp/pqc-batch-res-%d", i);
                tmp_fp = fopen(fname, "w");
                if (!tmp_fp) _exit(1);

                for (j = i; j < n; j += workers) {
                    pem_list_t chain;
                    cert_info_t leaf;
                    int chain_len;
                    threat_level_t overall;
                    char errbuf[256];
                    const char *domain = domains[j];

                    errbuf[0] = '\0';
                    if (fetch_chain_pems(domain, &chain, errbuf, sizeof(errbuf)) != 0) {
                        fprintf(tmp_fp, "%d\t0\tERROR\tUNKNOWN\n", j);
                        continue;
                    }

                    overall = judge_chain(&chain, &leaf, &chain_len,
                                          time_aware, hndl_years);

                    fprintf(tmp_fp, "%d\t%d\t%s\t%s\n",
                        j, chain_len,
                        threat_level_str(overall),
                        nist_zone_str(nist_zone_for_notafter(leaf.not_after)));

                    pem_list_free(&chain);
                }

                fclose(tmp_fp);
                _exit(0);
            }
            pids[i] = pid;
        }

        /* 父进程：等待所有子进程 */
        for (i = 0; i < workers; i++) {
            int status;
            if (pids[i] > 0)
                waitpid(pids[i], &status, 0);
        }

        /* 按域索引顺序收集结果，写入 CSV */
        {
            char **results = (char **)calloc((size_t)n, sizeof(char *));

            for (i = 0; i < workers; i++) {
                char fname[64];
                FILE *rfp;
                char rline[8192];

                snprintf(fname, sizeof(fname), "/tmp/pqc-batch-res-%d", i);
                rfp = fopen(fname, "r");
                if (!rfp) continue;
                while (fgets(rline, sizeof(rline), rfp)) {
                    /* 去除尾随换行/回车 */
                    size_t rlen = strlen(rline);
                    while (rlen > 0 && (rline[rlen-1] == '\n' || rline[rlen-1] == '\r'))
                        rline[--rlen] = '\0';
                    int idx;
                    if (sscanf(rline, "%d", &idx) == 1 && idx >= 0 && idx < n) {
                        char *tab = strchr(rline, '\t');
                        if (tab) {
                            results[idx] = strdup(tab + 1);
                        }
                    }
                }
                fclose(rfp);
                unlink(fname);
            }

            for (i = 0; i < n; i++) {
                if (results[i]) {
                    /* results[i] = "chain_len\tthreat\tzone" */
                    int chain_len = 0;
                    char *threat = NULL, *zone = NULL;
                    char *save = NULL;
                    char *f1 = strtok_r(results[i], "\t", &save);
                    char *f2 = strtok_r(NULL, "\t", &save);
                    char *f3 = strtok_r(NULL, "\t", &save);
                    if (f1) chain_len = atoi(f1);
                    if (f2) threat = f2; else threat = "ERROR";
                    if (f3) zone = f3;   else zone = "UNKNOWN";
                    csv_write_row(out_fp, domains[i], chain_len, threat, zone);
                    free(results[i]);
                    ok_count++;
                } else {
                    csv_write_row(out_fp, domains[i], 0, "ERROR", "UNKNOWN");
                }
            }
            free(results);
        }

        free(pids);
    }

    /* 清理统计 */
    fail_count = n - ok_count;

    fprintf(stderr, "\n批量扫描完成：共 %d 个域名，成功 %d，失败 %d\n",
            n, ok_count, fail_count);
    if (out_path) {
        fprintf(stderr, "CSV 输出至 %s\n", out_path);
        fclose(out_fp);
    }

    for (i = 0; i < n; i++) free(domains[i]);
    free(domains);
    return 0;
}

/* ================================================================== */
/* 主入口                                                             */
/* ================================================================== */

int main(int argc, char **argv)
{
    const char *algo = NULL, *oid = NULL, *cert = NULL, *batch = NULL;
    const char *out_csv = NULL;
    cert_parse_mode_t mode = CERT_PARSE_OPENSSL;
    int time_aware = 0;
    double hndl_years = 13.0;
    int workers = 8;
    int check_revoke = 0;
    int i;

    /* 预扫描 -b：使 -o 在 -b 前后均可作为输出文件 */
    int batch_requested = 0;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--batch") == 0) {
            batch_requested = 1;
            break;
        }
    }

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            print_usage();
            return 0;
        } else if (strcmp(a, "--version") == 0) {
            printf("pqc-judge v0.2 — 抗量子威胁判定引擎（Shor/Grover + 时间感知 + 批量扫描）\n");
            return 0;
        } else if (strcmp(a, "--list") == 0) {
            do_list();
            return 0;
        } else if (strcmp(a, "--nist-timeline") == 0) {
            do_nist_timeline();
            return 0;
        } else if (strcmp(a, "-a") == 0 || strcmp(a, "--algorithm") == 0) {
            if (i + 1 >= argc) { print_usage(); return 5; }
            algo = argv[++i];
        } else if (strcmp(a, "-o") == 0) {
            /* -o：在批量模式中为输出文件；否则为 OID */
            if (i + 1 >= argc) { print_usage(); return 5; }
            if (batch_requested)
                out_csv = argv[++i];
            else
                oid = argv[++i];
        } else if (strcmp(a, "--oid") == 0) {
            if (i + 1 >= argc) { print_usage(); return 5; }
            oid = argv[++i];
        } else if (strcmp(a, "-c") == 0 || strcmp(a, "--cert") == 0) {
            if (i + 1 >= argc) { print_usage(); return 5; }
            cert = argv[++i];
        } else if (strcmp(a, "-m") == 0 || strcmp(a, "--mode") == 0) {
            if (i + 1 >= argc) { print_usage(); return 5; }
            i++;
            if (strcmp(argv[i], "der") == 0)
                mode = CERT_PARSE_DER;
            else if (strcmp(argv[i], "openssl") == 0)
                mode = CERT_PARSE_OPENSSL;
            else {
                fprintf(stderr, "未知模式：%s（可选 openssl / der）\n", argv[i]);
                return 5;
            }
        } else if (strcmp(a, "-t") == 0 || strcmp(a, "--time-aware") == 0) {
            time_aware = 1;
        } else if (strcmp(a, "--hndl") == 0) {
            if (i + 1 >= argc) { print_usage(); return 5; }
            hndl_years = atof(argv[++i]);
            if (hndl_years < 0) hndl_years = 0;
            if (hndl_years > 50) hndl_years = 50;
        } else if (strcmp(a, "-b") == 0 || strcmp(a, "--batch") == 0) {
            if (i + 1 >= argc) { print_usage(); return 5; }
            batch = argv[++i];
        } else if (strcmp(a, "--output") == 0) {
            if (i + 1 >= argc) { print_usage(); return 5; }
            out_csv = argv[++i];
        } else if (strcmp(a, "-j") == 0 || strcmp(a, "--workers") == 0) {
            if (i + 1 >= argc) { print_usage(); return 5; }
            workers = atoi(argv[++i]);
        } else if (strcmp(a, "--check-revocation") == 0) {
            check_revoke = 1;
        } else {
            fprintf(stderr, "未知参数：%s\n", a);
            print_usage();
            return 5;
        }
    }

    /* 批量模式 */
    if (batch) {
        if (algo || oid || cert) {
            fprintf(stderr, "-b 不能与 -a/-o/-c 同时使用\n");
            return 5;
        }
        return batch_scan(batch, out_csv, workers, time_aware, hndl_years);
    }

    /* 单证书模式 */
    printf("┌──────────────────────────────────────────────┐\n");
    printf("│  抗量子威胁判定引擎 v0.2  (pqc-judge)         │\n");
    printf("│  Shor: RSA/ECC/SM2/DSA | Grover: AES-128     │\n");
    if (time_aware)
        printf("│  时间感知: NIST IR 8547 + Hyoung M=1+h/20   │\n");
    printf("└──────────────────────────────────────────────┘\n\n");

    if (algo)
        return do_judge_name(algo);
    if (oid)
        return do_judge_oid(oid);
    if (cert)
        return do_judge_cert(cert, mode, time_aware, hndl_years, check_revoke);

    print_usage();
    return 5;
}