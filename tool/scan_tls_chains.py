#!/usr/bin/env python3
"""
中国 Top N 网站 TLS 证书链扫描器 v0.1
方法：openssl s_client -tls1_2 -showcerts（TLS 1.2 强制，服务器发送完整链）
用途：方向一"中国 TLS 量子就绪度评估"数据采集（Phase 2）
约束：低频、只读握手、单目标并发 ≤8、超时 10s、最多 2 次重试
"""
import subprocess, sys, os, json, re, tempfile, argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

CERT_BEGIN = "-----BEGIN CERTIFICATE-----"

def extract_certs_from_openssl_out(text):
    """从 openssl s_client 输出中提取所有 PEM 证书块"""
    certs = []
    blocks = text.split(CERT_BEGIN)
    for i, block in enumerate(blocks[1:], 1):
        if "-----END CERTIFICATE-----" in block:
            pem = CERT_BEGIN + block.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n"
            certs.append(pem)
    return certs

def scan_one(domain, timeout=10, retries=2, port=443):
    """扫描单个域名的证书链。返回 (domain, status, certs, raw_tail)"""
    for attempt in range(retries + 1):
        try:
            cmd = [
                "openssl", "s_client",
                "-connect", f"{domain}:{port}",
                "-servername", domain,
                "-tls1_2",          # 强制 TLS 1.2：服务器发送完整链（含中间 CA）
                "-showcerts",       # 显示整个链
                "-no_ign_eof",
            ]
            r = subprocess.run(cmd, input=b"", capture_output=True, timeout=timeout)
            text = r.stdout.decode("utf-8", errors="replace")
            err = r.stderr.decode("utf-8", errors="replace")

            certs = extract_certs_from_openssl_out(text)

            # 提取验证结果
            verify = "unknown"
            m = re.search(r"Verification:\s*(.+)", text)
            if m:
                verify = m.group(1).strip()
            elif "Verify return code" in text:
                m2 = re.search(r"Verify return code:\s*(.+)", text)
                verify = m2.group(1).strip() if m2 else "unknown"

            if certs:
                return (domain, "ok", certs, verify)
            elif "errno=111" in err or "Connection refused" in err:
                return (domain, "refused", [], err.strip()[:120])
            elif "timed out" in err or "Operation timed out" in err:
                if attempt < retries:
                    continue
                return (domain, "timeout", [], err.strip()[:120])
            else:
                return (domain, "no_cert", [], (text + err)[-200:])
        except subprocess.TimeoutExpired:
            if attempt < retries:
                continue
            return (domain, "timeout", [], "exceeded 10s")
        except Exception as e:
            return (domain, "error", [], str(e)[:120])
    return (domain, "error", [], "exhausted retries")

def main():
    ap = argparse.ArgumentParser(description="TLS 证书链扫描器")
    ap.add_argument("--list", required=True, help="域名列表文件（一行一个）")
    ap.add_argument("--outdir", default="data/chains", help="输出目录")
    ap.add_argument("--workers", type=int, default=8, help="并发数（默认 8，保持低频）")
    ap.add_argument("--limit", type=int, default=0, help="只扫前 N 个（调试用）")
    args = ap.parse_args()

    with open(args.list) as f:
        domains = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    if args.limit:
        domains = domains[:args.limit]

    os.makedirs(args.outdir, exist_ok=True)
    os.makedirs(os.path.join(args.outdir, "pem"), exist_ok=True)
    os.makedirs(os.path.join(args.outdir, "json"), exist_ok=True)

    summary = {"start": datetime.now().isoformat(), "total": len(domains),
               "ok": 0, "refused": 0, "timeout": 0, "no_cert": 0, "error": 0,
               "targets": []}
    chain_stats = []

    print(f"[*] 开始扫描 {len(domains)} 个域名（并发 {args.workers}），输出到 {args.outdir}")
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(scan_one, d): d for d in domains}
        done = 0
        for fut in as_completed(futures):
            domain, status, certs, verify = fut.result()
            done += 1
            summary[status if status in summary else "error"] += 1
            summary["targets"].append({"domain": domain, "status": status, "verify": verify})

            if status == "ok":
                # 保存 PEM 链
                pem_path = os.path.join(args.outdir, "pem", domain.replace("/", "_") + ".pem")
                with open(pem_path, "w") as f:
                    f.write("".join(certs))
                # 记录链信息
                chain_stats.append({
                    "domain": domain, "chain_length": len(certs),
                    "verify": verify, "pem": pem_path,
                    "cert_subjects": []
                })
                # 提取每个证书的 subject/issuer（轻量：openssl x509 -noout）
                for ci, pem in enumerate(certs):
                    try:
                        r2 = subprocess.run(
                            ["openssl", "x509", "-noout", "-subject", "-issuer", "-dates", "-text"],
                            input=pem, capture_output=True, text=True, timeout=5)
                        out = r2.stdout
                        m_sub = re.search(r"subject=(.+)", out)
                        m_iss = re.search(r"issuer=(.+)", out)
                        m_pka = re.search(r"Public Key Algorithm:\s*(.+)", out)
                        m_sig = re.search(r"Signature Algorithm:\s*(.+)", out)
                        chain_stats[-1]["cert_subjects"].append({
                            "idx": ci, "subject": m_sub.group(1).strip() if m_sub else "?",
                            "issuer": m_iss.group(1).strip() if m_iss else "?",
                            "pk_algo": m_pka.group(1).strip() if m_pka else "?",
                            "sig_algo": m_sig.group(1).strip() if m_sig else "?",
                        })
                    except Exception:
                        chain_stats[-1]["cert_subjects"].append({"idx": ci, "subject": "parse_err"})
            if done % 50 == 0 or done == len(domains):
                print(f"  [{done}/{len(domains)}] ok={summary['ok']} refused={summary['refused']} "
                      f"timeout={summary['timeout']} no_cert={summary['no_cert']} error={summary['error']}")

    summary["end"] = datetime.now().isoformat()
    summary["chain_stats"] = chain_stats

    with open(os.path.join(args.outdir, "summary.json"), "w") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"[✓] 完成。ok={summary['ok']} refused={summary['refused']} "
          f"timeout={summary['timeout']} no_cert={summary['no_cert']} error={summary['error']}")
    print(f"[✓] 摘要: {args.outdir}/summary.json")

if __name__ == "__main__":
    main()
