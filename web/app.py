#!/usr/bin/env python3
"""
证书续费 PQC 升级指南 — Flask Backend

Endpoints:
  GET /              -> serve index.html
  GET /api/scan?domain=xxx  -> scan TLS certificate chain (renewal guide)
  GET /api/trust-store?ca=XXX -> lookup CA info from local trust store
  GET /api/status    -> tool status / data source info

Data sources:
  - trust_store_data/cacert.pem   (Mozilla NSS root store, 121 roots)
  - trust_store_data/ccadb_v5.csv (CCADB V5, ~15k records)
  - trust_store_data/china/       (SM2/GM root certs)
  - built-in CA PQC readiness dict (GlobalSign/DigiCert/Let's Encrypt/CFCA/...)
"""

import subprocess
import re
import os
import json
import csv
import io
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, request, jsonify, send_from_directory

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
TRUST_STORE_DIR = BASE_DIR.parent / "trust_store_data"
CACERT_PEM = TRUST_STORE_DIR / "cacert.pem"
CCADB_CSV = TRUST_STORE_DIR / "ccadb_v5.csv"
CHINA_DIR = TRUST_STORE_DIR / "china"

OPENSSL_TIMEOUT = 10  # seconds

# Chinese CA keywords for issuer matching
CHINA_CA_KEYWORDS = {
    "CFCA": {
        "name": "China Financial Certification Authority (CFCA)",
        "type": "国密/国际双轨",
        "note": "中国CA，国密双轨体系",
    },
    "TrustAsia": {
        "name": "TrustAsia Technologies, Inc.",
        "type": "国际证书",
        "note": "中国CA",
    },
    "BJCA": {
        "name": "Beijing Certificate Authority (BJCA)",
        "type": "国际/政务",
        "note": "中国CA",
    },
    "BEIJING CERTIFICATE AUTHORITY": {
        "name": "Beijing Certificate Authority (BJCA)",
        "type": "国际/政务",
        "note": "中国CA",
    },
    "WoSign": {
        "name": "WoSign CA Limited",
        "type": "国密/国际",
        "note": "中国CA，2017年被Mozilla移除",
    },
    "WoTrus": {
        "name": "WoTrus (沃通)",
        "type": "国密SM2",
        "note": "中国CA，国密双轨体系",
    },
    "CNNIC": {
        "name": "China Internet Network Information Center (CNNIC)",
        "type": "国际（已移除）",
        "note": "中国CA，已被Mozilla移除/MS禁用",
    },
    "iTrusChina": {
        "name": "iTrusChina Co., Ltd.",
        "type": "国际证书",
        "note": "中国CA",
    },
    "vTrus": {
        "name": "iTrusChina / vTrus",
        "type": "国际证书",
        "note": "中国CA",
    },
    "SHECA": {
        "name": "Shanghai Electronic Certification Authority (SHECA/UCA)",
        "type": "国际/政务",
        "note": "中国CA，国密双轨体系",
    },
    "UniTrust": {
        "name": "UniTrust (SHECA)",
        "type": "国际/政务",
        "note": "中国CA",
    },
    "GDCA": {
        "name": "Guangdong Digital Certificate Authority (GDCA)",
        "type": "国密/国际",
        "note": "中国CA",
    },
    "Wangsu": {
        "name": "Wangsu CA",
        "type": "CDN证书",
        "note": "中国CA",
    },
    "Chunghwa Telecom": {
        "name": "Chunghwa Telecom CA",
        "type": "国际证书",
        "note": "中国CA（台湾）",
    },
    "TWCA": {
        "name": "TWCA (Taiwan Certificate Authority)",
        "type": "国际证书",
        "note": "中国CA（台湾）",
    },
    "Hongkong Post": {
        "name": "Hongkong Post CA",
        "type": "国际证书",
        "note": "中国CA（香港）",
    },
    "NRCAC": {
        "name": "国家SM2根 (NRCAC)",
        "type": "国密SM2根",
        "note": "国家SM2根，有效期2012-2042，国密双轨体系",
    },
    "OSCCA": {
        "name": "国家RSA根 (OSCCA)",
        "type": "国密根（已过期）",
        "note": "国家RSA根，已于2025-08-23过期",
    },
}

# CA PQC readiness data (built-in, matched by fuzzy issuer string)
# has_pqc_root: True = already issues PQC certs, False = not yet, None = unknown
CA_PQC_READINESS = {
    "globalsign": {
        "has_pqc_root": True,
        "detail": "GlobalSign 已签发 PQC 混合证书（ML-KEM + RSA）",
    },
    "digicert": {
        "has_pqc_root": True,
        "detail": "DigiCert 已支持 ML-KEM/ML-DSA 证书",
    },
    "lets encrypt": {
        "has_pqc_root": False,
        "detail": "Let's Encrypt 2026年10月 PQC 测试中，暂未正式签发",
    },
    "cfca": {
        "has_pqc_root": False,
        "detail": "CFCA EV ROOT 2029年到期，目前根证书均为 RSA/ECC",
    },
    "trustasia": {
        "has_pqc_root": False,
        "detail": "TrustAsia 暂无 PQC 证书支持信息",
    },
    "wotrus": {
        "has_pqc_root": False,
        "detail": "WoTrus 暂无 PQC 证书支持信息",
    },
    "bjca": {
        "has_pqc_root": None,
        "detail": "BJCA 尚未公开 PQC 证书支持信息",
    },
    "wosign": {
        "has_pqc_root": None,
        "detail": "WoSign 2017年被 Mozilla 移除，PQC 支持情况不明确",
    },
    "sheca": {
        "has_pqc_root": None,
        "detail": "SHECA 尚未公开 PQC 证书支持信息",
    },
    "gdca": {
        "has_pqc_root": None,
        "detail": "GDCA 尚未公开 PQC 证书支持信息",
    },
    "wangsu": {
        "has_pqc_root": None,
        "detail": "Wangsu CA 尚未公开 PQC 证书支持信息",
    },
    "itruschina": {
        "has_pqc_root": None,
        "detail": "iTrusChina 尚未公开 PQC 证书支持信息",
    },
    "vtrus": {
        "has_pqc_root": None,
        "detail": "vTrus 尚未公开 PQC 证书支持信息",
    },
    "cnnic": {
        "has_pqc_root": None,
        "detail": "CNNIC 已被 Mozilla 移除/MS 禁用，PQC 支持情况不明确",
    },
}

# SM2 OID for detection
SM2_CURVE_OIDS = ["1.2.156.10197.1.301", "sm2p256v1"]
SM2_SIG_OIDS = ["1.2.156.10197.1.501", "sm3withsm2"]

app = Flask(__name__, static_folder=str(BASE_DIR), static_url_path="")


# ---------------------------------------------------------------------------
# Trust-store index (lazy-loaded)
# ---------------------------------------------------------------------------
_trust_index = None
_ccadb_china_index = None
_ccadb_total = 0


def _load_trust_index():
    """Build in-memory index of all known CA roots.

    Returns list of dicts.
    """
    global _trust_index
    if _trust_index is not None:
        return _trust_index
    _trust_index = []

    # 1) Parse cacert.pem (Mozilla root store)
    if CACERT_PEM.exists():
        pem_text = CACERT_PEM.read_text()
        blocks = pem_text.split("-----BEGIN CERTIFICATE-----")
        for block in blocks:
            if "-----END CERTIFICATE-----" not in block:
                continue
            pem = ("-----BEGIN CERTIFICATE-----" + block.split("-----END CERTIFICATE-----")[0] +
                   "-----END CERTIFICATE-----").strip()
            info = _parse_cert_pem(pem)
            if info:
                _trust_index.append({
                    "source": "cacert.pem (Mozilla)",
                    "subject": info.get("subject", ""),
                    "issuer": info.get("issuer", ""),
                    "pk_algo": info.get("pk_algo", ""),
                    "key_size": info.get("key_size", 0),
                    "not_after": info.get("not_after", ""),
                    "mozilla_status": "Included",
                    "store_type": "Mozilla",
                })

    # 2) Load CCADB China CA index separately
    _load_ccadb_china()

    # 3) Add CCADB entries to trust index
    for entry in _ccadb_china_index:
        _trust_index.append(entry)

    return _trust_index


def _load_ccadb_china():
    """Parse CCADB CSV for Chinese CA entries.

    Builds _ccadb_china_index and sets _ccadb_total.
    """
    global _ccadb_china_index, _ccadb_total
    if _ccadb_china_index is not None:
        return _ccadb_china_index
    _ccadb_china_index = []
    _ccadb_total = 0

    if not CCADB_CSV.exists():
        return _ccadb_china_index

    try:
        # Read raw lines (CSV has quoted commas, so we use csv module)
        with open(CCADB_CSV, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)

        if len(rows) < 2:
            return _ccadb_china_index

        header = rows[0]
        # Find column indices
        col_map = {}
        for i, col in enumerate(header):
            col_map[col.strip('"')] = i

        def get(row, name, default=""):
            idx = col_map.get(name)
            if idx is not None and idx < len(row):
                return row[idx].strip('"')
            return default

        _ccadb_total = len(rows) - 1

        # China CA owner substrings for filtering
        china_ca_owners = [
            "China Financial",
            "TrustAsia",
            "BEIJING CERTIFICATE",
            "WoSign",
            "WoTrus",
            "CNNIC",
            "iTrusChina",
            "Shanghai Electronic",
            "UniTrust",
            "Chunghwa Telecom",
            "TWCA",
            "Hongkong Post",
            "Wangsu",
            "GDCA",
        ]

        for row in rows[1:]:
            if len(row) < 5:
                continue
            ca_owner = get(row, "CA Owner")
            cert_name = get(row, "Certificate Name")
            record_type = get(row, "Certificate Record Type", "Root Certificate")
            mozilla = get(row, "Mozilla Status", "Not Included")
            chrome = get(row, "Chrome Status", "Not Included")
            ms = get(row, "Microsoft Status", "Not Included")
            valid_to = get(row, "Valid To (GMT)", "")
            sha256 = get(row, "SHA-256 Fingerprint", "")

            # Match Chinese CA owners
            matched_ca = None
            for kw in china_ca_owners:
                if kw.lower() in ca_owner.lower():
                    matched_ca = ca_owner
                    break

            # Also match by keywords
            if not matched_ca:
                for kw in CHINA_CA_KEYWORDS:
                    if kw.lower() in ca_owner.lower():
                        matched_ca = ca_owner
                        break

            if not matched_ca:
                continue

            _ccadb_china_index.append({
                "source": "CCADB V5",
                "subject": f"CN={cert_name}" if cert_name else ca_owner,
                "ca_owner": ca_owner,
                "cert_name": cert_name,
                "record_type": record_type,
                "mozilla_status": mozilla,
                "chrome_status": chrome,
                "ms_status": ms,
                "not_after": valid_to,
                "sha256": sha256,
                "store_type": "CCADB",
            })

    except Exception as e:
        print(f"Warning: CCADB CSV parse error: {e}")

    return _ccadb_china_index


# ---------------------------------------------------------------------------
# Certificate parsing via openssl
# ---------------------------------------------------------------------------

def _run_openssl(args, input_data=None, timeout=5):
    """Run an openssl subcommand and return (stdout, stderr) or raise."""
    r = subprocess.run(
        ["openssl"] + args,
        input=input_data,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if r.returncode != 0:
        raise RuntimeError(f"openssl {' '.join(args)} failed: {r.stderr.strip()}")
    return r.stdout, r.stderr


def _parse_cert_pem(pem_text):
    """Parse a single PEM cert with openssl x509 -text -noout.

    Returns dict with subject, issuer, pk_algo, key_size, sig_algo,
    not_before, not_after, serial, or None.
    """
    try:
        text, _ = _run_openssl(["x509", "-text", "-noout"], input_data=pem_text, timeout=5)
    except Exception:
        return None

    info = {}

    # Subject
    m = re.search(r"Subject:\s*(.+?)(?:\n|$)", text)
    info["subject"] = m.group(1).strip() if m else "?"

    # Issuer
    m = re.search(r"Issuer:\s*(.+?)(?:\n|$)", text)
    info["issuer"] = m.group(1).strip() if m else "?"

    # Validity
    m = re.search(r"Not Before:\s*(.+?)\n", text)
    info["not_before"] = m.group(1).strip() if m else "?"
    m = re.search(r"Not After\s*:\s*(.+?)\n", text)
    info["not_after"] = m.group(1).strip() if m else "?"

    # Serial
    m = re.search(r"Serial Number:\s*(.+?)(?:\n|$)", text)
    info["serial"] = m.group(1).strip() if m else "?"

    # Public key algorithm + size
    m = re.search(r"Public Key Algorithm:\s*(.+?)\n", text)
    raw_algo = m.group(1).strip() if m else "?"
    info["pk_algo_raw"] = raw_algo

    # Look for curve OID in the text (important for SM2 detection)
    curve_oid_match = re.search(r"ASN1 OID:\s*(.+?)(?:\n|$)", text)
    curve_oid = curve_oid_match.group(1).strip() if curve_oid_match else ""

    # Check for SM2 by curve OID or raw algo
    raw_lower = raw_algo.lower()
    is_sm2 = False
    if "sm2" in raw_lower or "1.2.156.10197.1.301" in curve_oid or "sm2p256v1" in curve_oid.lower():
        is_sm2 = True

    # Find key size
    m_rsa = re.search(r"RSA Public-Key:\s*\((\d+) bit\)", text)
    m_pub = re.search(r"(?:pub|EC )?Public-Key:\s*\((\d+) bit\)", text)

    # Normalize algorithm names
    raw_lower = raw_algo.lower()

    if is_sm2:
        info["pk_algo"] = "SM2"
        info["key_size"] = 256  # SM2 is always 256-bit
    elif m_rsa:
        info["pk_algo"] = "RSA"
        info["key_size"] = int(m_rsa.group(1))
    elif m_pub:
        info["key_size"] = int(m_pub.group(1))
        if "rsaencryption" in raw_lower or raw_algo == "RSA":
            info["pk_algo"] = "RSA"
        elif "id-ec" in raw_lower or "ec" in raw_lower:
            info["pk_algo"] = "ECC"
        elif "dsa" in raw_lower:
            info["pk_algo"] = "DSA"
        elif "dh" in raw_lower:
            info["pk_algo"] = "DH"
        else:
            info["pk_algo"] = raw_algo
    elif "rsaencryption" in raw_lower:
        info["pk_algo"] = "RSA"
        info["key_size"] = 0
    elif "id-ec" in raw_lower:
        info["pk_algo"] = "ECC"
        info["key_size"] = 0
    elif "ed25519" in raw_lower:
        info["pk_algo"] = "Ed25519"
        info["key_size"] = 256
    elif "ed448" in raw_lower:
        info["pk_algo"] = "Ed448"
        info["key_size"] = 448
    elif "x25519" in raw_lower:
        info["pk_algo"] = "X25519"
        info["key_size"] = 256
    elif "x448" in raw_lower:
        info["pk_algo"] = "X448"
        info["key_size"] = 448
    else:
        info["pk_algo"] = raw_algo
        info["key_size"] = 0

    # Signature algorithm
    m = re.search(r"Signature Algorithm:\s*(.+?)\n", text)
    info["sig_algo"] = m.group(1).strip() if m else "?"

    # Detect SM3withSM2 signature
    sig_lower = info["sig_algo"].lower()
    if "sm3" in sig_lower or "1.2.156.10197.1.501" in sig_lower:
        if info["pk_algo"] not in ("SM2",):
            info["pk_algo"] = "SM2"
        info["sig_algo"] = "SM3withSM2"

    return info


def _parse_time(date_str):
    """Parse cert date string -> datetime or None."""
    cleaned = date_str.replace("GMT", "UTC")
    for fmt in [
        "%b %d %H:%M:%S %Y %Z",
        "%b %d %H:%M:%S %Y",
        "%Y-%m-%d",
    ]:
        try:
            dt = datetime.strptime(cleaned, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    # Try ISO format
    try:
        dt = datetime.fromisoformat(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        pass
    return None


# ---------------------------------------------------------------------------
# Threat & NIST analysis
# ---------------------------------------------------------------------------

def _threat_level(pk_algo, key_size):
    """Classify quantum threat.

    Returns one of: THREAT_NONE, THREAT_GROVER, THREAT_SHOR, THREAT_CRITICAL
    """
    algo = pk_algo.upper()
    # PQC / post-quantum safe
    if algo in ("DILITHIUM", "FALCON", "SPHINCS+", "KYBER", "ML-KEM", "ML-DSA", "SLH-DSA", "BIKE", "HQC", "MAYO", "SNOVA", "MQDSS", "RAINBOW"):
        return "THREAT_NONE"
    # Grover's-affected (symmetric-equivalent strength, but smaller margin)
    if algo in ("ED25519", "ED448", "X25519", "X448"):
        return "THREAT_GROVER"
    # Shor's-affected (all factoring & discrete-log based)
    if algo in ("RSA", "ECC", "ECDSA", "ECDH", "DSA", "DH", "SM2"):
        if algo == "RSA" and key_size < 2048:
            return "THREAT_CRITICAL"
        if algo == "RSA" and key_size < 4096:
            return "THREAT_SHOR"
        return "THREAT_SHOR"
    # Default: conservative
    return "THREAT_SHOR"


def _nist_phase(not_after_str):
    """Map certificate expiry year to NIST IR 8547 timeline.

    PRE2030      - expires before 2031 (≤2030, natural rotation)
    DURING2030   - expires between 2030 and 2035 inclusive (transition window)
    POST2035     - expires after 2035 (must actively migrate, high risk)
    UNKNOWN      - could not parse date
    """
    dt = _parse_time(not_after_str)
    if dt is None:
        return "UNKNOWN"
    year = dt.year
    if year <= 2030:
        return "PRE2030"
    elif year <= 2035:
        return "DURING2030"
    else:
        return "POST2035"


def _threat_label(threat):
    labels = {
        "THREAT_NONE": "安全 (PQC)",
        "THREAT_GROVER": "中等风险 (Grover)",
        "THREAT_SHOR": "高风险 (Shor)",
        "THREAT_CRITICAL": "极危",
    }
    return labels.get(threat, threat)


def _nist_label(phase):
    labels = {
        "PRE2030": "2030前 (自然轮换)",
        "DURING2030": "2030-2035 (过渡期)",
        "POST2035": "2035后 (需主动迁移)",
        "UNKNOWN": "未知",
    }
    return labels.get(phase, phase)


# ---------------------------------------------------------------------------
# Renewal guide helpers (cert overview / CA PQC readiness / renewal advice)
# ---------------------------------------------------------------------------

def _format_remaining(not_after_str):
    """Format time until expiry as 'X 年 Y 月' (Chinese). Returns str or None."""
    dt = _parse_time(not_after_str)
    if dt is None:
        return None
    now = datetime.now(timezone.utc)
    if dt <= now:
        return "已过期"

    total_months = (dt.year - now.year) * 12 + (dt.month - now.month)
    if dt.day < now.day:
        total_months -= 1

    years = total_months // 12
    months = total_months % 12

    parts = []
    if years > 0:
        parts.append(f"{years} 年")
    if months > 0:
        parts.append(f"{months} 月")
    if not parts:
        parts.append("不足 1 个月")
    return " ".join(parts)


def _extract_ca_short_name(issuer_str):
    """Extract a short CA name from an issuer DN (e.g. 'GlobalSign nv-sa')."""
    if not issuer_str:
        return "未知 CA"
    # Prefer O= (organization), fall back to CN=
    m = re.search(r'(?<![A-Za-z])O\s*=\s*([^,]+)', issuer_str)
    if m:
        name = m.group(1).strip().strip('"').strip()
        if name:
            return name
    m = re.search(r'(?<![A-Za-z])CN\s*=\s*([^,]+)', issuer_str)
    if m:
        name = m.group(1).strip().strip('"').strip()
        if name:
            return name
    return issuer_str[:60]


def _lookup_ca_pqc(issuer_str):
    """Fuzzy-match issuer against the built-in CA PQC readiness dict.

    First tries the extracted CA short name against dict keys.
    Falls back to matching CHINA_CA_KEYWORDS entries against the raw issuer string.
    Returns (ca_name, dict) where dict has has_pqc_root/detail.
    Unknown CAs return has_pqc_root=None.
    """
    ca_name = _extract_ca_short_name(issuer_str)
    ca_lower = ca_name.lower().replace("'", "").replace(" ", "")

    # Pass 1: match extracted name against dict keys (case/space/apostrophe tolerant)
    best = None
    best_key = None
    for key, info in CA_PQC_READINESS.items():
        key_normal = key.lower().replace("'", "").replace(" ", "")
        if key_normal in ca_lower or ca_lower in key_normal:
            if best_key is None or len(key) > len(best_key):
                best = info
                best_key = key

    # Pass 2: for Chinese CAs, try keyword fallback via CHINA_CA_KEYWORDS
    if best is None:
        issuer_lower = issuer_str.lower().replace("'", "").replace(" ", "")
        for kw in CHINA_CA_KEYWORDS:
            kw_normal = kw.lower().replace("'", "").replace(" ", "")
            if kw_normal in issuer_lower:
                for key, info in CA_PQC_READINESS.items():
                    key_normal = key.lower().replace("'", "").replace(" ", "")
                    if kw_normal == key_normal or kw_normal in key_normal or key_normal in kw_normal:
                        best = info
                        best_key = key
                        break
            if best:
                break

    if best is not None:
        return ca_name, dict(best)
    return ca_name, {"has_pqc_root": None, "detail": f"{ca_name} 的 PQC 支持情况未知，建议直接咨询 CA"}


def _compute_years_remaining(not_after_str):
    """Fractional years until expiry (floored at 0), or None."""
    dt = _parse_time(not_after_str)
    if dt is None:
        return None
    now = datetime.now(timezone.utc)
    return max(0.0, (dt - now).total_seconds() / (365.25 * 24 * 3600))


def _compute_cert_overview(leaf_cert):
    """Build cert_overview from the leaf certificate info."""
    algo = leaf_cert.get("pk_algo", "?")
    key_size = leaf_cert.get("key_size", 0)
    algo_str = f"{algo}-{key_size}" if key_size > 0 else algo

    issuer_str = leaf_cert.get("issuer", "")
    issuer_short = _extract_ca_short_name(issuer_str)

    not_after = leaf_cert.get("not_after", "?")
    not_after_dt = _parse_time(not_after)
    if not_after_dt:
        expiry_year = not_after_dt.year
        expiry_date = not_after_dt.strftime("%Y-%m-%d")
        if expiry_year <= 2030:
            nist_label = "2030前（自然轮换）"
            nist_color = "green"
        elif expiry_year <= 2035:
            nist_label = "2030-2035（过渡期）"
            nist_color = "orange"
        else:
            nist_label = "2035后（需主动迁移）"
            nist_color = "red"
    else:
        expiry_year = None
        expiry_date = not_after
        nist_label = "未知"
        nist_color = "grey"

    return {
        "algo": algo_str,
        "issuer": issuer_short,
        "not_after": expiry_date,
        "years_remaining": _compute_years_remaining(not_after),
        "remaining_display": _format_remaining(not_after),
        "expiry_year": expiry_year,
        "nist_label": nist_label,
        "nist_color": nist_color,
    }


def _compute_ca_pqc_readiness(leaf_cert, ca_store_match):
    """Build ca_pqc_readiness from leaf issuer + trust-store match."""
    issuer_str = leaf_cert.get("issuer", "")
    ca_name, pqc_info = _lookup_ca_pqc(issuer_str)

    china_detail = _get_china_ca_detail(issuer_str)
    is_china_ca = china_detail is not None

    moz_status = "Unknown"
    chrome_status = "Unknown"
    ms_status = "Unknown"
    if ca_store_match and ca_store_match.get("matched"):
        moz_status = ca_store_match.get("mozilla_status", "Unknown")
        chrome_status = ca_store_match.get("chrome_status", "Unknown")
        ms_status = ca_store_match.get("ms_status", "Unknown")

    return {
        "ca_name": ca_name,
        "has_pqc_root": pqc_info["has_pqc_root"],
        "pqc_detail": pqc_info["detail"],
        "is_china_ca": is_china_ca,
        "china_detail": china_detail.get("note") if china_detail else None,
        "moz_status": moz_status,
        "chrome_status": chrome_status,
        "ms_status": ms_status,
    }


def _compute_renewal_advice(cert_overview, ca_pqc_readiness, overall_nist):
    """Build renewal_advice from cert expiry + CA PQC readiness."""
    ca_name = ca_pqc_readiness.get("ca_name", "你的 CA")
    expiry_year = cert_overview.get("expiry_year")
    remaining_display = cert_overview.get("remaining_display")
    has_pqc = ca_pqc_readiness.get("has_pqc_root")
    is_china_ca = ca_pqc_readiness.get("is_china_ca", False)

    if expiry_year is None:
        return {
            "urgency": "unknown",
            "summary": "无法确定证书到期时间",
            "items": ["请手动检查证书到期日期，并与 CA 确认 PQC 支持情况"],
        }

    items = []
    if overall_nist == "PRE2030":
        urgency = "low"
        summary = "自然轮换即可"
        nist_line = "2030前到期 → 自然轮换即可"
        items.append(f"下次续费时向 {ca_name} 要求 PQC 混合证书")
        items.append("确认服务器中间件兼容 PQC 证书")
        if has_pqc is True:
            items.append(f"✅ {ca_name} 已支持 PQC，无需更换 CA")
        elif has_pqc is False:
            items.append(f"⚠️ {ca_name} 目前尚不支持 PQC 证书，请关注其路线图")
        else:
            items.append(f"ℹ️ {ca_name} 的 PQC 支持情况需进一步确认")
    elif overall_nist == "DURING2030":
        urgency = "medium"
        summary = "过渡期内需规划迁移"
        nist_line = "2030-2035 到期 → 过渡期需规划迁移"
        items.append(f"联系 {ca_name} 确认其 PQC 证书支持时间表")
        items.append("评估服务器和中间件对 PQC 证书的兼容性")
        items.append("考虑混合证书（RSA + ML-KEM）作为过渡方案")
        if has_pqc is True:
            items.append(f"✅ {ca_name} 已支持 PQC，本次续费即可升级")
        elif has_pqc is False:
            items.append(f"⚠️ {ca_name} 尚未支持 PQC，可能需要评估更换 CA")
        else:
            items.append(f"ℹ️ 向 {ca_name} 咨询 PQC 路线图")
    else:  # POST2035
        urgency = "high"
        summary = "跨越 NIST 2035 截止线 → 不会自然轮换"
        nist_line = "跨越 NIST 2035 截止线 → 不会自然轮换"
        items.append("⚠️ 立即联系你的 CA 规划提前迁移至 PQC 证书")
        items.append("评估中间件对 PQC 证书的兼容性")
        items.append("考虑混合证书（RSA + ML-KEM）作为过渡方案")
        items.append("参考 NIST IR 8547 时间线制定迁移计划")

    if is_china_ca:
        items.append("关注 GM/T 0126-2024 国密 PQC 标准进展（等保/关基合规）")

    return {
        "urgency": urgency,
        "summary": summary,
        "nist_line": nist_line,
        "items": items,
        "expiry_year": expiry_year,
        "remaining_display": remaining_display,
    }


# ---------------------------------------------------------------------------
# CA matching in trust store
# ---------------------------------------------------------------------------

def _match_ca_in_store(issuer_str):
    """Match certificate issuer against local trust-store index.

    Returns dict with matched CA info, or None.
    Strategy:
      1) Try CN= or O= fields from issuer against known CA owner names
      2) Try subject substring match against Mozilla root store
      3) Keyword match against known Chinese CAs
    """
    issuer_lower = issuer_str.lower()
    index = _load_trust_index()

    # Extract CN and O components from issuer DN
    def _extract_dn_components(dn):
        """Extract CN= and O= values from a DN string."""
        parts = {}
        for match in re.finditer(r'(?<![A-Za-z])([A-Za-z]+)\s*=\s*("(?:\\.|[^"\\])*"|(?:,(?! )|(?!,))[^,]+)', dn):
            key = match.group(1).upper()
            val = match.group(2).strip().strip('"').strip()
            if key in ('CN', 'O', 'OU'):
                parts[key] = val
        # Also try simpler split
        if not parts:
            for piece in dn.split(','):
                piece = piece.strip()
                if '=' in piece:
                    k, v = piece.split('=', 1)
                    k, v = k.strip().upper(), v.strip().strip('"')
                    if k in ('CN', 'O', 'OU'):
                        parts[k] = v
        return parts

    issuer_parts = _extract_dn_components(issuer_str)
    issuer_cn = issuer_parts.get('CN', '').lower()
    issuer_o = issuer_parts.get('O', '').lower()

    # Pass 1: Match by CN/O against known Mozilla root subjects
    # This is the most reliable - match issuer cert's subject against our root store
    for entry in index:
        if entry.get("store_type") != "Mozilla":
            continue
        sub = entry.get("subject", "")
        sub_parts = _extract_dn_components(sub)
        sub_cn = sub_parts.get('CN', '').lower()
        sub_o = sub_parts.get('O', '').lower()

        # Try CN match (CN is usually unique)
        if sub_cn and sub_cn == issuer_cn:
            ca_detail = _get_china_ca_detail(sub)
            return {
                "matched": True,
                "source": entry.get("source", ""),
                "subject": entry.get("subject", ""),
                "ca_owner": sub_o or sub_cn,
                "in_mozilla": True,
                "mozilla_status": "Included",
                "not_after": entry.get("not_after", ""),
                "is_china_ca": ca_detail is not None,
                "china_ca_detail": ca_detail,
            }

    # Pass 2: Try CCADB China entries - match by cert_name (CN) or ca_owner (O)
    for entry in _ccadb_china_index:
        owner = entry.get("ca_owner", "").lower()
        cert_name = entry.get("cert_name", "").lower()

        # Match by cert_name / subject CN
        if cert_name and (cert_name == issuer_cn or issuer_cn in cert_name or cert_name in issuer_cn):
            ca_detail = _get_china_ca_detail(entry.get("ca_owner", ""))
            return {
                "matched": True,
                "source": entry.get("source", ""),
                "ca_owner": entry.get("ca_owner", ""),
                "cert_name": entry.get("cert_name", ""),
                "record_type": entry.get("record_type", ""),
                "in_mozilla": entry.get("mozilla_status", "") == "Included",
                "mozilla_status": entry.get("mozilla_status", ""),
                "chrome_status": entry.get("chrome_status", ""),
                "ms_status": entry.get("ms_status", ""),
                "not_after": entry.get("not_after", ""),
                "is_china_ca": True,
                "china_ca_detail": ca_detail,
            }

        # Match by ca_owner against O field (require significant overlap)
        if owner and issuer_o:
            # Check if the owner name contains words that appear in issuer O
            owner_words = set(w for w in owner.replace('(', ' ').replace(')', ' ').replace(',', ' ').split() if len(w) > 4)
            issuer_words = set(w for w in issuer_o.replace('(', ' ').replace(')', ' ').replace(',', ' ').split() if len(w) > 4)
            if owner_words and issuer_words and owner_words & issuer_words:
                ca_detail = _get_china_ca_detail(entry.get("ca_owner", ""))
                return {
                    "matched": True,
                    "source": entry.get("source", ""),
                    "ca_owner": entry.get("ca_owner", ""),
                    "cert_name": entry.get("cert_name", ""),
                    "record_type": entry.get("record_type", ""),
                    "in_mozilla": entry.get("mozilla_status", "") == "Included",
                    "mozilla_status": entry.get("mozilla_status", ""),
                    "chrome_status": entry.get("chrome_status", ""),
                    "ms_status": entry.get("ms_status", ""),
                    "not_after": entry.get("not_after", ""),
                    "is_china_ca": True,
                    "china_ca_detail": ca_detail,
                }

    # Pass 3: keyword match against known Chinese CAs
    # Use word-boundary matching to avoid false positives (e.g. "CA" matching "Root CA")
    for keyword, meta in CHINA_CA_KEYWORDS.items():
        if len(keyword) <= 2:
            # Skip single/double-character keywords to avoid false matches
            continue
        pattern = re.compile(re.escape(keyword.lower()), re.IGNORECASE)
        if pattern.search(issuer_str) and keyword.lower() not in ("ca",):
            return {
                "matched": True,
                "source": "keyword_match",
                "ca_owner": meta["name"],
                "ca_type": meta["type"],
                "in_mozilla": "Check Mozilla store (not in local index)",
                "note": meta["note"],
                "is_china_ca": True,
                "china_ca_detail": meta,
            }

    return None


def _get_china_ca_detail(text):
    """Check if a text string matches any known China CA keyword."""
    text_lower = text.lower()
    for keyword, meta in CHINA_CA_KEYWORDS.items():
        if keyword.lower() in text_lower:
            return meta
    return None


# ---------------------------------------------------------------------------
# Main scan logic
# ---------------------------------------------------------------------------

def _scan_domain(domain):
    """Scan a domain's TLS certificate chain via openssl s_client.

    Returns dict with status, chain, chain_length, overall_threat, overall_nist,
    advice, and ca_info (if matched).
    """
    cmd = [
        "openssl", "s_client", "-showcerts", "-servername", domain,
        "-connect", f"{domain}:443",
    ]
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=OPENSSL_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": f"连接超时（{OPENSSL_TIMEOUT}s）"}
    except FileNotFoundError:
        return {"status": "error", "error": "未找到 openssl，请先安装 OpenSSL"}

    output = r.stdout + r.stderr

    # Connection error detection
    if "connect: Connection refused" in output:
        return {"status": "error", "error": "连接被拒，该域名可能不支持 HTTPS"}
    if "connect: Connection timed out" in output or "timed out" in output.lower():
        return {"status": "error", "error": "连接超时"}
    if "no peer certificate available" in output:
        return {"status": "error", "error": "未获取到对端证书（可能非 TLS 服务）"}
    if r.returncode != 0 and "BEGIN CERTIFICATE" not in output:
        return {"status": "error", "error": f"SSL 握手失败: {r.stderr.strip()[:200]}"}

    # Extract PEM certificates
    cert_pems = []
    parts = output.split("-----BEGIN CERTIFICATE-----")
    for part in parts[1:]:
        if "-----END CERTIFICATE-----" in part:
            pem = ("-----BEGIN CERTIFICATE-----" + part.split("-----END CERTIFICATE-----")[0] +
                   "-----END CERTIFICATE-----").strip()
            cert_pems.append(pem)

    if not cert_pems:
        return {"status": "error", "error": "未找到任何证书，请检查域名是否正确"}

    # Parse each certificate
    chain = []
    for idx, pem in enumerate(cert_pems):
        info = _parse_cert_pem(pem)
        if not info:
            continue

        threat = _threat_level(info.get("pk_algo", ""), info.get("key_size", 0))
        nist_phase = _nist_phase(info.get("not_after", ""))

        entry = {
            "index": idx,
            "subject": info.get("subject", "?"),
            "issuer": info.get("issuer", "?"),
            "pk_algo": info.get("pk_algo", "?"),
            "key_size": info.get("key_size", 0),
            "sig_algo": info.get("sig_algo", "?"),
            "serial": info.get("serial", "?"),
            "not_before": info.get("not_before", "?"),
            "not_after": info.get("not_after", "?"),
            "threat": threat,
            "threat_label": _threat_label(threat),
            "nist_phase": nist_phase,
            "nist_label": _nist_label(nist_phase),
        }

        # Try to match issuer with local trust store
        issuer_match = _match_ca_in_store(info.get("issuer", ""))
        if issuer_match:
            entry["ca_info"] = issuer_match

        chain.append(entry)

    if not chain:
        return {"status": "error", "error": "无法解析证书链"}

    # Overall assessment
    threats = [c["threat"] for c in chain]
    phases = [c["nist_phase"] for c in chain]

    threat_priority = ["THREAT_CRITICAL", "THREAT_SHOR", "THREAT_GROVER", "THREAT_NONE"]
    overall_threat = next((t for t in threat_priority if t in threats), "THREAT_NONE")

    phase_priority = ["POST2035", "DURING2030", "PRE2030", "UNKNOWN"]
    overall_nist = next((p for p in phase_priority if p in phases), "UNKNOWN")

    # Migration advice
    advice = _generate_advice(chain, overall_threat, overall_nist)

    # ---- Renewal guide fields (new) ----
    leaf = chain[0] if chain else {}

    # 1) Cert overview (simplified one-liner)
    cert_overview = _compute_cert_overview(leaf)

    # 2) CA PQC readiness (built-in dict + trust-store status)
    ca_store_match = leaf.get("ca_info")
    ca_pqc_readiness = _compute_ca_pqc_readiness(leaf, ca_store_match)

    # 3) Renewal advice (based on leaf cert expiry year — the cert you'd renew)
    leaf_nist = _nist_phase(leaf.get("not_after", "")) if leaf else overall_nist
    renewal_advice = _compute_renewal_advice(cert_overview, ca_pqc_readiness, leaf_nist)

    return {
        "status": "ok",
        "domain": domain,
        "cert_overview": cert_overview,
        "ca_pqc_readiness": ca_pqc_readiness,
        "renewal_advice": renewal_advice,
        "chain": chain,
        "chain_length": len(chain),
        "overall_threat": overall_threat,
        "overall_threat_label": _threat_label(overall_threat),
        "overall_nist": overall_nist,
        "overall_nist_label": _nist_label(overall_nist),
        "advice": advice,
    }


def _generate_advice(chain, overall_threat, overall_nist):
    """Generate human-readable migration advice list."""
    advices = []

    # Threat-based advice
    if overall_threat == "THREAT_NONE":
        advices.append("✅ 证书链已使用 PQC 算法，当前抗量子。")
    elif overall_threat == "THREAT_GROVER":
        advices.append("⚠️ 证书链使用 Grover-脆弱算法（如 Ed25519），建议关注 PQC 迁移进展。")
    elif overall_threat == "THREAT_SHOR":
        advices.append("❌ 证书链使用 RSA 或 ECC 算法，Shor 算法可在量子计算机上破解。")
        advices.append("   - 建议联系 CA 申请 PQC 混合证书（如含 ML-KEM/Dilithium 的证书）。")
        advices.append("   - 关注 NIST PQC 标准化进展和 CA 支持情况。")
    else:
        advices.append("⚠️ 存在极危威胁（如 RSA < 2048bit），请立即评估！")

    # NIST phase advice
    if overall_nist == "POST2035":
        advices.append("⏰ 证书到期日在 2035 年之后，超过了 NIST 建议的 PQC 迁移截止线。")
        advices.append("   - 建议在 2035 年前主动更换为 PQC 证书。")
        advices.append("   - 当前可在混合模式下部署（传统 + PQC 双证书）。")
    elif overall_nist == "DURING2030":
        advices.append("📅 证书到期日在 2030-2035 过渡期，处于 NIST 建议的迁移窗口。")
        advices.append("   - 建议在本次证书更新时考虑 PQC 混合方案。")
    elif overall_nist == "PRE2030":
        advices.append("✅ 证书在 2030 年前到期，将自然轮换。下次更新时可选择 PQC 证书。")

    # Per-certificate advice
    for cert in chain:
        idx = cert['index'] + 1
        if cert["pk_algo"] == "RSA" and cert.get("key_size", 0) < 2048:
            advices.append(f"⚠️ 证书 #{idx} RSA 密钥长度 {cert['key_size']} 偏小，建议立即升级。")
        elif cert["pk_algo"] == "RSA" and cert.get("key_size", 0) < 4096:
            advices.append(f"ℹ️ 证书 #{idx} RSA 密钥长度 {cert['key_size']}，建议未来迁移至 4096+ 或 PQC。")
        if cert["pk_algo"] == "ECC" and cert.get("key_size", 0) < 256:
            advices.append(f"⚠️ 证书 #{idx} ECC 密钥长度 {cert['key_size']} 偏小。")
        if cert["pk_algo"] == "SM2":
            advices.append(f"ℹ️ 证书 #{idx} 使用国密 SM2 算法。SM2 同样受 Shor 算法威胁，请关注国密 PQC 进展。")

        # NIST-specific per-cert advice
        if cert["nist_phase"] == "POST2035" and cert["threat"] in ("THREAT_SHOR", "THREAT_CRITICAL"):
            nist_year = _parse_time(cert["not_after"])
            if nist_year:
                advices.append(f"⚠️ 证书 #{idx} 到期于 {nist_year.year} 年，跨越 NIST 2035 截止线且使用量子脆弱算法。")

    return advices


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(str(BASE_DIR), "index.html")


@app.route("/api/status")
def api_status():
    """Tool status and data source info."""
    # Check openssl
    try:
        openssl_v = subprocess.run(["openssl", "version"], capture_output=True, text=True, timeout=3).stdout.strip()
        openssl_ok = True
    except Exception:
        openssl_v = ""
        openssl_ok = False

    # Load indices for counts
    trust_idx = _load_trust_index()
    moz_roots = sum(1 for e in trust_idx if e.get("store_type") == "Mozilla")
    ccadb_records = _ccadb_total
    china_ccadb = len(_ccadb_china_index)

    return jsonify({
        "status": "ok",
        "tool": "证书续费 PQC 升级指南",
        "version": "1.0.0",
        "openssl_available": openssl_ok,
        "openssl_version": openssl_v,
        "data_sources": {
            "moz_roots": moz_roots,
            "ccadb_records": ccadb_records,
            "china_ca_ccadb": china_ccadb,
        },
        "nist_milestones": {
            "high_priority": "2030",
            "remove_classic": "2035",
        },
    })


@app.route("/api/trust-store")
def api_trust_store():
    """Search CA in trust store by keyword."""
    ca_query = request.args.get("ca", "").strip()
    if not ca_query:
        return jsonify({"status": "error", "error": "缺少 ca 参数"})

    index = _load_trust_index()
    results = []
    q = ca_query.lower()
    seen = set()
    for entry in index:
        subj = entry.get("subject", "").lower()
        owner = entry.get("ca_owner", "").lower()
        cert_name = entry.get("cert_name", "").lower()
        if q in subj or q in owner or q in cert_name:
            key = (subj, owner)
            if key not in seen:
                seen.add(key)
                results.append(entry)

    return jsonify({
        "status": "ok",
        "query": ca_query,
        "count": len(results),
        "results": results[:50],  # limit output
    })


@app.route("/api/scan")
def api_scan():
    """Scan a domain's TLS certificate chain."""
    domain = request.args.get("domain", "").strip().lower()
    if not domain:
        return jsonify({"status": "error", "error": "缺少 domain 参数"})

    # Basic domain validation
    domain_re = re.compile(r"^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$")
    if not domain_re.match(domain):
        return jsonify({"status": "error", "error": "域名格式不正确"})

    result = _scan_domain(domain)
    return jsonify(result)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Warm up data sources on startup
    try:
        openssl_ver = subprocess.run(["openssl", "version"], capture_output=True, text=True, timeout=3).stdout.strip()
    except Exception:
        openssl_ver = "N/A"

    trust_idx = _load_trust_index()
    moz_roots = sum(1 for e in trust_idx if e.get("store_type") == "Mozilla")
    china_ccadb = len(_ccadb_china_index)

    print(f"🚀 证书续费 PQC 升级指南 - 后端启动")
    print(f"   OpenSSL: {openssl_ver}")
    print(f"   Mozilla 根证书: {moz_roots}")
    print(f"   CCADB 记录: {_ccadb_total}")
    print(f"   CCADB 中国 CA: {china_ccadb}")
    print(f"   总信任库条目: {len(trust_idx)}")
    print(f"   访问地址: http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)