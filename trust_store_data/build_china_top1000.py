#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_china_top1000.py — 构建"中国 Top 1000 网站域名列表"（可复现脚本）

数据源: 站长之家 中文网站总排名 (https://top.chinaz.com/all/)
榜单更新日期(源): 2026-09-13   数据获取日期(UTC): 2026-09-19

用法:
    python3 build_china_top1000.py                 # 重新抓取 chinaz 前 45 页并构建列表
    python3 build_china_top1000.py --offline       # 仅用已缓存页面重建（不抓取）

输出:
    china_top1000_domains.txt   纯域名, 一行一个, 最多 1000 个（去重, www 归一化, eTLD+1）
    china_top1000_ranking.csv   审计用: 源排名, 原始主机名, 规范化域名

依赖: Python >=3.10, tldextract (pip install tldextract)
建议在虚拟环境中运行 (系统 Python 可能受 PEP 668 管理):
    python3 -m venv /tmp/pslvenv && /tmp/pslvenv/bin/pip install tldextract
    /tmp/pslvenv/bin/python build_china_top1000.py [--offline]
"""
import argparse
import glob
import os
import re
import subprocess
import sys
import time
from collections import Counter

import tldextract

BASE_URL = "https://top.chinaz.com/all/index{page}.html"   # page="" 为第 1 页
CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".chinaz_cache")
NUM_PAGES = 45          # 覆盖源排名 1 ~ 1248 条, 归一化后唯一域名 1070 个, 截取前 1000
PER_PAGE = 30
OUT_DIR = os.path.dirname(os.path.abspath(__file__))
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"

ext = tldextract.TLDExtract(cache_dir=os.path.join(OUT_DIR, ".psl_cache"))


def fetch_pages():
    os.makedirs(CACHE_DIR, exist_ok=True)
    for i in range(1, NUM_PAGES + 1):
        page = "" if i == 1 else f"_{i}"
        path = os.path.join(CACHE_DIR, f"page_{i}.html")
        if os.path.exists(path):
            continue
        url = BASE_URL.format(page=page)
        subprocess.run(
            ["curl", "-s", "-o", path, url, "-A", UA,
             "--connect-timeout", "20", "--max-time", "60"],
            check=True)
        time.sleep(0.8)


def norm_host(h):
    """规范化: 小写 -> 剔除 IP -> eTLD+1 (含 www 前缀剥除)。"""
    h = h.strip().lower()
    if not h:
        return None
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", h):
        return None                       # 纯 IP 剔除
    e = ext(h)
    if not e.suffix or not e.domain:
        return None                       # 公共后缀本身/无效条目剔除
    return f"{e.domain}.{e.suffix}"


def parse_pages():
    entries = []                          # (rank, raw_hostname, normalized)
    for path in sorted(glob.glob(os.path.join(CACHE_DIR, "page_*.html")),
                       key=lambda p: int(re.search(r"page_(\d+)", p).group(1))):
        text = open(path, encoding="utf-8", errors="ignore").read()
        for li in re.findall(r'<li class="clearfix.*?</li>', text, re.S):
            mrank = re.search(r'<strong class="col-red02"[^>]*>\s*(\d+)\s*</strong>', li)
            mhost = re.search(r'<span class="col-gray">([^<]+)</span>', li)
            if mrank and mhost:
                entries.append((int(mrank.group(1)),
                                mhost.group(1).strip(),
                                norm_host(mhost.group(1))))
    # 按源排名排序; 去重(同一规范化域名保留最优排名)
    seen = {}
    for rank, host, norm in sorted(entries, key=lambda x: x[0]):
        if norm and norm not in seen:
            seen[norm] = (rank, host)
    return sorted(seen.items(), key=lambda x: x[1][0])   # [(domain, (rank, host)), ...]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true", help="不重新抓取, 仅用缓存页面")
    args = ap.parse_args()

    if not args.offline:
        fetch_pages()
    domains = parse_pages()

    final = domains[:1000]
    with open(os.path.join(OUT_DIR, "china_top1000_domains.txt"), "w") as f:
        for d, _ in final:
            f.write(d + "\n")
    with open(os.path.join(OUT_DIR, "china_top1000_ranking.csv"), "w") as f:
        f.write("rank,hostname,domain\n")
        for d, (r, h) in final:
            f.write(f"{r},{h},{d}\n")

    tlds = Counter(d.split(".", 1)[1] for d, _ in final)
    print(f"唯一规范化域名(候选): {len(domains)}")
    print(f"最终列表: {len(final)} 个域名")
    print("TLD 分布:")
    for t, c in tlds.most_common():
        print(f"  .{t}: {c}")


if __name__ == "__main__":
    main()
