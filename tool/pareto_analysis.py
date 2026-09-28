#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pareto_analysis.py — 哈希签名参数选择 Pareto 前沿分析（参数表 v3 标注生成）

数据源: research/哈希签名参数选择参照表.xlsx（sheet「实测数据总览」22 行实测 + 各家族参数 sheet）
输出  :
  1) research/pareto_frontier.csv      — 每行参数集的 Pareto 标注（族内 / 跨族）
  2) research/pareto_plot_data.csv     — 供用户在 Excel 中画 XY 散点图的数据
  3) stdout                            — 文字分析报告（前沿参数集、被支配说明、数据质量）

度量归一化约定（重要）:
  - SPHINCS+ 时间单位 ms，直接使用
  - LMS/HSS  KeyGen 为 s -> 乘以 1000 得 ms；Sign/Verify 已是 ms
  - XMSS     KeyGen 为 s -> 乘以 1000 得 ms；Sign/Verify 为 cycles
             -> 按 CPU 标称主频 3.8 GHz 换算: 1 cycle = 1/3.8e9 s = 2.6316e-4 ms
             实际运行频率可能高于标称（睿频），换算的 ms 为保守上限估计，跨族对比结论对该假设不敏感
  - 签名大小统一为字节 B

Pareto 定义（所有目标越小越优）:
  点 p 支配点 q <=> p 在所有目标上不差于 q 且至少一个目标严格优于 q。
  前沿 = 集合中不被任何其它点支配的点。

用法: /tmp/xlsxenv/bin/python3 tool/pareto_analysis.py
依赖: openpyxl（仅此一个第三方依赖）
"""

import csv
import re
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
XLSX_PATH = BASE_DIR / "research" / "哈希签名参数选择参照表.xlsx"
OUT_CSV = BASE_DIR / "research" / "pareto_frontier.csv"
PLOT_CSV = BASE_DIR / "research" / "pareto_plot_data.csv"

# 测试环境 CPU（见 xlsx「实测数据总览」顶部说明）
CPU_HZ = 3.8e9          # AMD Ryzen 7 7840HS 标称主频 3.8 GHz
CYCLES_TO_MS = 1000.0 / CPU_HZ   # 1 cycle -> ms

OVERVIEW_SHEET = "实测数据总览"
FAMILY_SHEETS = {
    "SPHINCS+": "SLH-DSA参数集(FIPS205)",
    "LMS/HSS": "LMS-HSS参数集(RFC8554)",
    "XMSS": "XMSS参数集(RFC8391)",
}

# ---------------------------------------------------------------- 数值解析

_NUM_RE = re.compile(r"^\s*([\d.,]+(?:[eE][+-]?\d+)?)\s*([A-Za-z%]*)\.?\s*$")


def parse_value(text):
    """把 '17,088 B' / '1,238 ms' / '5.42e6 cycles' / '0.03 s' 解析为 (float, unit)。"""
    if text is None:
        return None, None
    text = str(text).strip().replace("\u2009", " ").replace("\xa0", " ")
    m = _NUM_RE.match(text)
    if not m:
        return None, None
    num_str = m.group(1).replace(",", "")
    try:
        num = float(num_str)
    except ValueError:
        return None, None
    unit = (m.group(2) or "").lower()
    return num, unit


def to_ms(number, unit):
    """统一换算到毫秒。unit: ms / s / cycles(cyc)。B 等非时间单位返回 None。"""
    if number is None:
        return None
    if unit in ("ms", "msec", "millisecond"):
        return number
    if unit in ("s", "sec", "second"):
        return number * 1000.0
    if unit in ("cycles", "cycle", "cyc", "c"):
        return number * CYCLES_TO_MS
    return None


# ---------------------------------------------------------------- 数据装载

def load_overview_rows(wb):
    """读取「实测数据总览」，返回 row dict 列表。"""
    ws = wb[OVERVIEW_SHEET]
    header = None
    rows = []
    for row in ws.iter_rows(values_only=True):
        if row[0] is None:
            continue
        if row[0].strip() == "参数集":
            header = [str(c).strip() if c is not None else "" for c in row]
            continue
        if header is None:
            continue
        d = dict(zip(header, row))
        if not d.get("参数集"):
            continue
        rows.append(d)
    return rows


def load_slhdsa_params(wb):
    """SPHINCS+ 参数 sheet -> {参数集名称: {n,h,d,a,k,lgw,m,sec}}。"""
    ws = wb[FAMILY_SHEETS["SPHINCS+"]]
    header = None
    out = {}
    for row in ws.iter_rows(values_only=True):
        if row[0] is None:
            continue
        if str(row[0]).strip() == "参数集名称":
            header = [str(c).strip() if c is not None else "" for c in row]
            continue
        if header is None:
            continue
        d = dict(zip(header, row))
        name = str(d.get("参数集名称", "")).strip()
        if not name or name.startswith("参数"):
            continue
        out[name] = {
            "n_bytes": _int_or(d.get("n(字节)")),
            "h": _int_or(d.get("h(树高)")),
            "d": _int_or(d.get("d(层数)")),
            "a": _int_or(d.get("a(FORS)")),
            "k": _int_or(d.get("k(FORS)")),
            "lgw": _int_or(d.get("lgw(WOTS+基)")),
            "m": _int_or(d.get("m(字节)")),
            "sec_category": str(d.get("安全类别", "") or ""),
        }
    return out


def load_xmss_params(wb):
    """XMSS 参数 sheet -> {名称: {n,w,len,h,d}}。"""
    ws = wb[FAMILY_SHEETS["XMSS"]]
    header = None
    out = {}
    for row in ws.iter_rows(values_only=True):
        if row[0] is None:
            continue
        if str(row[0]).strip() == "参数集名称":
            header = [str(c).strip() if c is not None else "" for c in row]
            continue
        if header is None:
            continue
        d = dict(zip(header, row))
        name = str(d.get("参数集名称", "")).strip()
        if not name or name.startswith("参数"):
            continue
        out[name] = {
            "n_bytes": _int_or(d.get("n(字节)")),
            "w": _int_or(d.get("w(WOTS+基)")),
            "len": _int_or(d.get("len")),
            "h": _int_or(d.get("h(总树高)")),
            "d": _int_or(d.get("d(层数)")),
        }
    return out


def load_lms_params(wb):
    """LMS/HSS 参数 sheet：LM-OTS 基参数 + 各配置的 h。"""
    ws = wb[FAMILY_SHEETS["LMS/HSS"]]
    lmots = {}   # w -> p
    configs = {}  # 'LMS h=10' -> {'h': '10'}
    header = None
    section = None
    for row in ws.iter_rows(values_only=True):
        if row[0] is None:
            continue
        first = str(row[0]).strip()
        if first == "LM-OTS参数集":
            section = "lmots"
            continue
        if first == "LMS/HSS 配置":
            section = "config"
            header = None
            continue
        if first in ("LMOTS_SHA256_N32_W1", "LMOTS_SHA256_N32_W2",
                     "LMOTS_SHA256_N32_W4", "LMOTS_SHA256_N32_W8"):
            # 列: 名称,哈希,n(字节),w,p(链数),ls,OTS签名(字节)
            lmots[_int_or(row[3])] = {"p": _int_or(row[4]), "ls": _int_or(row[5])}
            continue
        if section == "config":
            if first == "LMS/HSS 配置":
                continue
            if first and first not in ("LMS/HSS 配置",):
                # 列: 名称,哈希,n(字节),h,实测KeyGen,实测Sign,实测Verify,实测签名,最大签名数,来源
                configs[first] = {"h": str(row[3]).strip() if row[3] is not None else "",
                                  "n_bytes": _int_or(row[2]),
                                  "w": 8}
    return configs, lmots


def _int_or(v):
    try:
        return int(str(v).replace(",", "").strip())
    except (ValueError, AttributeError, TypeError):
        return None


# ---------------------------------------------------------------- Pareto 核心

def dominates(a, b):
    """最小化假设: a 支配 b <=> 所有分量 a<=b 且至少一个 a<b。a,b 为数值向量。"""
    return all(x <= y for x, y in zip(a, b)) and any(x < y for x, y in zip(a, b))


def _directed(point, objectives):
    """按目标方向（min/max）变换坐标。"""
    return [v if obj == "min" else -v for v, obj in zip(point, objectives)]


def pareto_frontier(points, objectives):
    """返回 Pareto 前沿点的索引列表（不被集合内其它点支配）。
    points: 数值向量列表; objectives: 与列对应的 'min'/'max' 列表。
    """
    n = len(points)
    vecs = [_directed(points[i], objectives) for i in range(n)]
    frontier = [
        i for i in range(n)
        if not any(i != j and dominates(vecs[j], vecs[i]) for j in range(n))
    ]
    return frontier


def explain_dominance(points, objectives, names, frontier_idx):
    """对每个非前沿点，给出一个支配它的点，便于报告。"""
    n = len(points)
    vecs = [_directed(points[i], objectives) for i in range(n)]
    dom = {}
    for i in range(n):
        if i in frontier_idx:
            continue
        for j in range(n):
            if j != i and dominates(vecs[j], vecs[i]):
                dom.setdefault(i, []).append(j)
    return {names[i]: [names[j] for j in dom.get(i, [])] for i in range(n) if i not in frontier_idx}


def minmax_scale(values):
    lo, hi = min(values), max(values)
    span = hi - lo
    return [(v - lo) / span if span > 0 else 0.5 for v in values]


# ---------------------------------------------------------------- 主流程

def main():
    import openpyxl  # 延迟导入，便于无 openpyxl 时报错信息更友好

    wb = openpyxl.load_workbook(XLSX_PATH, data_only=True)

    overview = load_overview_rows(wb)
    slh = load_slhdsa_params(wb)
    xmss = load_xmss_params(wb)
    lms_cfg, _ = load_lms_params(wb)

    # ---- 组装数据集（决策变量按家族 sheet 匹配）----
    dataset = []
    for row in overview:
        name = str(row["参数集"]).strip()
        family = str(row["算法族"]).strip()
        size_b, _ = parse_value(row["签名大小"])
        kg_n, kg_u = parse_value(row["KeyGen"])
        sg_n, sg_u = parse_value(row["Sign"])
        vf_n, vf_u = parse_value(row["Verify"])

        params = {}
        if family == "SPHINCS+":
            params = slh.get(name, {})
        elif family == "XMSS":
            params = xmss.get(name, {})
        elif family == "LMS/HSS":
            # 总览名 'LMS h=10 (w=8)' -> 家族 sheet 名 'LMS h=10'
            key = name.split(" (")[0] if " (" in name else name
            cfg = lms_cfg.get(key, {})
            params = dict(cfg)

        dataset.append({
            "name": name,
            "family": family,
            "size_B": size_b,
            "sign_ms": to_ms(sg_n, sg_u),
            "verify_ms": to_ms(vf_n, vf_u),
            "keygen_ms": to_ms(kg_n, kg_u),
            "keygen_raw": row["KeyGen"],
            "params": params,
        })

    # ---- 数据质量检查 ----
    bad = [d["name"] for d in dataset if any(
        d[k] is None for k in ("size_B", "sign_ms", "verify_ms"))]
    if bad:
        print(f"[WARN] 以下行的目标值缺失/无法解析，将排除: {bad}")

    usable = [d for d in dataset if all(
        d[k] is not None for k in ("size_B", "sign_ms", "verify_ms"))]
    print(f"可用参数集: {len(usable)} / {len(dataset)}\n")

    # ---- 目标定义 ----
    OBJ3 = ["size_B", "sign_ms", "verify_ms"]          # 三目标: 大小、签名、验证
    OBJ4 = ["size_B", "keygen_ms", "sign_ms", "verify_ms"]  # 四目标(补充): 加 KeyGen
    OBJECTIVES = ["min"] * 3
    OBJECTIVES4 = ["min"] * 4

    # ---- 族内 Pareto ----
    # fam_frontier3/4[fam] 存放"usable 全局索引"（CSV 行号），而非族内子列表索引
    fam_frontier3, fam_frontier4 = {}, {}
    print("=" * 78)
    print("族内 Pareto 前沿（目标: 签名大小 / 签名时间 / 验证时间，均越小越优）")
    print("=" * 78)
    for fam in ("SPHINCS+", "LMS/HSS", "XMSS"):
        pairs = [(ui, d) for ui, d in enumerate(usable) if d["family"] == fam]
        rows = [d for _, d in pairs]
        pts3 = [[d["size_B"], d["sign_ms"], d["verify_ms"]] for d in rows]
        pts4 = [[d["size_B"], d["keygen_ms"], d["sign_ms"], d["verify_ms"]] for d in rows]
        fi3 = set(pareto_frontier(pts3, OBJECTIVES))
        fi4 = set(pareto_frontier(pts4, OBJECTIVES4))
        fam_frontier3[fam] = {pairs[i][0] for i in fi3}   # 映射回全局索引
        fam_frontier4[fam] = {pairs[i][0] for i in fi4}
        names = [d["name"] for d in rows]
        print(f"\n--- {fam} ({len(rows)} 参数集) ---")
        print("前沿(3目标): " + "; ".join(names[i] for i in sorted(fi3)))
        dom = explain_dominance(pts3, OBJECTIVES, names, fi3)
        for nm, by in dom.items():
            print(f"  被支配: {nm}  <- 支配它: {', '.join(by)}")
        add4 = sorted(fi4 - fi3)
        if add4:
            print(f"补充: 加入 KeyGen 目标后新增前沿点: {[names[i] for i in add4]}")
        for i in sorted(fi3 | fi4):
            d = rows[i]
            print(f"  [{names[i]}] size={d['size_B']:>6}B sign={d['sign_ms']:>10.3f}ms "
                  f"verify={d['verify_ms']:>7.3f}ms keygen={d['keygen_ms']:>10.1f}ms")

    # ---- 跨族 Pareto ----
    print("\n" + "=" * 78)
    print("跨族 Pareto（全部 22 参数集, 时间已统一为 ms）")
    print("=" * 78)
    pts3 = [[d["size_B"], d["sign_ms"], d["verify_ms"]] for d in usable]
    pts4 = [[d["size_B"], d["keygen_ms"], d["sign_ms"], d["verify_ms"]] for d in usable]
    xfi3 = set(pareto_frontier(pts3, OBJECTIVES))
    xfi4 = set(pareto_frontier(pts4, OBJECTIVES4))
    names = [d["name"] for d in usable]
    print("\n跨族前沿(3目标):")
    for i in sorted(xfi3):
        d = usable[i]
        print(f"  [{d['family']:>7}] {names[i]:<28} size={d['size_B']:>6}B "
              f"sign={d['sign_ms']:>8.3f}ms verify={d['verify_ms']:>6.3f}ms")
    dom = explain_dominance(pts3, OBJECTIVES, names, xfi3)
    print("\n被支配点（跨族）:")
    for nm, by in sorted(dom.items()):
        print(f"  {nm:<28} <- {', '.join(by)}")
    add4 = sorted(xfi4 - xfi3)
    if add4:
        print("\n补充: 加入 KeyGen 目标后跨族前沿新增:")
        for i in add4:
            d = usable[i]
            print(f"  [{d['family']:>7}] {names[i]:<28} size={d['size_B']:>6}B "
                  f"keygen={d['keygen_ms']:>9.1f}ms sign={d['sign_ms']:>8.3f}ms "
                  f"verify={d['verify_ms']:>6.3f}ms")

    # ---- 相对归一化（0~1，min-max，跨全数据集）----
    rel = {
        "size_B": minmax_scale([d["size_B"] for d in usable]),
        "sign_ms": minmax_scale([d["sign_ms"] for d in usable]),
        "verify_ms": minmax_scale([d["verify_ms"] for d in usable]),
    }

    # ---- 输出标注 CSV ----
    fields = [
        "parameter_set", "family", "size_B", "sign_ms", "verify_ms", "keygen_ms",
        "rel_size", "rel_sign", "rel_verify",
        "is_pareto_frontier_in_family", "is_pareto_frontier_cross_family",
        "is_pareto_frontier_in_family_4obj", "is_pareto_frontier_cross_family_4obj",
        "n_bytes", "h", "d", "w", "k", "a", "lgw", "m", "sec_category",
    ]
    with open(OUT_CSV, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for i, d in enumerate(usable):
            p = d["params"]
            row = {
                "parameter_set": d["name"],
                "family": d["family"],
                "size_B": d["size_B"],
                "sign_ms": round(d["sign_ms"], 4),
                "verify_ms": round(d["verify_ms"], 4),
                "keygen_ms": round(d["keygen_ms"], 2) if d["keygen_ms"] is not None else "",
                "rel_size": round(rel["size_B"][i], 4),
                "rel_sign": round(rel["sign_ms"][i], 4),
                "rel_verify": round(rel["verify_ms"][i], 4),
                "is_pareto_frontier_in_family": i in fam_frontier3[d["family"]],
                "is_pareto_frontier_cross_family": i in xfi3,
                "is_pareto_frontier_in_family_4obj": i in fam_frontier4[d["family"]],
                "is_pareto_frontier_cross_family_4obj": i in xfi4,
                "n_bytes": p.get("n_bytes", ""),
                "h": p.get("h", ""),
                "d": p.get("d", ""),
                "w": p.get("w", ""),
                "k": p.get("k", ""),
                "a": p.get("a", ""),
                "lgw": p.get("lgw", ""),
                "m": p.get("m", ""),
                "sec_category": p.get("sec_category", ""),
            }
            w.writerow({k: ("" if v is None else v) for k, v in row.items()})

    # ---- 绘图数据（Excel 散点图用）----
    with open(PLOT_CSV, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=[
            "parameter_set", "family", "size_B", "sign_ms", "verify_ms",
            "in_family_frontier", "cross_family_frontier",
        ])
        w.writeheader()
        for i, d in enumerate(usable):
            w.writerow({
                "parameter_set": d["name"],
                "family": d["family"],
                "size_B": d["size_B"],
                "sign_ms": round(d["sign_ms"], 4),
                "verify_ms": round(d["verify_ms"], 4),
                "in_family_frontier": i in fam_frontier3[d["family"]],
                "cross_family_frontier": i in xfi3,
            })

    print(f"\n已写出: {OUT_CSV}")
    print(f"已写出: {PLOT_CSV}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
