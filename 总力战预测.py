# -*- coding: utf-8 -*-
"""
总力战「边际难度及以上通关人数」预测器 v6.3（数据来源：什亭之匣 arona.icu）
运行：双击“双击运行预测.bat”；命令行加 -v 查看技术细节

框架（2026-10-31 定调）：
  1. 预测目标 = 正在进行的一期；没有进行中的才预测下一期。
  2. 核心量 = 边际难度(TM)及以上通关人数（含更高难度；TM极难的首领边际难度按INS口径）。
     输出中位数=预测值，区间=误差范围。
  3. 进行中期：数据龄<60小时用“趋势锚”（同格上期终值×成熟期同格复刻增速下限~近期最慢增速，
     成熟期同格复刻从未下降是硬先验）；≥60小时切“曲线比值法”（误差随数据龄收窄，
     历史自检：64h±15%、96h±6%）。28小时时点比值误差±55%以上，只做进度参考。
  4. 下一期：同格锚×近期增速（成熟期滚动窗口校准池+严格留出自检验）。
  5. 一档线判定用“档位阶梯”：TM及以上≥名额→TM带；否则满分线及以上≥名额→满分带；
     否则打穿线及以上≥名额→打穿带。跌落时刻用“完成度节奏法”：TM达到最终值r比例的
     历史时刻分布（37期曲线，回测s50误差4h/s73误差2h）。
  6. 不做回归，不做分数点预测。
"""
import contextlib
import io
import json
import math
import os
import sys
import time
import statistics as st
from datetime import datetime, timezone, timedelta

CST = timezone(timedelta(hours=8))
BASE = os.path.dirname(os.path.abspath(__file__))
SERVERS = ((2, "B服", 8000), (1, "官服", 20000))   # (server_id, 名称, 一档名额)
ROLL_K = 8
MIN_TM = 2000
THRESH_NEED = 0.6
VERBOSE = "-v" in sys.argv
TREND_FLOOR = 1.15        # 成熟期同格复刻最小总增幅（17对全部≥+16%）
RATIO_SWITCH_H = 60       # 数据龄该小时数后，比值法转为主判
CUT_S = 15_330_000        # 打穿线阈值（1,564万×98%）

THRESH_GAP = {52: 785.9, 62: 1010.6, 64: 894.5, 65: 980.5, 66: 985.9, 67: 921.6,
              68: 980.3, 69: 1064.5, 70: 910.4, 71: 949.7, 72: 936.1, 73: 914.3}
FALLBACK_TARGET = {"season": 75, "boss": "格里高利", "map": "室内",
                   "startTime": "2026-11-12 14:00", "endTime": "2026-11-19 03:59"}

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


# ---------------- 什亭之匣加解密（wasm-bindgen 胶水的 Python 移植） ----------------
class Crypto:
    def __init__(self, wasm_path):
        from wasmtime import Store, Module, Engine, Instance, Func, FuncType, ValType
        self.I, self.F = ValType.i32(), ValType.f64()
        engine = Engine()
        self.store = Store(engine)
        module = Module.from_file(engine, wasm_path)
        self.heap = [None] * 128 + [None, None, True, False]
        self.heap_next = len(self.heap)

        def ev(a, b):
            pass  # wasm 内嵌的浏览器反调试代码，PC端直接忽略
        def string_get(a, b):
            obj = self.heap[b]
            if isinstance(obj, str):
                ptr = self._exp["__wbindgen_malloc"](self.store, len(obj.encode()), 1)
                self.memory.write(self.store, obj.encode(), ptr)
                self._pair(a, ptr, len(obj.encode()))
            else:
                self._pair(a, 0, 0)
        def drop_ref(a):
            if a >= 132:
                self.heap[a] = self.heap_next
                self.heap_next = a
        def new0():
            return self._add(datetime.now())
        def get_time(a):
            return self.heap[a].timestamp() * 1000.0
        def throw_wbg(a, b):
            raise RuntimeError("wasm throw")

        imports = []
        for imp in module.imports:
            n = imp.name
            table = {
                "__wbg_eval_cecfe67ad804e2b4": ([self.I, self.I], [], ev),
                "__wbindgen_string_get": ([self.I, self.I], [], string_get),
                "__wbindgen_object_drop_ref": ([self.I], [], drop_ref),
                "__wbg_new0_ad75dd38f92424e2": ([], [self.I], new0),
                "__wbg_getTime_ed6ee333b702f8fc": ([self.I], [self.F], get_time),
                "__wbindgen_throw": ([self.I, self.I], [], throw_wbg),
            }
            args, results, fn = table[n]
            imports.append(Func(self.store, FuncType(args, results), fn))
        inst = Instance(self.store, module, imports)
        self.e = inst.exports(self.store)
        self._exp = self.e
        self.memory = self.e["memory"]

    def _pair(self, ptr, ptr_val, len_val):
        import struct
        self.memory.write(self.store, struct.pack("<ii", ptr_val, len_val), ptr)

    def o(self, mode):
        return self.e["o"](self.store, mode) & 0xFFFFFFFF

    def f(self, mode, payload):
        ret = self.e["__wbindgen_add_to_stack_pointer"](self.store, -16)
        try:
            idx = self._add(payload)
            self.e["f"](self.store, ret, mode, idx)
            import struct
            ptr = struct.unpack("<i", bytes(self.memory.read(self.store, ret, ret + 4)))[0]
            ln = struct.unpack("<i", bytes(self.memory.read(self.store, ret + 4, ret + 8)))[0]
            if ptr:
                out = bytes(self.memory.read(self.store, ptr, ptr + ln)).decode("utf-8")
                self.e["__wbindgen_free"](self.store, ptr, ln, 1)
                return out
            return None
        finally:
            self.e["__wbindgen_add_to_stack_pointer"](self.store, 16)

    def _add(self, obj):
        if self.heap_next == len(self.heap):
            self.heap.append(len(self.heap) + 1)
        idx = self.heap_next
        self.heap_next = self.heap[idx]
        self.heap[idx] = obj
        return idx


def encrypt_params(crypto, params):
    body = dict(params)
    body["timestamp"] = int(time.time() * 1000)
    return crypto.f(crypto.o(1), json.dumps(body, separators=(",", ":")))


def decrypt(crypto, b64):
    return json.loads(crypto.f(crypto.o(2), b64))


def api_post(crypto, endpoint, params, retries=3):
    import urllib.request
    body = json.dumps({"crypt": encrypt_params(crypto, params)}).encode()
    headers = {
        "Content-Type": "application/json", "ba-language": "zh",
        "Origin": "https://arona.icu", "Referer": "https://arona.icu/raidRank",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    }
    for i in range(retries):
        try:
            req = urllib.request.Request("https://api.arona.icu" + endpoint, method="POST",
                                         data=body, headers=headers)
            j = json.loads(urllib.request.urlopen(req, timeout=30).read())
            if j.get("crypt") and j.get("data"):
                j["data"] = decrypt(crypto, j["data"])
            return j
        except Exception:
            if i == retries - 1:
                raise
            time.sleep(2 * (i + 1))


# ---------------- 人口外推核心（静默计算） ----------------
def parse_dt(s):
    return datetime.strptime(s, "%Y-%m-%d %H:%M").replace(tzinfo=CST)


def value_at(series, elapsed_h, tol=3.0):
    best, bd = None, None
    for h, v in series:
        d = abs(h - elapsed_h)
        if bd is None or d < bd:
            best, bd = (h, v), d
    return best[1] if best and bd <= tol else None


def build_cells(baseline_srv):
    cells = {}
    for k in baseline_srv:
        try:
            sn = int(k)
        except ValueError:
            continue
        a = baseline_srv[k]
        tm = a.get("throughTM")
        if tm and tm >= 100:
            cells.setdefault((a["boss"], a["map"]), []).append((sn, tm))
    for v in cells.values():
        v.sort()
    return cells


def build_pairs(cells, min_tm=MIN_TM):
    pairs = []
    for cell, lst in cells.items():
        for (sa, va), (sb, vb) in zip(lst, lst[1:]):
            if va >= min_tm and vb >= min_tm and 0 < sb - sa <= 99:
                pairs.append({"cell": cell, "sa": sa, "sb": sb, "a": va, "b": vb,
                              "span": sb - sa, "rate": (vb / va) ** (1.0 / (sb - sa))})
    pairs.sort(key=lambda p: p["sb"])
    return pairs


def pool_asof(pairs, asof_season, k, exclude=None):
    lo = asof_season - k + 1
    latest = {}
    for p in pairs:
        if lo <= p["sb"] <= asof_season and p is not exclude:
            cur = latest.get(p["cell"])
            if cur is None or p["sb"] > cur["sb"]:
                latest[p["cell"]] = p
    return sorted(latest.values(), key=lambda p: p["sb"])


def spearman(xs, ys):
    def rank(v):
        s = sorted(range(len(v)), key=lambda i: v[i])
        r = [0.0] * len(v)
        i = 0
        while i < len(s):
            j = i
            while j + 1 < len(s) and v[s[j + 1]] == v[s[i]]:
                j += 1
            avg = (i + j) / 2 + 1
            for t in range(i, j + 1):
                r[s[t]] = avg
            i = j + 1
        return r
    rx, ry = rank(xs), rank(ys)
    mx, my = st.mean(rx), st.mean(ry)
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    den = math.sqrt(sum((a - mx) ** 2 for a in rx) * sum((b - my) ** 2 for b in ry))
    return num / den if den else 0.0


def loo_selftest(pairs, quota, k):
    rows = []
    for tgt in pairs:
        pool = pool_asof(pairs, tgt["sb"] - 1, k, exclude=tgt)
        if len(pool) < 2:
            continue
        g = st.median(p["rate"] for p in pool)
        pred = tgt["a"] * g ** tgt["span"]
        rows.append({"tgt": tgt, "pred": pred,
                     "ape": abs(pred / tgt["b"] - 1) * 100,
                     "hit": (pred >= quota) == (tgt["b"] >= quota)})
    return rows


def choose_rule(cells, quota):
    best, table = None, []
    for k in (6, 8, 10):
        rows = loo_selftest(build_pairs(cells), quota, k)
        if not rows:
            continue
        med = st.median(r["ape"] for r in rows)
        hit = sum(r["hit"] for r in rows) / len(rows)
        table.append((k, len(rows), med, hit))
        if best is None or (med, -hit) < best[0]:
            best = ((med, -hit), k, rows)
    return (best[1] if best else ROLL_K), table, (best[2] if best else [])


def crossing_hours_frac(baseline_srv, r):
    """各结算期TM人口达到自身最终值r比例的时刻（小时）列表"""
    hs = []
    for k in baseline_srv:
        a = baseline_srv[k]
        if not (a.get("throughTM") and a.get("tm_hourly")):
            continue
        fin = a["throughTM"]
        for h, v in a["tm_hourly"]:
            if v >= r * fin:
                hs.append(h)
                break
    return sorted(hs)


def drop_window(baseline_srv, final_proj, quota, min_hour=None):
    """给定预期最终值F，穿越名额的时刻分布 → (中位, p25, p75, n)。
       min_hour：进行中期按当前数据起点截断，避免给出“过去”的窗口"""
    if not final_proj or final_proj < quota:
        return None
    r = quota / final_proj
    hs = crossing_hours_frac(baseline_srv, r)
    if len(hs) < 3:
        return None
    try:
        q = st.quantiles(hs, n=4)
        p25, p75 = q[0], q[2]
    except Exception:
        p25, p75 = hs[0], hs[-1]
    med = st.median(hs)
    if min_hour is not None:
        clipped = p25 < min_hour
        p25 = max(p25, min_hour)
        med = max(med, p25)
        if clipped and p75 < p25:
            p75 = p25 + 12
    return med, p25, p75, len(hs)


def crossing_pool(baseline_srv, quota):
    """历次真实穿越名额的先例。key=结算前小时数（不同期赛程长度不同，
       用"开战后第X小时"跨期平移会错位，必须用结算前口径）"""
    pool = []
    for k in baseline_srv:
        a = baseline_srv[k]
        th = a.get("tm_hourly") or []
        if a.get("throughTM") and a["throughTM"] >= quota and th:
            xh = next((h for h, v in th if v >= quota), None)
            dur = th[-1][0]
            if xh is not None:
                pool.append({"sn": int(k), "boss": a["boss"],
                             "r": quota / a["throughTM"], "h": xh,
                             "off": dur - xh})
    pool.sort(key=lambda x: x["off"])
    return pool


def drop_estimate(baseline_srv, final_proj, quota):
    """跌落时刻=历次真实穿越先例（结算前小时口径）。
       B服3次先例：提前50/5/9小时（中位9h=结算当天傍晚）；
       官服9次：提前2~77小时，且与超额r几乎完美单调——穿越时刻本质上由最终人数决定"""
    pool = crossing_pool(baseline_srv, quota)
    if not pool or not final_proj or final_proj < quota:
        return None
    offs = sorted(p["off"] for p in pool)
    r_proj = quota / final_proj
    r_min = min(p["r"] for p in pool)
    r_max = max(p["r"] for p in pool)
    note = None
    if r_proj < r_min - 0.03:
        note = (f"预期超额{100*(1-r_proj):.0f}%创历史纪录（先例最大"
                f"{100*(1-r_min):.0f}%）——若趋势成立，穿越可能早于先例窗口")
    elif r_proj > r_max + 0.02:
        note = "贴线过线，穿越可能压哨（结算前几小时）"
    return {"med_off": st.median(offs), "min_off": min(offs), "max_off": max(offs),
            "n": len(pool), "r": r_proj, "r_range": (r_min, r_max),
            "note": note, "pool": pool}


def ratio_error(h):
    """比值法误差包络（2026-10-31历史自检：48h前±55%、60-84h±25%、84-108h±12%、之后±8%）"""
    for hh, e in ((60, 0.55), (84, 0.25), (108, 0.12)):
        if h < hh:
            return e
    return 0.08


def _rank_scores_at(cdata, t0ms, h, tol=4.0):
    """各名次线在数据龄h时的分数（站点人口计数器对次高难度千位取整，
    此处改用名次线分数轨迹间接推断档位人口）"""
    pts = []
    for rk, arr in cdata["data"].items():
        try:
            rk_i = int(rk)
        except ValueError:
            continue
        best, bd = None, None
        for t, v2 in zip(cdata["time"], arr):
            if v2 is None:
                continue
            hh = (t - t0ms) / 3600000
            d = abs(hh - h)
            if bd is None or d < bd:
                best, bd = v2, d
        if best is not None and bd <= tol:
            pts.append((rk_i, best))
    pts.sort()
    return pts


def tier_estimate(cdata, t0ms, score, h, tol=4.0):
    """档位人口间接推断：返回 (插值人口|None, 夹逼下界|None, 夹逼上界|None)"""
    pts = _rank_scores_at(cdata, t0ms, h, tol)
    if not pts:
        return None, None, None
    crossed = [rk for rk, s in pts if s >= score]
    below = [rk for rk, s in pts if s < score]
    lo = max(crossed) if crossed else 0
    hi = min(below) if below else None
    # 插值：夹逼对之间线性
    pair = [(rk, s) for rk, s in pts if rk == lo]
    up = [(rk, s) for rk, s in pts if hi is not None and rk == hi]
    if not crossed:
        est = 0
    elif hi is None:
        est = lo
    elif pair and up:
        frac = (pair[0][1] - score) / (pair[0][1] - up[0][1]) if pair[0][1] != up[0][1] else 0
        est = lo + frac * (hi - lo)
    else:
        est = lo
    return est, (lo if crossed else None), hi


def compute_forecast(cells, baseline_srv, target, quota):
    """下一期：同格锚×增速（静默）"""
    tmap = target["map"]["value"] if isinstance(target["map"], dict) else target["map"]
    cell = (target["boss"], tmap)
    lst = cells.get(cell, [])
    if not lst:
        return None
    anchor_sn, anchor_v = lst[-1]
    gap = target["season"] - anchor_sn
    pairs = build_pairs(cells)
    k, grid, loo_rows = choose_rule(cells, quota)
    pool = pool_asof(pairs, target["season"] - 1, k)
    rates = sorted(p["rate"] for p in pool) if pool else []
    res = {"mode": "next", "cell": cell, "anchor": (anchor_sn, anchor_v), "gap": gap,
           "pool": pool, "rates": rates, "k": k, "grid": grid, "loo_rows": loo_rows}
    xs = [THRESH_GAP[p["sa"]] for p in pool if p["sa"] in THRESH_GAP]
    ys = [(p["rate"] - 1) * 100 for p in pool if p["sa"] in THRESH_GAP]
    res["rho"] = spearman(xs, ys) if len(xs) >= 4 else None
    if rates:
        lo, med, hi = rates[0], st.median(rates), rates[-1]
        res["scen"] = {"保守": anchor_v * lo ** gap, "中位": anchor_v * med ** gap,
                       "乐观": anchor_v * hi ** gap}
        res["cross"] = sum(1 for r in rates if anchor_v * r ** gap >= quota)
    else:
        res["scen"], res["cross"] = {}, None
    # 档位阶梯：同格锚期的满分线/打穿线及以上人口 × 中位增速
    base_entry = baseline_srv.get(str(anchor_sn), {})
    for key, field in (("full", "pop_full"), ("cut", "pop_cut")):
        curve = base_entry.get(field) or []
        if curve:
            res[key + "_anchor"] = curve[-1][1]
    res["drop_est"] = drop_estimate(baseline_srv, res["scen"].get("中位"), quota) if res["scen"] else None
    res["drop_tm"] = res["drop_est"]
    res["loo_med"] = st.median(r["ape"] for r in loo_rows) if loo_rows else None
    res["loo_hit"] = (sum(r["hit"] for r in loo_rows), len(loo_rows)) if loo_rows else None
    return res


def compute_forecast_live(baseline_srv, cur, tm_now, data_last_h, charts, ins_max, quota):
    """进行中期预测：数据龄<60h用趋势锚，≥60h用比值法；附档位阶梯与跌落窗口。
       档位人口不读站点计数器（次高难度千位取整），改由名次线分数轨迹间接推断"""
    cell = (cur["boss"], cur["map"]["value"])
    h_ref = data_last_h if data_last_h else \
        (datetime.now(CST) - parse_dt(cur["startTime"])).total_seconds() / 3600
    entries = []
    for k in baseline_srv:
        try:
            ksn = int(k)
        except ValueError:
            continue
        a = baseline_srv[k]
        if (a["boss"], a["map"]) == cell and a.get("throughTM") and \
                a.get("tm_hourly") and ksn < cur["season"]:
            entries.append((ksn, a))
    entries.sort()
    if not entries or not tm_now:
        return None
    ksn, prior = entries[-1]
    gap = cur["season"] - ksn
    ref = value_at(prior["tm_hourly"], h_ref)
    # 校准池最慢增速（趋势锚上限用）
    pairs = build_pairs(build_cells(baseline_srv))
    pool = pool_asof(pairs, cur["season"] - 1, ROLL_K)
    g_min = min((p["rate"] for p in pool), default=1.0)
    # 趋势锚：成熟期同格复刻从未下降
    t_lo = prior["throughTM"] * TREND_FLOOR
    t_hi = prior["throughTM"] * (g_min ** gap) if gap > 0 else prior["throughTM"]
    t_hi = max(t_hi, t_lo)
    # 比值法
    r_point = r_lo = r_hi = None
    if ref and ref >= 5:
        r_point = prior["throughTM"] * tm_now / ref
        e = ratio_error(h_ref)
        r_lo, r_hi = r_point * (1 - e), r_point * (1 + e)
    use_ratio = h_ref >= RATIO_SWITCH_H and r_point
    if use_ratio:
        point, lo, hi = r_point, r_lo, r_hi
        if lo < t_lo * 0.9:      # 比值法下界跌破趋势底线的90%时，以趋势底线托底
            lo = t_lo * 0.9
    else:
        point = math.sqrt(t_lo * t_hi)
        lo, hi = t_lo, t_hi
    res = {"mode": "live", "cell": cell, "point": point, "lo": lo, "hi": hi,
           "trend": (ksn, prior["throughTM"], t_lo, t_hi, g_min, gap),
           "ratio": {"point": r_point, "lo": r_lo, "hi": r_hi, "ref": ref,
                     "val": tm_now, "h": h_ref,
                     "ratio": (tm_now / ref) if (ref and ref >= 5) else None},
           "use_ratio": use_ratio, "h_ref": h_ref, "tm_now": tm_now, "quota": quota}
    # 档位阶梯：满分线及以上 / 打穿线及以上（名次线间接推断 × 上期曲线比值）
    tiers = {}
    pf = prior.get("pop_full") or []
    pc = prior.get("pop_cut") or []
    if charts and pf and pc:
        t0ms = int(parse_dt(cur["startTime"]).timestamp() * 1000)
        full_thr = (ins_max or 27_700_000) * 0.98
        for name, thr, curve in (("full", full_thr, pf), ("cut", CUT_S, pc)):
            est, blo, bhi = tier_estimate(charts, t0ms, thr, h_ref)
            ref = value_at(curve, h_ref)
            fin = curve[-1][1]
            tiers[name] = {"now": est, "bracket": (blo, bhi), "thr": thr,
                           "proj": fin * est / ref if (est is not None and ref and ref >= 5) else None,
                           "prior_final": fin}
    res["tiers"] = tiers
    res["drop_est"] = drop_estimate(baseline_srv, point, quota)
    res["drop_tm"] = drop_window(baseline_srv, point, quota, min_hour=h_ref + 6)
    return res


# ---------------- 实时状态 ----------------
def live_status(crypto, server_id, quota):
    """返回 (进行中期|None, 下一期|None, TM人口|None, 数据龄h|None, 名次线|None,
       INS最高分|None, 状态行|None)"""
    now = datetime.now(CST)
    try:
        seasons = api_post(crypto, "/api/season/list", {"server": server_id})["data"]
    except Exception:
        return None, None, None, None, None, None, None
    cur = next((s for s in seasons
                if parse_dt(s["startTime"]) <= now < parse_dt(s["endTime"])), None)
    nxt = min((s for s in seasons if parse_dt(s["startTime"]) > now),
              key=lambda s: s["startTime"], default=None)
    tm_now = data_last_h = None
    charts = None
    ins_max = None
    lines = []
    if cur:
        sn = cur["season"]
        elapsed = (now - parse_dt(cur["startTime"])).total_seconds() / 3600
        lines.append(f"本期进行到第{sn}期（开战后{elapsed:.0f}小时）")
        try:
            lr = api_post(crypto, "/api/v2/rank/list_by_last_rank",
                          {"server": server_id, "season": sn})["data"]
            tml = [r for r in lr if r["hard"] == "TM"]
            if tml:
                tm_now = max(r["rank"] for r in tml)
            insl = [r["bestRankingPoint"] for r in lr if r["hard"] == "INS"]
            if insl:
                ins_max = max(insl)
            try:
                ch = api_post(crypto, "/api/v2/rank/new/charts",
                              {"server": server_id, "season": sn})
                if ch.get("code") == 200 and ch.get("data"):
                    charts = ch["data"]
                    ts = max((t for t in charts.get("time", [])), default=None)
                    if ts:
                        data_last_h = (ts - int(parse_dt(cur["startTime"]).timestamp() * 1000)) / 3600000
            except Exception:
                pass
            age = f"数据截至开战后{data_last_h:.0f}小时" if data_last_h else "数据滞后约0.5-1天"
            if tm_now:
                lines.append(f"TM及以上现有人口 {tm_now:,}（{age}）")
        except Exception:
            pass
    return cur, nxt, tm_now, data_last_h, charts, ins_max, ("\n".join(lines) or None)


# ---------------- 可信度自评 ----------------
def credibility(res, quota):
    """每次预测给出可信度自评。返回 (星数1-5, 等级词, 原因|None, 分数)"""
    reasons = []
    if res.get("mode") == "live":
        h = res["h_ref"]
        pt, lo, hi = res["point"], res["lo"], res["hi"]
        score = 72
        if h >= 84:
            score += 18
        elif h >= 60:
            score += 8
        else:
            score -= 8
            reasons.append("开战不久，主要靠往期规律外推")
        tr = res.get("trend")
        if tr:
            t_geo = math.sqrt(max(tr[2], 1) * max(tr[3], 1))
            div = abs(pt - t_geo) / max(pt, 1)
            pen = min(18, int(div * 100))
            score -= pen
            if pen >= 10:
                reasons.append("当期进度与往期规律分歧较大")
        width = (hi - lo) / max(pt, 1)
        if width > 0.45:
            score -= 12
            reasons.append("波动范围还比较宽")
        elif width > 0.25:
            score -= 5
        if lo < quota <= hi:
            score -= 10
            reasons.append("预测正好骑在名额线上")
    else:
        lm = res.get("loo_med")
        score = 82 if lm else 65
        if lm:
            score -= min(22, lm)
            if lm > 20:
                reasons.append("这套类比的历史误差偏大")
        scen = res.get("scen") or {}
        if scen:
            vals = [v for v in scen.values() if v]
            width = (max(vals) - min(vals)) / max(min(vals), 1)
            if width > 0.4:
                score -= 10
                reasons.append("各情景分歧较大")
        n, c = len(res.get("rates") or []), res.get("cross")
        if res.get("scen") and 0 < (c or 0) < n:
            score -= 10
            reasons.append("过线情景存在分歧")
    stars = 5 if score >= 85 else 4 if score >= 70 else 3 if score >= 55 else 2
    word = {5: "高", 4: "较高", 3: "中等", 2: "偏低"}[stars]
    return stars, word, (reasons[0] if reasons else None), score


# ---------------- 玩家视图输出 ----------------
def fmt_dt(dt):
    return dt.strftime("%m-%d %H:%M") if dt else "—"


def fmt_win(win, t0str):
    if not win:
        return None
    med, p25, p75, n = win
    t0 = parse_dt(t0str)
    return (f"{fmt_dt(t0 + timedelta(hours=p25))} ~ {fmt_dt(t0 + timedelta(hours=p75))}"
            f"（中位 {fmt_dt(t0 + timedelta(hours=med))}，{n}期节奏）")


def print_live_block(quota, res):
    stars, word, reason, _score = credibility(res, quota)
    tag = f"｜可信度 {'★' * stars} {word}"
    if reason:
        tag += f"（{reason}）"
    print(f"  ◈ 预期TM及以上通关人数：约 {res['point']:,.0f} 人"
          f"（区间 {res['lo']:,.0f} ～ {res['hi']:,.0f}）{tag}")
    q = quota
    tiers = res.get("tiers") or {}
    if res["point"] >= q and res["lo"] >= q:
        print(f"  ◈ 一档线（第{q:,}名）：在TM带（TM通关分一线），名额将被TM玩家占满")
    else:
        if res["point"] >= q:
            head = f"一档线（第{q:,}名）：倾向TM带，但区间跨线——"
        else:
            head = f"一档线（第{q:,}名）：TM预计不足{q:,}——"
        parts = []
        t = tiers.get("full")
        if t and t.get("proj") is not None:
            fp = round(t["proj"])
            parts.append(f"退到满分带{'稳（预计' + format(fp, ',') + '人）' if fp >= q else '也悬（仅预计' + format(fp, ',') + '人）'}")
        t = tiers.get("cut")
        if t and t.get("proj") is not None:
            cp = round(t["proj"])
            parts.append(f"打穿带{'兜底（预计' + format(cp, ',') + '人）' if cp >= q else '同样危险（预计' + format(cp, ',') + '人）'}")
        print(f"  ◈ {head}{'；'.join(parts)}")
    frozen_h = None
    if res.get("_elapsed_h") and res.get("h_ref") is not None:
        frozen_h = res["_elapsed_h"] - res["h_ref"]
        if frozen_h > 24:
            print(f"  ⚠ 站点数据管道冻结中：最后更新在开战后{res['h_ref']:.0f}小时，"
                  f"已停更{frozen_h:.0f}小时（站点通常在定榜前后恢复）。"
                  f"本预测以趋势锚为主，不依赖实时点，结论不受影响")
    if res["point"] >= q and res.get("drop_est"):
        de = res["drop_est"]
        end = parse_dt(res.get("_end") or res.get("_start"))
        wmed = fmt_dt(end - timedelta(hours=de["med_off"]))
        wlo = fmt_dt(end - timedelta(hours=de["max_off"]))
        wmin = fmt_dt(end - timedelta(hours=de["min_off"]))
        print(f"  ◈ 一档线跌落：最可能结算前{de['med_off']:.0f}小时（{wmed}）前后；"
              f"先例范围结算前{de['min_off']:.0f}~{de['max_off']:.0f}小时"
              f"（{wmin} ~ {wlo}），共{de['n']}次先例")
        ranks = sorted(x + 800 for x in (res["lo"], res["point"], res["hi"]))
        print(f"      贴线玩家届时约排第 {ranks[1]:,.0f} 名"
              f"（+100～+2,500，取决于满分带内用时排名），跌出一档")
        extra = []
        if de["note"]:
            extra.append(de["note"])
        if res["tm_now"] < q * 0.5:
            extra.append("现值进度落后，穿越更可能落在窗口后段甚至不发生")
        if extra:
            print("      " + "；".join(extra))
    else:
        print("  ◈ 一档线跌落：预计不发生" + ("（仅乐观情形才可能）" if res["hi"] >= quota else ""))


def print_player(server_id, srv_name, quota, target, res, live_line):
    tmap = target["map"]["value"] if isinstance(target["map"], dict) else target["map"]
    print("─" * 56)
    tag = "进行中" if res and res.get("mode") == "live" else "未开战"
    print(f"【{srv_name}】第{target['season']}期 {target['boss']}·{tmap}"
          f"　{target.get('startTime', '')[:16]} 开战（{tag}）")
    if live_line:
        for ln in live_line.split("\n"):
            print(f"  {ln}")
    if res is None:
        print("  （历史基准无该格TM数据，无法预测）")
        return
    if res.get("mode") == "live":
        print_live_block(quota, res)
        print("  （数据源 arona.icu）")
        return
    anchor_sn, anchor_v = res["anchor"]
    stars, word, reason, _score = credibility(res, quota)
    tag = f"｜可信度 {'★' * stars} {word}"
    if reason:
        tag += f"（{reason}）"
    if res["scen"]:
        v = res["scen"]
        print(f"  ◈ 预期TM及以上通关人数（含更高难度）：约 {v['中位']:,.0f} 人"
              f"（区间 {v['保守']:,.0f} ～ {v['乐观']:,.0f}）{tag}")
        n, c = len(res["rates"]), res["cross"]
        if anchor_v >= quota:
            band = "一档线已在TM带内，预计维持（无新增跌落）"
        elif c * 2 > n:
            band = "大概率翻入TM带（一档线将被TM通关分占据）"
        elif c * 2 == n:
            band = "过线/不过线情景各半——临界期，开战后以实际爬坡为准"
        else:
            fa = res.get("full_anchor")
            extra = f"；退一步满分带也稳（同格锚{fa:,.0f}人）" if fa and fa >= quota else ""
            band = f"大概率维持满分带（TM不足以占满{quota:,}{extra}）"
        print(f"  ◈ 一档线（第{quota:,}名）：{band}")
        if v["中位"] >= quota and anchor_v < quota and res.get("drop_est"):
            de = res["drop_est"]
            end = parse_dt(target.get("endTime"))
            wmed = fmt_dt(end - timedelta(hours=de["med_off"]))
            wlo = fmt_dt(end - timedelta(hours=de["max_off"]))
            ranks = sorted(x + 800 for x in (v["保守"], v["中位"], v["乐观"]))
            wmin = fmt_dt(end - timedelta(hours=de["min_off"]))
            print(f"  ◈ 一档线跌落：最可能结算前{de['med_off']:.0f}小时（{wmed}）前后；"
                  f"先例范围结算前{de['min_off']:.0f}~{de['max_off']:.0f}小时"
                  f"（{wmin} ~ {wlo}），共{de['n']}次先例，"
                  f"贴线玩家届时约排第 {ranks[1]:,.0f} 名")
            if de["note"]:
                print(f"      {de['note']}")
        elif v["中位"] < quota:
            print("  ◈ 一档线跌落：预计不发生" + ("（仅乐观情形才可能）" if v["乐观"] >= quota else ""))
    else:
        print(f"  ◈ 预期TM及以上通关人数：锚 s{anchor_sn}={anchor_v:,}，近期无可比复刻对")
    print("  （数据源 arona.icu）")


# ---------------- 技术细节（-v） ----------------
def print_verbose(res, quota):
    if res is None:
        return
    print("  ── 技术细节 ──")
    if res.get("mode") == "live":
        ksn, pfinal, t_lo, t_hi, g_min, gap = res["trend"]
        print(f"  趋势锚：s{ksn}={pfinal:,}×[{TREND_FLOOR}, {g_min:.3f}^{gap}] → [{t_lo:,.0f}, {t_hi:,.0f}]"
              f"，几何中位 {res['point']:,.0f}")
        r = res["ratio"]
        if r.get("point"):
            print(f"  比值法：{r['val']:,}/{r['ref']:,}=×{r['ratio']:.2f}→{r['point']:,.0f}"
                  f" [{r['lo']:,.0f}, {r['hi']:,.0f}]（数据龄{r['h']:.0f}h，"
                  f"{'主判' if res['use_ratio'] else '参考'}）")
        for name, t in (res.get("tiers") or {}).items():
            print(f"  档位[{name}]：现值{t['now'] or 0:,.0f} → 比值推算终值{t['proj'] or 0:,.0f}"
                  f"（上期终值{t['prior_final']:,.0f}）")
        if res.get("drop_est"):
            de = res["drop_est"]
            pool = "、".join(f"s{p['sn']}(提前{p['off']:.0f}h,r={p['r']:.2f})" for p in de["pool"])
            print(f"  跌落先例池：{pool} → 中位提前{de['med_off']:.0f}h、范围{de['min_off']:.0f}~{de['max_off']:.0f}h；"
                  f"本次r={de['r']:.3f}（先例范围{de['r_range'][0]:.3f}~{de['r_range'][1]:.3f}）")
        if res.get("drop_tm"):
            med, p25, p75, n = res["drop_tm"]
            print(f"  完成度节奏法（次级参考，混入小终值期会偏早）：r={quota/res['point']:.3f} → "
                  f"中位{med:.0f}h，p25~p75 {p25:.0f}~{p75:.0f}h")
        print(f"  可信度打分：{credibility(res, quota)[3]}（≥85高 / 70较高 / 55中等 / <55偏低）")
        return
    print("  校准池（每格最近成熟复刻对，双端TM≥%s，滚动窗口K=%d）：" % (f"{MIN_TM:,}", res["k"]))
    for p in res["pool"]:
        print(f"    {p['cell'][0]}·{p['cell'][1]} s{p['sa']}→s{p['sb']}"
              f"（间隔{p['span']}期）：{p['a']:,}→{p['b']:,}，+{(p['rate']-1)*100:.1f}%/期")
    if res["rates"]:
        print(f"    每期增速中位：+{(st.median(res['rates'])-1)*100:.2f}%")
    if res["rho"] is not None:
        print(f"    Boss门槛差因子检验：Spearman ρ={res['rho']:+.2f}"
              f"{' ≥0.6会启用' if abs(res['rho']) >= THRESH_NEED else '，<0.6不采用'}")
    print("  严格留出自检验（预测每对只用其结算前已完成的其他格复刻对）：")
    for r in sorted(res["loo_rows"], key=lambda r: r["tgt"]["sb"]):
        t = r["tgt"]
        print(f"    {t['cell'][0]}·{t['cell'][1]} s{t['sa']}→s{t['sb']}: "
              f"实际{t['b']:,} 预测{r['pred']:,.0f} 误差{r['ape']:.0f}% "
              f"过线判定{'对' if r['hit'] else '错'}")
    print("  滚动窗口K网格：" + "；".join(
        f"K={kk}可评{n}对中位APE{m:.0f}%命中{h*100:.0f}%" for kk, n, m, h in res["grid"]))
    if res["drop_tm"]:
        med, p25, p75, n = res["drop_tm"]
        print(f"  跌落窗口：完成度节奏法（{n}期曲线），r={quota/res['scen']['中位']:.3f} → "
              f"中位{med:.0f}h，p25~p75 {p25:.0f}~{p75:.0f}h（回测s50误差4h/s73误差2h）")
    if res.get("drop_est"):
        de = res["drop_est"]
        pool = "、".join(f"s{p['sn']}(提前{p['off']:.0f}h,r={p['r']:.2f})" for p in de["pool"])
        print(f"  跌落先例池：{pool} → 中位提前{de['med_off']:.0f}h、范围{de['min_off']:.0f}~{de['max_off']:.0f}h；"
              f"本次r={de['r']:.3f}（先例范围{de['r_range'][0]:.3f}~{de['r_range'][1]:.3f}）")
    print(f"  可信度打分：{credibility(res, quota)[3]}（≥85高 / 70较高 / 55中等 / <55偏低）")


# ---------------- 历史基准自我迭代 ----------------
def _step_series(keys, vals):
    return [(t, v) for t, v in zip(keys, vals) if v is not None]


def _step_at(series, t_ms, default=0):
    v = default
    for t, x in series:
        if t <= t_ms:
            v = x
        else:
            break
    return v


def build_season_record(crypto, server_id, s_info):
    """把一期定榜数据整理成历史基准记录（字段与既有基准一致）"""
    sn = s_info["season"]
    lr = api_post(crypto, "/api/v2/rank/list_by_last_rank", {"server": server_id, "season": sn})
    if lr.get("code") != 200:
        return None, "边界数据获取失败"
    entries = lr["data"]
    tml = [r["rank"] for r in entries if r["hard"] == "TM"]
    if not tml:
        return None, "无TM通关（太早期的赛季）"
    through_tm = max(tml)
    insl = [r["bestRankingPoint"] for r in entries if r["hard"] == "INS"]
    ins_max = max(insl) if insl else None
    hc = api_post(crypto, "/api/v2/rank/season/hard/rank_charts", {"server": server_id, "season": sn})
    ch = api_post(crypto, "/api/v2/rank/new/charts", {"server": server_id, "season": sn})
    if hc.get("code") != 200 or ch.get("code") != 200:
        return None, "人口/名次线数据获取失败"
    hc, chd = hc["data"], ch["data"]
    t0 = int(parse_dt(s_info["startTime"]).timestamp() * 1000)
    end_ms = int(parse_dt(s_info["endTime"]).timestamp() * 1000)
    # TM曲线：LU时代TM在secondHighest，用“终值=边界值”挑选
    best = None
    for kname in ("maximumDifficulty", "secondHighestDifficulty"):
        ser = hc.get(kname) or {}
        sv = _step_series(ser.get("key", []), ser.get("value", []))
        if not sv:
            continue
        if best is None or abs(sv[-1][1] - through_tm) < abs(best[1][-1][1] - through_tm):
            best = (kname, sv)
    if best is None or abs(best[1][-1][1] - through_tm) > 50:
        return None, "人口曲线与边界对不上（站点数据未完整）"
    tm_series = best[1]
    if tm_series[-1][0] < end_ms - 6 * 3600000:
        return None, f"数据只到开战后{(tm_series[-1][0] - t0) / 3600000:.0f}小时（未完整）"
    hours = int((tm_series[-1][0] - t0) / 3600000)
    tm_hourly = [[h, _step_at(tm_series, t0 + h * 3600000)] for h in range(hours + 1)]
    rank_steps = {}
    for rk, arr in chd["data"].items():
        try:
            rk_i = int(rk)
        except ValueError:
            continue
        rank_steps[rk_i] = _step_series(chd["time"], arr)

    def pop_at(score, t_ms):
        pts = sorted((rk, _step_at(svs, t_ms)) for rk, svs in rank_steps.items())
        prev_r, prev_s = 0, float("inf")
        for rk, s in pts:
            if s >= score:
                prev_r, prev_s = rk, s
            else:
                if prev_s == float("inf") or s == prev_s:
                    return prev_r
                return prev_r + (prev_s - score) / (prev_s - s) * (rk - prev_r)
        return prev_r

    full_thr = (ins_max or 27_700_000) * 0.98
    pop_full = [[h, round(pop_at(full_thr, t0 + h * 3600000), 1)] for h in range(0, hours + 1, 4)]
    pop_cut = [[h, round(pop_at(CUT_S, t0 + h * 3600000), 1)] for h in range(0, hours + 1, 4)]
    f8_arr = rank_steps.get(8000)
    f8 = f8_arr[-1][1] if f8_arr else None
    band = ("TM带" if (f8 and ins_max and f8 > 1.1 * ins_max)
            else "打穿带" if (f8 and ins_max and f8 < 0.8 * ins_max) else "满分带")
    rec = {"boss": s_info["boss"], "map": s_info["map"]["value"], "start": s_info["startTime"],
           "INS_max": ins_max, "F8": f8, "band": band, "throughTM": through_tm,
           "tm_hourly": tm_hourly, "pop_full": pop_full, "pop_cut": pop_cut}
    return rec, None


def update_baseline(crypto, baseline, base_file):
    """自我迭代：发现基准里没有的已结算期，拉定榜数据并入基准（每次每服最多补一期）"""
    import shutil
    updated, now, checked = [], datetime.now(CST), 0
    for server_id, srv_name, quota in SERVERS:
        try:
            seasons = api_post(crypto, "/api/season/list", {"server": server_id})["data"]
        except Exception:
            print(f"  [{srv_name}] 赛季列表拉取失败，本次跳过基准更新")
            continue
        checked += 1
        bl = baseline.setdefault(srv_name, {})
        have = max((int(k) for k in bl if str(k).isdigit()), default=-1)
        for s in seasons:
            if now < parse_dt(s["endTime"]) + timedelta(hours=12):
                continue  # 结算未满12小时，让站点先定榜
            if s["season"] <= have:
                continue
            rec, err = build_season_record(crypto, server_id, s)
            if rec is None:
                print(f"  [{srv_name}] 第{s['season']}期未吸收：{err}")
                continue
            bl[str(s["season"])] = rec
            updated.append(f"{srv_name}第{s['season']}期")
            break  # 一次补一期，其余下轮运行再补
    if updated:
        try:
            if os.path.exists(base_file):
                shutil.copy2(base_file, base_file + ".bak")
            json.dump(baseline, open(base_file, "w", encoding="utf-8"), ensure_ascii=False)
            print(f"✓ 历史基准已自我更新：{'、'.join(updated)}（原文件备份为 .bak）")
        except Exception as e:
            print(f"✗ 基准保存失败：{e}")
    elif checked:
        print("✓ 历史基准已是最新")


# ---------------- 主流程 ----------------
def main():
    now = datetime.now(CST)
    print("=" * 56)
    print(f"总力战边际难度通关人数预测　{now.strftime('%Y-%m-%d %H:%M')}　（数据源：什亭之匣 arona.icu）")
    print("=" * 56)
    base_file = os.path.join(BASE, "历史基准.json")
    if not os.path.exists(base_file):
        print("缺少 历史基准.json（与脚本同目录）")
        return
    baseline = json.load(open(base_file, encoding="utf-8"))

    crypto = None
    wasm = os.path.join(BASE, "yuyuko.wasm")
    if os.path.exists(wasm):
        try:
            try:
                import wasmtime  # noqa
            except ImportError:
                print("首次运行：正在安装依赖 wasmtime ...")
                os.system(f'"{sys.executable}" -m pip install wasmtime -q')
            crypto = Crypto(wasm)
        except Exception as e:
            print(f"实时拉取不可用（{e}），仅离线预测")

    if crypto:
        try:
            update_baseline(crypto, baseline, base_file)
        except Exception as e:
            print(f"基准更新出错（不影响本次预测）：{e}")

    summary = {}
    report_buf = io.StringIO()
    _orig = sys.stdout

    class _Tee:
        def write(self, txt):
            _orig.write(txt)
            report_buf.write(txt)
            return len(txt)

        def flush(self):
            _orig.flush()

    with contextlib.redirect_stdout(_Tee()):
        for server_id, srv_name, quota in SERVERS:
            baseline_srv = baseline.get(srv_name, {})
            if not baseline_srv:
                continue
            cells = build_cells(baseline_srv)
            cur = nxt = None
            live_line = None
            tm_now = data_last_h = None
            charts = None
            if crypto:
                try:
                    cur, nxt, tm_now, data_last_h, charts, ins_max, live_line = \
                        live_status(crypto, server_id, quota)
                except Exception:
                    pass
            if cur:
                target = cur
                res = compute_forecast_live(baseline_srv, cur, tm_now, data_last_h,
                                            charts, ins_max, quota)
                if res is None:
                    res = compute_forecast(cells, baseline_srv, target, quota)
                if res is not None and res.get("mode") == "live":
                    res["_start"] = target.get("startTime")
                    res["_end"] = target.get("endTime")
                    res["_elapsed_h"] = (datetime.now(CST) - parse_dt(
                        target["startTime"])).total_seconds() / 3600
            else:
                target = nxt or FALLBACK_TARGET
                if crypto is None:
                    print(f"【{srv_name}】实时不可用，使用内置目标期")
                res = compute_forecast(cells, baseline_srv, target, quota)
            print_player(server_id, srv_name, quota, target, res, live_line)
            if VERBOSE:
                print_verbose(res, quota)
            if res and res.get("mode") == "live":
                summary[srv_name] = {"season": target["season"], "mode": "live",
                                     "median": round(res["point"]), "lo": round(res["lo"]),
                                     "hi": round(res["hi"])}
            elif res and res.get("scen"):
                summary[srv_name] = {"season": target["season"], "mode": "next",
                                     "median": round(res["scen"]["中位"]),
                                     "lo": round(res["scen"]["保守"]), "hi": round(res["scen"]["乐观"]),
                                     "cross": res["cross"]}
            print()

    # 在线版（GitHub仓库/Pages 直接可看）：每次覆盖为最新报告
    nl = chr(10)
    md = ("# 总力战一档预测（适配官服B服）" + nl * 2
          + f"> 运行时间：{now.strftime('%Y-%m-%d %H:%M')}（北京时间）｜"
          + "数据来源：[什亭之匣 arona.icu](https://arona.icu)" + nl * 2
          + "```" + nl + report_buf.getvalue().rstrip() + nl + "```" + nl)
    for fn, head in (("预测结果.md", ""),
                     ("index.md", "---" + nl + "title: 总力战一档预测（适配官服B服）"
                      + nl + "---" + nl + nl)):
        try:
            open(os.path.join(BASE, fn), "w", encoding="utf-8").write(head + md)
        except Exception:
            pass

    out_file = os.path.join(BASE, "预测结果.txt")
    with open(out_file, "a", encoding="utf-8") as f:
        f.write(f"\n{'='*50}\n{now.strftime('%Y-%m-%d %H:%M')} v6.3\n")
        f.write(json.dumps(summary, ensure_ascii=False, default=str) + "\n")
    print(f"结果已追加：{out_file}")
    if sys.stdin.isatty():
        try:
            input("回车退出...")
        except EOFError:
            pass


if __name__ == "__main__":
    main()
