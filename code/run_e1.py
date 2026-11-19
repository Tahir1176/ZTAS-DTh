"""
E1 driver (revision v2). Usage:
  python3 run_e1.py main  ../data/raw/e1_main.csv          # 9 topologies x 30 graphs x 50 runs, 2 profiles, 5 configs (+ablations on reference)
  python3 run_e1.py pv    ../data/raw/e1_pv.csv            # p_v x f_art sweep, all topologies
  python3 run_e1.py oat   ../data/raw/e1_oat.csv           # one-at-a-time sensitivity, reference topology
Seeds: graph_seed = 10000*topology_index + g ; run_seed = 1000003*graph_seed + r  (recorded in every row).
"""
import sys, csv, itertools
from multiprocessing import Pool
import numpy as np
import topologies as tp
import dth_sim as ds

TOPOS = list(tp.TOPOLOGIES)
PROFILES = {"noisy": 55.0, "stealthy": 28.0}
MAIN_CFGS = ["perimeter", "zones", "zt", "zt_prov", "ztas"]
ABL_CFGS = ["ztas_no_seg", "ztas_no_risk", "ztas_no_prov", "ztas_uniform_w"]
METRICS = ["frac", "reach_O", "t_reach_O", "n_phases", "path_len", "detected", "t_detect", "contained", "residual"]
N_GRAPHS, N_RUNS = 30, 50


def gseed(ti, g): return 10000 * ti + g
def rseed(gs, r): return 1000003 * gs + r


def task_main(args):
    ti, g = args
    topo = TOPOS[ti]; gs = gseed(ti, g)
    prep = ds.Prepared(tp.build(topo, gs)); rows = []
    for r in range(N_RUNS):
        rs = rseed(gs, r); D = ds.draws(prep, ds.DEFAULTS["T"], rs)
        for prof, mu in PROFILES.items():
            P = dict(ds.DEFAULTS, mu_mal=mu)
            S = ds.scores(D, P, ds.W_ADAPT); SU = None
            cfgs = MAIN_CFGS + (ABL_CFGS if topo == "reference" else [])
            for c in cfgs:
                if c == "ztas_uniform_w":
                    SU = ds.scores(D, P, ds.W_UNIFORM) if SU is None else SU
                    res = ds.simulate(prep, D, c, P, SU)
                else:
                    res = ds.simulate(prep, D, c, P, S)
                rows.append([topo, g, gs, r, rs, prof, c] + [res[m] for m in METRICS])
    return rows


PV = [0.0, 0.1, 0.3, 0.5, 0.7, 0.8, 0.9, 0.95, 0.99]
FART = [0.5, 1.0]


def task_pv(args):
    ti, g = args
    topo = TOPOS[ti]; gs = gseed(ti, g)
    prep = ds.Prepared(tp.build(topo, gs)); rows = []
    for r in range(20):
        rs = rseed(gs, r); D = ds.draws(prep, ds.DEFAULTS["T"], rs)
        for prof, mu in PROFILES.items():
            P0 = dict(ds.DEFAULTS, mu_mal=mu); S = ds.scores(D, P0, ds.W_ADAPT)
            for fa, pv in itertools.product(FART, PV):
                P = dict(P0, f_art=fa, p_v=pv)
                for c in ["zt_prov", "ztas"]:
                    res = ds.simulate(prep, D, c, P, S)
                    rows.append([topo, g, gs, r, rs, prof, c, fa, pv] + [res[m] for m in METRICS])
            # reference points without provenance (p_v irrelevant)
            for c in ["zt", "ztas_no_prov"]:
                for fa in FART:
                    res = ds.simulate(prep, D, c, dict(P0, f_art=fa), S)
                    rows.append([topo, g, gs, r, rs, prof, c, fa, np.nan] + [res[m] for m in METRICS])
    return rows


OAT = {
    "p_exploit": [0.15, 0.30, 0.45], "p_auth": [0.25, 0.50, 0.75], "d_generic": [0.01, 0.05, 0.10],
    "p_act": [0.1, 0.3, 0.6, 1.0], "f_art": [0.2, 0.5, 0.8, 1.0], "p_v": [0.5, 0.9, 0.99],
    "kappa": [1.0, 2.0, 3.0, 5.0], "stepup_fail": [0.3, 0.7, 0.9], "mu_mal": [15.0, 28.0, 40.0, 55.0],
    "T": [30, 60, 120], "approval_delay": [0, 2, 5], "zone_detect": [0.1, 0.2, 0.4],
}


def task_oat(args):
    ti, g = args
    topo = TOPOS[ti]; gs = gseed(ti, g)
    prep = ds.Prepared(tp.build(topo, gs)); rows = []
    for r in range(30):
        rs = rseed(gs, r); D120 = ds.draws(prep, 120, rs)
        for par, vals in OAT.items():
            for val in vals:
                P = dict(ds.DEFAULTS, mu_mal=28.0); P[par] = val
                T = int(P["T"]); D = {k: (v[:T] if isinstance(v, np.ndarray) else v) for k, v in D120.items()}
                S = ds.scores(D, P, ds.W_ADAPT)
                cfgs = ["zones"] if par == "zone_detect" else ["zt", "zt_prov", "ztas"]
                for c in cfgs:
                    res = ds.simulate(prep, D, c, P, S)
                    rows.append([topo, g, gs, r, rs, "stealthy", c, par, val] + [res[m] for m in METRICS])
    return rows


if __name__ == "__main__":
    mode, out = sys.argv[1], sys.argv[2]
    if mode == "main":
        tasks = [(ti, g) for ti in range(len(TOPOS)) for g in range(N_GRAPHS)]
        hdr = ["topology", "graph", "graph_seed", "run", "run_seed", "profile", "config"] + METRICS; fn = task_main
    elif mode == "pv":
        tasks = [(ti, g) for ti in range(len(TOPOS)) for g in range(N_GRAPHS)]
        hdr = ["topology", "graph", "graph_seed", "run", "run_seed", "profile", "config", "f_art", "p_v"] + METRICS; fn = task_pv
    else:
        tasks = [(0, g) for g in range(N_GRAPHS)]
        hdr = ["topology", "graph", "graph_seed", "run", "run_seed", "profile", "config", "param", "value"] + METRICS; fn = task_oat
    with open(out, "w", newline="") as f:
        w = csv.writer(f); w.writerow(hdr)
        with Pool(2) as pool:
            for k, rows in enumerate(pool.imap_unordered(fn, tasks)):
                w.writerows(rows)
                if k % 30 == 0:
                    print(mode, k, "/", len(tasks), flush=True)
    print("done", out)
