"""
E1 supplement: ZTAS-DTh with the evidence policy recommended by E2 (kappa=3, per-step decay 0.95),
evaluated on exactly the same graphs and run seeds as run_e1.py main (paired with e1_main.csv).
Usage: python3 run_e1_rec.py ../data/raw/e1_main_rec.csv
"""
import sys, csv
from multiprocessing import Pool
import topologies as tp, dth_sim as ds
from run_e1 import TOPOS, PROFILES, METRICS, N_GRAPHS, N_RUNS, gseed, rseed
REC = dict(kappa=3.0, decay=0.95)

def task(args):
    ti, g = args; topo = TOPOS[ti]; gs = gseed(ti, g)
    prep = ds.Prepared(tp.build(topo, gs)); rows = []
    for r in range(N_RUNS):
        rs = rseed(gs, r); D = ds.draws(prep, ds.DEFAULTS["T"], rs)
        for prof, mu in PROFILES.items():
            P = dict(ds.DEFAULTS, mu_mal=mu, **REC); S = ds.scores(D, P, ds.W_ADAPT)
            res = ds.simulate(prep, D, "ztas", P, S)
            rows.append([topo, g, gs, r, rs, prof, "ztas_rec"] + [res[m] for m in METRICS])
    return rows

if __name__ == "__main__":
    with open(sys.argv[1], "w", newline="") as f:
        w = csv.writer(f); w.writerow(["topology", "graph", "graph_seed", "run", "run_seed", "profile", "config"] + METRICS)
        with Pool(2) as p:
            for rows in p.imap_unordered(task, [(ti, g) for ti in range(len(TOPOS)) for g in range(N_GRAPHS)]):
                w.writerows(rows)
    print("done")
