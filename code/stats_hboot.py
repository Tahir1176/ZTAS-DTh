"""
Hierarchical (two-stage) bootstrap for clustered Monte-Carlo data: runs nested in graph instances.
Stage 1 resamples graphs with replacement; stage 2 resamples runs within each selected graph.
This accounts for between-graph variability instead of treating all runs as independent (audit C6).

Usage: python3 stats_hboot.py ../data/raw/e1_main.csv,../data/raw/e1_main_rec.csv ../data/processed
Outputs: e1_summary.csv, e1_per_graph.csv, e1_effects.csv
"""
import sys, os
import numpy as np
import pandas as pd

B = 2000
METRICS = ["frac", "reach_O", "n_phases", "path_len", "detected", "t_detect", "contained", "residual", "t_reach_O"]


def matrix(df, metric):
    piv = df.pivot_table(index="graph", columns="run", values=metric, aggfunc="first")
    return piv.to_numpy(float)


def hboot(X, rng, stat=np.nanmean):
    G, R = X.shape
    gi = rng.integers(G, size=(B, G))
    ri = rng.integers(R, size=(B, G, R))
    samp = X[gi[:, :, None], ri]
    with np.errstate(all="ignore"):
        m = np.nanmean(samp.reshape(B, -1), axis=1)
    return np.nanpercentile(m, [2.5, 97.5])


def summarize(df, rng):
    rows = []
    for (topo, prof, cfg), d in df.groupby(["topology", "profile", "config"]):
        for met in METRICS:
            X = matrix(d, met); flat = X[~np.isnan(X)]
            if flat.size == 0:
                rows.append([topo, prof, cfg, met] + [np.nan] * 9); continue
            lo, hi = hboot(X, rng)
            gm = np.nanmean(X, axis=1)
            naive = 1.96 * flat.std(ddof=1) / np.sqrt(flat.size)
            rows.append([topo, prof, cfg, met, flat.mean(), flat.std(ddof=1), np.median(flat), lo, hi,
                         np.nanstd(gm, ddof=1), flat.mean() - naive, flat.mean() + naive, flat.size])
    return pd.DataFrame(rows, columns=["topology", "profile", "config", "metric", "mean", "sd", "median",
                                       "ci_lo", "ci_hi", "sd_between_graphs", "naive_ci_lo", "naive_ci_hi", "n"])


def effects(df, rng, target="ztas", baselines=("perimeter", "zones", "zt", "zt_prov"),
            metrics=("frac", "reach_O", "contained")):
    rows = []
    key = ["topology", "profile", "graph", "run"]
    for (topo, prof), d in df.groupby(["topology", "profile"]):
        t = d[d.config == target].set_index(["graph", "run"])
        for b in list(baselines) + ([] if target == "zt_prov" else []):
            bb = d[d.config == b].set_index(["graph", "run"])
            for met in metrics:
                diff = (t[met] - bb[met]).reset_index()
                X = diff.pivot_table(index="graph", columns="run", values=met).to_numpy(float)
                lo, hi = hboot(X, rng)
                gm = np.nanmean(X, axis=1)
                dz = gm.mean() / gm.std(ddof=1) if gm.std(ddof=1) > 0 else np.nan
                frac_graphs_better = float(np.mean(gm < 0)) if met != "contained" else float(np.mean(gm > 0))
                rows.append([topo, prof, target, b, met, np.nanmean(X), lo, hi, dz, frac_graphs_better,
                             bb[met].mean(), t[met].mean()])
    return pd.DataFrame(rows, columns=["topology", "profile", "target", "baseline", "metric", "mean_diff",
                                       "ci_lo", "ci_hi", "d_z_graph_level", "share_graphs_favouring_target",
                                       "baseline_mean", "target_mean"])


if __name__ == "__main__":
    srcs, outdir = sys.argv[1].split(","), sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    rng = np.random.default_rng(20261118)
    df = pd.concat([pd.read_csv(x) for x in srcs], ignore_index=True)
    summ = summarize(df, rng); summ.to_csv(os.path.join(outdir, "e1_summary.csv"), index=False)
    pg = df.groupby(["topology", "profile", "config", "graph", "graph_seed"])[METRICS].mean().reset_index()
    pg.to_csv(os.path.join(outdir, "e1_per_graph.csv"), index=False)
    eff = pd.concat([effects(df, rng, target="ztas_rec", baselines=("perimeter", "zones", "zt", "zt_prov", "ztas")),
                     effects(df, rng),
                     effects(df, rng, target="zt_prov", baselines=("zt",)),
                     effects(df[df.topology == "reference"], rng, target="ztas",
                             baselines=("ztas_no_seg", "ztas_no_risk", "ztas_no_prov", "ztas_uniform_w"))])
    eff.to_csv(os.path.join(outdir, "e1_effects.csv"), index=False)
    print(summ[summ.metric == "frac"].head(12).to_string())
    print(eff[(eff.metric == "frac")].round(3).to_string())
