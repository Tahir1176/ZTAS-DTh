"""
Provenance-verification sensitivity analysis (R1). Reads ../data/raw/e1_pv.csv and writes
  ../data/processed/provenance_sensitivity.csv      (all topologies, hierarchical-bootstrap CIs)
p_v is a SIMULATION PARAMETER (assumed probability that a provenance gate rejects a malicious artifact),
not an experimentally measured detection rate.
"""
import sys, os
import numpy as np
import pandas as pd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from stats_hboot import hboot

METS = {"frac": "compromised_fraction", "reach_O": "propagation_prob_to_operations",
        "contained": "containment_prob", "detected": "detection_prob", "residual": "residual_compromise"}

if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else "../data/raw/e1_pv.csv"
    out = sys.argv[2] if len(sys.argv) > 2 else "../data/processed/provenance_sensitivity.csv"
    rng = np.random.default_rng(7)
    df = pd.read_csv(src)
    rows = []
    for key, d in df.groupby(["topology", "profile", "config", "f_art", "p_v"], dropna=False):
        rec = dict(zip(["topology", "profile", "config", "f_art", "p_v"], key))
        rec["n_graphs"] = d.graph.nunique(); rec["n_runs"] = len(d)
        for m, name in METS.items():
            X = d.pivot_table(index="graph", columns="run", values=m).to_numpy(float)
            lo, hi = hboot(X, rng)
            rec[name] = float(np.nanmean(X)); rec[name + "_ci_lo"] = lo; rec[name + "_ci_hi"] = hi
        rows.append(rec)
    res = pd.DataFrame(rows)
    res.to_csv(out, index=False)
    r = res[(res.topology == "reference")]
    print(r[["profile", "config", "f_art", "p_v", "compromised_fraction", "propagation_prob_to_operations",
             "containment_prob", "residual_compromise"]].round(3).to_string())
