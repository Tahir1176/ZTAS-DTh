"""
Generate LaTeX table bodies (complete tabular environments) and CSV copies from ../data only.
Usage: python3 make_tables.py  -> ../tables/*.tex, ../tables/*.csv
"""
import os, json
import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
D = lambda *p: os.path.join(HERE, "..", "data", *p)
T = os.path.join(HERE, "..", "tables"); os.makedirs(T, exist_ok=True)
TOPO = ["reference", "sparse", "dense", "hub_spoke", "high_interconnect", "shared_repo", "multi_supplier", "feedback_loop", "multi_org"]
TOPOL = ["Reference", "Sparse", "Dense", "Hub-and-spoke", "Highly interconnected", "Shared repository", "Multi-supplier", "Feedback loop", "Multi-organisation"]
CFG = ["perimeter", "zones", "zt", "zt_prov", "ztas_rec"]


def w(name, s): open(os.path.join(T, name), "w").write(s)


def f3(m, lo, hi): return f"{m:.3f} [{lo:.3f}, {hi:.3f}]"


S = pd.read_csv(D("processed", "e1_summary.csv")); E = pd.read_csv(D("processed", "e1_effects.csv"))

# ---- Table: main E1 (stealthy, fraction compromised) per topology
rows = []
for t, tl in zip(TOPO, TOPOL):
    cells = []
    for c in CFG:
        r = S[(S.topology == t) & (S.profile == "stealthy") & (S.config == c) & (S.metric == "frac")].iloc[0]
        cells.append(f"{r['mean']:.2f}\\,[{r.ci_lo:.2f},{r.ci_hi:.2f}]")
    rows.append(tl + " & " + " & ".join(cells) + r" \\")
w("tab_e1_main.tex", "\\begin{tabular}{@{}lccccc@{}}\n\\toprule\nTopology & Perimeter & Static zones & Static ZT & ZT + prov. & ZTAS-DTh \\\\\n\\midrule\n"
  + "\n".join(rows) + "\n\\bottomrule\n\\end{tabular}\n")
S.to_csv(os.path.join(T, "e1_summary_all_metrics.csv"), index=False)

# ---- Table: paired effects ZTAS-DTh(rec) vs ZT+prov and vs ZT, both profiles
rows = []
for t, tl in zip(TOPO, TOPOL):
    cells = []
    for prof in ["noisy", "stealthy"]:
        for b in ["zt", "zt_prov"]:
            r = E[(E.topology == t) & (E.profile == prof) & (E.target == "ztas_rec") & (E.baseline == b) & (E.metric == "frac")].iloc[0]
            cells.append(f"{r.mean_diff:+.2f}\\,[{r.ci_lo:+.2f},{r.ci_hi:+.2f}]")
    rows.append(tl + " & " + " & ".join(cells) + r" \\")
w("tab_e1_effects.tex", "\\begin{tabular}{@{}lcccc@{}}\n\\toprule\n & \\multicolumn{2}{c}{Noisy attacker} & \\multicolumn{2}{c}{Stealthy attacker} \\\\\n"
  "\\cmidrule(lr){2-3}\\cmidrule(lr){4-5}\nTopology & vs.\\ static ZT & vs.\\ ZT + prov. & vs.\\ static ZT & vs.\\ ZT + prov. \\\\\n\\midrule\n"
  + "\n".join(rows) + "\n\\bottomrule\n\\end{tabular}\n")
E.to_csv(os.path.join(T, "e1_effects.csv"), index=False)

# ---- Table: reference topology, all metrics, stealthy
mets = [("frac", "Compromised"), ("reach_O", "P(reach O)"), ("n_phases", "Phases"), ("path_len", "Path len."),
        ("t_detect", "Steps to det."), ("contained", "Contained"), ("residual", "Residual")]
rows = []
names = dict(perimeter="Perimeter", zones="Static zones", zt="Static ZT", zt_prov="ZT + prov.", ztas_rec="ZTAS-DTh")
for c in CFG:
    cells = []
    for m, _ in mets:
        r = S[(S.topology == "reference") & (S.profile == "stealthy") & (S.config == c) & (S.metric == m)].iloc[0]
        cells.append("--" if np.isnan(r["mean"]) else (f"{r['mean']:.2f}" if m not in ("n_phases", "path_len", "t_detect") else f"{r['mean']:.1f}"))
    rows.append(names[c] + " & " + " & ".join(cells) + r" \\")
w("tab_e1_metrics.tex", "\\begin{tabular}{@{}l" + "c" * len(mets) + "@{}}\n\\toprule\nConfiguration & " + " & ".join(l for _, l in mets)
  + " \\\\\n\\midrule\n" + "\n".join(rows) + "\n\\bottomrule\n\\end{tabular}\n")

# ---- Table: risk engine metrics (production weights, prevalence 1%)
M = pd.read_csv(D("processed", "e2_metrics.csv"))
m = M[(M.prevalence == 0.01)]
rows = []
lab = dict(gaussian="Gaussian", skewed="Skewed", heavy_tailed="Heavy-tailed", correlated="Correlated", overlapping="Overlapping", shift="Distribution shift")
for _, r in m.iterrows():
    if r.weights == "uniform" and r.family not in ("gaussian",):
        continue
    wl = {"production": "prod.", "uniform": "unif.", "maintenance": "mode-aware"}[r.weights]
    rows.append(f"{lab[r.family]} & {int(r.mu_mal)} & {wl} & {r.TPR:.3f} & {r.FPR:.4f} & {r.precision:.3f} & {r.F1:.3f} & {r.ROC_AUC:.3f} & {r.PR_AUC:.3f} \\\\")
w("tab_risk.tex", "\\begin{tabular}{@{}lrlcccccc@{}}\n\\toprule\nScore family & $\\mu_{mal}$ & Weights & TPR & FPR & Prec. & F1 & ROC-AUC & PR-AUC \\\\\n\\midrule\n"
  + "\n".join(rows) + "\n\\bottomrule\n\\end{tabular}\n")
M.to_csv(os.path.join(T, "e2_metrics.csv"), index=False)
pd.read_csv(D("processed", "e2_confusion.csv")).to_csv(os.path.join(T, "e2_confusion.csv"), index=False)

# ---- Table: evidence accumulation
EV = pd.read_csv(D("processed", "e2_evidence_accumulation.csv"))
pol = [("no_decay_no_reset", "No decay, no reset (v1)"), ("reset_on_success", "Reset on success"), ("decay_h30", "Decay"), ("decay_h30_conn_aware", "Decay + outage-aware")]
rows = []
for p, pl in pol:
    cells = []
    for k in [2, 3]:
        for cls in ["human_operator", "field_device"]:
            r = EV[(EV.kind == "legitimate") & (EV.scenario == "heavy_tailed_fpr") & (EV.cls == cls) & (EV.policy == p) & (EV.kappa == k)].iloc[0]
            cells.append(f"{100 * r.false_isolation_per_shift:.2f}")
        a = EV[(EV.kind == "malicious") & (EV.scenario == "stealthy") & (EV.policy == p) & (EV.kappa == k)].iloc[0]
        cells.append(f"{a.median_requests_to_isolation:.0f}")
    rows.append(pl + " & " + " & ".join(cells) + r" \\")
w("tab_evidence.tex", "\\begin{tabular}{@{}lcccccc@{}}\n\\toprule\n & \\multicolumn{3}{c}{$\\kappa=2$} & \\multicolumn{3}{c}{$\\kappa=3$} \\\\\n"
  "\\cmidrule(lr){2-4}\\cmidrule(lr){5-7}\nPolicy & Human & Device & Attacker & Human & Device & Attacker \\\\\n\\midrule\n"
  + "\n".join(rows) + "\n\\bottomrule\n\\end{tabular}\n")
EV.to_csv(os.path.join(T, "e2_evidence_accumulation.csv"), index=False)

# ---- Table: crypto
R = json.load(open(D("raw", "e3_crypto_v2.json")))
rows = []
for k, v in R["sig"].items():
    rows.append(f"{k} & {v['sign']['median_us']:.1f} & {v['sign']['p99_us']:.1f} & {v['verify']['median_us']:.1f} & {v['verify']['p99_us']:.1f} & {v['sig_B']} & {v['pk_B']} \\\\")
kem = R["kem"]
rows.append("\\midrule")
rows.append(f"X25519 (exchange) & -- & -- & {kem['X25519']['exchange']['median_us']:.1f} & {kem['X25519']['exchange']['p99_us']:.1f} & 32 & 32 \\\\")
rows.append(f"ML-KEM-768 (encaps / decaps) & {kem['ML-KEM-768']['encaps']['median_us']:.1f} & {kem['ML-KEM-768']['encaps']['p99_us']:.1f} & {kem['ML-KEM-768']['decaps']['median_us']:.1f} & {kem['ML-KEM-768']['decaps']['p99_us']:.1f} & {kem['ML-KEM-768']['ct_B']} & {kem['ML-KEM-768']['pk_B']} \\\\")
w("tab_crypto.tex", "\\begin{tabular}{@{}lrrrrrr@{}}\n\\toprule\nScheme & Sign med. & Sign p99 & Verify med. & Verify p99 & Sig./ct (B) & PK (B) \\\\\n\\midrule\n"
  + "\n".join(rows) + "\n\\bottomrule\n\\end{tabular}\n")

# ---- Table: PoC latency
P = json.load(open(D("raw", "poc_results.json")))
L = P["latency"]; rows = []
for k, lab_ in [("direct_to_twin_baseline", "Direct call to twin (no controls)"), ("end_to_end_no_artifact", "End-to-end, no artifact"),
                ("end_to_end_with_artifact", "End-to-end, with artifact")]:
    v = L[k]; rows.append(f"{lab_} & {v['median_us']/1e3:.2f} & {v['p95_us']/1e3:.2f} & {v['p99_us']/1e3:.2f} \\\\")
rows.append("\\midrule")
for k, lab_ in [("token_us", "Token + revocation check"), ("segment_us", "Segment check (RPC)"), ("provenance_us", "Provenance + lineage check"),
                ("pdp_us", "Policy decision (RPC)"), ("forward_us", "Forward to twin (RPC)"), ("pep_total_us", "PEP total")]:
    v = L["components"][k]; rows.append(f"{lab_} & {v['median_us']/1e3:.2f} & {v['p95_us']/1e3:.2f} & {v['p99_us']/1e3:.2f} \\\\")
w("tab_poc.tex", "\\begin{tabular}{@{}lrrr@{}}\n\\toprule\nPath / stage (1000 requests) & Median (ms) & p95 (ms) & p99 (ms) \\\\\n\\midrule\n"
  + "\n".join(rows) + "\n\\bottomrule\n\\end{tabular}\n")
print("tables written:", sorted(os.listdir(T)))
