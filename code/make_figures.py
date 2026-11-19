"""
All result figures of the revised manuscript, generated ONLY from files in ../data.
Usage: python3 make_figures.py   (writes ../figures/*.pdf)
"""
import os, json
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
D = lambda *p: os.path.join(HERE, "..", "data", *p)
OUT = os.path.join(HERE, "..", "figures"); os.makedirs(OUT, exist_ok=True)
C = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6"]
INK, INK2 = "#0b0b0b", "#52514e"
plt.rcParams.update({"font.family": "serif", "font.size": 7.5, "axes.edgecolor": INK2, "axes.labelcolor": INK,
                     "xtick.color": INK2, "ytick.color": INK2, "axes.spines.top": False, "axes.spines.right": False,
                     "axes.grid": True, "grid.color": "#e4e3df", "grid.linewidth": 0.5, "axes.axisbelow": True,
                     "legend.frameon": False, "pdf.fonttype": 42})
CFG = ["perimeter", "zones", "zt", "zt_prov", "ztas_rec"]
CFGL = ["Perimeter", "Static zones", "Static ZT", "Static ZT + prov.", "ZTAS-DTh"]
TOPO = ["reference", "sparse", "dense", "hub_spoke", "high_interconnect", "shared_repo", "multi_supplier", "feedback_loop", "multi_org"]
TOPOL = ["Reference", "Sparse", "Dense", "Hub-spoke", "High\ninterconn.", "Shared\nrepo", "Multi-\nsupplier", "Feedback\nloop", "Multi-org"]

S = pd.read_csv(D("processed", "e1_summary.csv"))


def fig_propagation():
    fig, ax = plt.subplots(2, 1, figsize=(7.1, 3.9), sharex=True)
    x = np.arange(len(TOPO)); w = 0.16
    for r, (met, lab) in enumerate([("frac", "Fraction compromised"), ("reach_O", "P(reach operations)")]):
        for i, c in enumerate(CFG):
            d = S[(S.metric == met) & (S.profile == "stealthy") & (S.config == c)].set_index("topology").loc[TOPO]
            ax[r].bar(x + (i - 2) * w, d["mean"], w * 0.92, color=C[i], label=CFGL[i],
                      yerr=[d["mean"] - d["ci_lo"], d["ci_hi"] - d["mean"]], error_kw=dict(lw=0.5, capsize=1, ecolor=INK2))
        ax[r].set_ylabel(lab); ax[r].set_ylim(0, 1.05)
    ax[1].set_xticks(x, TOPOL, fontsize=6.8)
    fig.legend(*ax[0].get_legend_handles_labels(), loc="upper center", ncol=5, fontsize=7)
    fig.tight_layout(rect=(0, 0, 1, 0.93)); fig.savefig(os.path.join(OUT, "fig_propagation.pdf")); plt.close()


def fig_ablation():
    order = ["ztas_rec", "ztas", "ztas_no_seg", "ztas_no_risk", "ztas_no_prov", "ztas_uniform_w", "zt_prov", "zt"]
    lab = ["Full\n(rec. rule)", "Full\n(v1 rule)", "w/o\nsegment.", "w/o risk\nengine", "w/o\nprov.", "uniform\nweights", "ZT +\nprov.", "Static\nZT"]
    fig, ax = plt.subplots(figsize=(3.5, 2.4)); x = np.arange(len(order)); w = 0.38
    for j, (prof, col) in enumerate([("noisy", C[0]), ("stealthy", C[1])]):
        d = S[(S.metric == "frac") & (S.topology == "reference") & (S.profile == prof)].set_index("config").loc[order]
        ax.bar(x + (j - 0.5) * w, d["mean"], w * 0.9, color=col, label=prof.capitalize() + " attacker",
               yerr=[d["mean"] - d["ci_lo"], d["ci_hi"] - d["mean"]], error_kw=dict(lw=0.5, capsize=1, ecolor=INK2))
    ax.set_xticks(x, [l.replace("\n", " ") for l in lab], fontsize=5.8, rotation=35, ha="right"); ax.set_ylabel("Fraction compromised"); ax.set_ylim(0, 1); ax.legend(fontsize=6.5)
    fig.tight_layout(); fig.savefig(os.path.join(OUT, "fig_ablation.pdf")); plt.close()


def fig_sensitivity():
    ps = pd.read_csv(D("processed", "provenance_sensitivity.csv"))
    oat = pd.read_csv(D("raw", "e1_oat.csv"))
    fig, ax = plt.subplots(1, 2, figsize=(7.1, 2.5))
    k = 0
    for cfg, col in [("zt_prov", C[3]), ("ztas", C[0])]:
        for fa, ls, mk in [(0.5, "-", "o"), (1.0, "--", "s")]:
            d = ps[(ps.topology == "reference") & (ps.profile == "stealthy") & (ps.config == cfg) & (ps.f_art == fa)].sort_values("p_v")
            ax[0].plot(d.p_v, d.compromised_fraction, ls, color=col, marker=mk, ms=3, lw=1.3,
                       label=f"{'ZT + prov.' if cfg == 'zt_prov' else 'ZTAS-DTh (v1 rule)'}, $f_{{art}}$={fa}")
            ax[0].fill_between(d.p_v, d.compromised_fraction_ci_lo, d.compromised_fraction_ci_hi, color=col, alpha=0.12, lw=0)
    ax[0].set_xlabel(r"Provenance detection probability $p_v$ (assumed)"); ax[0].set_ylabel("Fraction compromised")
    ax[0].set_ylim(0, 0.9); ax[0].legend(fontsize=6); ax[0].set_title("(a) Provenance sensitivity, stealthy attacker", fontsize=7.5)
    z = oat[oat.config == "ztas"].groupby(["param", "value"])["frac"].mean().reset_index()
    base = z[(z.param == "p_v") & (z.value == 0.9)]["frac"].iloc[0]
    rng = z.groupby("param")["frac"].agg(["min", "max"]); rng["span"] = rng["max"] - rng["min"]
    rng = rng.drop(index=[p for p in ["zone_detect"] if p in rng.index]).sort_values("span")
    names = {"p_act": r"$p_{act}$ segment open", "d_generic": r"$d$ generic detect.", "p_exploit": r"$p_x$ exploit",
             "p_auth": r"$p_a$ authN defeat", "f_art": r"$f_{art}$ artifact share", "mu_mal": r"$\mu_{mal}$ stealth",
             "p_v": r"$p_v$ provenance", "kappa": r"$\kappa$ evidence thr.", "T": "horizon $T$",
             "stepup_fail": "step-up failure", "approval_delay": "approval delay"}
    y = np.arange(len(rng))
    ax[1].barh(y, rng["max"] - rng["min"], left=rng["min"], color=C[0], height=0.6)
    ax[1].axvline(base, color=INK2, lw=0.8, ls=":")
    ax[1].set_yticks(y, [names.get(p, p) for p in rng.index], fontsize=6.5)
    ax[1].set_xlabel("Fraction compromised (range over tested values)")
    ax[1].set_title("(b) One-at-a-time sensitivity of ZTAS-DTh (v1 rule)", fontsize=7.5)
    fig.tight_layout(); fig.savefig(os.path.join(OUT, "fig_sensitivity.pdf")); plt.close()


def fig_risk():
    cur = pd.read_csv(D("raw", "e2_curves.csv")); ev = pd.read_csv(D("processed", "e2_evidence_accumulation.csv"))
    fig, ax = plt.subplots(1, 2, figsize=(7.1, 2.5))
    fams = [("gaussian", 28, "Gaussian"), ("skewed", 28, "Skewed"), ("heavy_tailed", 28, "Heavy-tailed"),
            ("correlated", 28, "Correlated"), ("overlapping", 20, r"Overlapping ($\mu$=20)"), ("shift", 28, "Shift (unadapted)")]
    for i, (f, mu, lab) in enumerate(fams):
        d = cur[(cur.family == f) & (cur.mu_mal == mu) & (cur.weights == "production")].sort_values("threshold")
        ax[0].plot(d.FPR, d.TPR, color=C[i], lw=1.2, label=lab)
        t = d[d.threshold == 30]; ax[0].plot(t.FPR, t.TPR, "o", color=C[i], ms=3.5, mec="white", mew=0.6)
    d = cur[(cur.family == "shift") & (cur.weights == "maintenance")].sort_values("threshold")
    ax[0].plot(d.FPR, d.TPR, "--", color=C[5], lw=1.2, label="Shift, mode-aware weights")
    ax[0].set_xscale("symlog", linthresh=1e-3); ax[0].set_xlim(0, 1)
    ax[0].set_xlabel("False-positive rate (legitimate escalated)"); ax[0].set_ylabel("True-positive rate")
    ax[0].set_title(r"(a) ROC, stealthy attacker, markers at $\theta_1$=30", fontsize=7.5); ax[0].legend(fontsize=5.8, loc="upper left")
    l = ev[(ev.kind == "legitimate") & (ev.scenario == "heavy_tailed_fpr") & (ev.cls == "field_device")]
    pol = [("no_decay_no_reset", "No decay, no reset (v1)"), ("reset_on_success", "Reset on success"),
           ("decay_h30", "Decay ($h$=30)"), ("decay_h30_conn_aware", "Decay + outage-aware")]
    for i, (p, lab) in enumerate(pol):
        d = l[l.policy == p].sort_values("kappa")
        ax[1].plot(d.kappa, d.false_isolation_per_shift * 100, "-o", color=C[i], ms=3, lw=1.2, label=lab)
    ax[1].set_xlabel(r"Evidence threshold $\kappa$"); ax[1].set_ylabel("Legitimate devices isolated per shift (%)")
    ax[1].set_title("(b) False isolation, field devices, heavy-tailed scores", fontsize=7.5); ax[1].legend(fontsize=6)
    fig.tight_layout(); fig.savefig(os.path.join(OUT, "fig_risk.pdf")); plt.close()


def fig_crypto():
    R = json.load(open(D("raw", "e3_crypto_v2.json"))); bl = pd.read_csv(D("processed", "e3_batching_latency.csv"))
    fig, ax = plt.subplots(1, 2, figsize=(7.1, 2.4))
    B = [m["batch"] for m in R["merkle"]]
    ax[0].plot(B, [m["sign_per_record_us"] for m in R["merkle"]], "-o", color=C[0], ms=3, label="Signing (tree + ML-DSA-65) / record")
    ax[0].plot(B, [m["verify_per_record_us_independent"] for m in R["merkle"]], "-s", color=C[1], ms=3, label="Verify one record (sig. + proof)")
    ax[0].plot(B, [m["verify_per_record_us_batch"] for m in R["merkle"]], "-^", color=C[2], ms=3, label="Verify whole batch / record")
    ax[0].set_xscale("log", base=2); ax[0].set_yscale("log"); ax[0].set_xlabel("Batch size $B$"); ax[0].set_ylabel(r"Median cost per record ($\mu$s)")
    ax[0].set_title("(a) Measured cost (server CPU)", fontsize=7.5); ax[0].legend(fontsize=6)
    for i, (Bt, tau, lab) in enumerate([(1, np.inf, "$B$=1"), (64, 100.0, "$B$=64, $\\tau$=100 ms"), (256, 100.0, "$B$=256, $\\tau$=100 ms"),
                                         (1024, 1000.0, "$B$=1024, $\\tau$=1 s")]):
        d = bl[(bl.batch_target == Bt) & (bl.timeout_ms == tau)].sort_values("arrival_rate")
        stable = d.stable.astype(bool)
        ax[1].plot(d.arrival_rate[stable], d.latency_p99_ms[stable], "-o", color=C[i], ms=3, label=lab)
        ax[1].plot(d.arrival_rate[~stable], np.full((~stable).sum(), 1e5), "x", color=C[i], ms=5)
    ax[1].set_xscale("log"); ax[1].set_yscale("log"); ax[1].set_xlabel("Record arrival rate (records/s)")
    ax[1].set_ylabel("p99 signing latency incl. batch wait (ms)"); ax[1].set_title("(b) Modelled latency; x = signer saturated", fontsize=7.5)
    ax[1].legend(fontsize=6)
    fig.tight_layout(); fig.savefig(os.path.join(OUT, "fig_crypto.pdf")); plt.close()


if __name__ == "__main__":
    fig_propagation(); fig_ablation(); fig_sensitivity(); fig_risk(); fig_crypto(); print("figures written to", OUT)
