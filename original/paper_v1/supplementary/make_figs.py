import json, sys
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import os
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import sim_propagation as sp

C = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]
INK, INK2 = "#0b0b0b", "#52514e"
plt.rcParams.update({"font.family": "serif", "font.size": 8, "axes.edgecolor": INK2,
                     "axes.labelcolor": INK, "xtick.color": INK2, "ytick.color": INK2,
                     "axes.spines.top": False, "axes.spines.right": False,
                     "axes.grid": True, "grid.color": "#e4e3df", "grid.linewidth": 0.5,
                     "axes.axisbelow": True, "legend.frameon": False, "pdf.fonttype": 42})
S = json.load(open(os.path.join(HERE, "results_sim.json")))
K = json.load(open(os.path.join(HERE, "results_crypto.json")))
OUT = os.path.join(HERE, "..", "figs") + os.sep
import os; os.makedirs(OUT, exist_ok=True)
cfgs = ["perimeter", "zones", "zt_static", "ztas"]
lab = ["Perimeter", "Static zones\n(IEC 62443)", "Static ZT\n(SP 800-207)", "ZTAS-DTh"]

# Fig: main comparison, two panels (fraction compromised | P(reach operations))
fig, ax = plt.subplots(1, 2, figsize=(7.0, 2.3))
x = np.arange(4); w = 0.38
for j, (key, name) in enumerate([("main", "Noisy attacker"), ("main_stealthy", "Stealthy attacker")]):
    for i, (m, mci, title) in enumerate([("frac", "frac_ci", "(a) Fraction of DTh nodes compromised"),
                                         ("reachO", "reachO_ci", "(b) P(attack reaches operations phase)")]):
        v = [S[key][c][m] for c in cfgs]; e = [S[key][c][mci] for c in cfgs]
        ax[i].bar(x + (j - 0.5) * w, v, w - 0.03, yerr=e, color=C[j], label=name,
                  error_kw=dict(lw=0.6, capsize=1.5, ecolor=INK2))
        ax[i].text(3 + (j - 0.5) * w, v[3] + 0.04, f"{v[3]:.2f}", ha="center", fontsize=6.5, color=INK)
        ax[i].set_title(title, fontsize=8, color=INK); ax[i].set_xticks(x, lab, fontsize=6.5)
        ax[i].set_ylim(0, 1.12)
fig.legend(*ax[0].get_legend_handles_labels(), loc="upper center", ncol=2, fontsize=7)
fig.tight_layout(rect=(0, 0, 1, 0.9)); fig.savefig(OUT + "fig_propagation.pdf"); plt.close()

# Fig: ablation (stealthy)
A = S["ablation"]
order = ["full", "no_seg", "no_risk", "no_prov", "uniform_w", "none"]
alab = ["Full", "w/o dyn.\nsegment.", "w/o risk\nengine", "w/o prov.\nverif.", "uniform\nweights", "auth.\nonly"]
fig, ax = plt.subplots(figsize=(3.45, 2.1))
v = [A[k]["frac"] for k in order]; e = [A[k]["frac_ci"] for k in order]
ax.bar(range(6), v, 0.6, yerr=e, color=C[0], error_kw=dict(lw=0.6, capsize=1.5, ecolor=INK2))
for i, vi in enumerate(v): ax.text(i, vi + 0.03, f"{vi:.2f}", ha="center", fontsize=6.5)
ax.set_xticks(range(6), alab, fontsize=6.5); ax.set_ylabel("Fraction compromised"); ax.set_ylim(0, 1.1)
fig.tight_layout(); fig.savefig(OUT + "fig_ablation.pdf"); plt.close()

# Fig: sensitivity (two panels)
fig, ax = plt.subplots(1, 2, figsize=(7.0, 2.2))
mu = [r["mu_mal"] for r in S["sens_mu"]]
ax[0].errorbar(mu, [r["frac"] for r in S["sens_mu"]], [r["frac_ci"] for r in S["sens_mu"]],
               color=C[0], marker="o", ms=4, lw=1.5, capsize=2, label="Fraction compromised")
ax[0].errorbar(mu, [r["contained"] for r in S["sens_mu"]], [r["contained_ci"] for r in S["sens_mu"]],
               color=C[1], marker="s", ms=4, lw=1.5, capsize=2, label="Isolation ratio")
ax[0].axvline(15, color=INK2, lw=0.6, ls=":"); ax[0].text(15.5, 0.45, "legitimate\nmean", fontsize=6, color=INK2)
ax[0].set_xlabel(r"Attacker behavioural-risk mean $\mu_{mal}$"); ax[0].set_ylim(0, 1.05)
ax[0].set_title("(a) Attacker stealth", fontsize=8); ax[0].legend(fontsize=6.5, loc="center right")
pv = [r["prov_detect"] for r in S["sens_prov"]]
ax[1].errorbar(pv, [r["frac"] for r in S["sens_prov"]], [r["frac_ci"] for r in S["sens_prov"]],
               color=C[0], marker="o", ms=4, lw=1.5, capsize=2, label="Fraction compromised")
ax[1].errorbar(pv, [r["reachO"] for r in S["sens_prov"]], [r["reachO_ci"] for r in S["sens_prov"]],
               color=C[2], marker="^", ms=4, lw=1.5, capsize=2, label="P(reach operations)")
ax[1].set_xlabel(r"Provenance check detection probability $p_v$"); ax[1].set_ylim(0, 1.05)
ax[1].set_title("(b) Phase-boundary provenance verification", fontsize=8); ax[1].legend(fontsize=6.5)
fig.tight_layout(); fig.savefig(OUT + "fig_sensitivity.pdf"); plt.close()

# Fig: operating characteristic of the risk engine
fig, ax = plt.subplots(figsize=(3.45, 2.4))
P = sp.PARAMS
for j, (mu, ls) in enumerate([(55.0, "-"), (28.0, "--")]):
    P2 = dict(P, mu_mal=mu)
    for wv, wn, c in [(sp.W_ADAPT, "context-adaptive", C[0]), (sp.W_UNIFORM, "uniform", C[1])]:
        r, _ = sp.roc(P2, wv, n=20000)
        fpr = [a[2] for a in r]; tpr = [a[1] for a in r]
        ax.plot(fpr, tpr, ls, color=c, lw=1.5, label=f"{wn}, $\\mu_{{mal}}$={mu:.0f}")
        th = r[30]; ax.plot(th[2], th[1], "o", color=c, ms=4, mec="white", mew=0.8)
ax.set_xscale("symlog", linthresh=1e-3); ax.set_xlim(0, 1)
ax.set_xlabel("Legitimate requests escalated (FPR)"); ax.set_ylabel("Malicious requests escalated (TPR)")
ax.legend(fontsize=6, loc="lower right")
fig.tight_layout(); fig.savefig(OUT + "fig_roc.pdf"); plt.close()

# Fig: Merkle batching cost (two panels, one measure each)
B = K["batch"]
bs = [b["batch"] for b in B]
fig, ax = plt.subplots(1, 2, figsize=(7.0, 2.1))
ax[0].plot(bs, [b["per_record_us"] for b in B], "-o", color=C[0], ms=4, lw=1.5)
ax[0].set_xscale("log", base=2); ax[0].set_yscale("log")
ax[0].set_xlabel("Batch size $B$ (records per signed Merkle root)"); ax[0].set_ylabel(r"Signing cost per record ($\mu$s)")
ax[0].set_title("(a) Amortised ML-DSA-65 signing cost", fontsize=8)
ax[1].plot(bs, [b["sig_bytes_per_record"] for b in B], "-s", color=C[1], ms=4, lw=1.5)
ax[1].set_xscale("log", base=2); ax[1].set_yscale("log")
ax[1].set_xlabel("Batch size $B$"); ax[1].set_ylabel("Authenticator bytes per record")
ax[1].set_title("(b) Signature + inclusion-proof overhead", fontsize=8)
fig.tight_layout(); fig.savefig(OUT + "fig_batching.pdf"); plt.close()
print("ok")
