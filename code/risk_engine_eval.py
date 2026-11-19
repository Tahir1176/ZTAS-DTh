"""
E2 (revision v2): risk-engine validation under alternative SYNTHETIC score distributions, plus an
evidence-accumulation study. None of these distributions represents measured industrial telemetry.

Usage: python3 risk_engine_eval.py ../data/raw ../data/processed
"""
import sys, os, json
import numpy as np
import pandas as pd

N = 50_000
W = {"production": np.array([0.10, 0.10, 0.35, 0.30, 0.15]),
     "uniform": np.full(5, 0.2),
     "maintenance": np.array([0.05, 0.05, 0.35, 0.40, 0.15])}   # mode-aware: temporal/spatial down-weighted
THETA = (30.0, 70.0, 90.0)


def clip(x): return np.clip(x, 0, 100)


def legit(rng, fam, n=N):
    if fam == "skewed":
        return clip(rng.gamma(2.0, 7.5, (n, 5)))                       # mean 15, right-skewed
    if fam == "heavy_tailed":
        return clip(15 + 8 * rng.standard_t(3, (n, 5)))                # rare large legitimate deviations
    if fam == "correlated":
        C = np.full((5, 5), 0.6); np.fill_diagonal(C, 1.0)
        return clip(15 + 8 * rng.multivariate_normal(np.zeros(5), C, n))
    if fam == "shift":
        x = clip(15 + 8 * rng.standard_normal((n, 5)))
        x[:, 0] = clip(x[:, 0] + 25); x[:, 1] = clip(x[:, 1] + 20)     # night-shift / remote maintenance
        return x
    return clip(15 + 8 * rng.standard_normal((n, 5)))                  # gaussian (v1) and overlapping


def malicious(rng, fam, mu, n=N):
    x = legit(rng, fam if fam != "shift" else "gaussian", n)
    deg = rng.random(n) < 0.5
    if fam == "skewed":
        b = rng.lognormal(np.log(mu), 0.45, n); s = rng.lognormal(np.log(mu), 0.45, n)
    elif fam == "heavy_tailed":
        b = mu + 15 * rng.standard_t(3, n); s = mu + 15 * rng.standard_t(3, n)
    elif fam == "correlated":
        z = rng.standard_normal(n)                                      # common latent factor
        b = mu + 15 * (0.6 * z + 0.8 * rng.standard_normal(n)); s = mu + 15 * (0.6 * z + 0.8 * rng.standard_normal(n))
        x[:, 0] = clip(x[:, 0] + 0.3 * (b - 15)); x[:, 1] = clip(x[:, 1] + 0.3 * (b - 15))
    else:
        b = mu + 15 * rng.standard_normal(n); s = mu + 15 * rng.standard_normal(n)
    x[:, 2] = clip(b); x[:, 3] = np.where(deg, clip(s), x[:, 3])
    return x


FAMILIES = [("gaussian", 55), ("gaussian", 28), ("skewed", 55), ("skewed", 28), ("heavy_tailed", 55),
            ("heavy_tailed", 28), ("correlated", 55), ("correlated", 28), ("overlapping", 20), ("shift", 28)]


def auc(pos, neg):
    allv = np.concatenate([pos, neg]); ranks = allv.argsort().argsort() + 1.0
    # average ranks for ties
    s = pd.Series(allv).rank().to_numpy()
    rp = s[:len(pos)].sum()
    return (rp - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg))


def pr_auc(pos, neg, prev):
    th = np.unique(np.concatenate([pos, neg]))[::-1]
    ps, ns = np.sort(pos), np.sort(neg)
    tpr = 1 - np.searchsorted(ps, th, side="right") / len(ps)
    fpr = 1 - np.searchsorted(ns, th, side="right") / len(ns)
    tp = prev * tpr; fp = (1 - prev) * fpr
    prec = np.where(tp + fp > 0, tp / np.maximum(tp + fp, 1e-300), 1.0)
    rec = tpr
    o = np.argsort(rec); rec, prec = rec[o], prec[o]
    return float(np.sum(np.diff(np.concatenate([[0], rec])) * prec))


def evaluate(out_raw, out_proc, rng):
    rows, curves, conf = [], [], []
    for fam, mu in FAMILIES:
        Lx = legit(rng, fam); Mx = malicious(rng, fam, mu)
        for wname in (["production", "uniform"] + (["maintenance"] if fam == "shift" else [])):
            l = Lx @ W[wname]; m = Mx @ W[wname]
            a = auc(m, l)
            for prev in (0.01, 0.10):
                tpr = float((m > THETA[0]).mean()); fpr = float((l > THETA[0]).mean())
                prec = prev * tpr / (prev * tpr + (1 - prev) * fpr) if (tpr + fpr) > 0 else np.nan
                f1 = 2 * prec * tpr / (prec + tpr) if prec and tpr else 0.0
                rows.append(dict(family=fam, mu_mal=mu, weights=wname, prevalence=prev, threshold=THETA[0],
                                 TPR=tpr, FPR=fpr, FNR=1 - tpr, precision=prec, recall=tpr, F1=f1,
                                 ROC_AUC=a, PR_AUC=pr_auc(m, l, prev),
                                 legit_escalation=fpr, legit_block=float((l > THETA[1]).mean()),
                                 legit_isolation=float((l > THETA[2]).mean()),
                                 mal_stepup=float(((m > THETA[0]) & (m <= THETA[1])).mean()),
                                 mal_block=float(((m > THETA[1]) & (m <= THETA[2])).mean()),
                                 mal_isolate=float((m > THETA[2]).mean()),
                                 legit_mean=float(l.mean()), mal_mean=float(m.mean())))
                if prev == 0.01:
                    n = 100_000; P = int(n * prev); Nn = n - P
                    conf.append(dict(family=fam, mu_mal=mu, weights=wname, per=n, prevalence=prev,
                                     TP=round(P * tpr), FN=round(P * (1 - tpr)), FP=round(Nn * fpr), TN=round(Nn * (1 - fpr))))
            for th in range(0, 101):
                curves.append(dict(family=fam, mu_mal=mu, weights=wname, threshold=th,
                                   TPR=float((m > th).mean()), FPR=float((l > th).mean())))
    pd.DataFrame(rows).to_csv(os.path.join(out_proc, "e2_metrics.csv"), index=False)
    pd.DataFrame(curves).to_csv(os.path.join(out_raw, "e2_curves.csv"), index=False)
    pd.DataFrame(conf).to_csv(os.path.join(out_proc, "e2_confusion.csv"), index=False)
    return pd.DataFrame(rows)


# ---------------- evidence accumulation (sequence model) ----------------
CLASSES = {
    # per-request legitimate step-up/re-attestation failure probability, normal and during outage
    "human_operator": dict(fail=0.02, fail_out=0.02),
    "field_device": dict(fail=0.005, fail_out=0.40),
    "edge_service": dict(fail=0.001, fail_out=0.20),
}
ROUTINE = 0.02   # assumed share of legitimate requests that trigger routine periodic re-verification
POLICIES = ["no_decay_no_reset", "reset_on_success", "decay_h30", "decay_h30_conn_aware"]
KAPPAS = [1, 2, 3, 5, 8]


def run_entity(rng, n_req, p_escalate, fail, fail_out, policy, kappa, outage_frac=0.05, outage_len=10, malicious=False):
    ev = 0.0; out = False
    lam = 0.5 ** (1 / 30)
    p_start = outage_frac / (outage_len * (1 - outage_frac))
    for i in range(n_req):
        if out:
            if rng.random() < 1 / outage_len: out = False
        elif rng.random() < p_start:
            out = True
        if policy.startswith("decay"):
            ev *= lam
        if rng.random() >= p_escalate:
            continue
        f = (0.7 if malicious else (fail_out if out else fail))
        if rng.random() < f:
            if policy == "decay_h30_conn_aware" and out:
                continue                    # failure attributed to known outage: deferred, not counted
            ev += 1.0
            if ev >= kappa:
                return i + 1                # isolated at request i+1
        elif policy == "reset_on_success":
            ev = 0.0
        elif policy.startswith("decay"):
            ev = max(0.0, ev - 1.0)         # a successful step-up removes one unit of evidence
    return None


def evidence_study(metrics, out_proc, rng):
    m = metrics[(metrics.prevalence == 0.01) & (metrics.weights == "production")].set_index(["family", "mu_mal"])
    scen = {"gaussian_fpr": m.loc[("gaussian", 28), "FPR"], "heavy_tailed_fpr": m.loc[("heavy_tailed", 28), "FPR"],
            "shift_unadapted_fpr": m.loc[("shift", 28), "FPR"]}
    mal_tpr = {"noisy": m.loc[("gaussian", 55), "TPR"], "stealthy": m.loc[("gaussian", 28), "TPR"]}
    rows = []
    n_shift = 480; n_ent = 2000
    for sname, fpr in scen.items():
        for cname, c in CLASSES.items():
            for pol in POLICIES:
                for k in KAPPAS:
                    pe = min(1.0, fpr + ROUTINE)
                    iso = sum(run_entity(rng, n_shift, pe, c["fail"], c["fail_out"], pol, k) is not None
                              for _ in range(n_ent))
                    rows.append(dict(kind="legitimate", scenario=sname, cls=cname, policy=pol, kappa=k,
                                     p_escalate=pe, false_isolation_per_shift=iso / n_ent,
                                     false_isolation_per_year=1 - (1 - iso / n_ent) ** 730))
    for prof, tpr in mal_tpr.items():
        for pol in POLICIES:
            for k in KAPPAS:
                t = [run_entity(rng, 2000, tpr, 0, 0, pol, k, malicious=True) for _ in range(2000)]
                tt = np.array([x for x in t if x is not None], float)
                rows.append(dict(kind="malicious", scenario=prof, cls="attacker", policy=pol, kappa=k,
                                 p_escalate=tpr, isolated_within_2000=len(tt) / 2000,
                                 median_requests_to_isolation=float(np.median(tt)) if len(tt) else np.nan,
                                 p90_requests_to_isolation=float(np.percentile(tt, 90)) if len(tt) else np.nan))
    df = pd.DataFrame(rows); df.to_csv(os.path.join(out_proc, "e2_evidence_accumulation.csv"), index=False)
    return df


if __name__ == "__main__":
    out_raw, out_proc = sys.argv[1], sys.argv[2]
    rng = np.random.default_rng(424242)
    met = evaluate(out_raw, out_proc, rng)
    print(met[met.prevalence == 0.01][["family", "mu_mal", "weights", "TPR", "FPR", "precision", "F1", "ROC_AUC", "PR_AUC",
                                         "legit_isolation", "mal_block", "mal_isolate"]].round(4).to_string())
    ev = evidence_study(met, out_proc, rng)
    print(ev.round(4).to_string())
