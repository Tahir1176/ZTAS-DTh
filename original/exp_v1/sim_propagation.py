"""
E1/E2: Monte-Carlo simulation of cross-phase attack propagation on a synthetic
Digital Thread (DTh) graph under four security configurations, plus ablation
and sensitivity analysis of the ZTAS-DTh mechanisms.

All parameters are modelling assumptions (documented in PARAMS and in the paper).
Results characterise the *relative* effect of the mechanisms under these
assumptions; they are not measurements of a deployed system.
"""
import json, sys
import numpy as np
import networkx as nx

PHASES = ["D", "M", "O", "S"]          # design, manufacturing, operations, service
PARAMS = dict(
    nodes_per_phase=14, n_supplier=4, p_intra=0.30, n_cross=6,   # graph
    T=60, runs=1000, graphs=10,                                  # MC
    p_exploit=0.30,          # per-step success prob. of traversing one reachable edge
    zone_filter=0.5,         # static zones: conduit inspection halves exploit prob
    zone_detect=0.20,        # static zones: detection prob of a cross-zone attempt
    auth_block=0.50,         # ZT: prob. per-request authN/authZ defeats lateral move
    d_generic=0.05,          # ZT-static: generic anomaly detection per node per step
    p_active=0.30,           # ZTAS-DTh: prob. a flow's dynamic segment is open
    mu_legit=15.0, sd_legit=8.0,     # risk-score component distribution, legitimate
    mu_mal=55.0, sd_mal=15.0,        # behavioural/system component, malicious
    stepup_fail=0.70,        # prob. attacker fails step-up/re-attestation
    prov_detect=0.90,
    strikes=2,               # failed step-ups before quarantine (evidence accumulation)        # prob. tampered artefact crossing a phase fails signature/lineage check
)
W_UNIFORM = np.array([0.2, 0.2, 0.2, 0.2, 0.2])          # temporal, spatial, behavioural, system, business
W_ADAPT = np.array([0.10, 0.10, 0.35, 0.30, 0.15])         # operations-mode weights (Sec. IV)


def build_graph(rng, P):
    G = nx.DiGraph()
    for ph in PHASES:
        ids = [f"{ph}{i}" for i in range(P["nodes_per_phase"])]
        for n in ids:
            G.add_node(n, phase=ph)
        for a in ids:
            for b in ids:
                if a != b and rng.random() < P["p_intra"]:
                    G.add_edge(a, b)
    # lifecycle flows D->M->O->S and feedback S->D, O->D (bidirectional thread)
    for a, b in [("D", "M"), ("M", "O"), ("O", "S"), ("S", "D"), ("O", "D"), ("M", "D")]:
        for _ in range(P["n_cross"]):
            u = f"{a}{rng.integers(P['nodes_per_phase'])}"
            v = f"{b}{rng.integers(P['nodes_per_phase'])}"
            G.add_edge(u, v)
    for i in range(P["n_supplier"]):
        s = f"X{i}"; G.add_node(s, phase="X")
        for ph in ["D", "M", "S"]:
            G.add_edge(s, f"{ph}{rng.integers(P['nodes_per_phase'])}")
    return G


def risk_score(rng, malicious, w, P):
    """5-D weighted risk score in [0,100]; malicious requests shift behavioural and system dims."""
    r = rng.normal(P["mu_legit"], P["sd_legit"], 5)
    if malicious:
        r[2] = rng.normal(P["mu_mal"], P["sd_mal"])            # behavioural deviation
        if rng.random() < 0.5:                                  # device integrity degraded
            r[3] = rng.normal(P["mu_mal"], P["sd_mal"])
    r = np.clip(r, 0, 100)
    return float(w @ r)


def simulate(G, rng, cfg, P, w=W_ADAPT, mech=("seg", "risk", "prov")):
    nodes = list(G.nodes)
    entry = rng.choice([n for n in nodes if n.startswith("X")] + [n for n in nodes if n[0] in "DMS"])
    comp = {entry}; isolated = set(); t_contain = None; strikes = {}
    for t in range(P["T"]):
        new = set()
        active = [c for c in comp if c not in isolated]
        if not active:
            t_contain = t; break
        for u in active:
            # node-level detection
            if cfg == "zt_static" and rng.random() < P["d_generic"]:
                isolated.add(u); continue
            for v in G.successors(u):
                if v in comp:
                    continue
                cross = G.nodes[u]["phase"] != G.nodes[v]["phase"]
                p = P["p_exploit"]
                if cfg == "perimeter":
                    pass
                elif cfg == "zones":
                    if cross:
                        if rng.random() < P["zone_detect"]:
                            isolated.add(u); break
                        p *= P["zone_filter"]
                elif cfg == "zt_static":
                    p *= (1 - P["auth_block"])
                elif cfg == "ztas":
                    p *= (1 - P["auth_block"])
                    if "seg" in mech and rng.random() > P["p_active"]:
                        continue                         # flow segment closed: edge unreachable
                    if "risk" in mech:
                        s = risk_score(rng, True, w, P)
                        if s > 90:
                            isolated.add(u); break
                        if s > 70:
                            isolated.add(u); break       # block + alert -> node quarantined
                        if s > 30 and rng.random() < P["stepup_fail"]:
                            strikes[u] = strikes.get(u, 0) + 1   # failed step-up raises an alert
                            if strikes[u] >= P["strikes"]:
                                isolated.add(u); break
                            continue
                    if "prov" in mech and cross and rng.random() < P["prov_detect"]:
                        isolated.add(u); break
                if rng.random() < p:
                    new.add(v)
        comp |= new
    else:
        if all(c in isolated for c in comp):
            t_contain = P["T"]
    phases = {G.nodes[c]["phase"] for c in comp}
    n_int = sum(1 for n in nodes if not n.startswith("X"))
    frac = sum(1 for c in comp if not c.startswith("X")) / n_int
    iso = len([c for c in comp if c in isolated]) / len(comp)
    return dict(frac=frac, reach_O=("O" in phases), n_phases=len(phases - {"X"}), contained=iso)


def run(cfg, P, w=W_ADAPT, mech=("seg", "risk", "prov"), seed=1):
    rng = np.random.default_rng(seed)
    res = []
    for g in range(P["graphs"]):
        G = build_graph(np.random.default_rng(1000 + g), P)
        for _ in range(P["runs"] // P["graphs"]):
            res.append(simulate(G, rng, cfg, P, w, mech))
    f = np.array([r["frac"] for r in res]); o = np.array([r["reach_O"] for r in res])
    c = np.array([r["contained"] for r in res]); k = np.array([r["n_phases"] for r in res])
    ci = lambda x: 1.96 * x.std(ddof=1) / np.sqrt(len(x))
    return dict(frac=f.mean(), frac_ci=ci(f), reachO=o.mean(), reachO_ci=ci(o.astype(float)),
                phases=k.mean(), contained=c.mean(), contained_ci=ci(c.astype(float)))


def roc(P, w, n=20000, seed=7):
    """Operating characteristic of the policy decision rule (E2)."""
    rng = np.random.default_rng(seed)
    leg = np.array([risk_score(rng, False, w, P) for _ in range(n)])
    mal = np.array([risk_score(rng, True, w, P) for _ in range(n)])
    out = []
    for th in range(0, 101, 1):
        out.append((th, float((mal > th).mean()), float((leg > th).mean())))
    tiers = dict(
        legit={k: float(v) for k, v in zip(["allow", "stepup", "block", "isolate"],
               np.histogram(leg, [-1, 30, 70, 90, 101])[0] / n)},
        mal={k: float(v) for k, v in zip(["allow", "stepup", "block", "isolate"],
             np.histogram(mal, [-1, 30, 70, 90, 101])[0] / n)})
    return out, tiers


if __name__ == "__main__":
    P = PARAMS
    out = {"params": P}
    out["main"] = {c: run(c, P) for c in ["perimeter", "zones", "zt_static", "ztas"]}
    PS = dict(P, mu_mal=28.0)          # stealthy attacker profile
    out["main_stealthy"] = {c: run(c, PS) for c in ["perimeter", "zones", "zt_static", "ztas"]}
    for k, v in out["main_stealthy"].items():
        print("stealthy", k, {a: round(float(b), 3) for a, b in v.items()})
    P_noisy = P; P = PS
    abl = {}
    for name, mech in [("full", ("seg", "risk", "prov")), ("no_seg", ("risk", "prov")),
                       ("no_risk", ("seg", "prov")), ("no_prov", ("seg", "risk")),
                       ("none", ())]:
        abl[name] = run("ztas", P, mech=mech)
    abl["uniform_w"] = run("ztas", P, w=W_UNIFORM)
    out["ablation"] = abl
    P = P_noisy
    sens = []
    for mu in [15, 20, 25, 30, 35, 45, 55]:
        P2 = dict(P, mu_mal=mu, runs=500)
        r = run("ztas", P2)
        sens.append(dict(mu_mal=mu, **r))
    out["sens_mu"] = sens
    sens2 = []
    for pa in [0.1, 0.3, 0.5, 0.7, 1.0]:
        P2 = dict(P, mu_mal=28.0, p_active=pa, runs=500)
        sens2.append(dict(p_active=pa, **run("ztas", P2)))
    out["sens_pactive"] = sens2
    sens3 = []
    for pv in [0.0, 0.25, 0.5, 0.75, 0.9, 0.99]:
        P2 = dict(P, mu_mal=28.0, prov_detect=pv, runs=500)
        sens3.append(dict(prov_detect=pv, **run("ztas", P2)))
    out["sens_prov"] = sens3
    for k in ["sens_mu", "sens_pactive", "sens_prov"]:
        for r in out[k]:
            print(k, {a: round(float(b), 3) for a, b in r.items()})
    out["roc_adapt"], out["tiers_adapt"] = roc(P, W_ADAPT)
    out["roc_uniform"], out["tiers_uniform"] = roc(P, W_UNIFORM)
    json.dump(out, open(sys.argv[1], "w"), indent=1)
    for k, v in out["main"].items():
        print(k, {a: round(b, 3) for a, b in v.items()})
    for k, v in abl.items():
        print("abl", k, {a: round(b, 3) for a, b in v.items()})
    print("tiers adapt", out["tiers_adapt"]); print("tiers uniform", out["tiers_uniform"])
