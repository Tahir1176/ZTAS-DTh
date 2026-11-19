"""
DTh attack-propagation simulator, revision v2.

Changes w.r.t. v1 (see REVISION_AUDIT.md, findings C1-C10):
  * Common random numbers: for each (graph, run) all random draws are generated ONCE and every
    configuration is evaluated on the same draws -> exactly paired comparisons.
  * Provenance gates apply only to ARTIFACT-MEDIATED moves across a gate boundary (phase, repository
    or organisational boundary). Interface-mediated moves (credential/API pivots) bypass them (C1).
  * New baseline 'zt_prov' = static ZT + phase-boundary provenance verification.
  * ZTAS-DTh is a strict superset of static ZT (keeps generic anomaly detection) (C3).
  * Block tier = deny + alert + evidence (no isolation), matching Algorithm 1 (C4).
  * Evidence counter with optional exponential decay; isolation of operations-phase (safety-relevant)
    entities requires human approval, modelled as a delay of `approval_delay` steps.
  * Additional metrics: path length, phases, detection, time to detection, containment, residual.

All probabilities are SIMULATION PARAMETERS (assumptions), not measured properties.
"""
import numpy as np

DEFAULTS = dict(
    T=60,
    p_exploit=0.30,     # per-step probability that one attempted move along a reachable flow succeeds
    zone_filter=0.5,    # static zones: conduit inspection multiplies p_exploit on boundary moves
    zone_detect=0.20,   # static zones: probability a boundary-crossing attempt is detected
    p_auth=0.50,        # ZT: probability per-request authN/authZ defeats a lateral move
    d_generic=0.05,     # ZT: per-step probability generic monitoring isolates an active compromised entity
    p_act=0.30,         # ZTAS: probability that the dynamic segment containing a flow is open at a step
    f_art=0.50,         # share of flows on which lateral movement is artifact-mediated
    p_v=0.90,           # probability a provenance gate rejects a malicious artifact (scenario-dependent)
    mu_legit=15.0, sd_legit=8.0,
    mu_mal=55.0, sd_mal=15.0, p_sysdeg=0.5,
    stepup_fail=0.70,   # probability attacker fails step-up / re-attestation
    kappa=2.0,          # evidence threshold for quarantine
    decay=1.0,          # per-step multiplicative evidence decay (1.0 = no decay)
    w_block=2.0,        # evidence added by a block-tier decision
    approval_delay=2,   # steps before isolation of an operations-phase entity takes effect
    theta=(30.0, 70.0, 90.0),
)
W_ADAPT = np.array([0.10, 0.10, 0.35, 0.30, 0.15])   # temporal, spatial, behavioural, system, business
W_UNIFORM = np.full(5, 0.2)

CONFIGS = {
    # name: set of mechanisms
    "perimeter": set(),
    "zones": {"zones"},
    "zt": {"auth", "generic"},
    "zt_prov": {"auth", "generic", "prov"},
    "ztas": {"auth", "generic", "prov", "seg", "risk"},
    # ablations of ZTAS-DTh
    "ztas_no_seg": {"auth", "generic", "prov", "risk"},
    "ztas_no_risk": {"auth", "generic", "prov", "seg"},
    "ztas_no_prov": {"auth", "generic", "seg", "risk"},
    "ztas_uniform_w": {"auth", "generic", "prov", "seg", "risk", "uniform"},
}
CONTROL_BUDGET = {
    "perimeter": "none",
    "zones": "zone/conduit inspection + conduit detection",
    "zt": "per-request authN/authZ + generic monitoring",
    "zt_prov": "zt + provenance gates on gate boundaries",
    "ztas": "zt_prov + flow-scoped segments + 5-D risk engine with evidence accumulation",
}


class Prepared:
    """Graph converted to index form."""
    def __init__(self, G):
        self.nodes = list(G.nodes)
        self.idx = {v: i for i, v in enumerate(self.nodes)}
        self.n = len(self.nodes)
        self.phase = [G.nodes[v]["phase"] for v in self.nodes]
        self.org = [G.nodes[v]["org"] for v in self.nodes]
        self.succ = [[self.idx[w] for w in G.successors(v)] for v in self.nodes]
        self.u_art = {(self.idx[a], self.idx[b]): G.edges[a, b]["u_art"] for a, b in G.edges()}
        self.internal = np.array([p != "X" for p in self.phase])
        self.entry_pool = [i for i, p in enumerate(self.phase) if p in ("X", "D", "M", "S")]
        # gate boundary: phase change, repository involvement, or organisation change
        self.boundary = {(a, b): (self.phase[a] != self.phase[b]) or (self.org[a] != self.org[b])
                         for (a, b) in self.u_art}
        self.zone = [(self.org[i], self.phase[i]) for i in range(self.n)]


def draws(prep, T, seed):
    """All random numbers for one (graph, run): shared by every configuration."""
    rng = np.random.default_rng(seed)
    n = prep.n
    return dict(
        entry=prep.entry_pool[rng.integers(len(prep.entry_pool))],
        exploit=rng.random((T, n, n)), auth=rng.random((T, n, n)), seg=rng.random((T, n, n)),
        prov=rng.random((T, n, n)), zone=rng.random((T, n, n)), stepup=rng.random((T, n, n)),
        generic=rng.random((T, n)),
        z=rng.standard_normal((T, n, n, 5)), sysdeg=rng.random((T, n, n)),
    )


def scores(D, P, w):
    """Risk scores for malicious requests on every (t,u,v), from the shared standard normals."""
    comp = P["mu_legit"] + P["sd_legit"] * D["z"]
    comp[..., 2] = P["mu_mal"] + P["sd_mal"] * D["z"][..., 2]
    deg = D["sysdeg"] < P["p_sysdeg"]
    comp[..., 3] = np.where(deg, P["mu_mal"] + P["sd_mal"] * D["z"][..., 3], comp[..., 3])
    return np.clip(comp, 0, 100) @ w


def simulate(prep, D, cfg, P, S=None):
    mech = CONFIGS[cfg]
    T = P["T"]; th1, th2, th3 = P["theta"]
    comp = np.zeros(prep.n, bool); iso = np.zeros(prep.n, bool)
    depth = np.full(prep.n, -1)
    pending = {}                 # node -> step at which approved isolation takes effect
    ev = np.zeros(prep.n)
    e = D["entry"]; comp[e] = True; depth[e] = 0
    t_detect = None; t_reach_O = None

    def isolate(u, t):
        nonlocal t_detect
        if t_detect is None:
            t_detect = t
        if prep.phase[u] == "O" and P["approval_delay"] > 0:
            pending.setdefault(u, t + P["approval_delay"])
        else:
            iso[u] = True

    for t in range(T):
        for u, tt in list(pending.items()):
            if tt <= t:
                iso[u] = True; del pending[u]
        if "risk" in mech and P["decay"] < 1.0:
            ev *= P["decay"]
        active = np.flatnonzero(comp & ~iso)
        if active.size == 0:
            break
        new = []
        for u in active:
            if "generic" in mech and D["generic"][t, u] < P["d_generic"]:
                isolate(u, t); continue
            for v in prep.succ[u]:
                if comp[v]:
                    continue
                p = P["p_exploit"]
                bnd = prep.boundary[(u, v)]
                art = prep.u_art[(u, v)] < P["f_art"]
                if "zones" in mech and prep.zone[u] != prep.zone[v]:
                    if D["zone"][t, u, v] < P["zone_detect"]:
                        isolate(u, t); break
                    p *= P["zone_filter"]
                if "auth" in mech and D["auth"][t, u, v] < P["p_auth"]:
                    continue
                if "seg" in mech and D["seg"][t, u, v] > P["p_act"]:
                    continue
                if "prov" in mech and bnd and art and D["prov"][t, u, v] < P["p_v"]:
                    isolate(u, t); break
                if "risk" in mech:
                    s = S[t, u, v]
                    if s > th3:
                        isolate(u, t); break
                    if s > th2:
                        ev[u] += P["w_block"]
                        if ev[u] >= P["kappa"]:
                            isolate(u, t); break
                        continue
                    if s > th1 and D["stepup"][t, u, v] < P["stepup_fail"]:
                        ev[u] += 1.0
                        if ev[u] >= P["kappa"]:
                            isolate(u, t); break
                        continue
                if D["exploit"][t, u, v] < p:
                    new.append((v, u))
        for v, u in new:
            if not comp[v]:
                comp[v] = True; depth[v] = depth[u] + 1
                if prep.phase[v] == "O" and t_reach_O is None:
                    t_reach_O = t + 1
    # metrics
    internal = prep.internal
    ncomp = comp.sum()
    active = comp & ~iso
    can_move = any((not comp[v]) for u in np.flatnonzero(active) for v in prep.succ[u])
    phases = {prep.phase[i] for i in np.flatnonzero(comp)} & {"D", "M", "O", "S"}
    reach_O = t_reach_O is not None
    return dict(
        frac=float((comp & internal).sum() / internal.sum()),
        reach_O=float(reach_O),
        t_reach_O=float(t_reach_O) if reach_O else np.nan,
        n_phases=float(len(phases)),
        path_len=float(depth.max()),
        detected=float(t_detect is not None),
        t_detect=float(t_detect) if t_detect is not None else np.nan,
        contained=float((not reach_O) and (not can_move)),
        residual=float(active.sum() / ncomp),
    )
