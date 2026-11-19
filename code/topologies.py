"""
Synthetic digital-thread (DTh) topology generators (revision v2).

Every generator returns a networkx.DiGraph whose nodes carry
  phase : 'D','M','O','S' (lifecycle phases), 'R' (shared repository), 'X' (external supplier)
  org   : owning organisation / trust domain
  hub   : True for integration hubs (PLM, MES, SCADA/historian, service platform)
and whose edges carry
  u_art : U(0,1) draw; an edge is artifact-mediated when u_art < f_art (lets f_art be swept
          without regenerating the graph, i.e. common random numbers across the sweep).

Parameter values are MODELLING ASSUMPTIONS unless stated otherwise. Qualitative structure follows
published reference architectures: hub-centred integration of PLM/MES/ERP/SCADA (IEC 62264 / ISA-95
functional hierarchy; Helu et al. 2017 DTh reference architecture), shared authoritative repositories
(Zhang et al. 2024 "authoritative source of truth"), multi-tier suppliers (Krima et al. 2019), and
multi-organisation data sharing (Mabkhot et al. 2025). No published dataset of DTh topologies exists
to our knowledge, so densities are swept rather than fitted.
"""
import numpy as np
import networkx as nx

PH = ["D", "M", "O", "S"]
FWD = [("D", "M"), ("M", "O"), ("O", "S")]
FB = [("S", "D"), ("O", "D"), ("M", "D")]

TOPOLOGIES = {
    # name: (description, parameter dict)
    "reference":    ("v1 model: ER within phase, fixed cross-phase flows", dict(n=14, p=0.30, cross=6, sup=4)),
    "sparse":       ("few intra-phase and cross-phase flows", dict(n=14, p=0.10, cross=3, sup=4)),
    "dense":        ("many intra-phase and cross-phase flows", dict(n=14, p=0.50, cross=12, sup=4)),
    "hub_spoke":    ("integration hubs per phase (PLM/MES/SCADA/service), hub-to-hub thread", dict(n=14, p=0.05, cross=2, sup=4)),
    "high_interconnect": ("scale-free (BA, m=3) within phase + dense cross-phase", dict(n=14, m=3, cross=15, sup=4)),
    "shared_repo":  ("two shared repositories (PDM vault, data lake) mediate most cross-phase data", dict(n=14, p=0.30, cross=2, sup=4, repos=2, repo_frac=0.4)),
    "multi_supplier": ("16 tier-1/tier-2 suppliers with chained links", dict(n=14, p=0.30, cross=6, sup=16)),
    "feedback_loop": ("strong feedback (O/S/M -> D, O/S -> M)", dict(n=14, p=0.30, cross=6, sup=4, fb=12)),
    "multi_org":    ("phases split across OEM, contract manufacturer, operator, service provider", dict(n=14, p=0.30, cross=6, sup=4, partner_frac=0.3)),
}


def _add_phase_nodes(G, n, orgmap=None):
    for ph in PH:
        for i in range(n):
            G.add_node(f"{ph}{i}", phase=ph, org=(orgmap or {}).get(ph, "OEM"), hub=False)


def _er_within(G, rng, n, p):
    for ph in PH:
        ids = [f"{ph}{i}" for i in range(n)]
        for a in ids:
            for b in ids:
                if a != b and rng.random() < p:
                    G.add_edge(a, b)


def _cross(G, rng, n, k, pairs):
    """k distinct flows per ordered phase pair (sampled without replacement)."""
    for a, b in pairs:
        cand = [(i, j) for i in range(n) for j in range(n)]
        idx = rng.choice(len(cand), size=min(k, len(cand)), replace=False)
        for t in idx:
            i, j = cand[t]
            G.add_edge(f"{a}{i}", f"{b}{j}")


def _suppliers(G, rng, n, s, chain=False):
    for i in range(s):
        x = f"X{i}"
        G.add_node(x, phase="X", org=f"SUP{i}", hub=False)
        targets = ["D", "M", "S"]
        k = rng.integers(2, 5) if chain else 3
        for _ in range(k):
            ph = targets[rng.integers(3)]
            G.add_edge(x, f"{ph}{rng.integers(n)}")
    if chain:  # tier-2 -> tier-1 supply links
        for i in range(s // 2, s):
            G.add_edge(f"X{i}", f"X{rng.integers(0, s // 2)}")


def build(topo, seed):
    rng = np.random.default_rng(seed)
    P = TOPOLOGIES[topo][1]
    n = P["n"]
    G = nx.DiGraph()
    if topo == "multi_org":
        _add_phase_nodes(G, n, {"D": "OEM", "M": "CM", "O": "OPR", "S": "SVC"})
        # a share of each phase's entities is owned by a partner organisation
        partner = {"D": "CM", "M": "OEM", "O": "SVC", "S": "OPR"}
        for ph in PH:
            for i in range(n):
                if rng.random() < P["partner_frac"]:
                    G.nodes[f"{ph}{i}"]["org"] = partner[ph]
    else:
        _add_phase_nodes(G, n)

    if topo == "high_interconnect":
        for ph in PH:
            ba = nx.barabasi_albert_graph(n, P["m"], seed=int(rng.integers(1 << 30)))
            for a, b in ba.edges():
                G.add_edge(f"{ph}{a}", f"{ph}{b}"); G.add_edge(f"{ph}{b}", f"{ph}{a}")
    elif topo == "hub_spoke":
        _er_within(G, rng, n, P["p"])
        for ph in PH:
            G.nodes[f"{ph}0"]["hub"] = True
            for i in range(1, n):
                G.add_edge(f"{ph}0", f"{ph}{i}"); G.add_edge(f"{ph}{i}", f"{ph}0")
        for a, b in FWD + FB:
            G.add_edge(f"{a}0", f"{b}0")
    else:
        _er_within(G, rng, n, P["p"])

    _cross(G, rng, n, P["cross"], FWD + FB)
    if topo == "feedback_loop":
        _cross(G, rng, n, P["fb"], FB + [("O", "M"), ("S", "M")])
    if topo == "shared_repo":
        for r in range(P["repos"]):
            rid = f"R{r}"
            G.add_node(rid, phase="R", org="OEM", hub=True)
            for ph in PH:
                for i in range(n):
                    if rng.random() < P["repo_frac"]:
                        G.add_edge(f"{ph}{i}", rid); G.add_edge(rid, f"{ph}{i}")
    _suppliers(G, rng, n, P["sup"], chain=(topo == "multi_supplier"))

    for u, v in G.edges():
        G.edges[u, v]["u_art"] = float(rng.random())
    return G


def describe(G):
    internal = [v for v in G if G.nodes[v]["phase"] != "X"]
    cross = sum(1 for u, v in G.edges() if G.nodes[u]["phase"] != G.nodes[v]["phase"])
    orgx = sum(1 for u, v in G.edges() if G.nodes[u]["org"] != G.nodes[v]["org"])
    return dict(nodes=G.number_of_nodes(), internal=len(internal), edges=G.number_of_edges(),
                cross_phase_edges=cross, cross_org_edges=orgx,
                mean_out_degree=G.number_of_edges() / G.number_of_nodes())
