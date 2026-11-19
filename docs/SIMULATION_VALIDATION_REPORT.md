# SIMULATION_VALIDATION_REPORT.md (E1, reviewer concern R2)

All numbers are from `data/raw/e1_main.csv`, `e1_main_rec.csv`, `e1_oat.csv` and the processed files listed below.
All parameters are modelling assumptions; nothing here is an industrial measurement.

## 1. The original (v1) model, documented before changing it

| Aspect | v1 behaviour (`original/exp_v1/sim_propagation.py`) |
|---|---|
| Nodes | 14 per phase (D, M, O, S) = 56 internal; 4 suppliers (X) |
| Intra-phase edges | independent directed edges, p = 0.30 (Erdős–Rényi) |
| Inter-phase edges | 6 draws per ordered pair D→M, M→O, O→S, S→D, O→D, M→D, **with replacement** (duplicates collapse, so ≤ 6) |
| Feedback loops | yes (S→D, O→D, M→D) |
| Suppliers | 3 random links each into D, M, S |
| Shared repositories / organisations / hubs | not modelled |
| Graph instances | 10, seeds 1000–1009, **the same graphs for every configuration** |
| Run randomness | one RNG stream (seed 1) consumed differently per configuration → entry points and draws **not paired** |
| Provenance | applied to every cross-phase lateral move (implicit f_art = 1) |
| ZTAS-DTh vs static ZT | ZTAS-DTh lacked static ZT's generic monitoring (not a superset) |
| Block tier | isolated the source entity (Algorithm 1 says deny + alert) |
| Uncertainty | 1.96·sd/√1000, treating runs on 10 graphs as independent |

## 2. Revised model (v2)

* Generator: `code/topologies.py`; simulator: `code/dth_sim.py`; driver: `code/run_e1.py`, `code/run_e1_rec.py`.
* Nine topology families × 30 graphs; graph seed = 10000·topology_index + g; run seed = 1000003·graph_seed + r.
* Common random numbers: `draws()` generates all randomness for a (graph, run) once; every configuration (and every
  sweep value) is evaluated on it.
* Edge attribute `u_art ~ U(0,1)`; an edge is artifact-mediated iff `u_art < f_art` (sweepable without regenerating).
* Gate boundary = phase change, repository involvement, or ownership change.
* Configurations and control budgets: perimeter (none); zones (conduit inspection ×0.5, crossing detection 0.2);
  zt (authorisation p_a = 0.5, generic monitoring d = 0.05); zt_prov (zt + gates); ztas (zt_prov + segments p_act = 0.3 +
  risk engine). `ztas_rec` = ztas with the evidence rule recommended by E2 (κ = 3, per-step decay 0.95); `ztas` keeps
  the v1 rule (κ = 2, no decay) and is the basis of the ablations.

### Topology statistics (mean ± sd over 30 graphs; `data/processed/topology_statistics.csv`)

| Family | Nodes | Edges | Cross-phase edges | Cross-owner edges | Mean out-degree |
|---|---|---|---|---|---|
| reference | 60 | 264.6 ± 12.6 | 47.7 ± 0.5 | 11.7 ± 0.5 | 4.4 |
| sparse | 60 | 102.7 ± 9.7 | 29.8 ± 0.4 | 11.8 ± 0.4 | 1.7 |
| dense | 60 | 448.3 ± 10.3 | 83.6 ± 0.6 | 11.6 ± 0.6 | 7.5 |
| hub_spoke | 60 | 168.0 ± 6.5 | 29.6 ± 0.6 | 11.7 ± 0.5 | 2.8 |
| high_interconnect | 60 | 365.8 ± 0.5 | 101.8 ± 0.5 | 11.8 ± 0.5 | 6.1 |
| shared_repo | 62 | 326.6 ± 15.2 | 109.8 ± 7.9 | 11.7 ± 0.5 | 5.3 |
| multi_supplier | 72 | 310.9 ± 14.3 | 82.8 ± 2.9 | 54.8 ± 2.9 | 4.3 |
| feedback_loop | 60 | 325.6 ± 14.6 | 106.7 ± 1.3 | 11.8 ± 0.5 | 5.4 |
| multi_org | 60 | 267.7 ± 11.1 | 47.6 ± 0.6 | 132.0 ± 11.3 | 4.5 |

(Cross-owner edges outside `multi_org` are the supplier links.)

### Justification of structure and assumptions
* Hub-and-spoke: PLM/MES/SCADA-historian/service-platform hubs follow the functional hierarchy of IEC 62264 and the DTh
  reference architecture of Helu et al. (2017).
* Shared repository: authoritative sources of truth (Zhang et al. 2024) and permissioned data stores (Joannou et al. 2020).
* Multi-supplier: tier-1/tier-2 product-data exchange (Krima et al. 2019).
* Multi-organisation: data sharing across OEM, contract manufacturer, operator and service provider (Mabkhot et al. 2025).
* Densities, flow counts, partner share (30%), repository coverage (40%) and supplier counts are **assumptions**; no
  public dataset of industrial DTh topologies was found, so they are varied across families instead of fitted.

## 3. Validation checks performed

| Check | Result |
|---|---|
| Pairing: all configurations use identical draws | by construction (`draws()` once per run); verified by the exact equality below |
| ZTAS at p_v = 0 equals the no-provenance ablation (all topologies, profiles, f_art) | max abs. difference = 0.0 (notebook §3) |
| Baselines that ignore risk scores give identical results for both attacker profiles | yes (e.g. reference zt: 0.832 for both) |
| Monotonicity: ZT+prov compromised fraction non-increasing in p_v | yes for all 9 topologies at f_art = 0.5 and 1.0 (`provenance_sensitivity.csv`) |
| Monotonicity in p_x, p_a, d (OAT) | yes for zt, zt_prov, ztas (`e1_oat.csv`) |
| Hierarchical vs naive CI width (reference, ZT+prov) | 0.079 vs 0.040 (≈2×) |

## 4. Main results (stealthy attacker, compromised fraction, mean [95% hierarchical CI])

See `tables/tab_e1_main.tex` (Table VIII in the paper). ZTAS-DTh (revised rule) ranges from 0.04 [0.03, 0.04] (sparse)
to 0.34 [0.31, 0.37] (dense); reference 0.14 [0.13, 0.15] vs ZT+prov 0.49 [0.45, 0.53] and static ZT 0.83 [0.81, 0.85].

### Per-graph variability of ZTAS-DTh (stealthy), `data/processed/e1_per_graph.csv`

| Family | min | max | sd across graphs |
|---|---|---|---|
| reference | 0.099 | 0.239 | 0.032 |
| sparse | 0.025 | 0.046 | 0.006 |
| dense | 0.183 | 0.573 | 0.076 |
| hub_spoke | 0.050 | 0.172 | 0.027 |
| high_interconnect | 0.129 | 0.297 | 0.049 |
| shared_repo | 0.066 | 0.190 | 0.028 |
| multi_supplier | 0.068 | 0.206 | 0.031 |
| feedback_loop | 0.074 | 0.227 | 0.040 |
| multi_org | 0.030 | 0.114 | 0.017 |

### Effect sizes (paired, `data/processed/e1_effects.csv`)
ZTAS-DTh (revised rule) minus ZT+prov, stealthy: −0.04 (sparse) … −0.40 (dense); graph-level d_z between −1.6 and
−5.9; all 30 graphs favour ZTAS-DTh in every family. No significance tests are reported.

## 5. Sensitivity (one-at-a-time, reference topology, stealthy attacker, ztas with v1 rule; `e1_oat.csv`)

| Parameter | Tested values | ZTAS-DTh compromised fraction |
|---|---|---|
| p_act (segment open) | 0.1 / 0.3 / 0.6 / 1.0 | 0.039 / 0.122 / 0.253 / 0.367 |
| d (generic detection) | 0.01 / 0.05 / 0.10 | 0.272 / 0.122 / 0.063 |
| p_x (exploit) | 0.15 / 0.30 / 0.45 | 0.050 / 0.122 / 0.216 |
| p_a (authorisation) | 0.25 / 0.50 / 0.75 | 0.190 / 0.122 / 0.061 |
| f_art | 0.2 / 0.5 / 0.8 / 1.0 | 0.192 / 0.122 / 0.082 / 0.064 |
| μ_mal | 15 / 28 / 40 / 55 | 0.153 / 0.122 / 0.056 / 0.027 |
| κ | 1 / 2 / 3 / 5 | 0.077 / 0.122 / 0.133 / 0.136 |
| p_v | 0.5 / 0.9 / 0.99 | 0.154 / 0.122 / 0.119 |
| T | 30 / 60 / 120 | 0.092 / 0.122 / 0.136 |
| approval delay | 0 / 2 / 5 | 0.120 / 0.122 / 0.128 |

**Interpretation.** The segmentation result is the least robust: it is essentially determined by the assumed p_act.
The headline comparison with ZT+prov should be read as conditional on p_act = 0.3.

## 6. Exclusions and deviations
* No runs were excluded. The v1 results are preserved in `original/` and are superseded, not deleted.
* The first v2 draft of the evidence-accumulation code treated malicious and legitimate entities asymmetrically in the
  decay/outage rules; this was corrected before any reported run (see `REVISION_CHANGELOG.md`).
