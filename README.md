# ZTAS-DTh: Zero-Trust Security Architecture for the Digital Thread

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24372429.svg)](https://doi.org/10.5281/zenodo.24372429)

> **Release v1.1.0 (second revision).** The complete revision package (joint sensitivity analysis, extended risk-engine evaluation, continuous-time evidence study, formal model M4, proof-of-concept v3 with concurrency and failure tests, cryptographic and queueing re-analysis, attacker profiles, clean-checkout reproduction of v1.0.0, revised manuscript, supplementary material, response to reviewers and a SHA-256 manifest) is in [`revision_v1.1.0/ZTAS-DTh_v1.1.0_revision_package.zip`](revision_v1.1.0/ZTAS-DTh_v1.1.0_revision_package.zip). Unzip it and start with its `README.md`. The DOI above always resolves to the latest version; v1.0.0 is doi:10.5281/zenodo.24372430.

Code and data accompanying the manuscript

> M. Tahir, W. Ahmed, A. Hassan and I. Rashid, "ZTAS-DTh: A Lifecycle-Spanning Zero-Trust Security Architecture for
> the Digital Thread — Design, Bounded Formal Analysis, and Simulation-Based Evaluation," submitted to *IEEE
> Transactions on Industrial Informatics*, 2026.

Department of Information Security, Military College of Signals (MCS), National University of Sciences and Technology
(NUST), Islamabad, Pakistan. Corresponding author: Imran Rashid (irashid@mcs.edu.pk).

**Scope of the evidence.** The results are from simulation, synthetic score distributions, server-CPU
micro-benchmarks, bounded model checking of abstract models, and a single-host software proof of concept. Nothing in
this repository is an industrial measurement or deployment. All detection probabilities in the simulation are
assumptions (see `docs/SIMULATION_VALIDATION_REPORT.md`).

## Contents

| Path | What it is |
|---|---|
| `code/` | Simulation (`topologies.py`, `dth_sim.py`, `run_e1.py`, `run_e1_rec.py`), statistics (`stats_hboot.py`, `analyze_pv.py`), risk-engine study (`risk_engine_eval.py`), crypto benchmarks (`bench_crypto_v2.py`, `batching_latency.py`), figure/table generators |
| `poc/ztas_poc.py` | Software proof of concept: IdP, PDP, segmentation controller, provenance service, twin endpoint and PEP as separate processes on localhost |
| `formal/` | Bounded explicit-state model checker (`model_check.py`), logs, and a TLA+ specification (`ProvenanceGate.tla`, **not executed**) |
| `notebooks/` | `provenance_sensitivity_analysis.ipynb` (executed) |
| `data/raw/` | Raw outputs: E1 simulation CSVs (gzipped), E2 ROC curves, E3 benchmark JSON and raw timing samples (`.npz`), PoC results |
| `data/processed/` | Summaries with hierarchical-bootstrap CIs, paired effects, per-graph results, provenance sensitivity, risk metrics, batching model |
| `figures/`, `tables/` | Generated from `data/` only |
| `docs/` | Revision audit and validation reports (simulation, provenance, risk engine, formal model, cryptography, related work, reproducibility, change log) |
| `original/` | The superseded v1 code and results, kept for transparency |
| `data/CHECKSUMS.sha256` | SHA-256 of every data file |

## Quick start

```bash
pip install -r requirements.txt          # Python 3.13 tested; Linux x86_64
bash run_all.sh analysis                 # recompute statistics, figures, tables from the shipped raw data (~2 min)
bash run_all.sh                          # re-run every experiment from scratch (~40-60 min on 2 cores)
```

Individual experiments: `bash run_all.sh e1|e2|e3|e4|formal|figs`.

| Experiment | Command | Main outputs |
|---|---|---|
| E1 propagation simulation (9 topologies × 30 graphs × 50 runs, paired) | `run_all.sh e1` | `data/raw/e1_*.csv`, `data/processed/e1_*.csv`, `provenance_sensitivity.csv` |
| E2 risk engine (6 synthetic distributions, evidence accumulation) | `run_all.sh e2` | `data/processed/e2_*.csv` |
| E3 cryptographic costs and batching latency | `run_all.sh e3` | `data/raw/e3_crypto_v2.json`, `data/processed/e3_batching_latency.csv` |
| E4 proof of concept | `run_all.sh e4` | `data/raw/poc_results.json` (uses ports 18101–18106) |
| Bounded model checking | `run_all.sh formal` | `formal/logs/` |

E1, E2 and the formal checks are deterministic given the seeds (graph seed = 10000·topology_index + g; run seed =
1000003·graph_seed + r; bootstrap seed 20261118; E2 seed 424242). E3 and E4 are timing measurements and depend on the
machine.

## Licence
* Code: MIT (`LICENSE`).
* Data, figures, tables and documentation: CC BY 4.0 (`LICENSE-DATA`).

## Citation
See `CITATION.cff`. Until the article is published, please cite this software/data archive (Zenodo DOI added on release).

## Contact
Muhammad Tahir (tahir1176@gmail.com) · Waqas Ahmed (waqassignals@gmail.com) · Ammar Hassan
(ammar.hassan@mcs.nust.edu.pk) · Imran Rashid (irashid@mcs.edu.pk)
