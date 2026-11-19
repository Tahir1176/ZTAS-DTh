# REPRODUCIBILITY_README.md

Everything needed to regenerate every number, table and figure of the revised ZTAS-DTh manuscript.
No repository URL or DOI exists yet — the package has **not** been deposited. Add the DOI after depositing
(e.g. on Zenodo) and update the "Data and Code Availability" section of the manuscript.

## 1. Environment
* Tested on: Linux 6.18 (x86_64), Intel Xeon @ 2.10 GHz, 2 vCPU, 8 GB RAM, Python 3.13.18, TeX Live 2023 (IEEEtran).
* Python packages: `pip install -r requirements.txt` (pinned versions).
* Java is **not** required (TLA+ was not executed). To check the TLA+ spec yourself: install `tla2tools.jar` and run
  `java -cp tla2tools.jar tlc2.TLC -config ProvenanceGate.cfg ProvenanceGate` in `formal/`.

## 2. Layout
```
ZTAS_DTh_MAJOR_REVISION/
  original/            v1 manuscript, code, raw results (unchanged; CHECKSUMS.sha256)
  code/                topologies.py, dth_sim.py, run_e1.py, run_e1_rec.py, stats_hboot.py, analyze_pv.py,
                       risk_engine_eval.py, bench_crypto_v2.py, batching_latency.py, make_figures.py, make_tables.py
  poc/ztas_poc.py      software proof of concept (6 services, localhost)
  formal/              model_check.py, logs/, ProvenanceGate.tla/.cfg (not executed)
  notebooks/           provenance_sensitivity_analysis.ipynb (executed)
  data/raw/            simulation, benchmark and PoC outputs (+ e3_crypto_samples.npz raw timings)
  data/processed/      summaries, CIs, effects, per-graph results, sensitivity, batching
  figures/, tables/    generated from data only
  manuscript/          main.tex, refs.bib, figs/, tables/  ->  FINAL_MANUSCRIPT.pdf
  run_all.sh           one command per experiment
```

## 3. One command per experiment

| Experiment | Command | Output | Time (2 cores) |
|---|---|---|---|
| E1 main + revised rule + p_v sweep + OAT + stats + notebook | `bash run_all.sh e1` | `data/raw/e1_*.csv`, `data/processed/e1_*.csv`, `provenance_sensitivity.csv` | ≈ 35 min |
| E2 risk engine | `bash run_all.sh e2` | `data/processed/e2_*.csv`, `data/raw/e2_curves.csv` | ≈ 2.5 min |
| E3 crypto + batching | `bash run_all.sh e3` | `data/raw/e3_crypto_v2.json`, `.npz`, `data/processed/e3_batching_latency.csv` | ≈ 1.5 min |
| E4 proof of concept | `bash run_all.sh e4` | `data/raw/poc_results.json` | ≈ 1 min (uses ports 18101–18106) |
| Formal checks | `bash run_all.sh formal` | `formal/logs/*` | < 1 s |
| Figures, tables, PDF | `bash run_all.sh figs` | `figures/`, `tables/`, `manuscript/main.pdf` | < 1 min |
| Everything | `bash run_all.sh` | all of the above | ≈ 40–60 min |

## 4. Seeds and determinism
* E1: graph seed = 10000·topology_index + g (g = 0…29); run seed = 1000003·graph_seed + r; both written to every CSV row.
  Common random numbers: all draws for a (graph, run) are generated once and shared by all configurations.
* Hierarchical bootstrap seed 20261118; p_v summary seed 7; E2 seed 424242; batching model seed 99.
* E1–E2 and the formal checks are deterministic given the seeds. E3 and E4 are timing measurements and will differ
  between machines and runs; regenerate them on your hardware.

## 5. Integrity
`data/CHECKSUMS.sha256` lists SHA-256 hashes of all raw and processed data used in the manuscript;
`original/CHECKSUMS.sha256` covers the v1 results.

## 6. Known deviations and exclusions
* No runs excluded. v1 results are preserved, superseded, and documented in `REVISION_AUDIT.md`.
* A first draft of the evidence-accumulation code applied decay/outage rules asymmetrically to legitimate and malicious
  entities; it was corrected before the reported run (see `REVISION_CHANGELOG.md`).
* TLA+ tooling could not be downloaded; bounded checks used a purpose-written checker.
* `FINAL_MANUSCRIPT.docx` is an automatic pandoc conversion for convenience; the LaTeX source is authoritative.
