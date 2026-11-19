#!/usr/bin/env bash
# Reproduce every principal experiment of the ZTAS-DTh revision (approx. 40-60 min on 2 cores).
# Usage: bash run_all.sh            (all)      |  bash run_all.sh e1 | e2 | e3 | e4 | formal | figs | analysis
#   analysis = recompute statistics, figures and tables from the SHIPPED raw data without re-running simulations
set -euo pipefail
cd "$(dirname "$0")"
bash scripts/unpack_data.sh
cd code
step=${1:-all}
if [[ $step == all || $step == e1 ]]; then
  python3 run_e1.py main ../data/raw/e1_main.csv          # ~5 min
  python3 run_e1_rec.py ../data/raw/e1_main_rec.csv       # ~4 min
  python3 run_e1.py pv  ../data/raw/e1_pv.csv             # ~8 min
  python3 run_e1.py oat ../data/raw/e1_oat.csv            # ~15 min
  python3 stats_hboot.py ../data/raw/e1_main.csv,../data/raw/e1_main_rec.csv ../data/processed
  python3 analyze_pv.py ../data/raw/e1_pv.csv ../data/processed/provenance_sensitivity.csv
  (cd ../notebooks && jupyter nbconvert --to notebook --execute --inplace provenance_sensitivity_analysis.ipynb)
fi
if [[ $step == all || $step == e2 ]]; then python3 risk_engine_eval.py ../data/raw ../data/processed; fi
if [[ $step == all || $step == e3 ]]; then
  python3 bench_crypto_v2.py ../data/raw/e3_crypto_v2.json ../data/raw/e3_crypto_samples.npz
  python3 batching_latency.py ../data/raw/e3_crypto_v2.json ../data/processed/e3_batching_latency.csv
fi
if [[ $step == all || $step == e4 ]]; then (cd ../poc && python3 ztas_poc.py run ../data/raw/poc_results.json); fi
if [[ $step == all || $step == formal ]]; then (cd ../formal && python3 model_check.py logs/model_check_results.json | tee logs/model_check.log); fi
if [[ $step == analysis ]]; then
  python3 stats_hboot.py ../data/raw/e1_main.csv,../data/raw/e1_main_rec.csv ../data/processed
  python3 analyze_pv.py ../data/raw/e1_pv.csv ../data/processed/provenance_sensitivity.csv
  python3 batching_latency.py ../data/raw/e3_crypto_v2.json ../data/processed/e3_batching_latency.csv
fi
if [[ $step == all || $step == figs || $step == analysis ]]; then
  python3 make_figures.py && python3 make_tables.py
  if [ -d ../manuscript ]; then
    cp ../figures/fig_*.pdf ../manuscript/figs/ && cp ../tables/*.tex ../manuscript/tables/
    (cd ../manuscript && pdflatex -interaction=nonstopmode main >/dev/null && bibtex main >/dev/null && pdflatex -interaction=nonstopmode main >/dev/null && pdflatex -interaction=nonstopmode main >/dev/null)
  fi
fi
echo "done: $step"
