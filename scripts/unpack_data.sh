#!/usr/bin/env bash
# Decompress the shipped raw CSV files (data/raw/*.csv.gz -> data/raw/*.csv), keeping the .gz files.
set -euo pipefail
cd "$(dirname "$0")/../data/raw"
for f in *.csv.gz; do [ -f "${f%.gz}" ] || gunzip -k "$f"; done
echo "raw data unpacked in data/raw"
