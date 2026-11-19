"""
E3b: batch-formation and end-to-end provenance latency under Poisson record arrivals, with size- and
timeout-based batch closure and a single signing core (FIFO). Service times come from the MEASURED
medians in e3_crypto_v2.json (server CPU), fitted as t(B) = a + b*B. Verification adds the measured
per-record independent verification cost (one ML-DSA-65 verify + one inclusion proof). Network and
ledger-anchoring delays are NOT included. This is a model driven by measurements, not a measurement.

Usage: python3 batching_latency.py ../data/raw/e3_crypto_v2.json ../data/processed/e3_batching_latency.csv
"""
import sys, json
import numpy as np
import pandas as pd


def fit(R):
    B = np.array([m["batch"] for m in R["merkle"]], float)
    t = np.array([m["build_and_sign"]["median_us"] for m in R["merkle"]], float)
    b, a = np.polyfit(B, t, 1)
    ver = np.median([m["verify_per_record_us_independent"] for m in R["merkle"]])
    return a, b, ver


def simulate(lam, Bt, tau, a, b, ver, horizon=60.0, rng=None):
    n = int(lam * horizon)
    arr = np.cumsum(rng.exponential(1 / lam, n))
    lat = np.empty(n); signer_free = 0.0; busy = 0.0; nb = 0; nto = 0; sizes = []
    i = 0
    while i < n:
        start = arr[i]; j = i
        deadline = start + tau
        # batch closes when Bt records collected or deadline reached
        k = min(i + Bt, n)
        idx_dead = np.searchsorted(arr, deadline, side="right")
        end = min(k, idx_dead)
        if end == i: end = i + 1
        if end - i < Bt and end < n:
            close = deadline; nto += 1
        else:
            close = arr[end - 1]
        size = end - i; sizes.append(size)
        svc = (a + b * size) / 1e6
        st = max(close, signer_free); fin = st + svc; signer_free = fin; busy += svc
        lat[i:end] = fin - arr[i:end] + ver / 1e6
        nb += 1; i = end
    span = max(arr[-1], signer_free) - arr[0]
    return dict(arrival_rate=lam, batch_target=Bt, timeout_ms=tau * 1e3 if np.isfinite(tau) else np.inf,
                mean_batch=float(np.mean(sizes)), frac_timeout_closed=nto / nb, signer_utilisation=busy / span,
                latency_p50_ms=float(np.median(lat) * 1e3), latency_p99_ms=float(np.percentile(lat, 99) * 1e3),
                latency_max_ms=float(lat.max() * 1e3), throughput_rec_s=n / span, stable=busy / span < 0.95)


if __name__ == "__main__":
    R = json.load(open(sys.argv[1])); a, b, ver = fit(R)
    print(f"fit: t(B) = {a:.0f} us + {b:.2f} us*B ; per-record verification {ver:.0f} us")
    rng = np.random.default_rng(99); rows = []
    for lam in [10, 100, 1000, 10000]:
        for Bt in [1, 16, 64, 256, 1024]:
            for tau in [0.01, 0.1, 1.0, np.inf]:
                h = 60.0 if lam <= 1000 else 20.0
                rows.append(simulate(lam, Bt, tau, a, b, ver, horizon=h, rng=rng))
    df = pd.DataFrame(rows); df["fit_a_us"] = a; df["fit_b_us_per_record"] = b; df["verify_us_per_record"] = ver
    df.to_csv(sys.argv[2], index=False)
    print(df[["arrival_rate", "batch_target", "timeout_ms", "mean_batch", "frac_timeout_closed", "signer_utilisation",
              "latency_p50_ms", "latency_p99_ms", "stable"]].round(3).to_string())
