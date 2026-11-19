# CRYPTOGRAPHIC_BENCHMARK_REPORT.md (E3, reviewer concern R5)

**Scope.** Server-class CPU only. These results must not be extrapolated to industrial edge gateways, PLC-class
microcontrollers or HSMs.

## 1. Re-analysis of the v1 benchmark (`original/exp_v1/bench_crypto.py`)

| Aspect | v1 | v2 (`code/bench_crypto_v2.py`) |
|---|---|---|
| Repetitions | 3000 (100 for SLH-DSA), 300/60 for batching | 5000 classical, 2000 ML-DSA-44/65, 1000 ML-DSA-87, 100 SLH-DSA; 40–200 for batching; 2000 for proofs |
| Warm-up | min(20, n) | 50 classical, 10 PQ, 5–20 batching |
| Timer | `time.perf_counter_ns`, single thread | same |
| Statistic | median, p95 | mean, sd, median, p5, p95, p99 |
| Outliers | none removed | none removed (medians used in text) |
| Raw samples | not saved | saved: `data/raw/e3_crypto_samples.npz` |
| Environment | stated in paper only | recorded in JSON (CPU, memory, platform, versions) |
| Verification costs | signature only | + inclusion-proof generation/verification, whole-batch verification |
| Merkle construction | odd-node duplication, root signed (collision; see FORMAL report) | odd-node promotion, signed header with leaf count, gateway, first seq |
| ECDSA public key size | hard-coded 64 B | measured 65 B (uncompressed point) |
| PQ implementation | not checked | library binary has no AVX2 symbols → **presumed** portable implementation (unverified) |

Environment: Intel Xeon @ 2.10 GHz, 2 vCPU (one used), 8 GB RAM, Linux 6.18, Python 3.13.18,
cryptography 50.0.1 (OpenSSL backend), pqcrypto 1.0.0.

## 2. Results (median µs; p99 in `data/raw/e3_crypto_v2.json`)

| Scheme | Sign | Verify | Signature (B) | Public key (B) | v1 sign / verify |
|---|---|---|---|---|---|
| Ed25519 | 32.3 | 116.2 | 64 | 32 | 28.7 / 102.4 |
| ECDSA P-256 | 28.2 | 78.6 | 71 | 65 | 28.5 / 92.3 |
| ML-DSA-44 | 6437 | 115.4 | 2420 | 1312 | 6489 / 114.8 |
| ML-DSA-65 | 9348 | 180.4 | 3309 | 1952 | 8895 / 194.5 |
| ML-DSA-87 | 13775 | 421.8 | 4627 | 2592 | — |
| SLH-DSA-SHA2-128f | 14205 | 980.3 | 17088 | 32 | 13191 / 855.3 |
| X25519 exchange | — | 38.5 | 32 | 32 | 30.5 |
| ML-KEM-768 encaps / decaps | 68.6 / 81.3 | | ct 1088 | 1184 | 62.5 / 77.4 |
| SHA-256 chain step (256 B) | 0.54 | | | | 0.48 |

v1 and v2 medians differ by up to ≈15%, which we attribute to run-to-run variation on a shared virtual machine; the
conclusions are unchanged.

### Merkle batching with ML-DSA-65 (corrected construction)

| B | Build + sign (µs) | Sign / record (µs) | Proof hashes | Verify one record (sig + proof, µs) | Verify whole batch / record (µs) | Authenticator B / record |
|---|---|---|---|---|---|---|
| 1 | 10136 | 10136 | 0 | 184.6 | 184.6 | 3313 |
| 4 | 8983 | 2246 | 2 | 185.4 | 47.4 | 892 |
| 16 | 8900 | 556 | 4 | 185.9 | 13.8 | 335 |
| 64 | 9160 | 143 | 6 | 194.8 | 6.0 | 244 |
| 256 | 10911 | 42.6 | 8 | 175.8 | 4.4 | 269 |
| 1024 | 10583 | 10.3 | 10 | 191.9 | 4.9 | 323 |
| 4096 | 12548 | 3.1 | 12 | 186.4 | 5.4 | 385 |

## 3. Batching latency model (`code/batching_latency.py`, `data/processed/e3_batching_latency.csv`)

Single FIFO signer; batch closes at B records or timeout τ after its first record; service time fitted to measured
medians t(B) = 9588 µs + 0.75 µs·B; per-record verification 186 µs added; Poisson arrivals for 60 s (20 s at 10⁴/s).
Network, ledger anchoring and HSM latencies are **not** included.

| Arrival (rec/s) | B | τ | Mean batch | Signer utilisation | p50 (ms) | p99 (ms) | Stable |
|---|---|---|---|---|---|---|---|
| 10 | 1 | — | 1 | 0.10 | 9.8 | 18.8 | yes |
| 10 | 64 | 100 ms | 2.2 | 0.05 | 103 | 110 | yes |
| 10 | 64 | none | 60 | 0.002 | 2889 | 7700 | yes |
| 100 | 1 | — | 1 | 0.96 | 76 | 263 | **no** |
| 100 | 64 | 100 ms | 10.8 | 0.09 | 66 | 110 | yes |
| 1000 | 64 | 100 ms | 64 | 0.15 | 41 | 82 | yes |
| 1000 | 1024 | 1 s | 984 | 0.01 | 506 | 999 | yes |
| 10000 | 64 | 100 ms | 64 | 1.00 | 5042 | 9968 | **no** |
| 10000 | 256 | 100 ms | 256 | 0.38 | 23 | 36 | yes |

Findings: per-record PQ signing saturates one core at ≈100 records/s; stable operation requires B ≳ λ·t_sign; the
timeout bounds latency when arrivals are slow and must always be set (without it, a 10 records/s stream waits up to
seconds); the v1 claim "1.1×10⁵ records/s per core" counted signing only and was removed.

## 4. Deployment constraints (paper Sec. VIII-C)
* **Gateways/HSMs:** HSM support for ML-DSA/ML-KEM varies; signing inside an HSM adds I/O latency and may be slower than
  a server core. Benchmark on the target gateway with `bench_crypto_v2.py` before sizing B and τ.
* **Key rotation:** per-gateway epochs; rotation creates a new epoch; verifiers accept both during an overlap window.
* **Revocation:** verifier refresh interval bounds exposure (PoC: 1 s); revoking an epoch also rejects genuine records
  signed before compromise unless anchored (Proposition 3).
* **Compromise recovery:** revoke, rekey, re-anchor; re-verify records signed since last known-good anchor.
* **Algorithm migration:** hybrid classical + PQ signatures during transition; periodic re-signing/re-anchoring of
  archives under new algorithms.
* **Long-term archival verification:** depends on trusted timestamps and ledger anchoring, not on key validity alone.
* **Ledger unavailability / network interruption:** gateways keep signing and buffer anchors; verifiers accept
  signed-but-unanchored records only for low-risk flows; queued anchors are flushed when the ledger returns.
* **Two-path design:** batched PQ signatures for lineage and audit; per-message authentication with hybrid ML-KEM-derived
  keys for time-critical commands, provenance recorded asynchronously.
