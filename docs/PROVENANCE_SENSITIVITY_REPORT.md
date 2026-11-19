# PROVENANCE_SENSITIVITY_REPORT.md (reviewer concern R1)

**p_v is a simulation parameter** — the assumed probability that a boundary provenance gate rejects a malicious
artifact. It has **not** been measured. **f_art** is the assumed share of flows on which lateral movement is
artifact-mediated; only those moves can be stopped by a provenance gate.

Files: `data/raw/e1_pv.csv` (raw), `data/processed/provenance_sensitivity.csv` (summary with hierarchical CIs),
`notebooks/provenance_sensitivity_analysis.ipynb` (executed), `figures/fig_sensitivity.pdf` (panel a),
`figures/nb_provenance_sensitivity.png`.
Design: 9 topologies × 30 graphs × 20 runs × 2 profiles × p_v ∈ {0, .1, .3, .5, .7, .8, .9, .95, .99} ×
f_art ∈ {0.5, 1.0} × {ZT+prov, ZTAS-DTh (v1 evidence rule)}, plus ZT and ZTAS-without-provenance references, all on
paired draws.

## 1. What each mechanism can establish

| Property | Established by | Guarantee | Not established |
|---|---|---|---|
| Cryptographic integrity | Hash chain, Merkle proof, ML-DSA header signature | Record/artifact unchanged since signing (key uncompromised) | Anything about content truth |
| Data authenticity | Signature + identity binding | Produced under the key of gateway g | That g or the actor was honest |
| Data provenance (lineage) | Parent links, actor role, lineage policy | Admissible derivation path and role | Malice within an admissible path |
| Freshness | Signed per-gateway sequence numbers, verifier state | No duplicate or out-of-order acceptance (per verifier) | Omission unless strict mode |
| Correctness | — (plausibility checks, redundancy, twin consistency) | none from cryptography | — |
| Semantic trustworthiness | — (inspection, sandboxing, review) | none from cryptography | — |
| Malicious transformation | Lineage (unauthorised role), behaviour analytics, two-person rule | partial | Authorised insider (S7) |

## 2. Adversary scenarios (paper Table III)

| Scenario | Crypto | Fresh. | Lineage | Other | Regime |
|---|---|---|---|---|---|
| S1 modified after signing | ✓ | | | | p_v ≈ 0.99 |
| S2 false data before signing | | | | plausibility, redundancy | 0.1–0.3 |
| S3 compromised identity signs | | | partial (out-of-role) | behaviour | 0.3–0.5 |
| S4 validly signed malicious supplier artifact | | | | inspection, sandbox, SBOM | 0.1–0.3 |
| S5 gateway compromised | | | partial | attestation, cross-gateway consistency | 0.1–0.5 |
| S6 signing key compromised | after revocation only | | | key-use anomaly detection | 0 until revocation |
| S7 authorised malicious transformation | | | | two-person rule, behaviour | ≈ 0.1 |
| S8 replay / reordering | ✓ | ✓ | | | ≈ 0.99 |

Regimes are assumptions used to read the sensitivity curves; they are not measured detection rates.
Demonstrated in the PoC: S1 (denied), S8 replay (denied), S3-type wrong role (denied by lineage), S4 (**accepted** —
limitation confirmed). Model checking: S6 violates integrity (expected), revocation then restores it.

## 3. Results at the requested p_v grid (reference topology)

Compromised fraction (mean; 95% CIs in the CSV):

| Config | f_art | Profile | 0.1 | 0.3 | 0.5 | 0.7 | 0.9 | 0.99 |
|---|---|---|---|---|---|---|---|---|
| ZT+prov | 0.5 | both* | 0.775 | 0.700 | 0.615 | 0.548 | 0.486 | 0.461 |
| ZT+prov | 1.0 | both* | 0.712 | 0.520 | 0.327 | 0.201 | 0.142 | 0.124 |
| ZTAS-DTh | 0.5 | noisy | 0.028 | 0.028 | 0.027 | 0.027 | 0.027 | 0.026 |
| ZTAS-DTh | 0.5 | stealthy | 0.212 | 0.183 | 0.156 | 0.138 | 0.126 | 0.119 |
| ZTAS-DTh | 1.0 | stealthy | 0.193 | 0.140 | 0.102 | 0.078 | 0.067 | 0.063 |

\*ZT+prov does not use risk scores, so both profiles give identical results.

Propagation probability to operations, containment probability, detection probability and residual compromise are in
the CSV for every cell; e.g. ZT+prov, f_art = 1, p_v = 0.9: propagation 0.020, containment 0.980; f_art = 0.5,
p_v = 0.9: propagation 0.453, containment 0.540. Detection probability is ≥ 0.99 for all ZT-based configurations because
generic monitoring eventually isolates some compromised entity; it is therefore not a discriminating metric here.

**Difference between attacker profiles (ZTAS-DTh, f_art = 0.5):** stealthy − noisy = +0.18 (p_v = 0.1) to +0.09
(p_v = 0.99). For the noisy attacker the risk engine alone contains the attack and p_v hardly matters.

## 4. Interpretation

1. In v1, f_art was implicitly 1 and p_v = 0.9, which made provenance look dominant. With f_art = 0.5 and the same p_v,
   ZT+prov compromises 0.49 of the reference thread instead of 0.14.
2. Provenance verification is valuable in proportion to the share of propagation that passes through artifacts **and**
   to the share of malicious artifacts that are detectable at a gate. Only S1 and S8 are reliably detectable by
   cryptography; S2, S4 and S7 sit at the low end of the curve, where the provenance contribution is small.
3. For full ZTAS-DTh the dependence on p_v is moderate, because segmentation and the risk engine also act on
   interface-mediated moves — but those mechanisms rest on their own unmeasured parameters (p_act, d).
4. Across topologies (notebook §4), the provenance benefit is largest where many cross-boundary flows exist
   (multi-organisation, shared repository, feedback loop) and smallest in sparse and dense graphs (ZT vs ZT+prov at p_v = 0.9, f_art = 0.5: −0.71, −0.55, −0.41 vs −0.07, −0.18).

## 5. What remains unvalidated
No detection probability has been measured. Measuring p_v per scenario requires real artifacts, real lineage policies
and red-team injections on an industrial or hardware-in-the-loop testbed.
