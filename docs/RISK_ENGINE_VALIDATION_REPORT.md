# RISK_ENGINE_VALIDATION_REPORT.md (E2, reviewer concern R3)

Script: `code/risk_engine_eval.py`. Outputs: `data/processed/e2_metrics.csv`, `e2_confusion.csv`,
`e2_evidence_accumulation.csv`, `data/raw/e2_curves.csv`; `figures/fig_risk.pdf`. Seed 424242.
**All score distributions are synthetic; none represents measured industrial telemetry.**

## 1. Audit of the v1 risk model

| Item | Finding | Action |
|---|---|---|
| Eq. (1) | Weighted sum, weights on simplex; consistent between paper and code | kept |
| Weights | production (0.10, 0.10, 0.35, 0.30, 0.15) vs uniform; only one mode defined | added mode-aware maintenance weights (0.05, 0.05, 0.35, 0.40, 0.15) for the shift scenario |
| Thresholds | θ = (30, 70, 90). Under every family, < 0.4% of malicious and 0% of legitimate requests exceed θ2 | stated; quarantine driven by evidence accumulation |
| Block tier | code isolated, paper said deny + alert | fixed: deny + alert + 2 units of evidence |
| Step-up | attacker fails with p = 0.7; legitimate failures not modelled | modelled per device class and connectivity state |
| Evidence counter | never decays or resets | Eq. (2): exponential decay (half-life h), −1 on success, outage-aware, floor 0 |
| Isolation of safety assets | automatic | operator approval required for operations-phase assets |

## 2. Distribution families and why each matters

| Family | Construction | Relevance |
|---|---|---|
| Gaussian (v1) | N(15, 8²) legit; malicious behaviour/system N(μ, 15²) | baseline |
| Skewed | Gamma(2, 7.5) legit; log-normal malicious | bounded, asymmetric telemetry (counts, durations) |
| Heavy-tailed | 15 + 8·t₃ legit; μ + 15·t₃ malicious | rare large legitimate deviations (unscheduled maintenance) |
| Correlated | pairwise ρ = 0.6; shared latent factor for malicious | anomalies raise several dimensions together |
| Overlapping | μ_mal = 20 | near-indistinguishable attacker |
| Distribution shift | legit temporal +25, spatial +20 | night-shift / remote maintenance not reflected in weights |

## 3. Detection metrics at θ1 = 30, prevalence 1% (production weights unless noted)

| Family | μ_mal | TPR | FPR | Precision | F1 | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|---|
| Gaussian | 55 | 0.689 | 0.0001 | 0.986 | 0.811 | 0.987 | 0.877 |
| Gaussian (uniform w) | 55 | 0.319 | 0.0000 | 0.988 | 0.482 | 0.959 | 0.678 |
| Gaussian | 28 | 0.108 | 0.0001 | 0.948 | 0.195 | 0.798 | 0.271 |
| Skewed | 28 | 0.153 | 0.0123 | 0.112 | 0.129 | 0.825 | 0.072 |
| Heavy-tailed | 28 | 0.178 | 0.0173 | 0.094 | 0.123 | 0.746 | 0.053 |
| Correlated | 28 | 0.182 | 0.0124 | 0.129 | 0.151 | 0.753 | 0.100 |
| Overlapping | 20 | 0.031 | 0.0001 | 0.841 | 0.061 | 0.637 | 0.092 |
| Shift (production w) | 28 | 0.111 | 0.0040 | 0.220 | 0.148 | 0.597 | 0.089 |
| Shift (mode-aware w) | 28 | 0.155 | 0.0016 | 0.495 | 0.236 | 0.709 | 0.183 |

FNR = 1 − TPR; recall = TPR. Prevalence-10% values, noisy variants and all uniform-weight rows are in
`e2_metrics.csv`; confusion matrices per 100,000 requests at 1% prevalence in `e2_confusion.csv`. Legitimate isolation
rate per request (r > θ3) was 0 in every family; malicious detection rate = TPR above.

**Reading.** Separation is good only under the optimistic Gaussian assumption. With skewed, heavy-tailed or correlated
scores and a stealthy attacker, most escalations at 1% prevalence come from legitimate requests (precision ≈ 0.1).
Mode-aware weights matter under distribution shift.

## 4. Evidence accumulation

Setting: 2000 legitimate entities per class, 480 requests per 8-h shift, routine re-verification 2% plus the family FPR;
legitimate step-up failure 2% (human), 0.5% (field device), 0.1% (edge service), raised to 40% / 20% during outages
(5% of time, mean 10 requests; human failure unchanged). Attacker: escalation probability = TPR of the family, step-up
failure 0.7, 2000 attacker sequences.

Legitimate entities isolated per shift (%), heavy-tailed scores; median escalated requests to quarantine a stealthy attacker:

| Policy | κ=2 human | κ=2 device | κ=2 attacker | κ=3 human | κ=3 device | κ=3 attacker |
|---|---|---|---|---|---|---|
| No decay, no reset (v1) | 4.90 | 8.00 | 22 | 0.45 | 1.75 | 35 |
| Reset on success | 0.55 | 3.00 | 24 | 0.00 | 0.50 | 48 |
| Decay (h = 30) | 0.00 | 0.20 | 43 | 0.00 | 0.00 | 84 |
| Decay + outage-aware | 0.00 | 0.00 | 47 | 0.00 | 0.00 | 86 |

All scenarios and κ ∈ {1, 2, 3, 5, 8} are in the CSV. κ = 1 isolates 1–33% of legitimate entities per shift (depending on class and policy) and is unusable.

Questions from the reviewer:
* *Can repeated legitimate step-up failures lead to isolation?* Yes — under the v1 rule, 8% of field devices per shift
  with heavy-tailed scores (≈ 100% per year).
* *How is the counter reset / does it decay?* v2: exponential decay (half-life 30 requests) and −1 per successful step-up.
* *Intermittent connectivity?* Device and service failures during outages dominate false isolation; excluding them
  (outage-aware) removes it, but an attacker who acts during outages also avoids evidence, so outage signals must come
  from an independent network-management source.
* *Different device classes?* Yes: devices are most affected by outages; thresholds and decay should be class-specific.
* *Human approval before isolating safety-critical assets?* Yes; implemented in the PDP and PoC (scenario S6).

**Recommendation (adopted as default, E1 configuration `ztas_rec`).** Decay + outage-aware counter, κ = 3,
class-specific calibration, operator approval for operations assets, reversible isolation. Cost: slower containment
(median 86 vs 22 escalated requests for the stealthy attacker); in E1 the reference-topology compromised fraction rose
from 0.126 (v1 rule) to 0.138.

Statistical note: zero observed false isolations in 2000 entities gives a 95% upper bound of 0.15% per shift (rule of
three), which is still large over a year; field calibration is required.
