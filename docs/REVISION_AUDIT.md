# REVISION_AUDIT.md — ZTAS-DTh major revision (Stage 0)

Date: 2026-11-18. Auditor: revision team (Claude, acting on the author's instructions).

## 0. Source of reviewer concerns

No separate reviewer report file was provided. The reviewer concerns audited here are the ones stated in the
author's revision brief (Sections 3–10 of the master prompt), labelled **R1–R8** below. If the actual decision
letter contains additional comments, they must be added to this table and to `RESPONSE_TO_REVIEWERS.md`.

| ID | Reviewer concern (paraphrased from brief) |
|---|---|
| R1 | Provenance verification (p_v = 0.9) is assumed, yet it drives the main result; properties conflated; adversary scenarios incomplete |
| R2 | Synthetic DTh graph model not representative; baselines incomplete (no "static ZT + provenance"); uncertainty treats 1000 runs as independent |
| R3 | Risk engine evaluated only with assumed Gaussian scores; metrics incomplete; evidence accumulation unexamined |
| R4 | Formal treatment insufficient for the security claims; proposition needs scrutiny |
| R5 | PQ evaluation ignores batching latency and deployment constraints |
| R6 | Mechanisms evaluated separately; no integrated proof of concept |
| R7 | Novelty beyond combining existing mechanisms not demonstrated; Table I criteria undefined |
| R8 | Industrial safety and operational feasibility under-discussed |

## 1. Inventory of the available research project (v1, preserved under `original/`)

| Item | Path | Notes |
|---|---|---|
| Manuscript source (v1) | `original/paper_v1/main.tex`, `refs.bib`, `main.bbl` | IEEEtran journal, 10 pp., 41 refs |
| Compiled manuscript | `original/paper_v1/main.pdf` | |
| Figures (v1) | `original/paper_v1/figs/*.pdf` (5) | Fig. 1 is TikZ inside main.tex |
| Simulation (E1/E2) | `original/exp_v1/sim_propagation.py` | single file, numpy + networkx |
| Crypto benchmark (E3) | `original/exp_v1/bench_crypto.py` | cryptography 50.0.1, pqcrypto 1.0.0 |
| Figure script | `original/exp_v1/make_figs.py` | |
| Raw results | `original/exp_v1/results_sim.json`, `results_crypto.json` | SHA-256 in `original/CHECKSUMS.sha256` |
| Configuration files | none (parameters hard-coded in `PARAMS`) | |
| Statistical analysis scripts | none (CI computed inline as 1.96·sd/√n) | |
| Literature files | none besides `refs.bib`; thesis `Tahir khan.docx` on the author's computer | |
| Reviewer report | **not provided** | see Section 0 |

## 2. Code audit — findings (v1)

| # | Finding | Location | Effect on v1 results | Class |
|---|---|---|---|---|
| C1 | Provenance check is applied to **every** cross-phase lateral move, i.e. all cross-phase propagation is assumed to be artifact-mediated. Interface-mediated pivots (stolen credentials, API abuse) would not be stopped by a lineage check. | `simulate()`, `"prov" in mech` branch | **Inflates** the provenance effect and the headline ZTAS-DTh result | Critical technical |
| C2 | p_v is a single assumed constant (0.9) that does not distinguish post-signing tampering (cryptographically detectable) from validly signed malicious content (not cryptographically detectable). | `PARAMS["prov_detect"]` | Main result rests on an unmeasured parameter | Critical technical |
| C3 | ZTAS-DTh configuration omits the generic per-step anomaly detection (d = 0.05) that static ZT has, so ZTAS-DTh is not a strict superset of its baseline. | `simulate()` | Slightly disfavours ZTAS-DTh; control budgets not comparable | Experimental weakness |
| C4 | Code isolates the source entity in the **block** tier (70 < r ≤ 90); manuscript Algorithm 1 says block = deny + alert. | `simulate()` line 104 | None in practice (tier never reached), but code ≠ paper | Formal-model / consistency |
| C5 | Configurations are **not paired**: one RNG stream (seed 1) is consumed differently by each configuration, so entry points differ across configurations. | `run()` | Adds between-configuration noise; no paired effect sizes possible | Experimental weakness |
| C6 | CIs use 1.96·sd/√1000, treating 1000 runs on 10 graphs as independent; graph-level clustering ignored. | `run()` | CIs too narrow | Experimental weakness / statistics |
| C7 | Only one topology family (Erdős–Rényi within phase, fixed cross-phase counts); cross-phase edges drawn with replacement so duplicates collapse (effective count ≤ 6); no shared repositories, no organisational trust domains, no hubs. | `build_graph()` | Limited external validity | Experimental weakness |
| C8 | Entry points: uniform over suppliers and D/M/S entities; operations entities never entry points. Undocumented in paper. | `simulate()` | Assumption not stated | Writing / reproducibility |
| C9 | "contained" metric is actually the fraction of compromised entities isolated (isolation ratio); entities whose successors are all compromised are never isolated because isolation is only triggered by attempts. | `simulate()` | Metric naming misleading | Experimental weakness |
| C10 | Legitimate traffic is not simulated in E1, so false isolation of legitimate entities has no cost in E1. | E1 design | Benefits shown without operational cost | Experimental weakness |
| C11 | Risk components drawn i.i.d. per request; no correlation, persistence, skew or heavy tails; E2 reports only escalation fractions. | `risk_score()`, `roc()` | Weak evidence for risk engine | Experimental weakness |
| C12 | Evidence counter never decays or resets; legitimate step-up failures not modelled. | `simulate()` | Unknown false-isolation behaviour | Critical technical (safety) |
| C13 | **Merkle construction duplicates the last node on odd levels without binding the leaf count**: leaf lists [a,b,c] and [a,b,c,c] give the same root (verified by script). A batch could be extended with a duplicated record without changing the signed root. | `bench_crypto.py::merkle_root` and paper Sec. IV-F | Correctness flaw in the described provenance construction (no effect on timings) | Critical technical |
| C14 | Proposition 1 covers post-signing alteration only; it does not address replay, reordering, omission of records/batches, freshness, or gateway compromise distinct from key compromise. | paper Sec. IV-F | Over-broad reading possible | Formal-model weakness |
| C15 | Benchmark: medians and p95 only, no raw samples saved, no mean/sd, no verification cost for inclusion proofs, no batch-formation latency; PQ backend (portable vs. AVX2) not verified; ECDSA pk size hard-coded as 64 B (uncompressed point is 65 B). | `bench_crypto.py` | Incomplete performance evidence | Reproducibility / experimental |
| C16 | Paper claims "1.1×10^5 records/s per core" from signing cost only (record hashing, proof generation and verification excluded). | paper Sec. VI-D | Overstated throughput | Writing / experimental |
| C17 | Table I coverage marks assigned from abstracts without stated criteria. | paper Table I | Possible unfair marks | Literature / novelty |
| C18 | Parameters (p_exploit, p_a, p_act, zone detection, etc.) not justified and not listed in a table in the paper. | paper Sec. V | Reproducibility | Reproducibility |

## 3. Reviewer-concern-to-revision mapping

| Reviewer concern | Manuscript location (v1) | Existing evidence | Required improvement | Proposed method | Class | Status |
|---|---|---|---|---|---|---|
| R1.1 Properties conflated (integrity vs. truthfulness) | Sec. IV-F, VII-A | Proposition 1 + caveat paragraph | Separate 7 properties; say what crypto does/doesn't give | New subsection + table; FORMAL_SECURITY_MODEL.md | Critical technical | Planned (Stage 4/9) |
| R1.2 Adversary scenarios for provenance | Sec. III-B, IV-F | none | 8 scenarios × detecting mechanism | Scenario table; scenario-specific simulation regimes | Critical technical | Planned (Stage 1) |
| R1.3 p_v sensitivity | Fig. 4b (6 values, stealthy only) | v1 sweep | Sweep {0.1,0.3,0.5,0.7,0.9,0.99} (+0, finer) × profiles × metrics; CSV + notebook | Re-run with new simulator; fix C1 (artifact fraction) | Critical technical | Planned (Stage 1) |
| R1.4 Interpretation | Abstract, Sec. VI-B, VII | headline numbers | Separate guaranteed / enforced / assumed / demonstrated / unvalidated | Rewrite; "evidence ladder" table | Writing | Planned (Stage 9) |
| R2.1 Document generator | none | code | Document original model | SIMULATION_VALIDATION_REPORT.md §1 | Reproducibility | Done in this audit (C5–C9), report in Stage 2 |
| R2.2 Topologies (8) | Sec. V-A | 1 family | 8 justified topology families | New generator module | Experimental | Planned (Stage 2) |
| R2.3 Fair baselines incl. ZT+prov | Sec. V-A | 4 configs | Add ZT+prov; ZTAS superset of ZT (C3); control-budget table | New config set | Experimental | Planned (Stage 2) |
| R2.4 Expanded MC + metrics | Table IV | 3 metrics | Path length, phases, detection, time-to-detection, containment, residual | New simulator | Experimental | Planned (Stage 2) |
| R2.5 Uncertainty | Table IV CIs | naive CIs (C6) | Hierarchical bootstrap, per-graph results, effect sizes, seeds | `stats_hboot.py` | Statistics | Planned (Stage 2) |
| R3.1 Audit risk model | Sec. IV-D, Alg. 1 | — | Consistency check (C4, C12, unreachable tiers) | Audit + fix | Formal-model | Planned (Stage 3) |
| R3.2 Alternative distributions | E2 | Gaussian only | skewed, heavy-tailed, correlated, overlapping, shift | `risk_engine_eval.py` | Experimental | Planned (Stage 3) |
| R3.3 Metrics | Fig. 5 | TPR/FPR curve | TPR, FPR, FNR, precision, recall, F1, ROC-AUC, PR-AUC, confusion matrices | same | Experimental | Planned (Stage 3) |
| R3.4 Evidence accumulation | Sec. IV-D | rule only | κ sweep, decay/reset, connectivity, device classes, human approval | sequence simulation | Critical technical (safety) | Planned (Stage 3) |
| R4.1 Security properties | Sec. IV | 1 proposition | 8 properties with assumptions/component/guarantee | FORMAL_SECURITY_MODEL.md | Formal-model | Planned (Stage 4) |
| R4.2 Proposition review | Sec. IV-F | proof sketch | Correct (C13, C14) | Revised propositions | Formal-model | Planned (Stage 4) |
| R4.3 Formal verification | none | — | Feasibility; execute if feasible | TLA+ / TLC (Java available) incl. negative control | Formal-model | Planned (Stage 4) |
| R5.1 Re-analyse benchmarks | Table V | medians | Method audit; raw samples; verification costs | `bench_crypto_v2.py` | Reproducibility | Planned (Stage 5) |
| R5.2 Batching trade-offs | Fig. 6 | signing cost only | Latency vs arrival rate, timeout closure, verification | queueing simulation driven by measured costs | Experimental | Planned (Stage 5) |
| R5.3 Deployment limits | Sec. VII | brief | Gateway/HSM, rotation, revocation, migration, archival, ledger outage | Discussion + report | Writing | Planned (Stage 5/9) |
| R6 Integration PoC | none | — | Controlled software PoC with measured latencies | Python micro-services on localhost | Experimental | Planned (Stage 6) |
| R7.1 Literature | Sec. II | 41 refs | Focused review, verified refs | Fast-Track/Crossref verification | Literature | Planned (Stage 7) |
| R7.2 Table I criteria | Table I | marks from abstracts (C17) | Evidence-type columns + defined criteria | Revised table | Literature | Planned (Stage 7) |
| R7.3 Worked example | none | — | Compromised artifact under 4 architectures | New subsection | Novelty | Planned (Stage 7) |
| R8 Safety/operations | Sec. VII-A | short | Isolation safety, governance, privacy, legacy, cost | New section | Writing | Planned (Stage 8) |

## 4. Technical inconsistencies found (manuscript ↔ code ↔ claims)

1. Algorithm 1 block tier vs. code (C4).
2. Abstract/Results present provenance as dominant mechanism while the simulator applies it to all cross-phase moves (C1).
3. "Isolation ratio" reported as containment (C9).
4. Merkle construction described in Sec. IV-F is vulnerable to leaf duplication (C13).
5. Proposition 1's guarantee does not extend to replay/omission/reordering although Sec. IV-F mentions hash-chaining "makes deletion or reordering detectable" — this only holds for records within a node's chain if the verifier sees the chain head; it does not hold for whole-batch omission without sequence numbers.
6. Throughput claim excludes verification and hashing (C16).
7. Thresholds θ2, θ3 unreachable under the E2 distributions — acknowledged in v1, but Algorithm 1 still presents them as operative.

## 5. Missing experimental evidence (v1)

- No measured provenance detection rate (p_v); none can be measured without industrial artifacts and a real lineage policy. **Cannot be fully resolved in this revision**; addressed by sensitivity analysis + scenario decomposition + PoC demonstration of the cryptographic part only.
- No legitimate-traffic cost in E1.
- No integrated system measurements.
- No measurements on edge-gateway or HSM hardware.
- No real DTh topologies.

## 6. Feasibility, compute and schedule

| Stage | Work | Feasible here? | Compute estimate (2 vCPU, 7 GB) |
|---|---|---|---|
| 1–2 | New simulator, 8 topologies × 5 configs × 2 profiles × 30 graphs × 100 runs; p_v sweep; one-at-a-time sensitivity; hierarchical bootstrap | Yes | ~20–40 min CPU |
| 3 | Risk-engine distributions, metrics, evidence accumulation | Yes | < 5 min |
| 4 | TLA+ model + TLC (incl. negative control) | Yes (Java present; tla2tools.jar from GitHub) | < 5 min |
| 5 | Re-benchmark + batching queue simulation | Yes (server CPU only) | ~10 min |
| 6 | Software PoC (localhost micro-services) | Yes, as controlled software PoC; **not** industrial | ~10 min |
| 7–8 | Literature verification, Table I, worked example, safety | Yes | — |
| 9 | Manuscript rewrite, reports, package | Yes | — |
| — | Edge-gateway / HSM benchmarks, industrial testbed, real topologies, measured p_v | **No** — requires hardware/partners | — |

## 7. Files to be created

`code/dth_sim.py`, `code/topologies.py`, `code/run_e1.py`, `code/stats_hboot.py`, `code/risk_engine_eval.py`,
`code/bench_crypto_v2.py`, `code/batching_latency.py`, `code/make_figures.py`, `formal/*.tla, *.cfg, logs`,
`poc/*`, `notebooks/provenance_sensitivity_analysis.ipynb`, `data/raw/*`, `data/processed/*` (incl.
`provenance_sensitivity.csv`), `figures/*`, `tables/*`, `manuscript/*`, and the 13 report files listed in the brief.

## 8. Tasks requiring the author's manual intervention

1. Supply the actual reviewer decision letter (if any comments beyond R1–R8 exist).
2. Confirm author list, affiliations, corresponding e-mail, funding statement.
3. Provide (or obtain from an industrial partner) real DTh topology data, real provenance artefacts/lineage policies, or step-up failure logs — needed to replace assumed parameters with measurements.
4. Run `bench_crypto_v2.py` on a representative edge gateway (and HSM if available).
5. Deposit code/data in a public repository (Zenodo/GitHub) and insert the real DOI/URL — not done here.
6. Decide on Word (.docx) output; LaTeX source is provided as the editable format.

## 9. Status

Stage 0 complete. Stages 1–9 proceed below; final status per item is recorded in `RESPONSE_TO_REVIEWERS.md`.

## 10. Final status (end of revision)

| Item | Status |
|---|---|
| R1.1–R1.4 | Done (Table III, Sec. V, VIII-B; PROVENANCE_SENSITIVITY_REPORT.md). p_v remains unmeasured. |
| R2.1–R2.5 | Done (9 topologies, ZT+prov baseline, paired CRN, hierarchical bootstrap). |
| R3.1–R3.4 | Done (6 families, full metrics, evidence-accumulation study; revised default rule). |
| R4.1–R4.2 | Done (8 properties, 3 propositions, Merkle fix). |
| R4.3 | Partially done: bounded explicit-state checking executed; TLA+ spec provided but not executed. |
| R5.1–R5.3 | Done on server CPU; gateway/HSM benchmarks not possible here. |
| R6 | Done as single-host software PoC; no industrial deployment. |
| R7 | Done (10 verified new references, Table I redesign, worked example); 5 abstract-only assessments flagged. |
| R8 | Done (Sec. VIII-C). |
| C1–C18 | All addressed; see REVISION_CHANGELOG.md. |
