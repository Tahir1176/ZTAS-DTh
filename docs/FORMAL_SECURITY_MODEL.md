# FORMAL_SECURITY_MODEL.md (reviewer concern R4)

## 0. What was and was not done
* **Done:** eight properties stated with assumptions; three propositions with proof sketches; bounded **explicit-state
  model checking** of three abstract models with a purpose-written Python checker (`formal/model_check.py`), 12 checks
  including 7 negative controls, all executed (`formal/logs/model_check.log`, `model_check_results.json`).
* **Not done:** TLA+/TLC execution. Downloading `tla2tools.jar` was not permitted in the revision environment. A TLA+
  specification of model M1 (`formal/ProvenanceGate.tla`, `.cfg`) is supplied for independent checking; it has **not
  been executed** and may contain errors. No verification of the implementation (PoC) or of unbounded systems is claimed.

## 1. System abstraction
Principals (human, device, twin, service, external), gateways g with signing key epochs k, verifiers (gates) with
per-gateway state `last[g]`, segments σ = (F, Π, purpose, expiry), PDP state (evidence e_s, quarantine set, pending
approvals), administrator principals for the control plane.

## 2. Properties

| ID | Property | Precise statement | Assumptions | Component | Mechanism | Guaranteed | Not guaranteed |
|---|---|---|---|---|---|---|---|
| P1 | Flow authorisation safety | delivery on e at t ⇒ ∃ σ: e ∈ F_σ, s ∈ Π_σ, t < expiry_σ, and PDP(q) = allow at t | complete mediation; PEP integrity | PEP, segmentation controller | Algorithm 1 lines 1–2, 11 | by construction for mediated flows; checked in M2 | unmediated legacy links; compromised PEP |
| P2 | Provenance integrity | accepted (x, ρ) = what an uncompromised gateway signed | EUF-CMA ML-DSA; SHA-256 CR; key uncompromised at signing | gate, provenance service | hash, inclusion proof, header signature | Proposition 1; M1 | truth/benignity of content (S2–S5, S7) |
| P3 | Freshness / replay resistance | per verifier, each (g, seq) accepted at most once, in increasing order; strict mode: no gaps | verifier state persistent; seq signed | gate | seq > last[g] (strict: = last+1) | Proposition 2; M1 (holds even under key compromise) | cross-verifier replay without shared state; omission in non-strict mode |
| P4 | Lifecycle-lineage consistency | accepted artifacts satisfy the lineage policy for their type | policy correct/complete; parent records authentic (P2) | gate | role + parent-type + release-status check | by construction; demonstrated in PoC (S4, S4b) | malicious content by an authorised role |
| P5 | Batch binding | distinct leaf lists ⇒ distinct signed headers | SHA-256 CR | provenance service | domain separation, odd-node promotion, signed leaf count | M3 (exhaustive to length 5 over 3 symbols) | — |
| P6 | Revocation enforcement | after revocation of epoch k reaches a verifier, no record under k is accepted | revocation delivery within refresh bound | identity, gate | epoch check | Proposition 3; M1 | acceptance during propagation (PoC: 1.02 s); genuine pre-compromise records also rejected unless ledger-anchored earlier |
| P7 | Containment after identity compromise | after quarantine of s takes effect, no request of s is allowed | decisions re-evaluated per request (no cached allow) | PDP, PEP | quarantine set checked first | M2; PoC S6 | damage before detection; approval delay for O assets |
| P8 | Control/data-plane separation | only admin principals change policy, segments, weights | admin credentials uncompromised | policy administration | role check on control-plane API | M2 | malicious administrator |

## 3. Review of the v1 proposition and corrections
v1: "If x or ρ was altered after signing, the gate rejects it except with negligible probability", with a Merkle root
signed per batch.

| Check | Finding |
|---|---|
| Cryptographic assumptions | correct (EUF-CMA, collision resistance) but not stated for the Merkle encoding |
| Merkle encoding | **incorrect as described**: duplicating the last node of odd levels without binding the leaf count makes [a,b,c] and [a,b,c,c] share a root (found by M3; also by direct script, `REVISION_AUDIT.md` C13) |
| Key compromise | assumed away correctly, but gateway compromise (honest key, dishonest content) was not distinguished |
| Hash collision resistance | needed for content hash, leaf hashes and node hashes; domain separation was present in code but not in the paper |
| Event ordering / replay / missing events | not covered; hash chaining alone does not detect whole-batch omission or replay at a verifier |

Corrected construction: leaf = H(0x00‖ρ), node = H(0x01‖l‖r), odd node promoted, header
η = H(0x02 ‖ n ‖ R ‖ g ‖ seq_first) signed with ML-DSA-65; per-gateway signed sequence numbers; verifier state.

**Proposition 1 (Integrity).** If (x, ρ) is accepted under header η signed with key k of gateway g, k uncompromised and
unrevoked at signing, and (x, ρ) differs from what g signed, then a SHA-256 collision or an ML-DSA forgery was found.
*Proof sketch:* acceptance requires H(x) = ρ.hash, a valid path from H(0x00‖ρ) to R, and a valid signature on η binding
(n, R). Each deviation maps to a collision (content, leaf/node, or equal (n, R) for a different leaf list — excluded by
domain separation and length binding) or a forgery on an unsigned η.

**Proposition 2 (Freshness).** If the verifier accepts from g only when seq > last[g] and then sets last[g] = seq, no
(g, seq) is accepted twice and accepted records are in signing order; in strict mode (seq = last[g] + 1) an omitted
record blocks further acceptance and raises an alarm. *Proof:* monotonic verifier state + P2 on the seq field.
Holds per verifier only.

**Proposition 3 (Revocation).** If revocation of epoch k reaches the verifier at t_r, no record under k is accepted
after t_r. Records signed under k *before* compromise are also rejected unless their header was anchored before
compromise and the verifier accepts ledger-anchored headers. *Proof:* epoch check precedes acceptance; the model checker
negative control without the check accepts a record of a revoked epoch.

## 4. Bounded model checking

Checker: breadth-first enumeration of all reachable states; invariants evaluated in every state; counterexample traces
printed. Bounds: M1 N ≤ 3 records (N = 2 for key-compromise variants), one rekey; M2 ≤ 3 deliveries, one policy change;
M3 leaf lists of length 1–5 over {a, b, c}.

| Model | Configuration | States | Expected | Result |
|---|---|---|---|---|
| M1 | full checks, no key compromise: integrity, no-replay, order | 280 | hold | hold |
| M1 | key compromise allowed: integrity | 29 | violation | violation (attacker injects validly signed record) |
| M1 | key compromise allowed: replay/order | 11,760 | hold | hold |
| M1 | NEG no sequence check: no-replay | 16 | violation | violation (same record accepted twice) |
| M1 | NEG no signature check: integrity | 14 | violation | violation (tampered record accepted) |
| M1 | revocation enforcement | 11,760 | hold | hold |
| M1 | NEG no revocation check | 84 | violation | violation (record of revoked epoch accepted) |
| M2 | continuous evaluation + plane separation: P1, P7, P8 | 312 | hold | hold |
| M2 | NEG cached session decision: P7 | 73 | violation | violation (quarantined device delivers) |
| M2 | NEG data-plane policy change: P8 | 4 | violation | violation |
| M3 | v1 Merkle encoding: P5 | 40 | violation | violation ([a,a,a] vs [a,a,a,a]) |
| M3 | corrected encoding: P5 | 363 | hold | hold |

Run: `cd formal && python3 model_check.py logs/model_check_results.json` (≈ 0.3 s).

## 5. Limitations
* Abstract models with very small bounds; no claims beyond them.
* Signatures and hashes are modelled symbolically (perfect cryptography) — computational guarantees come from the
  propositions, not from the checker.
* P1 assumes complete mediation, which legacy OT may violate.
* The checker itself is unverified code; the TLA+ specification is provided so that a second, independent tool can be used.
