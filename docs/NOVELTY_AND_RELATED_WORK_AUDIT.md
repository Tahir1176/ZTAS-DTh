# NOVELTY_AND_RELATED_WORK_AUDIT.md (reviewer concern R7)

## 1. Literature search
Tool: Fast-Track (OpenAlex + Semantic Scholar) search; every newly cited DOI verified against Crossref with the
Fast-Track `verify_reference` tool (authors, venue, volume, pages, year). Searches (Nov. 2026): industrial zero trust /
DT; DTh security, provenance, blockchain; PQC for IIoT; context/risk-aware ZT access control; micro-segmentation and
lateral movement in ICS; supply-chain and firmware integrity in ICS. Preprints and low-quality venues returned by the
searches were not cited.

### Added references (all DOIs Crossref-registered)
| Key | Work | Why cited |
|---|---|---|
| xiao2022sok | Xiao et al., SoK: Context and Risk Aware Access Control for Zero Trust Systems, SCN 2022 | context/risk-aware access control in ZT |
| azad2024zt | Azad et al., Verify and trust: ZT security for IoT, Internet of Things 27, 2024 | ZT for IoT survey |
| basta2022microseg | Basta et al., ZT micro-segmentation evaluation framework, NOMS 2022 | quantified micro-segmentation |
| zanasi2022ztics | Zanasi et al., A Zero Trust approach for ICS, NCA 2022 | ZT prototype for ICS |
| hu2014abac | Hu et al., NIST SP 800-162 (ABAC) | attribute-based access control |
| cruzpiris2025pqc | Cruz-Piris et al., PQC in IIoT scenarios, Internet of Things 34, 2025 | PQC measurements on IIoT |
| shahid2026pqiiot | Shahid et al., PQ authentication for IIoT, Sci. Rep. 16, 2026 | ML-KEM/ML-DSA in TLS on IIoT gateway |
| hildebrandt2020opcua | Hildebrandt et al., OPC UA supply-chain attack, IH&MMSec 2020 | validly deployed malicious component |
| conti2021testbeds | Conti et al., ICS testbeds and datasets, COMST 23(4), 2021 | testbed future work |
| iec62264 | IEC 62264-1 | functional hierarchy (hub topology) |

Earlier references (41) were re-used; their DOIs were verified in v1.

## 2. Table I revision
* Split into **capability coverage** (6 columns, criteria defined in the table note) and **evidence type** (concept,
  prototype, simulation, formal verification, lab experiment, industrial deployment).
* Coverage marks: ● mechanism specified; ○ discussed without mechanism; – not addressed. A work is not marked "–"
  merely for using different terminology: e.g. Fogli et al.'s selective, configurable machine access through DTs is
  marked ● for context-adaptive policy and ○ for twin identity and segmentation.
* Works assessed only from their published abstract are flagged (ᵃ); their marks are conservative and should be
  checked against the full texts before submission: Zanasi 2022, Fogli 2025, Basta 2022, Kuo & Yang 2026, Shahid 2026.
* ZTAS-DTh's evidence is stated as: software PoC (single host), simulation, bounded model checking of abstract models,
  server-CPU micro-benchmarks; **no industrial deployment**. Fogli et al. report an industrial-environment test, which
  is stronger evidence than ours.

## 3. Incremental novelty — what ZTAS-DTh adds

| Beyond… | Existing work provides | ZTAS-DTh adds |
|---|---|---|
| Zero-trust architectures (SP 800-207; Zanasi; Fogli; Paul & Rao) | per-request decisions, segmentation, ZT for machine access in one phase | enforcement over **lifecycle flows** across phases and owners; gates that check lineage at boundaries; twins as principals; evidence rule calibrated against false isolation and safety |
| Provenance systems (Krima; Joannou; Kuo & Yang; Suhail) | tamper-evident records, traceability | **coupling** of lineage verification to access decisions; sequence/freshness and revocation semantics; corrected batch encoding; explicit statement of what signatures do not establish |
| DT security frameworks (Alcaraz & Lopez; Mun; Eckhart; Dietz) | threat taxonomies; DT-based security simulation | a concrete enforcement architecture with properties and a paired quantitative comparison including a **static ZT + provenance** baseline |
| PQ industrial security (Cruz-Piris; Shahid) | primitive/protocol costs on IIoT hardware | batching design and latency model for lineage records; two-path separation of lineage and control traffic |

Honest assessment: individually the mechanisms are known. The contribution is (i) their composition around the
thread with explicit boundary semantics, (ii) properties and bounded checks for that composition, and (iii) evidence
— under stated assumptions — of the marginal benefit over static ZT with provenance, including where that benefit is
small (sparse graphs: −0.04; multi-organisation: −0.07).

## 4. Worked example (paper Sec. VIII-A)
Compromised CAM workstation at a contract manufacturer emits G-code with an altered heat-treatment parameter, derived
from a draft (unreleased) design.

| Architecture | Outcome | Information used |
|---|---|---|
| Perimeter | accepted, executed | network location |
| Static ZT | accepted (valid credentials); possibly detected later by generic monitoring | identity, device posture |
| Static ZT + provenance | signature and sequence valid → accepted **unless** lineage requires a released parent (then denied, PoC S4); edits derived from a released design pass | + record authenticity, lineage policy |
| ZTAS-DTh | same lineage check; transfer only inside the purpose-bound release segment; off-pattern activity raises behavioural/temporal risk → step-up → evidence → quarantine | + segment purpose and lifetime, cross-request context |

The extra benefit comes from three pieces of information: release status in lineage, segment purpose/lifetime, and
context accumulated across requests. If the attacker acts inside the segment, in normal hours, through an authorised
role, on a released design (scenario S7), ZTAS-DTh adds little over static ZT + provenance.
