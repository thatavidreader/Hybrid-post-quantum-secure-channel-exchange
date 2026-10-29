# Report Mapping and Compliance Checklist

Built from the four course documents: *Mini_project Template-1 (Main Report)*, *Mini_project Template-Main Sheets (Front Sheet)*, *Guidelines for Report Preparation*, and *Network Security Project Evaluation Rubrics* (Phase 1: 30, Phase 2: 30, Phase 3: 40 marks).

## 1. Chapter mapping (follows the official template, which has six chapters)

| Template chapter | Your five-chapter label | Feeds from (files / outputs) | Status |
|---|---|---|---|
| **1 Introduction** (1.1 Background, 1.2 Problem Statement, 1.3 Objectives) | Introduction | `README.md` (overview), `docs/threat_model.md` §1-2 (HNDL, attacker model). Objectives are measurable: 3 modes, 6 required attack tests, 100-run benchmarks, 4 network profiles | Drafted: `docs/report/01_introduction.md` (needs citations CITE-1..5) |
| **2 System Analysis** (2.1 Existing System, 2.2 Functional Requirements, 2.3 Proposed System, 2.4 Feasibility Study) | *(not in your five; the template requires it)* | 2.2: `docs/architecture.md` §1 and the protocol rules in the brief; 2.3: `docs/architecture.md` §2-4; 2.4: environment facts (Python 3.13, liboqs could not be built, so `kyber-py` fallback; 5-6 day schedule) | 2.2-2.4 drafted in `docs/report/02_system_analysis.md`; **2.1 is a structured framework with `[CITE-n]` placeholders: you must read sources and fill it in** |
| **3 System Design** (3.1 Architecture, 3.2 Topology, 3.3 Security Mechanism, 3.4 Workflow, 3.5 Threat Model) | System Design | 3.1: `docs/architecture.md` §1 (+ draw a block diagram); 3.3: `docs/architecture.md` §3-5, `src/handshake.py` and `src/record_layer.py` docstrings; 3.4: message-flow diagram in `docs/architecture.md` §2 (redraw as a figure); 3.5: `docs/threat_model.md` §3-4 | Drafted: `docs/report/03_system_design_topology.md` (Mermaid + ASCII topology, workflow diagram); render the diagrams to images for Word |
| **4 "SYSTEM DESIGN" in the template, but its subsections (4.1 Technologies Used, 4.2 Modules) are implementation** | Implementation | 4.1: `requirements.txt`, README (Python, `cryptography`, `kyber-py`, pytest, matplotlib); 4.2: one paragraph per module in `src/`, `attacks/`, `bench/`, `tests/` (table in `docs/architecture.md` §1) | Covered; ask your guide whether to retitle this chapter "Implementation" (the template heading looks like a copy error) |
| **5 Experimental Results** (template: 5.1 "Screenshot of web page", 2-3 sentences each) | Experimental Results | Security tests: `docs/test_matrix.md` (T1-T12 + 46-test inventory). Performance: `docs/results_interpretation.md` (Tables 5.1-5.6, Figs. 5.1-5.7). Raw data: `results/*.csv`. Evidence: `results/demo_output.txt` | Covered. Your project has no web page, so use the screenshots listed in §4 with 2-3 sentence captions |
| **6 Conclusion** | Conclusion | `docs/results_interpretation.md` Executive Summary + §5.4 (limitations), `docs/threat_model.md` §4 (future scope: ML-DSA, liboqs, real `tc netem`) | Covered; write a half-page summary |
| **References** | (same) | See §5 | **To be compiled and verified by you** |

## 2. Rubric coverage: where evidence exists and what is missing

| Rubric parameter (marks) | Evidence in the project | Gap / action before submission |
|---|---|---|
| **P1** Problem statement and objectives (5) | `README.md`, threat model §1-2 | Drafted in `docs/report/01_introduction.md` (objectives O1-O9) |
| **P1** Literature review and existing-system analysis (5) | **Framework only (`docs/report/02_system_analysis.md` §2.1); no citations yet** | Fill 2.1: compare classical-only TLS-style key exchange, PQ-only, and hybrid designs; state the gap this project addresses (downgrade detection + measured overhead). Cite real sources (§5). I have not invented any citations |
| **P1** Threat model and security requirements (5) | `docs/threat_model.md` (assets, attacker, 9 threats, mitigations, limits) | Add an explicit short "security requirements" list (confidentiality, integrity, authenticity, downgrade/replay resistance) |
| **P1** Proposed architecture (5) | `docs/architecture.md` (text + ASCII flow) | Draw proper diagrams for the report |
| **P1** Network topology and system design (5) | Lab is localhost: client ↔ (optional MITM/netem proxy) ↔ server | Drafted as Fig. 3.2 (Mermaid/ASCII) in `docs/report/03_system_design_topology.md`; render it |
| **P1** Project plan and feasibility (5) | Environment report in the conversation | Drafted in `docs/report/02_system_analysis.md` §2.4 |
| **P2** Security mechanism implementation (8) | `src/handshake.py`, `src/record_layer.py`, `src/crypto_suite.py` | Covered |
| **P2** Functional modules and integration (6) | End-to-end tests T1, T9-T12; demo | Covered |
| **P2** Network configuration and controls (5) | Pinning, `min_mode` policy, frame-size caps, fail-closed behaviour, emulation proxy | Covered; note `tc netem` was not used |
| **P2** Logging, monitoring, alerting (4) | `src/logger.py`, `src/log_summary.py`, coloured alerts, `results/demo_output.txt` | Covered |
| **P2** Testing and preliminary results (4) | `docs/test_matrix.md` | Covered |
| **P2** Implementation progress and documentation (3) | README (setup, run, reproduce), GitHub repo | Covered |
| **P3** Complete working system (10) | `demo.ps1` / `demo.sh`, 46/46 tests | Rehearse the demo |
| **P3** Security testing and results (8) | T1-T12 + inventory (normal ops, every required attack) | Covered |
| **P3** Performance evaluation and security analysis (5) | `docs/results_interpretation.md` | Covered, including limitations |
| **P3** Demonstration and viva (7) | Docstrings explain *why*; `docs/architecture.md` | Practise explaining the check order (policy → signature) and why Ed25519 is not PQ |
| **P3** Project report (7) | This mapping | Assemble the report per §3 |
| **P3** Innovation, limitations, future scope (3) | Hybrid + signed-transcript downgrade detection + measured overhead; limitations in §5.4; future scope in threat model §4 | Covered |

## 3. Formatting checklist (from *Guidelines for Report Preparation*)

- [ ] A4, one-sided; body Times New Roman 12 pt, line spacing 1.5, fully justified
- [ ] Margins: left 1.25", right 1.0", top and bottom 0.75"
- [ ] Order: inner title page → certificate → acknowledgments → abstract → table of contents → list of tables/figures (optional) → chapters → references; also include the PPT handout and the discussed paper
- [ ] Headings: chapter ~18 pt centred; section ~16 pt; subsection ~14 pt; decimal numbering (2.1, 2.2.1)
- [ ] Figures/tables numbered chapter-wise (Fig. 5.1, Table 3.1); a figure sits on the page of first reference or the next page, preferably top or bottom of the page
- [ ] SI units only; numbered equations with the number right-justified (use for the HKDF/AEAD nonce construction if included)
- [ ] References numbered in order of first citation, `[n]` in the text
- [ ] Guide's approval obtained before final printing; soft binding with a plastic cover for the title page
- [ ] **Front sheet template still contains another project's data** ("SkillTrack", other students' names and registration numbers, supervisor details, and inconsistent years "2025-26" / "2026-2027"): (drafted in `docs/report/00_front_sheet.md`, with `[ ]` fields for your details) replace every placeholder with your own project title, names, registration numbers, guide and year, and check the registration numbers against your records

## 4. Screenshots for Chapter 5 (2-3 sentence caption each)

1. `demo.ps1`, normal hybrid session (`results/demo_output.txt`, section 1)
2. Downgrade caught with policy (`DOWNGRADE_DETECTED`) and without policy (`SIG_INVALID`) (sections 2a, 2b)
3. Tampered ciphertext (`BAD_TAG`) and replayed record (`REPLAY_DETECTED`) (sections 3, 4)
4. `pytest` output: `46 passed`
5. `log_summary` event counts (demo section 5)
6. Charts: `results/plots/` (Figs. 5.1-5.7 in the interpretation document)

## 5. References to look up, read and cite properly (standards; verify details before citing)

- NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard* (ML-KEM)
- NIST FIPS 204, *Module-Lattice-Based Digital Signature Standard* (ML-DSA), for the future-scope claim
- IETF RFC 7748 (X25519), RFC 8032 (Ed25519), RFC 5869 (HKDF), RFC 8446 (TLS 1.3, for downgrade protection and transcript-bound handshakes)
- NIST SP 800-38D (GCM)
- IETF draft on hybrid key exchange in TLS 1.3 (`draft-ietf-tls-hybrid-design`); check its current status when citing
- Open Quantum Safe / liboqs project documentation (for the native-backend discussion)

For the literature review (rubric: "relevant studies critically analysed; gaps identified") you also need a few published papers on PQC/hybrid handshake performance; I did not search for or read any for this task, so none are listed.
