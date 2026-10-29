# Front sheet and certificate (drop into the Word template)

Fields still in `[brackets]` need your input: Bindhu Pagadala's registration number, the guide's name, and the Dean's name. The course template still contained another project's data (SkillTrack, other students, a different supervisor) and two different academic years. This version uses 2026-2027 everywhere, so check the certificate page of the Word file for leftovers.

---

## Cover page

**Mini Project Report**

On

**"Post-Quantum Secure Channel (pq-secure-channel)"**

By

| Name | Registration Number |
|---|---|
| Aishwarya Patil | 235805106 |
| Bindhu Pagadala | [Insert Reg No] |

Submitted in fulfilment of the requirements for the award of the degree of

**Bachelor of Technology (Honours)**
in
**COMPUTER SCIENCE AND ENGINEERING**

Under the Supervision of

[Guide name, designation]

Mini Project Coordinator: Dr. Prakash B Metre, Assistant Professor

Department of Computer Science and Engineering
Manipal Institute of Technology, Bengaluru
MAHE

**2026 – 2027**

---

## Certificate page

**DEPARTMENT OF COMPUTER SCIENCE AND ENGINEERING**

**CERTIFICATE**

This is to certify that the Mini Project Work entitled **"Post-Quantum Secure Channel (pq-secure-channel)"** has been successfully carried out by **Aishwarya Patil** and **Bindhu Pagadala** bearing Registration Numbers **235805106** and **[Insert Reg No]** in fulfilment of the requirements for the award of the **BACHELOR OF TECHNOLOGY (HONOURS) in COMPUTER SCIENCE AND ENGINEERING** by **MANIPAL INSTITUTE OF TECHNOLOGY** during the year **2026-2027**. The mini-project report has been approved, as it satisfies the academic requirements for the mini-project work prescribed for the said Degree.

| Guide | Program Coordinator | Dean |
|---|---|---|
| [Guide name] | Dr. Prakash B Metre | [Dean name] |

---

## Remaining front matter required by the guidelines (in this order)

1. Inner title page (white): same text as the cover
2. Certificate (above)
3. Acknowledgments: write these yourselves (guide, coordinator, department, peers)
4. Abstract (about 150 to 250 words): skeleton below
5. Table of contents, then the optional list of tables and figures
6. Chapters 1 to 6, References, then the PPT handout and the discussed paper

### Abstract skeleton

Every number below is measured (see `docs/results_interpretation.md`). Reword it so it reads as your own summary.

Quantum computers running Shor's algorithm would break the RSA and elliptic-curve key exchanges that protect current network traffic. Because an attacker can record encrypted traffic now and decrypt it later, the threat already applies to data with a long confidentiality lifetime. This project builds a client-server secure channel that derives session keys with a hybrid X25519 and ML-KEM-768 key exchange, authenticates the server with a pinned Ed25519 key over a signed handshake transcript, and protects data with AES-256-GCM records that carry explicit sequence numbers. The channel detects and rejects downgrade, tampering, replay and record-dropping attacks, and it logs each one as a structured security event. Forty-six automated tests pass, including man-in-the-middle attack scenarios. The classical, PQC-only and hybrid modes were benchmarked under emulated delay and loss. The hybrid handshake takes 3565 B on the wire against 514 B for classical. In our pure-Python implementation the cryptographic part of the handshake takes about 21 ms instead of 0.7 ms, but at 50 ms one-way latency the median end-to-end handshake is 264 ms for hybrid against 210 ms for classical. The report also states the limits of the work: a pure-Python ML-KEM backend, a single-machine test bed, an approximate loss model, and server authentication that is still classical.

**Keywords:** post-quantum cryptography, ML-KEM, hybrid key exchange, downgrade attack, secure channel, AES-GCM.
