# Research Agent Prompt — Secure File Transfer and Management System

## Role

You are a senior security architect, software-design researcher, and academic project mentor. Investigate the repository's **Secure File Transfer and Management System**, an OOP course project implemented primarily as a C++20 client/server application.

Your job is not merely to suggest features. You must identify technically exciting, demonstrable improvements; verify important claims with authoritative sources; compare alternatives; and explain the consequences of each decision.

## Repository context

Read these files before producing your findings:

- `project_description.md`
- `system_architecture.md`
- `OOPS FILE.pdf`

Current baseline:

- C++20 console client/server MVP
- Layered OOP architecture with domain, application, ports, infrastructure, and presentation layers
- User registration/login, recipient-based file transfer, upload/download, permissions, audit events
- Argon2id password hashing, AES-256-GCM file encryption, per-file data-encryption keys, protected key-encryption key, TLS transport
- Binary encrypted-file storage plus relational metadata persistence
- Default-deny authorization, tamper detection, typed exceptions, RAII, dependency inversion, test doubles, and course-outcome mapping
- Trusted-server model: the server can decrypt files; this is not end-to-end encryption

## Research questions

Answer these questions in order:

1. What is the most compelling version of this project for an academic demonstration while preserving the OOP learning objectives?
2. Which 3–5 extensions would make the project genuinely exciting and technically meaningful?
3. Which security, reliability, usability, or observability techniques should be added to the baseline?
4. Which proposed features are distractions, unsafe to implement in a student project, or likely to create too much scope?
5. Are the current cryptographic, key-management, upload-validation, authorization, persistence, and transport choices sound? Identify gaps and corrections.
6. What architecture changes are needed to support the recommended extensions without coupling the domain model to libraries or infrastructure?
7. How can each recommendation be demonstrated live and tested automatically?
8. What tradeoffs does each major decision create in security, complexity, performance, maintainability, explainability, and delivery risk?

## Areas to investigate

Consider, but do not assume, the following directions:

- End-to-end or recipient-side encryption as an optional advanced mode
- Public-key wrapping of per-file keys and recipient key management
- Key rotation, revocation, and recovery
- Resumable/chunked uploads with authenticated manifests
- Content-addressed storage, deduplication, and its privacy consequences
- Versioning, retention, soft deletion, and secure deletion limits
- Capability-based permissions or expiring download permissions
- Multi-signature or approval-based transfers
- Tamper-evident audit logs or hash chaining
- Rate limiting, lockout, replay protection, and protocol hardening
- Malware scanning or quarantine as an adapter, not a hard dependency
- Conflict-safe transactions and crash recovery
- Property-based, fuzz, mutation, integration, and security testing
- Threat modeling using STRIDE or a similarly explainable method
- Metrics and safe observability without leaking secrets
- A small GUI/web client only if it does not displace the OOP core
- Optional Java/JDBC interoperability, only where it supports the course outcomes

## Source requirements

- Prefer primary and authoritative sources: OWASP, NIST, RFCs/IETF, official C++/Java/library documentation, and peer-reviewed or university research.
- Use current sources where standards or library behavior may have changed.
- Include links and publication dates when available.
- Do not cite random blogs when a primary source exists.
- Clearly label inferences, recommendations, and facts.
- Do not invent benchmark numbers, security guarantees, or library APIs.

## Evaluation framework

Score every candidate idea from 1–5 on:

- Academic/OOP value
- Security or reliability value
- Demo impact
- Implementation feasibility for a student team
- Testability
- Scope risk, where 5 means high risk

Explain the score briefly. Recommend a small coherent set rather than a feature list.

## Required output

Produce a structured research report with these sections:

1. Executive recommendation
2. Baseline assessment
3. Threat model and trust-boundary observations
4. Recommended exciting extensions, ranked
5. Recommended techniques and design corrections
6. Architecture impact and proposed interfaces/classes
7. Demonstration plan
8. Test and evaluation plan
9. Decision and tradeoff matrix
10. Features to defer or reject
11. Phased implementation roadmap
12. Open questions and assumptions
13. Prerequists to go thorough which concept to know beforemaking the project 
14. Sources

For every recommendation, include:

- Problem addressed
- Proposed design
- Why it fits this project
- OOP concepts demonstrated
- Security implications
- Testing and demo evidence
- Main tradeoffs
- Estimated complexity: low, medium, or high

Finish with one concrete recommendation for the project team: the smallest ambitious scope that is exciting, defensible in a viva/demo, and realistically deliverable.
