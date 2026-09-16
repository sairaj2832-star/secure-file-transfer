# Secure File Transfer and Management System — Master Project Document

## 1. Project identity

**Project type:** C++20 OOP course project with a client/server security application  
**Course context:** CI2013 Object Oriented Programming  
**Primary goal:** Build a demonstrable system that securely transfers files between named, authenticated users while making object-oriented design, persistence, exception safety, and secure engineering visible in the implementation.

This document is the working source of truth for the project. The research report produced from `research_agent_prompt.md` should update the open decisions and extension choices here.

## 2. Problem statement

A shared folder or basic file upload does not adequately provide identity, confidentiality, integrity, authorization, transfer history, or accountability. The system allows a registered sender to transfer a file to a registered recipient. The server validates the request, encrypts the file, stores protected bytes and metadata, checks authorization during retrieval, and records security-relevant events.

The project deliberately targets an academic MVP rather than a production cloud-storage service.

## 3. Success criteria

The project succeeds when the team can demonstrate that:

1. Users can register, authenticate, upload, share, list, download, and delete according to their permissions.
2. Passwords, plaintext files, encryption keys, and sensitive diagnostics are not improperly stored or logged.
3. Ciphertext or authentication data tampering prevents plaintext delivery.
4. Unauthorized access is denied and audited.
5. Failures do not leave orphaned metadata, partial ciphertext, open resources, or invalid domain objects.
6. Interfaces can be replaced with test doubles to demonstrate runtime polymorphism and dependency inversion.
7. The code and live demonstration provide evidence for the course outcomes: OOP features, object lifecycle, constructors/destructors, inheritance/polymorphism, file persistence, exceptions, and generic programming.

## 4. Scope

### MVP scope

- Registration, login, logout, account status, and administrator metadata operations
- Recipient-based transfer between registered user IDs
- Filename, extension, content-signature, and size validation
- AES-256-GCM encryption with fresh nonces and per-file data-encryption keys
- Protected binary storage outside the executable/public directory
- Owner and active-recipient authorization with default deny
- Relational metadata for users, files, transfers, permissions, and audit events
- Transfer history and download status
- Audit events for authentication, upload, transfer, download, denial, deletion, and integrity failure
- Typed exceptions, RAII resource management, rollback/cleanup behavior, and automated tests

### Candidate extension scope

Select only a small coherent set after research. The strongest candidates are:

- Tamper-evident audit records
- Expiring or revocable permissions
- Resumable uploads with authenticated manifests
- Recipient public-key wrapping for an optional stronger privacy mode
- Threat-model-driven security testing and fuzz/property tests

### Explicitly deferred

Public anonymous links, production certificate operations, cloud clustering, high availability, full malware scanning, MFA, internet-scale deployment, and a full web product are outside the baseline unless the team has completed the core and has evidence that the extension is manageable.

## 5. Users and trust model

### Actors

- **Regular user:** registers, authenticates, uploads, chooses a recipient, views own transfers, downloads permitted files, and deletes owned files.
- **Administrator:** manages account status and inspects metadata/audit events. Administrative visibility does not automatically grant file-content access.
- **System operator:** configures storage, database, server endpoint, and protected key source.

### Trust assumptions

- The server process and its protected configuration are trusted for the MVP.
- The server can decrypt stored files; the baseline is server-side encryption, not end-to-end encryption.
- Clients and network traffic are not trusted by default.
- Cryptographic primitives are supplied by vetted libraries; the project does not implement AES, GCM, Argon2, or TLS.

## 6. Technical approach

### Architecture

Use a layered design with dependency inversion:

`Client UI -> request handlers -> application services -> domain model -> abstract ports -> infrastructure adapters`

- **Presentation:** commands, request parsing, safe response formatting, session handling.
- **Application:** authentication, transfer, file-query, administration, and transaction orchestration.
- **Domain:** `User`, `FileRecord`, `Transfer`, `Permission`, `AuditEvent`, value-type IDs, statuses, and invariants.
- **Ports:** repositories, encrypted storage, encryption provider, password hasher, audit logger, access policy, and transport.
- **Infrastructure:** binary file storage, SQLite or MySQL metadata adapter, cryptographic provider, TLS transport, configuration provider, and audit sink.

### Security flow for upload

1. Authenticate the session and validate the recipient.
2. Validate filename, allow-listed type, signature/content, and size limit.
3. Generate a server-side storage ID and fresh random per-file data-encryption key.
4. Encrypt the file using AES-256-GCM with a fresh nonce.
5. Wrap the data-encryption key using a protected key-encryption key.
6. Write ciphertext to protected storage and persist metadata.
7. Coordinate the write as one logical operation; remove ciphertext if metadata persistence fails.
8. Record a safe audit event without passwords, keys, plaintext, or unnecessary paths.

### Security flow for download

1. Authenticate the requester.
2. Apply default-deny authorization for owner or active recipient permission.
3. Load metadata only after authorization succeeds.
4. Read ciphertext, unwrap the data-encryption key, and verify the GCM tag.
5. Verify the stored digest as a consistency check.
6. Deliver plaintext only after verification succeeds.
7. Update transfer status and record success, denial, or integrity failure.

## 7. Proposed domain and interface model

### Core domain objects

- `User`, `RegularUser`, `Administrator`
- `FileRecord`, `Transfer`, `Permission`, `AuditEvent`
- `UserId`, `FileId`, `TransferId`, `Digest`, `WrappedKey`
- Status/value types with private state, validation, equality, ordering, and readable output where useful

### Ports

- `IUserRepository`
- `IFileRepository`
- `ITransferRepository`
- `IStorage`
- `IEncryptionProvider`
- `IPasswordHasher`
- `IAuditLogger`
- `IAccessPolicy`
- `ITransport`

Every abstraction must have a real implementation and, where useful, a fake/in-memory implementation for tests. Interfaces exist to isolate meaningful variation, not just to increase class count.

### OOP evidence

- Encapsulation through private state and invariant-preserving methods
- Composition through application services built from ports
- Inheritance and virtual contracts where alternate implementations are real
- Constructors that reject invalid state
- RAII and smart pointers for resources and ownership
- Typed exception hierarchy with translation at boundaries
- Templates for repositories, results, collections, or filtering utilities
- Operator overloads limited to value types where they improve clarity

## 8. Persistence and data protection

Use a relational metadata store for users, files, transfers, permissions, and audit events. Store encrypted bytes in a protected binary directory. The storage identifier is generated by the server; the original filename is display metadata only.

Important metadata includes ownership, size, digest, nonce, wrapped data-encryption key, status, timestamps, and safe content/signature information. The key-encryption key must come from protected configuration or an equivalent protected source and never be committed to source control.

## 9. Testing and demonstration

### Automated tests

- Invalid value-object and entity construction
- Authentication and password-storage rules
- File validation and upload limits
- Authorization allow/deny cases
- Binary round-trip behavior
- Ciphertext/tag/digest tamper detection
- Unique nonce generation
- Rollback after storage or metadata failure
- Resource cleanup under exceptions
- Repository persistence and relationship reconstruction
- Polymorphic substitution with fakes
- End-to-end register -> upload -> authorize -> download -> audit flow

### Live demonstration

1. Alice and Bob register.
2. Alice uploads `assignment.pdf` for Bob.
3. The server validates, encrypts, persists, and audits the transfer.
4. Bob downloads successfully.
5. An unauthorized user is denied and the denial is audited.
6. One ciphertext byte is changed; download fails integrity verification and releases no plaintext.
7. A fake storage or encryption implementation is substituted to demonstrate polymorphism.
8. A template-based query and exception-safe cleanup are shown.

## 10. Tradeoffs and chosen decisions

| Decision | Chosen direction | Benefit | Consequence/tradeoff |
|---|---|---|---|
| Language | C++20 | Strong evidence for RAII, streams, templates, and OOP | More memory/resource hazards than managed languages; requires disciplined ownership |
| UI | Console client first | Keeps the OOP core assessable and demo reliable | Less polished than a web UI |
| Encryption | AES-256-GCM via vetted library | Confidentiality and authenticity in one primitive | Nonce handling and key lifecycle must be correct |
| Passwords | Argon2id | Resistant to offline password cracking | Adds dependency/configuration and slower login by design |
| Key model | Per-file DEK wrapped by protected KEK | Limits blast radius and supports future key rotation | More metadata and key-management complexity |
| Server trust | Trusted server, server-side decryption | Feasible for an academic MVP and simple recipient workflow | Server compromise can expose plaintext; not end-to-end privacy |
| Metadata | Relational store | Clear relationships, queries, and persistence evidence | Database setup and transaction handling add complexity |
| File bytes | Binary encrypted storage | Demonstrates streams and avoids putting large blobs in metadata | Requires cleanup, path safety, and consistency logic |
| Authorization | Explicit owner/recipient policy, default deny | Easy to reason about and test | Less flexible than a general policy engine |
| Transport | TLS library | Avoids inventing cryptography | Certificate/configuration work can distract from OOP goals |
| Interfaces | Ports plus real/test implementations | Testability and runtime polymorphism | More files and abstraction overhead |
| Digest | SHA-256 consistency check plus GCM tag | Easier diagnostics and corruption detection | Digest is not a replacement for authenticated encryption |

The guiding rule is to accept complexity only when it improves security, testability, learning evidence, or demo value.

## 11. Delivery phases

### Phase 1 — Domain foundation

Implement value types, entities, statuses, exceptions, invariants, and unit tests.

### Phase 2 — Local application use cases

Implement repositories, fake storage, validation, authentication, authorization, and audit logging without networking.

### Phase 3 — Secure persistence

Add encrypted binary storage, metadata persistence, key wrapping, rollback, and tamper tests.

### Phase 4 — Client/server boundary

Add request handlers, sessions, TLS transport, safe error translation, and integration tests.

### Phase 5 — Research-selected extension

Implement only the highest-value extension that fits the completed core. Update this document with its final design and tradeoffs.

### Phase 6 — Evidence package

Prepare class/sequence diagrams, syllabus mapping, threat model, test report, limitations, and a scripted live demonstration.

## 12. Open decisions

- SQLite or MySQL Connector/C++ for the metadata adapter?
- Which TLS library and certificate workflow fit the environment without dominating the project?
- Which one or two extensions are selected after research?
- Should an optional end-to-end mode be included, or documented as future work?
- What upload-size and file-type limits are appropriate for the demonstration environment?
- What is the minimum transaction/recovery behavior needed for the grading demonstration?

## 13. Limitations and future work

The MVP does not provide production availability, disaster recovery, malware scanning, MFA, full certificate lifecycle management, or protection from a fully compromised trusted server. Future work may add recipient-side key management, key rotation/revocation, resumable authenticated uploads, tamper-evident audit storage, richer testing, and a GUI/web client after the core has been evaluated.

## 14. Source documents

- `project_description.md`
- `system_architecture.md`
- `OOPS FILE.pdf` — CI2013 Object Oriented Programming syllabus
- OWASP File Upload, Password Storage, and Cryptographic Storage Cheat Sheets
- NIST SP 800-57 Part 1 Rev. 5
- Official C++/Java and cryptographic-library documentation
