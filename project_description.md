# Secure File Transfer System — OOP Course Project Description

## 1. Project identity

**Project title:** Secure File Transfer and Management System  
**Subject:** C++/Java Object-Oriented Programming  
**Recommended implementation:** C++20 console client/server application  
**Persistence:** binary file streams plus a small relational metadata store (SQLite or MySQL Connector/C++)  
**Project size:** a demonstrable academic MVP, not a production cloud service

This project reuses the original secure-file-transfer idea but makes object-oriented design the central learning objective. The security features are implemented inside a coherent domain model rather than being presented only as web-framework configuration.

## 2. Problem statement

Students and small campus teams need to exchange files with a named recipient. A simple shared folder does not provide sufficient identity, permission checking, confidentiality, integrity verification, or an audit trail. The proposed application lets an authenticated sender select a recipient, encrypt a file, save its metadata, and allow only an authorized recipient or administrator to retrieve it.

## 3. Aim

To design and implement a secure file-transfer application that demonstrates object-oriented analysis, class design, encapsulation, inheritance, runtime polymorphism, constructors/destructors, exception handling, generic programming, file streams, persistent data management, and secure engineering practices.

## 4. OOP learning objectives

By the end of the project, the team should be able to:

1. Model users, files, transfers, permissions, keys, and audit events as cohesive classes.
2. Hide mutable state behind validated public methods and private data members.
3. Use constructors for valid object creation and destructors/RAII for file, socket, and database resources.
4. Use inheritance and virtual functions where a common contract has multiple implementations.
5. Use composition to assemble authentication, authorization, encryption, storage, and transfer services.
6. Use custom exception classes and exception-safe cleanup for invalid input, file I/O, authentication, authorization, and integrity failures.
7. Use templates for reusable repositories, result types, collections, or filtering utilities.
8. Use binary file streams for encrypted file data and persistent metadata records.
9. Explain how the design maps to the C++ syllabus and, if selected, implement a Java/JDBC persistence adapter as an extension.

## 5. Proposed solution

The MVP contains two programs:

- **Server:** owns user accounts, encrypted files, permissions, transfer records, and audit logs.
- **Client:** provides commands or a simple menu for registration, login, upload, share, list, download, and logout.

The sender uploads a file over a protected channel. The server validates the request, generates a unique per-file data-encryption key, encrypts the bytes with AES-256-GCM, stores only ciphertext, and creates a permission record for the selected recipient. During download, the server authenticates the requester, checks ownership or permission, verifies the authenticated-encryption tag and stored digest, then streams the plaintext to the authorized client.

The trusted-server assumption is explicit: this is server-side encryption, not end-to-end encryption. The project therefore teaches secure storage and access control without claiming that the server operator cannot decrypt files.

## 6. Scope of the MVP

### In scope

- Registration, login, logout, and account status
- Password hashing using a vetted Argon2id library
- Sender-to-recipient transfer by registered user ID
- File size and extension/content-signature validation
- AES-256-GCM encryption with a fresh IV/nonce per encryption operation
- Encrypted binary storage outside the executable's public/output directory
- Owner and recipient authorization
- Transfer history and download status
- Audit events for authentication, upload, transfer, download, denial, deletion, and integrity failure
- Relational metadata persistence and binary file streams
- Unit tests for domain rules, exceptions, access control, and tamper detection

### Out of scope for the MVP

- Public links, anonymous downloads, and end-to-end encryption
- Multi-factor authentication and malware scanning
- Cloud storage, clustering, and high availability
- Production certificate management and internet-scale deployment
- A browser UI; a GUI/web client may be added after the OOP core is assessed

## 7. Users and use cases

| Actor | Use cases |
|---|---|
| Regular user | Register, log in, upload, choose recipient, list sent/received transfers, download permitted files, delete owned files |
| Administrator | Log in, activate/deactivate users, inspect transfer metadata and audit events; no unrestricted file-content access in the MVP UI |
| System operator | Configure storage path, database connection, encryption-key source, and server endpoint |

## 8. Functional requirements

| ID | Requirement | OOP evidence |
|---|---|---|
| FR-01 | Create a valid user account and reject duplicate identity data. | User, UserRepository, validation exceptions |
| FR-02 | Authenticate without storing plaintext passwords. | Authenticator, PasswordHasher interface |
| FR-03 | Upload a bounded file and validate its name, extension, signature, and size. | FileValidator, UploadRequest |
| FR-04 | Encrypt every stored file before persistence. | EncryptionProvider polymorphism, RAII streams |
| FR-05 | Transfer only to an existing recipient. | TransferService, Permission |
| FR-06 | Permit download only to the owner or an active recipient permission. | AccessPolicy and default-deny rules |
| FR-07 | Detect ciphertext/tag/digest tampering and refuse delivery. | IntegrityException |
| FR-08 | Persist and display transfer history. | templated repositories and file/database I/O |
| FR-09 | Record security-relevant events without passwords, keys, or plaintext. | AuditLogger interface |
| FR-10 | Handle expected failures without leaking internal paths or stack traces. | exception hierarchy and error translation |

## 9. Explicit syllabus alignment

| Syllabus area | Project implementation |
|---|---|
| Classes, objects, encapsulation, abstraction | Domain entities with private state and validated methods |
| Constructors/destructors, memory management | Invariant-preserving constructors; RAII wrappers; smart pointers; no owning raw pointers |
| Inheritance and polymorphism | RegularUser/Administrator; IStorage, IEncryptionProvider, IAuditLogger, and IAccessPolicy implementations |
| Static/dynamic binding | Overloaded value types and virtual service contracts selected at runtime |
| Operator overloading | Equality/order/stream output for UserId, FileId, and TransferId value types where useful |
| Exceptions | AuthenticationException, AuthorizationException, FileValidationException, StorageException, IntegrityException |
| Templates/generic programming | Repository<T>, Result<T>, or reusable query/filter utilities |
| Files and streams | Binary encrypted-file streams, metadata export/import, stream-state checks |
| Persistence | Repository interfaces with a file-backed MVP and relational adapter |
| Java OOP/JDBC extension | Optional Java client or JDBC repository using the same domain contracts and use cases |

## 10. Non-functional requirements

- **Confidentiality:** plaintext files are never left in the managed storage directory after a successful upload.
- **Integrity:** AES-GCM authentication failure or digest mismatch blocks download.
- **Authorization:** every file operation is checked against the authenticated user and the permission record.
- **Reliability:** partially completed uploads are rolled back or removed; resources close during normal and exceptional control flow.
- **Maintainability:** domain, application, infrastructure, and presentation code are separate.
- **Usability:** command names and error messages are understandable to a non-technical user.
- **Testability:** security rules can be tested with fake storage, fake encryption, and fake audit implementations.

## 11. Demonstration scenario

1. Alice and Bob register; the administrator account is seeded separately.
2. Alice logs in and uploads assignment.pdf for Bob.
3. The server validates, encrypts, stores, and audits the transfer.
4. Bob logs in and downloads the file successfully.
5. Alice's or an unknown user's unauthorized download is denied and audited.
6. The team changes one byte of ciphertext; the next download raises an integrity exception and does not deliver data.
7. The team swaps the real storage implementation with an in-memory test double to demonstrate runtime polymorphism.
8. The team runs a template-based query over transfer records and demonstrates exception-safe file/database cleanup.

## 12. Security decisions

- Use a vetted cryptographic library; do not implement AES, GCM, Argon2, or TLS manually.
- Use a fresh unpredictable GCM IV/nonce for every encryption with a given key. Java's cryptographic documentation explicitly warns that reusing a GCM IV with the same key can enable forgery attacks.
- Use envelope encryption: a random data-encryption key per file, protected by a separately managed key-encryption key. The key-encryption key is supplied through protected configuration and is never committed to source control.
- Validate allow-listed extensions, content signatures, filenames, storage location, and upload limits; never trust the client MIME type alone.
- Store files under server-generated identifiers outside the executable/public directory.
- Hash passwords with Argon2id rather than SHA-256 or plaintext storage.

## 13. Expected deliverables

1. Source code with the package/folder structure in the architecture document.
2. Class diagram and sequence diagrams for upload and download.
3. Database/schema or metadata-file design.
4. Test report covering normal, invalid, unauthorized, and tampered-file cases.
5. Mapping table from syllabus outcomes to classes, methods, tests, and demonstration evidence.
6. Short security limitations and future-work report.

## 14. References

1. VIT, **CI2013: Object Oriented Programming**, syllabus PDF supplied in this repository, especially Units 1–6 and Practicals 1–14.
2. Oracle, **Object-Oriented Programming Concepts**: https://docs.oracle.com/javase/tutorial/java/concepts/
3. Oracle, **Interfaces and Inheritance**: https://docs.oracle.com/javase/tutorial/java/IandI/
4. Oracle, **Exceptions**: https://docs.oracle.com/javase/tutorial/essential/exceptions/
5. Oracle, **Java Cryptography Architecture — Cipher**: https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html
6. OWASP, **File Upload Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
7. OWASP, **Password Storage Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
8. OWASP, **Cryptographic Storage Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
9. NIST, **SP 800-57 Part 1 Rev. 5 — Recommendation for Key Management**: https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final
10. cppreference, **Classes** and **Templates**: https://en.cppreference.com/w/cpp/language/classes and https://en.cppreference.com/w/cpp/language/templates

