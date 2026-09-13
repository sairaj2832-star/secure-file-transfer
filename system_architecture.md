# Secure File Transfer System — OOP-Centered System Architecture

**Primary implementation:** C++20 client/server application  
**Optional extension:** Java client or JDBC persistence adapter  
**Architecture style:** layered object-oriented design with dependency inversion  
**Deployment target:** one protected server and authenticated clients for the course MVP

## 1. Architectural intent

The architecture makes the syllabus visible in the code. The user interface is thin; domain objects hold invariants; application services coordinate use cases; infrastructure classes handle streams, sockets, databases, and cryptography behind interfaces. This keeps security rules testable without requiring the whole system to run over a browser.

The core boundary is:

**Client UI -> application services -> domain model -> infrastructure adapters**

## 2. High-level components

~~~mermaid
flowchart LR
    C[Client application] -->|TLS protected protocol| S[Transfer server]
    S --> API[Command/request handlers]
    API --> APP[Application services]
    APP --> DOM[Domain model]
    APP --> PORTS[Abstract ports]
    PORTS --> DB[Metadata repository]
    PORTS --> FS[Encrypted file storage]
    PORTS --> CRYPTO[Crypto provider]
    PORTS --> AUDIT[Audit logger]
    CFG[Configuration] --> S
    KEY[Protected key source] --> CRYPTO
~~~

### Responsibilities

| Layer/component | Responsibility | Examples |
|---|---|---|
| Presentation | Parse commands, display safe messages, serialize requests | ClientConsole, ServerSession |
| Application | Orchestrate use cases and transactions | AuthenticationService, TransferService |
| Domain | Own business state and invariants | User, FileRecord, Transfer, Permission |
| Ports | Stable abstract contracts for replaceable dependencies | IUserRepository, IStorage, IEncryptionProvider |
| Infrastructure | Implement ports using OS/library resources | BinaryFileStorage, SqliteMetadataRepository, AesGcmProvider |
| Cross-cutting | Configuration, validation, audit, exception translation | Config, FileValidator, AuditLogger |

## 3. Domain model

~~~mermaid
classDiagram
    class User {
      -UserId id
      -string name
      -PasswordHash password
      -AccountStatus status
      +authenticate()
      +canLogin()
    }
    class RegularUser
    class Administrator
    User <|-- RegularUser
    User <|-- Administrator

    class FileRecord {
      -FileId id
      -UserId owner
      -string originalName
      -uint64 size
      -Digest digest
      -WrappedKey wrappedKey
      +isOwnedBy(UserId)
    }
    class Transfer {
      -TransferId id
      -FileId file
      -UserId sender
      -UserId recipient
      -TransferStatus status
      +markDownloaded()
    }
    class Permission {
      -FileId file
      -UserId user
      -PermissionType type
      +allowsDownload()
    }
    class AuditEvent
    User "1" --> "*" FileRecord : owns
    FileRecord "1" --> "*" Transfer : appears in
    Transfer "*" --> "1" User : sender
    Transfer "*" --> "1" User : recipient
    FileRecord "1" --> "*" Permission : grants
    Permission "*" --> "1" User : subject
~~~

### Domain rules

- IDs are value types with private representation and equality/order operators.
- Constructors reject invalid empty IDs, names, sizes, or timestamps.
- FileRecord never exposes a plaintext path; it stores a server-generated storage identifier.
- Transfer can move only through valid statuses.
- Permission is explicit and scoped to a file and user.
- Entity mutation occurs through methods, not public fields.
- Administrator has administrative metadata visibility but does not automatically receive file-content access.

## 4. OOP concept map

| Course concept | Concrete architecture decision |
|---|---|
| Encapsulation | Private entity data and validated commands |
| Abstraction | Interfaces for storage, crypto, repositories, audit, and policy |
| Inheritance | User base with RegularUser and Administrator; exception hierarchy |
| Polymorphism | Runtime-selected IStorage, IEncryptionProvider, IAuditLogger, and IAccessPolicy |
| Composition | TransferService is composed from repository, validator, crypto, storage, policy, and audit objects |
| Constructors/destructors | Constructors establish invariants; RAII guards close files, sockets, transactions, and locks |
| Memory management | std::unique_ptr for ownership; std::shared_ptr only where shared lifetime is justified |
| Templates | Repository<T>, Result<T>, PagedCollection<T>, and generic filtering |
| Operator overloading | Comparison and stream insertion for ID/value types only where readable |
| Exceptions | Typed domain/infrastructure exceptions translated at the presentation boundary |
| File streams | std::ifstream/std::ofstream in binary mode with explicit stream-state checks |
| Dynamic binding | Test doubles and alternate implementations selected through interface references |

## 5. Interfaces and principal classes

~~~text
domain/
  User, RegularUser, Administrator
  FileRecord, Transfer, Permission, AuditEvent
  UserId, FileId, TransferId, Digest, WrappedKey
  DomainException and derived exceptions

application/
  AuthenticationService
  TransferService
  FileQueryService
  AdministrationService
  TransactionCoordinator

ports/
  IUserRepository
  IFileRepository
  ITransferRepository
  IStorage
  IEncryptionProvider
  IPasswordHasher
  IAuditLogger
  IAccessPolicy
  ITransport

infrastructure/
  BinaryFileStorage
  SqliteMetadataRepository (or MySqlMetadataRepository)
  AesGcmProvider
  Argon2PasswordHasher
  FileAuditLogger / DatabaseAuditLogger
  TlsTransport
  ConfigurationProvider

presentation/
  ClientConsole
  RequestParser
  ResponseFormatter
  ServerRequestHandler
~~~

The interfaces are contracts, not empty classes added only to satisfy the syllabus. Each has at least two useful implementations where practical: real and test-double storage, database and file audit logging, or real and fake encryption.

## 6. Upload sequence

~~~mermaid
sequenceDiagram
    participant Client
    participant Handler
    participant Auth as Authentication/Policy
    participant Transfer as TransferService
    participant Validator as FileValidator
    participant Crypto as IEncryptionProvider
    participant Store as IStorage
    participant Repo as Repositories
    participant Audit as IAuditLogger

    Client->>Handler: UPLOAD(file, recipient)
    Handler->>Auth: requireAuthenticatedUser()
    Handler->>Transfer: upload(request)
    Transfer->>Validator: validate(name, type, size, signature)
    Transfer->>Repo: findRecipient(recipient)
    Transfer->>Crypto: encrypt(stream)
    Crypto-->>Transfer: ciphertext + nonce + wrapped DEK + digest
    Transfer->>Store: write(serverGeneratedId, ciphertext)
    Transfer->>Repo: save FileRecord, Transfer, Permission
    Transfer->>Audit: record(FILE_UPLOAD)
    Transfer-->>Client: success(transferId)
~~~

The metadata rows and the storage write are coordinated as one logical operation. If metadata persistence fails, the service removes the newly written ciphertext and reports a typed StorageException.

## 7. Download sequence

~~~mermaid
sequenceDiagram
    participant Client
    participant Handler
    participant Policy as IAccessPolicy
    participant Repo as Repositories
    participant Store as IStorage
    participant Crypto as IEncryptionProvider
    participant Audit as IAuditLogger

    Client->>Handler: DOWNLOAD(fileId)
    Handler->>Policy: authorize(userId, fileId, DOWNLOAD)
    alt denied
      Policy-->>Handler: false
      Handler->>Audit: record(ACCESS_DENIED)
      Handler-->>Client: safe error
    else allowed
      Handler->>Repo: load FileRecord
      Handler->>Store: open ciphertext
      Handler->>Crypto: decryptAndVerify(stream, wrappedKey, nonce, digest)
      Crypto-->>Handler: verified plaintext stream
      Handler->>Repo: mark transfer downloaded
      Handler->>Audit: record(FILE_DOWNLOAD)
      Handler-->>Client: plaintext over TLS
    end
~~~

Authorization happens before storage access. A failed GCM tag check or digest mismatch raises IntegrityException, records an integrity failure, and sends no plaintext.

## 8. Security architecture

| Concern | Design |
|---|---|
| Transport | TLS through a vetted library; do not invent a transport cipher |
| Passwords | Argon2id with per-password salt; never plaintext or fast SHA-256 |
| File encryption | AES-256-GCM authenticated encryption |
| Key hierarchy | Random per-file DEK wrapped by a protected KEK; no keys in source control |
| GCM nonce | Fresh unpredictable nonce for every encryption under a key; persist it with ciphertext metadata |
| File integrity | GCM authentication tag plus a stored SHA-256 digest of the original plaintext |
| Access control | Default-deny policy; owner or explicit active recipient permission |
| File names | Original name is display metadata; disk name is a generated ID |
| Upload validation | Allow-list, size limit, signature/content checks, safe storage location |
| Secrets/logs | Never log passwords, keys, plaintext, or full sensitive paths |
| Failure behavior | Generic client errors; detailed diagnostic data only in protected server logs |

The digest is a diagnostic and consistency check; the GCM tag is the cryptographic authenticity check. Both must pass before delivery.

## 9. Persistence model

A relational database is recommended for user, transfer, permission, and audit metadata. Encrypted bytes remain in a protected binary storage directory so the project demonstrates both the syllabus's file streams and structured persistence.

| Table/entity | Important fields |
|---|---|
| users | id, username, email, password hash, role, status, failed attempts |
| files | id, owner id, original name, storage id, size, MIME/signature, digest, wrapped DEK, nonce, created time |
| transfers | id, file id, sender id, recipient id, status, timestamps |
| permissions | file id, user id, permission type, granted time, active flag |
| audit_events | id, actor id, event type, safe detail, timestamp, source address |

Repositories expose domain operations; SQL strings and database handles remain in infrastructure. A file-backed repository may be used first for the MVP, then replaced by SQLite/MySQL without changing application services.

## 10. Error and exception design

~~~text
std::exception
└── AppException
    ├── ValidationException
    │   ├── InvalidCredentialsException
    │   └── InvalidFileException
    ├── AuthorizationException
    ├── NotFoundException
    ├── StorageException
    ├── CryptoException
    │   └── IntegrityException
    └── TransportException
~~~

Rules:

1. Catch exceptions at a boundary that can add context or choose a safe user message.
2. Do not catch everything and continue with a partially valid object.
3. Use RAII so exceptions cannot leak open files, sockets, locks, or transactions.
4. Convert library-specific errors to project exceptions in infrastructure adapters.
5. Test both the exception type and the absence of leaked plaintext/partial files.

## 11. Project folder structure

~~~text
secure-file-transfer/
├── CMakeLists.txt
├── include/
│   ├── domain/
│   ├── application/
│   ├── ports/
│   └── infrastructure/
├── src/
│   ├── domain/
│   ├── application/
│   ├── infrastructure/
│   └── presentation/
├── client/
├── server/
├── storage/encrypted/
├── database/schema.sql
├── tests/
│   ├── domain/
│   ├── application/
│   ├── security/
│   └── integration/
├── docs/
│   ├── project_description.md
│   └── system_architecture.md
├── config.example.ini
└── README.md
~~~

## 12. Test plan and evaluation evidence

| Test group | Evidence |
|---|---|
| Domain | Invalid constructors rejected; transfer state transitions work |
| OOP | Base-interface calls dispatch to alternate implementations; test doubles can be substituted |
| File I/O | Binary round trip preserves bytes; missing/partial files produce exceptions |
| Security | Unauthorized download denied; altered ciphertext fails verification; unique nonces are generated |
| Persistence | Save/load preserves relationships; failed transaction does not leave orphaned metadata |
| Exceptions | Resources close and partial ciphertext is removed on failure |
| Integration | Register -> upload -> authorize -> download -> audit works end to end |
| Course mapping | Each CO1–CO6 is linked to classes, code, tests, and a live demonstration |

## 13. Deliberate design limits

- The server can decrypt files; this is not end-to-end encryption.
- A single-server deployment has no availability or disaster-recovery guarantee.
- Local storage is appropriate for the course MVP, not large-scale production.
- Malware scanning, MFA, key rotation, and public-key recipient encryption are future work.
- A web UI is intentionally postponed so the core OOP design remains assessable.

## 14. References

1. VIT, **CI2013: Object Oriented Programming**, syllabus PDF supplied in this repository.
2. Oracle, **Object-Oriented Programming Concepts**: https://docs.oracle.com/javase/tutorial/java/concepts/
3. Oracle, **Interfaces and Inheritance**: https://docs.oracle.com/javase/tutorial/java/IandI/
4. Oracle, **Exceptions**: https://docs.oracle.com/javase/tutorial/essential/exceptions/
5. Oracle, **Java Cryptography Architecture — Cipher**: https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html
6. OWASP, **File Upload Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
7. OWASP, **Password Storage Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
8. OWASP, **Cryptographic Storage Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
9. NIST, **SP 800-57 Part 1 Rev. 5 — Recommendation for Key Management**: https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final
10. cppreference, **Classes**: https://en.cppreference.com/w/cpp/language/classes
11. cppreference, **Templates**: https://en.cppreference.com/w/cpp/language/templates

