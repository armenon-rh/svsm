# Design Document: CocoonFS vTPM State Replay and Clone Protection in SVSM

**Author:** Arun Menon (<armenon@redhat.com>)
**Status:** RFC / Proposed Specification
**Target Architecture:** SVSM / KBS / CocoonFS / TEE (AMD SEV-SNP & Intel TDX)

---

## 1. Problem Statement

In Confidential Virtualization environments, the virtual TPM (vTPM) state is highly sensitive and must be securely
stored, migrated, and restored. The `cocoon-tpm` project provides the **CocoonFS** filesystem—an encrypted, journaled,
and authenticated format designed specifically for TEEs.

During early boot, the Secure VM Service Module (SVSM) decrypts the CocoonFS filesystem using a Data Encryption Key
(DEK) retrieved from the Key Broker Service (KBS) after successful hardware attestation.

While standard KBS attestation verifies the **cryptographic liveness and identity** of the running SVSM instance
(via challenge-response attestation quotes), it **cannot prevent State Replay and Cloning Attacks** on the underlying
encrypted disk image:

1. **State Replay / Rollback Attack:** An untrusted hypervisor can snapshot an older encrypted image (`test_volume.img`)
along with its wrapped DEK. When booted on a genuine TEE host, SVSM successfully completes attestation, retrieves the
unwrapped key, and boots the **old snapshot**. In vTPM contexts, rollbacks allow double-spending of sealed keys,
transaction rollbacks, or resetting monotonic PCR security states.
2. **Cloning / Split-Brain Execution:** An attacker can launch multiple concurrent VM instances from the same valid disk
snapshot. Both instances attest successfully and receive the decryption key, causing divergent, conflicting states from
the same vTPM identity.

To prevent both attack vectors, the physical state of the encrypted image must be bound to the KBS backend through
**rolling session nonces**, **monotonic boot counters**, and **exclusive session leases**.

---

## 2. Architecture: Self-Describing Metadata, Structured Claims & Session Leases

We utilize CocoonFS's native, multi-entry **unencrypted auxiliary metadata headers** (`AuxFsMetadata`) to store
independent, self-describing configuration blocks:

1. **The Routing Block:** Identifies the KBS resource endpoint to retrieve the decryption key (e.g., `default/vtpm/<vmid>`).
2. **The Identity Block (for PKCS#11 flows):** Contains the unique VM resource ID string needed by the KBS to associate
an unwrap request with the correct session.
3. **The Anti-Replay Header Block:** Contains a versioned binary header with a rolling cryptographic nonce and a monotonic
boot counter that SVSM must attest to prove the current boot instance aligns with the latest authoritative state in KBS.

### 2.1 Auxiliary Metadata Header Layout

Inside the unencrypted aux-metadata key-value store, we define standardized UUIDs:

* `UUID_SECRET_STORAGE`: `bc27ddb0-0b61-4fa3-979a-ca81f4a476bc` (stores ASCII resource path)
* `UUID_PKCS11_UNWRAP`: `51cac867-fce7-4542-bd23-8a2435c3fc77` (stores wrapped DEK payload)
* `UUID_VM_IDENTITY`: `c848039c-50a3-48ef-827d-0fbdf3b556b6` (stores ASCII VM identity string)
* `UUID_SESSION_NONCE`: `aabbccdd-1122-3344-5566-77889900aabb` (stores binary `AntiReplayHeader`)

#### The 26-Byte Binary `AntiReplayHeader`
The value stored under `UUID_SESSION_NONCE` is a 26-byte packed binary structure:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   26-BYTE BINARY AntiReplayHeader                      │
├─────────────┬─────────────┬──────────────────────────┬─────────────────┤
│ Byte 0      │ Byte 1      │ Bytes 2..10              │ Bytes 10..26    │
│ version(u8) │ flags (u8)  │ boot_counter (u64 LE)    │ nonce ([u8; 16])│
└─────────────┴─────────────┴──────────────────────────┴─────────────────┘
```
*(For backwards compatibility, headers with length >= 16 and < 26 bytes are treated as legacy 16-byte raw nonces with
`boot_counter = 1` and `version = 1`.)*

#### Layout Option A: Secret Storage Flow
```
┌────────────────────────────────────────────────────────────────────────┐
│                      COCOONFS UNENCRYPTED HEADER                       │
├────────────────────────────────────────────────────────────────────────┤
│ ENTRY 1: ROUTING & IDENTITY BLOCK                                      │
│ ├── Key (UUID):   bc27ddb0-0b61-4fa3-979a-ca81f4a476bc                 │
│ │                 (UUID_SECRET_STORAGE)                                │
│ └── Value (Bytes): "default/vtpm/vm-101" (ASCII Resource ID)           │
│                                                                        │
│ ENTRY 2: ANTI-REPLAY HEADER BLOCK                                      │
│ ├── Key (UUID):   aabbccdd-1122-3344-5566-77889900aabb                 │
│ │                 (UUID_SESSION_NONCE)                                 │
│ └── Value (Bytes): [26-byte Binary AntiReplayHeader:                   │
│                     version=1, flags=0, boot_counter=N, nonce=16B]     │
└────────────────────────────────────────────────────────────────────────┘
```

#### Layout Option B: PKCS#11 Unwrap Flow
```
┌────────────────────────────────────────────────────────────────────────┐
│                      COCOONFS UNENCRYPTED HEADER                       │
├────────────────────────────────────────────────────────────────────────┤
│ ENTRY 1: IDENTITY BLOCK                                                │
│ ├── Key (UUID):   c848039c-50a3-48ef-827d-0fbdf3b556b6                 │
│ │                 (UUID_VM_IDENTITY)                                   │
│ └── Value (Bytes): "default/vtpm/vm-101" (ASCII Resource ID)           │
│                                                                        │
│ ENTRY 2: ROUTING & KEY PAYLOAD BLOCK                                   │
│ ├── Key (UUID):   51cac867-fce7-4542-bd23-8a2435c3fc77                 │
│ │                 (UUID_PKCS11_UNWRAP)                                 │
│ └── Value (Bytes): [256-byte Asymmetrically-Wrapped DEK Payload]       │
│                                                                        │
│ ENTRY 3: ANTI-REPLAY HEADER BLOCK                                      │
│ ├── Key (UUID):   aabbccdd-1122-3344-5566-77889900aabb                 │
│ │                 (UUID_SESSION_NONCE)                                 │
│ └── Value (Bytes): [26-byte Binary AntiReplayHeader:                   │
│                     version=1, flags=0, boot_counter=N, nonce=16B]     │
└────────────────────────────────────────────────────────────────────────┘
```

---

### 2.2 Cryptographic Binding via CoCo-AS Structured Runtime Data Claims

It is essential to distinguish between the two categories of nonces:

| Nonce / State Component | 1. Network Liveness Challenge | 2. Disk Anti-Replay State |
| :--- | :--- | :--- |
| **Components** | Single 48-byte random challenge | 16-byte random nonce + 64-bit monotonic boot counter |
| **Originator** | KBS during `/auth` negotiation | Admin provisioner (initial) & SVSM (each boot) |
| **Storage Location** | In-memory session on KBS | Disk unencrypted header (`UUID_SESSION_NONCE`) & KBS database |
| **Lifecycle** | Transient (per attestation handshake) | Persistent (across VM power cycles) |
| **Defense Scope** | Mitigates network replay attacks | Mitigates image rollback, cloning, and split-brain execution |

#### CoCo-AS Structured Runtime Data Integration
SVSM integrates with the standard Confidential Containers Attestation Service (CoCo-AS) evidence pipeline using
**Structured Runtime Data Claims**:

1. SVSM formats its runtime data as a JWS JSON object using `JwsJsonFormatter`, embedding the network challenge,
ephemeral TEE public key, and the anti-replay fields:
   ```json
   {
     "version": 1,
     "boot_counter": 1,
     "disk_nonce": "aabbccdd11223344556677889900aabb",
     "nonce": "<base64-encoded KBS live challenge>",
     "tee-pubkey": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." },
     "additional-evidence": ""
   }
   ```
2. The CPU hardware attestation quote (AMD SEV-SNP or Intel TDX) signs the cryptographic digest of this entire runtime
data structure into its hardware `REPORT_DATA` register.
3. During attestation (`POST /kbs/v0/attest`), KBS merges these non-reserved client runtime data claims
(`boot_counter`, `disk_nonce`, `version`) into `primary_runtime_data` forwarded to the Attestation Service.
4. CoCo-AS validates the hardware quote, verifies the runtime data digest matches the quote's signed `REPORT_DATA`,
and issues an Attestation Token (EAR/JWT) containing verified `runtime_data_claims`.
5. When SVSM requests the protected key (`GET /kbs/v0/resource/<path>`), KBS's `AntiReplayManager` extracts
`(version, boot_counter, disk_nonce)` from the verified token claims and verifies them against the KBS authoritative store.

---

### 2.3 Mutual Exclusion via Timed Session Leases

To prevent an attacker from launching **multiple concurrent VM instances from the same valid snapshot**, KBS enforces
mutual exclusion through timed session leases:

1. **Lease Grant:** When SVSM requests the decryption key, KBS validates the nonce and counter, marks the resource as
locked by an active session lease (`active_lease`, `lease_expiry`), and returns the session ID via the HTTP response header:
   ```http
   X-SVSM-Session-ID: <counter>-<timestamp>-<nonce_prefix>
   ```
2. **Conflict Detection:** If another VM attempts to retrieve the key for the same resource while a valid lease is
active, KBS rejects the request with **HTTP 409 Conflict** (`LeaseActive`).
3. **Background Lease Maintenance:** The attestation proxy (`aproxy`) spawns a background `LeaseRefresher` thread that
sends periodic heartbeats to `POST /kbs/v0/svsm/heartbeat` every 25 seconds.
4. **Transport Keep-Alive:** SVSM calls `driver.keep_alive()` to maintain the underlying transport connection open for
the duration of the guest lifecycle.
5. **Clean Release & Crash Recovery:**
   - On graceful guest shutdown or proxy exit, `aproxy` issues `POST /kbs/v0/svsm/release-lease` to unlock the resource
     immediately.
   - If the host crashes ungracefully, the lease expires automatically after `lease_duration_secs` (configurable, default 60s),
     permitting a subsequent boot without manual administrative intervention.

### 2.4 VM Migration and Host Portability

This architecture naturally supports standard QEMU VM relocation and offline migration between hosts:

1. **Clean Handover:** When a VM on the source host is shut down during migration, `aproxy` issues
`POST /kbs/v0/svsm/release-lease`, cleanly releasing the active session lease in the central KBS.
2. **Target Boot:** The CocoonFS image (containing the latest rolled nonce and boot counter) is transferred or attached
to the target host. When SVSM starts on the target host, it attests to the central KBS. Because the image's latest state
matches KBS storage and the lease is free, the target SVSM acquires a new session lease and boots cleanly.
3. **Split-Brain Mitigation:** If a hypervisor attempts to start the target VM while the source VM is still running,
the target boot is rejected with **HTTP 409 Conflict** (`LeaseActive`). Similarly, any attempt to boot a stale
pre-migration snapshot on either host is rejected with **HTTP 403 Forbidden** (`NonceMismatch`).

---

## 3. High-Level Integration Flows

### 3.1 Provisioning Workflow
The Administrator Tool (`vtpm-to-svsm-blk`) prepares and registers the image offline:

```
Admin Provisioning Tool                               Local Filesystem                                KBS (Key Broker Service)
[vtpm-to-svsm-blk]                                    [Host Storage]                                  [Central Key Server]
───────┬───────────────                               ───────┬──────                                  ────────┬───────────
       │                                                     │                                                │
       │ ── 1. Read Raw vTPM State ──►                       │                                                │
       │    (Fetch initial NVRAM/state)                      │                                                │
       │                                                     │                                                │
       │ ── 2. Generate Cryptographic Secrets ──►            │                                                │
       │    - Gen random [Filesystem DEK] (32-byte)          │                                                │
       │    - Gen random [Initial Nonce_A] (16-byte)         │                                                │
       │    - Set [boot_counter = 1, version = 1]            │                                                │
       │    - Format Resource ID: "default/vtpm/<vmid>"      │                                                │
       │                                                     │                                                │
       │ ── 3. Create & Format CocoonFS Image ──►            │                                                │
       │    - Pre-allocate image file                        │                                                │
       │    - Format via MkFs with [Filesystem DEK]          │                                                │
       │    - Authenticate-Encrypt state into Inode 16       │                                                │
       │                                                     │                                                │
       │ ── 4. Inject Offline Aux Metadata ──►               │                                                │
       │    - Inject 26-byte AntiReplayHeader                │                                                │
       │      under UUID_SESSION_NONCE                       │                                                │
       │    - Inject Resource ID under UUID_SECRET_STORAGE   │                                                │
       │                                                     │                                                │
       │ ── 5. Register Initial State in KBS ────────────────┼───────────────────────────────────────────────►│
       │    POST /kbs/v0/svsm/register-nonce (Admin Auth)    │                                                │
       │    Payload: { resource_id, boot_counter: 1,         │                                                │
       │               nonce: "<hex>", version: 1 }          │                                                │
       │                                                     │                                                │
       │ ── 6. Store Filesystem DEK in KBS ──────────────────┼───────────────────────────────────────────────►│
       │    POST /kbs/v0/resource/default/vtpm/<vmid>        │                                                │
       │    Payload: [Filesystem DEK]                        │                                                │
       │                                                     │                                                │
       │ ── 7. Image Ready for VM Attachment ──►             │                                                │
       │    - Attached as virtio-blk device to SVSM guest    │                                                │
       ▼                                                     ▼                                                ▼
```

---

### 3.2 SVSM Early Boot Decryption, Lease Acquisition & Nonce Rolling Workflow

```
 SVSM (Guest Kernel)                                    aproxy (Host Proxy)                             KBS (Key Broker Service)
 ───────────────────                                    ───────────────────                             ───────────────────────
         │                                                       │                                                 │
         │ ── 1. Read Plain Disk Header (Offline) ──►            │                                                 │
         │    - Discover disk & read AuxFsMetadata               │                                                 │
         │    - Extract: [Resource ID] ("default/vtpm/vm-101")   │                                                 │
         │    - Parse: AntiReplayHeader (counter=1, nonce=N_A)   │                                                 │
         │                                                       │                                                 │
         │ ── 2. GET /auth Negotiation ─────────────────────────►│ ───────────────────────────────────────────────►│
         │                                                       │                                                 │
         │ ◄── 3. Challenge Response ─────────────────────────── │ ◄───────────────────────────────────────────────│
         │    - Returns 48-byte live challenge nonce             │                                                 │
         │                                                       │                                                 │
         │ ── 4. Build JWS JSON Runtime Data & Quote ──►         │                                                 │
         │    - Embed challenge, tee-pubkey,                     │                                                 │
         │      boot_counter=1, disk_nonce=N_A                   │                                                 │
         │    - CPU generates hardware attestation quote         │                                                 │
         │                                                       │                                                 │
         │ ── 5. POST /attest with Evidence & Claims ───────────►│ ───────────────────────────────────────────────►│
         │                                                       │    - KBS merges runtime data claims             │
         │                                                       │    - CoCo-AS validates hardware quote           │
         │ ◄── 6. Returns Attestation Token (JWT) ───────────────│ ◄───────────────────────────────────────────────│
         │                                                       │                                                 │
         │ ── 7. Fetch Protected Secret (DEK) ──────────────────►│ ── 8. GET /kbs/v0/resource/default/vtpm/vm-101 ─►│
         │                                                       │    (Bearer JWT)                                 │
         │                                                       │                                                 │
         │                                                       │    ── 9. Anti-Replay & Lease Verification ──    │
         │                                                       │    • Verify no unexpired active lease (409)     │
         │                                                       │    • Verify disk_nonce == stored nonce (403)    │
         │                                                       │    • Verify boot_counter == stored counter (403)│
         │                                                       │    • Grant lease & generate session_id          │
         │                                                       │                                                 │
         │                                                       │ ◄── 10. HTTP 200 OK + Key + Lease Header ───────│
         │                                                       │     Header: X-SVSM-Session-ID: <session_id>     │
         │                                                       │     Body: JWE-encrypted DEK                     │
         │                                                       │                                                 │
         │                                                       │ ── 11. Spawn LeaseRefresher Worker ──┐          │
         │                                                       │    - Periodically POSTs /heartbeat   │          │
         │                                                       │      every 25 seconds                │          │
         │                                                       │    - POSTs /release-lease on drop    │          │
         │                                                       │    ◄─────────────────────────────────┘          │
         │                                                       │                                                 │
         │ ◄── 12. Deliver Decrypted Secret to SVSM ─────────────│                                                 │
         │                                                       │                                                 │
         │ ── 13. Local-First Offline Disk Commit ──┐            │                                                 │
         │    - Generate fresh Nonce_B via SvsmRng  │            │                                                 │
         │    - Increment counter: boot_counter = 2 │            │                                                 │
         │    - Overwrite AntiReplayHeader on disk  │            │                                                 │
         │      offline before mounting             │            │                                                 │
         │    ◄─────────────────────────────────────┘            │                                                 │
         │                                                       │                                                 │
         │ ── 14. Unlock & Mount CocoonFS ──┐                    │                                                 │
         │    - Decrypt and initialize vTPM state   │            │                                                 │
         │    ◄─────────────────────────────────────┘            │                                                 │
         │                                                       │                                                 │
         │ ── 15. Roll Nonce on KBS ────────────────────────────►│ ── 16. POST /kbs/v0/svsm/roll-nonce ──────────► │
         │    (via proxy AttestationDriver)                      │    Payload: { resource_id,                      │
         │                                                       │      new_boot_counter: 2,                       │
         │                                                       │      new_nonce: "<hex N_B>", version: 1 }       │
         │                                                       │                                                 │
         │                                                       │ ◄── 17. HTTP 200 OK (Rolled in KBS Store) ──────│
         │                                                       │                                                 │
         │ ── 18. Keep-Alive Transport Connection ──┐            │                                                 │
         │    - driver.keep_alive() holds connection│            │                                                 │
         │      open to preserve active lease       │            │                                                 │
         │    ◄─────────────────────────────────────┘            │                                                 │
         ▼                                                       ▼                                                 ▼
```

---

## 4. Component Interface & Schema Specifications

### 4.1 `cocoon-tpm`
* **Library Interface:** Exposes `cocoonfs-cli` as a library crate, providing `StdFileNvBlkDev` and `StdSyncTypes` publicly.
* **Role:** Enables administrative tools (`vtpm-to-svsm-blk`) to format volumes and inject unencrypted auxiliary
metadata using standard Linux file I/O.

---

### 4.2 `vtpm-to-svsm-blk` (Host Provisioner Tool)
* **Header Structure:** Injects the 26-byte binary header under `UUID_SESSION_NONCE`:
  ```rust
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub struct AntiReplayHeader {
      pub version: u8,
      pub flags: u8,
      pub boot_counter: u64,
      pub nonce: [u8; 16],
  }
  ```
* **CLI Arguments:** Accepts `--resource-id <ID>` or `--vmid <ID>` (formats `default/vtpm/<vmid>`).
* **Registration:** Registers initial record `{ resource_id, boot_counter: 1, nonce: "<hex>", version: 1 }` with KBS via `POST /kbs/v0/svsm/register-nonce`.

---

### 4.3 `svsm`, `libaproxy`, and `aproxy` (Guest Kernel & Host Proxy)

#### A. Kernel Boot Metadata & Persistence Schema
SVSM extracts boot metadata from `AuxFsMetadata` before launching attestation:
```rust
pub struct BootMetadataInfo {
    pub version: u8,
    pub boot_counter: u64,
    pub disk_nonce: [u8; 16],
    pub resource_id: alloc::string::String,
}
```

#### B. SVSM Early Boot Sequencing
1. **Metadata Discovery:** Reads offline auxiliary metadata without requiring keys; extracts `BootMetadataInfo`.
2. **Attestation:** Embeds `boot_counter` and `disk_nonce` into structured JWS JSON runtime data claims.
3. **Key Acquisition:** Retrieves unwrapped DEK and session lease ID (`X-SVSM-Session-ID`) from KBS.
4. **Local Disk Commit (First):** Increments `boot_counter`, generates random `new_nonce`, and commits `AntiReplayHeader`
to local disk offline before mounting.
5. **Filesystem Unlocking:** Mounts CocoonFS and initializes the vTPM subsystem.
6. **Remote State Rolling:** SVSM issues `roll_nonce` via `aproxy` to advance KBS authoritative storage.
7. **Connection Retention:** Calls `driver.keep_alive()` to hold the transport connection open for lease lifetime.

#### C. Proxy Protocol Schemas (`libaproxy`)
```rust
// Sent from SVSM to aproxy to roll the remote KBS state
pub struct RollNonceRequest {
    pub version: u8,
    pub resource_id: String,
    pub new_boot_counter: u64,
    pub new_nonce: Vec<u8>,
}

pub struct RollNonceResponse {
    pub success: bool,
    pub error_msg: Option<String>,
}
```

#### D. Attestation Proxy (`aproxy`) Lease Refresher
* Spawns background worker upon receiving `X-SVSM-Session-ID`.
* Dispatches heartbeats to `/kbs/v0/svsm/heartbeat` every 25 seconds.
* Dispatches release request to `/kbs/v0/svsm/release-lease` upon guest shutdown or proxy termination.

---

### 4.4 `trustee/kbs` (Key Broker Service)

#### A. Configuration & Storage Schema
```rust
pub struct AntiReplayConfig {
    pub enabled: bool,
    pub enforce_prefixes: Vec<String>, // Default: ["default/vtpm/"]
    pub lease_duration_secs: u64,      // Default: 60 seconds
}

pub struct AntiReplayRecord {
    pub version: u8,
    pub boot_counter: u64,
    pub nonce: String,                 // 32-character hex string (16 bytes)
    pub active_lease: Option<String>,  // Active Session ID holding the lease
    pub lease_expiry: Option<u64>,     // Unix timestamp in seconds
}
```

#### B. Validation Rules
When a resource matching `enforce_prefixes` is requested (`GET /kbs/v0/resource/<path>`):
1. **Lease Mutual Exclusion:** Verify that `active_lease` is either `None` or expired (`now >= lease_expiry`).
Reject with `HTTP 409 Conflict` if in use.
2. **Nonce Parity:** Compare presented `disk_nonce` against `record.nonce`. Reject with `HTTP 403 Forbidden` on mismatch.
3. **Monotonic Counter Parity:** Compare presented `boot_counter` against `record.boot_counter`. Reject with
`HTTP 403 Forbidden` on mismatch.
4. **Grant Lease:** Generate `session_id`, set `active_lease = session_id`, set `lease_expiry = now + lease_duration_secs`, and return `X-SVSM-Session-ID` header.

#### C. SVSM Lifecycle Endpoints
All anti-replay management routes are grouped under `/kbs/v0/svsm/*`:

| Endpoint | Method | Authentication | Description |
| :--- | :--- | :--- | :--- |
| `/kbs/v0/svsm/register-nonce` | `POST` | KBS Admin Auth | Registers initial `AntiReplayRecord` during provisioning. |
| `/kbs/v0/svsm/roll-nonce` | `POST` | Attestation Token | Rolls `new_nonce` and `new_boot_counter` after boot. |
| `/kbs/v0/svsm/heartbeat` | `POST` | Attestation Token | Extends `lease_expiry` every 25 seconds during VM execution. |
| `/kbs/v0/svsm/release-lease` | `POST` | Attestation Token | Clears `active_lease` on clean VM termination. |

#### D. HTTP Error Code Mappings
| Error Condition | Internal Variant | HTTP Status |
| :--- | :--- | :--- |
| Concurrent VM running / active lease held | `AntiReplayError::LeaseActive` | **409 Conflict** |
| State replay / spent nonce presented | `AntiReplayError::NonceMismatch` | **403 Forbidden** |
| Split-brain / stale boot counter presented | `AntiReplayError::CounterMismatch` | **403 Forbidden** |
| Resource not registered in anti-replay store | `AntiReplayError::NonceNotRegistered` | **404 Not Found** |
| Malformed hex or missing runtime claims | `AntiReplayError::BadRequest` | **400 Bad Request** |

---

## 5. Security Guarantees & Verification Plan

### 5.1 Threat Matrix & Coverage

| Threat Scenario | Protection Mechanism | Result |
| :--- | :--- | :--- |
| **Disk Image Rollback** (Attacker restores an earlier snapshot of `test_volume.img`) | Nonce Parity Check | **Blocked:** Old nonce in snapshot does not match current rolled nonce in KBS store (`HTTP 403 Forbidden`). |
| **Monotonic Counter Rollback** (Attacker attempts to replay an older counter) | Monotonic Counter Parity | **Blocked:** Attested counter does not match authoritative counter (`HTTP 403 Forbidden`). |
| **VM Cloning / Split-Brain Execution** (Attacker boots two instances from same current snapshot) | Exclusive Session Leases (`active_lease`) | **Blocked:** First instance secures lease; second instance receives `HTTP 409 Conflict`. |
| **Network Man-in-the-Middle** (Attacker intercepts or replays network attestation messages) | Hardware quote + KBS Live Challenge | **Blocked:** Challenge expires; quote is bound to CPU hardware root-of-trust. |
| **Host Crash Recovery** (Host power drops without clean lease release) | Automatic Lease Timeout (`lease_duration_secs`) | **Recoverable:** Lock expires after timeout; legitimate VM can reboot cleanly. |

### 5.2 Verification Test Scenarios

1. **Standard Boot & Roll:**
   - Provision a fresh CocoonFS image with `boot_counter = 1`.
   - Boot VM; verify SVSM retrieves the key, commits `boot_counter = 2` and a new random nonce to local disk, rolls KBS remotely, and mounts the filesystem cleanly.
   - Reboot VM; verify that boot 2 succeeds with `boot_counter = 2`.
2. **State Replay / Snapshot Rollback:**
   - Take a backup copy of the image at boot 1.
   - Allow boot 1 to finish (rolling disk and KBS state to boot 2).
   - Substitute the image with the boot 1 backup and attempt boot.
   - Verify KBS detects nonce mismatch and aborts key retrieval with **HTTP 403 Forbidden**.
3. **Split-Brain Monotonic Counter Verification:**
   - Attempt to attest with an invalid or desynchronized boot counter.
   - Verify KBS rejects with **HTTP 403 Forbidden** (`CounterMismatch`).
4. **Concurrent Boot / Mutual Exclusion:**
   - Launch a VM and keep it running with an active session lease.
   - Concurrently attempt to boot a clone of the image with the same credentials.
   - Verify KBS rejects the second boot with **HTTP 409 Conflict** (`LeaseActive`).
5. **Clean Release vs. Crash Recovery:**
   - Gracefully shut down VM; verify lease is immediately released (`POST /kbs/v0/svsm/release-lease`).
   - Terminate VM forcibly (`kill -9`); verify subsequent boot succeeds after `lease_duration_secs` has elapsed.
