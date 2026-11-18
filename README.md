# Confidential P2P Node (`confidential-p2p-node`)

A proof-of-concept Peer-to-Peer (P2P) mesh node written in C using the **Intel SGX SDK** (`SGX_MODE=SIM`) to isolate key exchange, local attestation, and authenticated symmetric encryption inside a Trusted Execution Environment (TEE) boundary.

## Architecture & Security Model

* **Trusted Enclave (`enclave/`):**
  * **Mutual SGX Local Attestation:** Peers exchange their `sgx_target_info_t` (`sgx_self_target`), generate an ephemeral NIST P-256 keypair inside the enclave, and bind the 64-byte uncompressed public key ($X \parallel Y$) into the `report_data` field of a peer-targeted `sgx_report_t` (`sgx_create_report`).
  * **Cryptographic Report & Identity Verification:** Incoming reports are verified inside the enclave via `sgx_verify_report()` (validating the report CMAC) before checking `MRSIGNER` and `MRENCLAVE` measurements.
  * **Single-Use Ephemeral ECDH & KDF:** Inside `ecall_verify_and_derive`, the enclave extracts the authenticated public key, computes the ECDH shared secret, derives a 128-bit AES key via SHA-256 truncation, and immediately scrubs both the ephemeral private key and the session key after a single encryption or decryption operation.
  * **Authenticated Encryption:** Payloads are encrypted and authenticated using **AES-128-GCM** via the Intel SGX Trusted Cryptography Library (`sgx_tcrypto`).

* **Untrusted Host (`node/`):**
  * Manages TCP sockets, 4-byte length-prefixed framing (`htonl`/`ntohl` with `read_full`/`write_full` loops), strict TCP port validation (`1–65535` via `strtol`), and a `pthread_mutex` serializing enclave sessions.
  * *Prototype Threat Model & Limitations:* In this interactive CLI prototype, plaintext messages enter from the untrusted host console (`[in, string]`) and decrypted payloads are printed via `ocall_print_string`. Moreover, the enclave runs in simulation mode (`SGX_MODE=SIM`) without a custom `Enclave.config.xml` (default debug signing configuration). Cross-host deployment on physical SGX hardware requires **Intel SGX DCAP** Quote generation and verification.

## Repository Structure

```text
confidential-p2p-node/
├── enclave/
│   ├── enclave.edl          # Enclave Definition Language interface (ECALLs / OCALLs)
│   ├── enclave.c            # Trusted attestation, ECDH KDF, and AES-128-GCM routines
│   └── Makefile             # Trusted enclave shared library build rules
├── node/
│   ├── main.c               # CLI loop, port validation, and multi-payload CSV benchmark
│   ├── p2p_network.c        # TCP listener, length-prefixed framing, and attested handshake
│   └── p2p_network.h        # Networking declarations and shared constants
├── scripts/
│   └── mitm_attack.py       # Active NIST P-256 MITM proxy for SGX report_data splicing tests
├── Dockerfile               # Ubuntu 22.04 + Intel SGX SDK 2.22 build environment
├── docker-compose.yml       # 7-node virtual P2P mesh (172.20.0.10 - 172.20.0.16)
├── Makefile                 # Root build orchestration (sgx_edger8r, app, enclave.signed.so)
└── benchmark_results.csv    # Raw latency samples (1,000 iterations per operation/payload)
```

## Quick Start (Docker Mesh)

### 1. Clone and Build

```bash
git clone https://github.com/filippo-zullo98/confidential-p2p-node.git
cd confidential-p2p-node
docker compose up --build -d
```

### 2. Interactive Node Commands

Open two terminals to observe the P2P exchange in real time.

In **Terminal 1**, follow the logs of the receiving node (`node_b` at `172.20.0.11`):

```bash
docker logs -f node_b
```

In **Terminal 2**, attach to the interactive CLI of the sending node (`node_a` at `172.20.0.10`):

```bash
docker attach node_a
```

Available commands inside the `p2p-node>` prompt:

* **Send an attested encrypted message:**
  ```text
  send 172.20.0.11 8080 Hello from node_a!
  ```
* **Test AES-128-GCM integrity (1-bit ciphertext flip in flight):**
  ```text
  tamper 172.20.0.11 8080 Tampered payload test
  ```
  *(Note: `node_c` at `172.20.0.12` is configured with `NODE_BEHAVIOR=MALICIOUS` and automatically performs bit-flipping on `send`.)*
* **Run the cryptographic & handshake benchmark (exports `benchmark_results.csv`):**
  ```text
  benchmark
  ```
* **Exit cleanly:**
  ```text
  quit
  ```

## Running the Active MITM Test (`scripts/mitm_attack.py`)

To verify that `sgx_verify_report()` blocks active Man-In-The-Middle key substitution in `report_data` (offset `320..383`):

1. Keep `docker logs -f node_b` open in **Terminal 1** to monitor the receiver's enclave checks.
2. In **Terminal 2**, start the MITM proxy on `node_c` (`172.20.0.12:9090` forwarding to `172.20.0.11:8080`):
   ```bash
   docker exec -it node_c python3 /app/scripts/mitm_attack.py --listen-port 9090 --target-ip 172.20.0.11 --target-port 8080
   ```
3. In **Terminal 3**, attach to `node_a` (`docker attach node_a`) and route a message through the proxy:
   ```text
   send 172.20.0.12 9090 Confidential test message
   ```
4. Both `node_a` and `node_b` reject the forged `sgx_report_t` with `SGX_ERROR_MAC_MISMATCH` (`0x3001`) and close the socket before any payload is transmitted.