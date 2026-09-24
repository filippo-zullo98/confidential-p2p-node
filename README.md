# Confidential P2P Node (Intel SGX)

A decentralized Peer-to-Peer (P2P) overlay network node leveraging **Intel SGX (Software Guard Extensions)** to implement a Zero-Trust architecture. 

This project was developed as part of a Bachelor's Thesis in Computer Science to evaluate the application of Confidential Computing in distributed systems, specifically focusing on mitigating "Insider Threats" (e.g., malicious raw socket injections) within a containerized environment.

## Core Features

* **Hardware-Isolated Enclaves:** Core cryptographic operations and message validations are executed inside SGX enclaves to prevent memory inspection from the host OS.
* **Secure Communication (AES-GCM):** Payload encryption and authentication using AES-GCM, ensuring data confidentiality and integrity.
* **Key Exchange:** ECDH handshake implementation for secure ephemeral session key derivation.
* **Robust Networking:** Custom TCP framing and strict port validation to handle packet fragmentation and unauthorized traffic.
* **Threat Simulation:** Docker Compose orchestration to simulate a network of trusted nodes and a compromised host attempting to inject unauthorized raw traffic.

## Architecture

The untrusted host process (```node/```) only ever see ciphertext; all key material and plaintext validation happen inside the SGX enclave (```enclave/```), so a compromised host process cannot forge or read 
traffic without also breaking into the enclave itself.

## Technologies & Stack

* **Language:** C 
* **Confidential Computing:** Intel SGX SDK (ECALLs / OCALLs, Edger8r)
* **Cryptography:** OpenSSL (Intel SGX SSL / Crypto API)
* **Infrastructure:** Docker, Docker Compose
* **Build System:** GNU Make

## Prerequisites

To build and run the simulation, the host machine must support Intel SGX (Hardware or Simulation mode). The primary dependencies are:
* Linux OS (Debian/Ubuntu Server recommended)
* [Intel SGX SDK](https://github.com/intel/linux-sgx)
* Docker & Docker Compose
* OpenSSL

## Build and Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/filippo-zullo98/confidential-p2p-node.git](https://github.com/filippo-zullo98/confidential-p2p-node.git)
   cd confidential-p2p-node
   ```
2. **Build the project:** The Makefile is configured to automatically generate the RSA private key (enclave_private.pem) required to sign the enclave if it is not present.
   ```bash
   make
   ```
## Running the simulation 
The project includes a Docker Compose configuration to spin up the P2P network and simulate the Insider Threat scenario:
  ```bash
  # Build the Docker images and start the network in detached mode
  docker-compose up --build -d
      
  # View the logs to observe the SGX enclave detecting and dropping unsigned packets
  docker-compose logs -f
  ```
## Repository Structure
- ```enclave/``` - Trusted code executed inside the SGX enclave (cryptography, EDL file).

- ```node/``` - Untrusted application code handling socket connections and P2P routing.

- ```docker-compose.yml``` - Network orchestration and threat simulation setup.

- ```Makefile``` - Build instructions and automated enclave signing.

## Security Consideration & Known Limitations
This project is a thesis-scale proof of concept, not a production-ready implementation.
Being explicit about what it does *not* cover:
- **No remote attestation:** the ECDH handshake currently establishes a session key between two enclaves whose identity is trusted implicitly. A production system would require SGX remote attestation (local or via Intel Attestation Service/DCAP) before the handshake, so each side can verify it is really talking to a genuine, unmodified enclave rather than compromised host impersonating one.
- **Enclave signing key handling:** the enclave signing key (```enclave_private.pem```) is generated locally by the Makefile and is git-ignored; in a real deployment this key should be managed by an HSM Or a dedicated signing service, never kept on the build host.
- **Threat model:** the simulated attacker is a compromised *host process* injecting or corrupting traffic at the network layer. Side-channel attacks against the enclave itself (e.g. speculative execution attacks like Foreshadow) are out of scope.

Documenting these gaps explicitly — rather than only the parts that work — is intentional: it mirrors how the design would be scrutinized in a real security review, and is discussed further in the thesis.

## Author

- Filippo Zullo - [filippo-zullo98](https://github.com/filippo-zullo98/)
