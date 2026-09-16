# Confidential P2P Node (Intel SGX)

A decentralized Peer-to-Peer (P2P) overlay network node leveraging **Intel SGX (Software Guard Extensions)** to implement a Zero-Trust architecture. 

This project was developed as part of a Bachelor's Thesis in Computer Science to evaluate the application of Confidential Computing in distributed systems, specifically focusing on mitigating "Insider Threats" (e.g., malicious raw socket injections) within a containerized environment.

## Core Features

* **Hardware-Isolated Enclaves:** Core cryptographic operations and message validations are executed inside SGX enclaves to prevent memory inspection from the host OS.
* **Secure Communication (AES-GCM):** Payload encryption and authentication using AES-GCM, ensuring data confidentiality and integrity.
* **Key Exchange:** ECDH handshake implementation for secure ephemeral session key derivation.
* **Robust Networking:** Custom TCP framing and strict port validation to handle packet fragmentation and unauthorized traffic.
* **Threat Simulation:** Docker Compose orchestration to simulate a network of trusted nodes and a compromised host attempting to inject unauthorized raw traffic.

## Technologies & Stack

* **Language:** C / C++
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
