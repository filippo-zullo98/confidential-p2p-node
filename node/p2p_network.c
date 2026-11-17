#include "p2p_network.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Enclave untrusted proxies
#include "enclave_u.h"
#include "sgx_tcrypto.h"
#include "sgx_report.h"

/*
 * Static context wrapper to pass arguments cleanly into the pthread worker
 */
typedef struct {
    int port;
} server_config_t;

/*
 * Helper to execute the mutual Local Attestation handshake from the client side.
 * Returns 0 on success, -1 on failure.
 */
static int perform_client_attested_handshake(int sock_fd) {
    sgx_status_t status = SGX_SUCCESS;
    sgx_status_t ecall_ret = SGX_SUCCESS;

    // 1. Export local target_info and exchange it with the server
    sgx_target_info_t client_ti = {0};
    status = ecall_get_target_info(global_eid, &ecall_ret, &client_ti);
    if (status != SGX_SUCCESS || ecall_ret != SGX_SUCCESS) {
        printf("[Client Error] Failed to obtain local target_info (0x%X / 0x%X).\n", status, ecall_ret);
        return -1;
    }

    ssize_t bytes_sent = write(sock_fd, &client_ti, sizeof(sgx_target_info_t));
    if (bytes_sent != sizeof(sgx_target_info_t)) {
        printf("[Client Error] Failed to transmit client target_info.\n");
        return -1;
    }

    sgx_target_info_t server_ti = {0};
    ssize_t bytes_read = read(sock_fd, &server_ti, sizeof(sgx_target_info_t));
    if (bytes_read != sizeof(sgx_target_info_t)) {
        printf("[Client Error] Failed to receive server target_info.\n");
        return -1;
    }

    // 2. Generate ephemeral ECDH keypair bound to an SGX Report targeted at server_ti
    sgx_report_t client_report = {0};
    status = ecall_generate_attested_key(global_eid, &ecall_ret, &server_ti, &client_report);
    if (status != SGX_SUCCESS || ecall_ret != SGX_SUCCESS) {
        printf("[Client Error] Failed to generate peer-targeted SGX Report (0x%X / 0x%X).\n", status, ecall_ret);
        return -1;
    }

    bytes_sent = write(sock_fd, &client_report, sizeof(sgx_report_t));
    if (bytes_sent != sizeof(sgx_report_t)) {
        printf("[Client Error] Failed to transmit client SGX Report.\n");
        return -1;
    }
    printf("[Host] Transmitted peer-targeted SGX Report (%ld bytes) to server.\n", bytes_sent);

    // 3. Receive server's SGX Report and verify + derive session key inside the enclave
    sgx_report_t server_report = {0};
    bytes_read = read(sock_fd, &server_report, sizeof(sgx_report_t));
    if (bytes_read != sizeof(sgx_report_t)) {
        printf("[Client Error] Failed to receive server SGX Report.\n");
        return -1;
    }
    printf("[Host] Ingested Server SGX Report (%ld bytes). Invoking enclave verification & KDF...\n", bytes_read);

    status = ecall_verify_and_derive(global_eid, &ecall_ret, &server_report);
    if (status != SGX_SUCCESS || ecall_ret != SGX_SUCCESS) {
        printf("[Client Security Alert] Server attestation or ECDH derivation failed (0x%X / 0x%X)! Aborting.\n", status, ecall_ret);
        return -1;
    }

    return 0;
}

/*
 * Private thread worker for background listening
 */
static void* server_worker_thread(void* arg) {
    server_config_t* config = (server_config_t*)arg;
    int port = config->port;
    free(config);

    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt_sock = 1;
    int addrlen = sizeof(address);
    char buffer[MAX_BUFFER_SIZE];

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("[Server Thread] Socket creation failed");
        pthread_exit(NULL);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt_sock, sizeof(opt_sock))) {
        perror("[Server Thread] Setsockopt failed");
        pthread_exit(NULL);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("[Server Thread] Bind failed");
        pthread_exit(NULL);
    }

    if (listen(server_fd, 10) < 0) {
        perror("[Server Thread] Listen failed");
        pthread_exit(NULL);
    }

    printf("[Server Thread] Daemon active. Listening for attested P2P traffic on port %d...\n\n", port);

    while (1) {
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
            perror("[Server Thread] Accept failed");
            continue;
        }

        printf("\n\n--- [INCOMING ATTESTED P2P HANDSHAKE DETECTED] ---\n");

        sgx_status_t status = SGX_SUCCESS;
        sgx_status_t ecall_ret = SGX_SUCCESS;

        // 1. Exchange sgx_target_info_t with connecting client
        sgx_target_info_t client_ti = {0};
        ssize_t bytes_read = read(new_socket, &client_ti, sizeof(sgx_target_info_t));
        if (bytes_read != sizeof(sgx_target_info_t)) {
            printf("[Server Error] Failed to read client target_info (%ld/%zu bytes).\n", bytes_read, sizeof(sgx_target_info_t));
            close(new_socket);
            continue;
        }

        sgx_target_info_t server_ti = {0};
        status = ecall_get_target_info(global_eid, &ecall_ret, &server_ti);
        if (status != SGX_SUCCESS || ecall_ret != SGX_SUCCESS) {
            printf("[Server Error] Failed to obtain local target_info (0x%X / 0x%X).\n", status, ecall_ret);
            close(new_socket);
            continue;
        }

        ssize_t bytes_sent = write(new_socket, &server_ti, sizeof(sgx_target_info_t));
        if (bytes_sent != sizeof(sgx_target_info_t)) {
            printf("[Server Error] Failed to transmit server target_info.\n");
            close(new_socket);
            continue;
        }

        // 2. Receive client's peer-targeted SGX Report
        sgx_report_t client_report = {0};
        bytes_read = read(new_socket, &client_report, sizeof(sgx_report_t));
        if (bytes_read != sizeof(sgx_report_t)) {
            printf("[Server Error] Failed to read complete client SGX Report (%ld/%zu bytes).\n", bytes_read, sizeof(sgx_report_t));
            close(new_socket);
            continue;
        }
        printf("[Host] Ingested Client SGX Report (%ld bytes).\n", bytes_read);

        // 3. Generate server's ephemeral keypair & Report targeted at client_ti
        sgx_report_t server_report = {0};
        status = ecall_generate_attested_key(global_eid, &ecall_ret, &client_ti, &server_report);
        if (status != SGX_SUCCESS || ecall_ret != SGX_SUCCESS) {
            printf("[Server Error] Failed to generate attested server report (0x%X / 0x%X).\n", status, ecall_ret);
            close(new_socket);
            continue;
        }

        bytes_sent = write(new_socket, &server_report, sizeof(sgx_report_t));
        if (bytes_sent != sizeof(sgx_report_t)) {
            printf("[Server Error] Failed to transmit server SGX Report reply.\n");
            close(new_socket);
            continue;
        }
        printf("[Host] Transmitted Server SGX Report (%ld bytes) back to Client.\n", bytes_sent);

        // 4. Verify client's Report MAC + measurements and derive session key inside enclave
        status = ecall_verify_and_derive(global_eid, &ecall_ret, &client_report);
        if (status != SGX_SUCCESS || ecall_ret != SGX_SUCCESS) {
            printf("[Server Security Alert] Client attestation rejected (0x%X / 0x%X)! Closing socket.\n", status, ecall_ret);
            close(new_socket);
            printf("p2p-node> ");
            fflush(stdout);
            continue;
        }

        // 5. Read and decrypt AES-GCM ciphertext
        memset(buffer, 0, MAX_BUFFER_SIZE);
        ssize_t valread = read(new_socket, buffer, MAX_BUFFER_SIZE);
        if (valread > 0) {
            printf("[Host] Ingested %ld bytes of AES-GCM ciphertext. Invoking decryption...\n", valread);
            status = ecall_decrypt_payload(global_eid, &ecall_ret, buffer, (size_t)valread);
            if (status != SGX_SUCCESS || ecall_ret != SGX_SUCCESS) {
                printf("[Server Security Alert] Payload decryption/authentication failed (0x%X / 0x%X).\n", status, ecall_ret);
            }
        }

        close(new_socket);
        printf("p2p-node> ");
        fflush(stdout);
    }
    return NULL;
}

int start_p2p_listener(int port, pthread_t* thread_id) {
    server_config_t* config = (server_config_t*)malloc(sizeof(server_config_t));
    if (config == NULL) return -1;
    config->port = port;

    if (pthread_create(thread_id, NULL, server_worker_thread, config) != 0) {
        free(config);
        return -1;
    }
    return 0;
}

void transmit_secure_message(const char* target_ip, int target_port, const char* plaintext_message) {
    int client_fd;
    struct sockaddr_in address;

    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("[Client Error] Socket creation error");
        return;
    }

    address.sin_family = AF_INET;
    address.sin_port = htons(target_port);

    if (inet_pton(AF_INET, target_ip, &address.sin_addr) <= 0) {
        printf("[Client Error] Invalid IP address configuration.\n");
        close(client_fd);
        return;
    }

    if (connect(client_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("[Client Error] Connection to target node failed");
        close(client_fd);
        return;
    }

    printf("\n[Client] Initiating Attested ECDH Handshake with %s:%d...\n", target_ip, target_port);

    if (perform_client_attested_handshake(client_fd) != 0) {
        close(client_fd);
        return;
    }

    char ciphertext_buffer[MAX_BUFFER_SIZE] = {0};
    size_t actual_crypto_len = 0;
    sgx_status_t ecall_ret = SGX_SUCCESS;
    sgx_status_t status = ecall_encrypt_payload(
        global_eid, &ecall_ret,
        plaintext_message,
        ciphertext_buffer, sizeof(ciphertext_buffer),
        &actual_crypto_len
    );

    if (status != SGX_SUCCESS || ecall_ret != SGX_SUCCESS || actual_crypto_len == 0) {
        printf("[Client Error] Payload encryption failed (0x%X / 0x%X).\n", status, ecall_ret);
        close(client_fd);
        return;
    }

    ssize_t sent = send(client_fd, ciphertext_buffer, actual_crypto_len, 0);
    if (sent == (ssize_t)actual_crypto_len) {
        printf("[Host] Secure AES-GCM stream (%ld bytes) successfully pushed to network.\n", sent);
    } else {
        printf("[Client Error] Incomplete ciphertext transmission.\n");
    }

    close(client_fd);
}

/*
 * Insider Threat simulation: completes a valid attested handshake using its
 * legitimate enclave identity, then flips 1 bit inside the AES-GCM ciphertext
 * body in flight to exercise the receiver's AES-GCM tag verification.
 */
void transmit_tampered_message(const char* target_ip, int target_port, const char* plaintext_message) {
    int client_fd;
    struct sockaddr_in address;

    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("[Malicious Client Error] Socket creation error");
        return;
    }

    address.sin_family = AF_INET;
    address.sin_port = htons(target_port);

    if (inet_pton(AF_INET, target_ip, &address.sin_addr) <= 0) {
        printf("[Malicious Client Error] Invalid IP address configuration.\n");
        close(client_fd);
        return;
    }

    if (connect(client_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("[Malicious Client Error] Connection to target node failed");
        close(client_fd);
        return;
    }

    printf("\n[MALICIOUS INTERCEPT] Insider threat active! Completing an ATTESTED ECDH handshake...\n");

    if (perform_client_attested_handshake(client_fd) != 0) {
        close(client_fd);
        return;
    }

    char ciphertext_buffer[MAX_BUFFER_SIZE] = {0};
    size_t actual_crypto_len = 0;
    sgx_status_t ecall_ret = SGX_SUCCESS;
    sgx_status_t status = ecall_encrypt_payload(
        global_eid, &ecall_ret,
        plaintext_message,
        ciphertext_buffer, sizeof(ciphertext_buffer),
        &actual_crypto_len
    );

    size_t tamper_offset = SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE;
    if (status != SGX_SUCCESS || ecall_ret != SGX_SUCCESS || actual_crypto_len <= tamper_offset) {
        printf("[Malicious Client Error] Encryption failed, nothing to tamper with.\n");
        close(client_fd);
        return;
    }

    // Flip 1 bit inside the encrypted body (past IV and GCM tag)
    ciphertext_buffer[tamper_offset] ^= 0x01;
    printf("[MALICIOUS INTERCEPT] Flipping 1 bit inside the AES-GCM ciphertext (offset %zu) before transmission...\n", tamper_offset);

    send(client_fd, ciphertext_buffer, actual_crypto_len, 0);
    printf("[MALICIOUS INTERCEPT] Tampered AES-GCM stream (%ld bytes) injected into the network.\n", actual_crypto_len);

    close(client_fd);
}
