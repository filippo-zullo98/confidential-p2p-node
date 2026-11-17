#include "p2p_network.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
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
 * Global mutex serializing enclave session state across listener and CLI threads
 */
static pthread_mutex_t g_enclave_session_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * Static context wrapper to pass arguments cleanly into the pthread worker
 */
typedef struct {
    int port;
} server_config_t;

/*
 * Exact-byte TCP read loop to prevent partial-read vulnerabilities
 */
static int read_full(int fd, void* buf, size_t len) {
    size_t total = 0;
    uint8_t* ptr = (uint8_t*)buf;
    while (total < len) {
        ssize_t n = read(fd, ptr + total, len - total);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return -1;
        }
        total += (size_t)n;
    }
    return 0;
}

/*
 * Exact-byte TCP write loop to guarantee complete frame transmission
 */
static int write_full(int fd, const void* buf, size_t len) {
    size_t total = 0;
    const uint8_t* ptr = (const uint8_t*)buf;
    while (total < len) {
        ssize_t n = write(fd, ptr + total, len - total);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return -1;
        }
        total += (size_t)n;
    }
    return 0;
}

/*
 * Executes the mutual SGX Local Attestation handshake from the client side.
 * Must be called while holding g_enclave_session_mutex.
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

    if (write_full(sock_fd, &client_ti, sizeof(sgx_target_info_t)) != 0) {
        printf("[Client Error] Failed to transmit client target_info.\n");
        return -1;
    }

    sgx_target_info_t server_ti = {0};
    if (read_full(sock_fd, &server_ti, sizeof(sgx_target_info_t)) != 0) {
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

    if (write_full(sock_fd, &client_report, sizeof(sgx_report_t)) != 0) {
        printf("[Client Error] Failed to transmit client SGX Report.\n");
        return -1;
    }
    printf("[Host] Transmitted peer-targeted SGX Report (%zu bytes) to server.\n", sizeof(sgx_report_t));

    // 3. Receive server's SGX Report and verify + derive session key inside the enclave
    sgx_report_t server_report = {0};
    if (read_full(sock_fd, &server_report, sizeof(sgx_report_t)) != 0) {
        printf("[Client Error] Failed to receive server SGX Report.\n");
        return -1;
    }
    printf("[Host] Ingested Server SGX Report (%zu bytes). Invoking enclave verification & KDF...\n", sizeof(sgx_report_t));

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
    socklen_t addrlen = sizeof(address);
    char buffer[MAX_BUFFER_SIZE];

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("[Server Thread] Socket creation failed");
        pthread_exit(NULL);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt_sock, sizeof(opt_sock)) < 0) {
        perror("[Server Thread] Setsockopt failed");
        close(server_fd);
        pthread_exit(NULL);
    }

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons((uint16_t)port);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("[Server Thread] Bind failed");
        close(server_fd);
        pthread_exit(NULL);
    }

    if (listen(server_fd, 10) < 0) {
        perror("[Server Thread] Listen failed");
        close(server_fd);
        pthread_exit(NULL);
    }

    printf("[Server Thread] Daemon active. Listening for attested P2P traffic on port %d...\n\n", port);

    while (1) {
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address, &addrlen)) < 0) {
            perror("[Server Thread] Accept failed");
            continue;
        }

        pthread_mutex_lock(&g_enclave_session_mutex);
        printf("\n\n--- [INCOMING ATTESTED P2P HANDSHAKE DETECTED] ---\n");

        sgx_status_t status = SGX_SUCCESS;
        sgx_status_t ecall_ret = SGX_SUCCESS;

        // 1. Exchange sgx_target_info_t with connecting client
        sgx_target_info_t client_ti = {0};
        if (read_full(new_socket, &client_ti, sizeof(sgx_target_info_t)) != 0) {
            printf("[Server Error] Failed to read complete client target_info (%zu bytes).\n", sizeof(sgx_target_info_t));
            pthread_mutex_unlock(&g_enclave_session_mutex);
            close(new_socket);
            continue;
        }

        sgx_target_info_t server_ti = {0};
        status = ecall_get_target_info(global_eid, &ecall_ret, &server_ti);
        if (status != SGX_SUCCESS || ecall_ret != SGX_SUCCESS) {
            printf("[Server Error] Failed to obtain local target_info (0x%X / 0x%X).\n", status, ecall_ret);
            pthread_mutex_unlock(&g_enclave_session_mutex);
            close(new_socket);
            continue;
        }

        if (write_full(new_socket, &server_ti, sizeof(sgx_target_info_t)) != 0) {
            printf("[Server Error] Failed to transmit server target_info.\n");
            pthread_mutex_unlock(&g_enclave_session_mutex);
            close(new_socket);
            continue;
        }

        // 2. Receive client's peer-targeted SGX Report
        sgx_report_t client_report = {0};
        if (read_full(new_socket, &client_report, sizeof(sgx_report_t)) != 0) {
            printf("[Server Error] Failed to read complete client SGX Report (%zu bytes).\n", sizeof(sgx_report_t));
            pthread_mutex_unlock(&g_enclave_session_mutex);
            close(new_socket);
            continue;
        }
        printf("[Host] Ingested Client SGX Report (%zu bytes).\n", sizeof(sgx_report_t));

        // 3. Generate server's ephemeral keypair & Report targeted at client_ti
        sgx_report_t server_report = {0};
        status = ecall_generate_attested_key(global_eid, &ecall_ret, &client_ti, &server_report);
        if (status != SGX_SUCCESS || ecall_ret != SGX_SUCCESS) {
            printf("[Server Error] Failed to generate attested server report (0x%X / 0x%X).\n", status, ecall_ret);
            pthread_mutex_unlock(&g_enclave_session_mutex);
            close(new_socket);
            continue;
        }

        if (write_full(new_socket, &server_report, sizeof(sgx_report_t)) != 0) {
            printf("[Server Error] Failed to transmit server SGX Report reply.\n");
            pthread_mutex_unlock(&g_enclave_session_mutex);
            close(new_socket);
            continue;
        }
        printf("[Host] Transmitted Server SGX Report (%zu bytes) back to Client.\n", sizeof(sgx_report_t));

        // 4. Verify client's Report MAC + measurements and derive session key inside enclave
        status = ecall_verify_and_derive(global_eid, &ecall_ret, &client_report);
        if (status != SGX_SUCCESS || ecall_ret != SGX_SUCCESS) {
            printf("[Server Security Alert] Client attestation rejected (0x%X / 0x%X)! Closing socket.\n", status, ecall_ret);
            pthread_mutex_unlock(&g_enclave_session_mutex);
            close(new_socket);
            printf("p2p-node> ");
            fflush(stdout);
            continue;
        }

        // 5. Read 4-byte network-order frame length followed by exact AES-GCM ciphertext
        uint32_t net_payload_len = 0;
        if (read_full(new_socket, &net_payload_len, sizeof(uint32_t)) != 0) {
            printf("[Server Error] Connection closed before receiving payload frame header.\n");
            pthread_mutex_unlock(&g_enclave_session_mutex);
            close(new_socket);
            printf("p2p-node> ");
            fflush(stdout);
            continue;
        }

        uint32_t payload_len = ntohl(net_payload_len);
        if (payload_len == 0 || payload_len > MAX_BUFFER_SIZE) {
            printf("[Server Security Alert] Invalid payload frame length (%u bytes). Dropping.\n", payload_len);
            pthread_mutex_unlock(&g_enclave_session_mutex);
            close(new_socket);
            printf("p2p-node> ");
            fflush(stdout);
            continue;
        }

        memset(buffer, 0, MAX_BUFFER_SIZE);
        if (read_full(new_socket, buffer, (size_t)payload_len) == 0) {
            printf("[Host] Ingested %u bytes of AES-GCM ciphertext. Invoking decryption...\n", payload_len);
            status = ecall_decrypt_payload(global_eid, &ecall_ret, buffer, (size_t)payload_len);
            if (status != SGX_SUCCESS || ecall_ret != SGX_SUCCESS) {
                printf("[Server Security Alert] Payload decryption/authentication failed (0x%X / 0x%X).\n", status, ecall_ret);
            }
        } else {
            printf("[Server Error] Incomplete AES-GCM ciphertext frame received.\n");
        }

        pthread_mutex_unlock(&g_enclave_session_mutex);
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

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)target_port);

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

    pthread_mutex_lock(&g_enclave_session_mutex);
    printf("\n[Client] Initiating Attested ECDH Handshake with %s:%d...\n", target_ip, target_port);

    if (perform_client_attested_handshake(client_fd) != 0) {
        pthread_mutex_unlock(&g_enclave_session_mutex);
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

    pthread_mutex_unlock(&g_enclave_session_mutex);

    if (status != SGX_SUCCESS || ecall_ret != SGX_SUCCESS || actual_crypto_len == 0 || actual_crypto_len > MAX_BUFFER_SIZE) {
        printf("[Client Error] Payload encryption failed (0x%X / 0x%X).\n", status, ecall_ret);
        close(client_fd);
        return;
    }

    // Transmit 4-byte network-order frame length followed by exact ciphertext bytes
    uint32_t net_len = htonl((uint32_t)actual_crypto_len);
    if (write_full(client_fd, &net_len, sizeof(uint32_t)) != 0 ||
        write_full(client_fd, ciphertext_buffer, actual_crypto_len) != 0) {
        printf("[Client Error] Incomplete ciphertext frame transmission.\n");
        close(client_fd);
        return;
    }

    printf("[Host] Secure AES-GCM frame (%zu bytes) successfully pushed to network.\n", actual_crypto_len);
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

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)target_port);

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

    pthread_mutex_lock(&g_enclave_session_mutex);
    printf("\n[MALICIOUS INTERCEPT] Insider threat active! Completing an ATTESTED ECDH handshake...\n");

    if (perform_client_attested_handshake(client_fd) != 0) {
        pthread_mutex_unlock(&g_enclave_session_mutex);
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

    pthread_mutex_unlock(&g_enclave_session_mutex);

    size_t tamper_offset = SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE;
    if (status != SGX_SUCCESS || ecall_ret != SGX_SUCCESS || actual_crypto_len <= tamper_offset) {
        printf("[Malicious Client Error] Encryption failed, nothing to tamper with.\n");
        close(client_fd);
        return;
    }

    // Flip 1 bit inside the encrypted body (past IV and GCM tag)
    ciphertext_buffer[tamper_offset] ^= 0x01;
    printf("[MALICIOUS INTERCEPT] Flipping 1 bit inside the AES-GCM ciphertext (offset %zu) before transmission...\n", tamper_offset);

    uint32_t net_len = htonl((uint32_t)actual_crypto_len);
    if (write_full(client_fd, &net_len, sizeof(uint32_t)) != 0 ||
        write_full(client_fd, ciphertext_buffer, actual_crypto_len) != 0) {
        printf("[Malicious Client Error] Failed to transmit tampered frame.\n");
        close(client_fd);
        return;
    }

    printf("[MALICIOUS INTERCEPT] Tampered AES-GCM frame (%zu bytes) injected into the network.\n", actual_crypto_len);
    close(client_fd);
}
