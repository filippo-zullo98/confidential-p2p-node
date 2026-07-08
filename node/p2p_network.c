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

/*
 * Static context wrapper to pass arguments cleanly into the pthread worker
 */
typedef struct {
    int port;
} server_config_t;

/*
 * Private thread worker for background listening
 */
static void* server_worker_thread(void* arg) {
    server_config_t* config = (server_config_t*)arg;
    int port = config->port;
    free(config); // Free the allocated config wrapper inside the thread

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

    printf("[Server Thread] Daemon active. Listening for secure P2P traffic on port %d...\n\n", port);

    while (1) {
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
            perror("[Server Thread] Accept failed");
            continue;
        }

        printf("\n\n--- [INCOMING P2P HANDSHAKE DETECTED] ---\n");

        sgx_ec256_public_t client_pub_key;
        ssize_t bytes_read = read(new_socket, &client_pub_key, sizeof(sgx_ec256_public_t));
        if (bytes_read != sizeof(sgx_ec256_public_t)) {
            printf("[Server Error] Failed to read complete client public key block.\n");
            close(new_socket);
            continue;
        }
        printf("[Host] Ingested Client ECDH Public Key (%ld bytes).\n", bytes_read);

        sgx_ec256_public_t server_pub_key;
        ecall_ecdh_generate_keypair(global_eid, &server_pub_key);

        ssize_t bytes_sent = write(new_socket, &server_pub_key, sizeof(sgx_ec256_public_t));
        if (bytes_sent != sizeof(sgx_ec256_public_t)) {
            printf("[Server Error] Failed to transmit server public key reply.\n");
            close(new_socket);
            continue;
        }
        printf("[Host] Transmitted Server ECDH Public Key back to Client.\n");

        ecall_ecdh_derive_shared_secret(global_eid, &client_pub_key);

        memset(buffer, 0, MAX_BUFFER_SIZE);
        ssize_t valread = read(new_socket, buffer, MAX_BUFFER_SIZE);
        
        if (valread > 0) {
            printf("[Host] Ingested %ld bytes of AES-GCM ciphertext. Invoking verification...\n", valread);
            ecall_decrypt_payload(global_eid, buffer, (size_t)valread);
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

    printf("\n[Client] Initiating Perfect Forward Secrecy ECDH Handshake with %s:%d...\n", target_ip, target_port);

    sgx_ec256_public_t client_pub_key;
    ecall_ecdh_generate_keypair(global_eid, &client_pub_key);

    ssize_t bytes_sent = write(client_fd, &client_pub_key, sizeof(sgx_ec256_public_t));
    if (bytes_sent != sizeof(sgx_ec256_public_t)) {
        printf("[Client Error] Failed to transmit public key handshake packet.\n");
        close(client_fd);
        return;
    }

    sgx_ec256_public_t server_pub_key;
    ssize_t bytes_read = read(client_fd, &server_pub_key, sizeof(sgx_ec256_public_t));
    if (bytes_read != sizeof(sgx_ec256_public_t)) {
        printf("[Client Error] Failed to receive remote public key response.\n");
        close(client_fd);
        return;
    }
    printf("[Host] Ingested Server ECDH Public Key response.\n");

    ecall_ecdh_derive_shared_secret(global_eid, &server_pub_key);

    char ciphertext_buffer[MAX_BUFFER_SIZE] = {0};
    size_t actual_crypto_len = 0;
    ecall_encrypt_payload(global_eid, plaintext_message, ciphertext_buffer, sizeof(ciphertext_buffer), &actual_crypto_len);

    if (actual_crypto_len > 0) {
        send(client_fd, ciphertext_buffer, actual_crypto_len, 0);
        printf("[Host] Secure AES-GCM stream (%ld bytes) successfully pushed to network.\n", actual_crypto_len);
    }

    close(client_fd);
}
