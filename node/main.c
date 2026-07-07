#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Intel SGX Untrusted Headers
#include "sgx_urts.h"
#include "enclave_u.h"
#include "sgx_tcrypto.h" // Needed to recognize sgx_ec256_public_t on the host side

#define ENCLAVE_FILENAME "enclave.signed.so"
#define MAX_BUFFER_SIZE 2048

// Global Enclave ID holder
sgx_enclave_id_t global_eid = 0;

/*
 * OCALL Implementation: Allows the trusted enclave 
 * to safely emit logs to the untrusted host's stdout.
 */
void ocall_print_string(const char *str) {
    if (str != NULL) {
        printf("%s", str);
        fflush(stdout);
    }
}

/*
 * Enclave Bootstrapper
 */
int init_enclave(void) {
    sgx_status_t ret = SGX_SUCCESS;
    sgx_launch_token_t token = {0};
    int updated = 0;

    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("[Host Error] Failed to initialize SGX Enclave. Status Code: 0x%X\n", ret);
        return -1;
    }
    printf("[Host] SGX Enclave initialized successfully. EID: %llu\n", global_eid);
    return 0;
}

/*
 * PARADIGM LAYER 1: BACKGROUND LISTENER (Server Thread)
 * This thread runs continuously in the background, accepting incoming P2P connections,
 * executing the live ECDH public key handshake, and then decrypting the subsequent payload.
 */
void* server_worker_thread(void* arg) {
    int port = *(int*)arg;
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

    // Asynchronous acceptance loop
    while (1) {
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
            perror("[Server Thread] Accept failed");
            continue;
        }

        printf("\n\n--- [INCOMING P2P HANDSHAKE DETECTED] ---\n");

        // 1. Receive client's ECC public key from the network stream
        sgx_ec256_public_t client_pub_key;
        ssize_t bytes_read = read(new_socket, &client_pub_key, sizeof(sgx_ec256_public_t));
        if (bytes_read != sizeof(sgx_ec256_public_t)) {
            printf("[Server Error] Failed to read complete client public key block.\n");
            close(new_socket);
            continue;
        }
        printf("[Host] Ingested Client ECDH Public Key (%ld bytes).\n", bytes_read);

        // 2. Invoke Enclave to generate server's ephemeral keypair and export public key
        sgx_ec256_public_t server_pub_key;
        ecall_ecdh_generate_keypair(global_eid, &server_pub_key);

        // 3. Write server's public key back to the client
        ssize_t bytes_sent = write(new_socket, &server_pub_key, sizeof(sgx_ec256_public_t));
        if (bytes_sent != sizeof(sgx_ec256_public_t)) {
            printf("[Server Error] Failed to transmit server public key reply.\n");
            close(new_socket);
            continue;
        }
        printf("[Host] Transmitted Server ECDH Public Key back to Client.\n");

        // 4. Securely compute the shared cryptographic secret inside the TEE
        ecall_ecdh_derive_shared_secret(global_eid, &client_pub_key);

        // 5. Ingest the encrypted telemetry payload
        memset(buffer, 0, MAX_BUFFER_SIZE);
        ssize_t valread = read(new_socket, buffer, MAX_BUFFER_SIZE);
        
        if (valread > 0) {
            printf("[Host] Ingested %ld bytes of AES-GCM ciphertext. Invoking verification...\n", valread);
            // Pass the raw ciphertext bytes into the TEE for decryption using the fresh session key
            ecall_decrypt_payload(global_eid, buffer, (size_t)valread);
        }
        
        close(new_socket);
        printf("p2p-node> "); // Restore prompt aesthetics
        fflush(stdout);
    }
    return NULL;
}

/*
 * PARADIGM LAYER 2: INTERACTIVE CLIENT (Main Thread)
 * Handles user input via CLI to dynamically connect, perform ECDH handshake, and send encrypted telemetry.
 */
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

    // 1. Generate client's ECC keypair inside Enclave and export public key
    sgx_ec256_public_t client_pub_key;
    ecall_ecdh_generate_keypair(global_eid, &client_pub_key);

    // 2. Push client's public key to the target node
    ssize_t bytes_sent = write(client_fd, &client_pub_key, sizeof(sgx_ec256_public_t));
    if (bytes_sent != sizeof(sgx_ec256_public_t)) {
        printf("[Client Error] Failed to transmit public key handshake packet.\n");
        close(client_fd);
        return;
    }

    // 3. Read the server's responding public key
    sgx_ec256_public_t server_pub_key;
    ssize_t bytes_read = read(client_fd, &server_pub_key, sizeof(sgx_ec256_public_t));
    if (bytes_read != sizeof(sgx_ec256_public_t)) {
        printf("[Client Error] Failed to receive remote public key response.\n");
        close(client_fd);
        return;
    }
    printf("[Host] Ingested Server ECDH Public Key response.\n");

    // 4. Securely compute the shared cryptographic secret inside our TEE
    ecall_ecdh_derive_shared_secret(global_eid, &server_pub_key);

    // 5. Encrypt the payload using the dynamically locked session key
    char ciphertext_buffer[MAX_BUFFER_SIZE] = {0};
    size_t actual_crypto_len = 0;
    ecall_encrypt_payload(global_eid, plaintext_message, ciphertext_buffer, sizeof(ciphertext_buffer), &actual_crypto_len);

    // 6. Push the encrypted container across the untrusted network
    if (actual_crypto_len > 0) {
        send(client_fd, ciphertext_buffer, actual_crypto_len, 0);
        printf("[Host] Secure AES-GCM stream (%ld bytes) successfully pushed to network.\n", actual_crypto_len);
    }

    close(client_fd);
}

void print_banner() {
    printf("====================================================\n");
    printf("  ZERO-TRUST P2P NODE (SGX CONFIDENTIAL COMPUTING)  \n");
    printf("====================================================\n");
    printf("Commands:\n");
    printf("  send <IP> <PORT> <MESSAGE>   (e.g., send 127.0.0.1 8081 Hello Node!)\n");
    printf("  quit                         (Shutdown node safely)\n");
    printf("====================================================\n");
}

int main(int argc, char* argv[]) {
    if (argc != 3 || strcmp(argv[1], "--port") != 0) {
        printf("Usage: %s --port <listening_port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    int local_port = atoi(argv[2]);

    // 1. Spin up the confidential environment
    if (init_enclave() < 0) {
        return EXIT_FAILURE;
    }

    // 2. Launch the asynchronous background listener
    pthread_t server_thread;
    if (pthread_create(&server_thread, NULL, server_worker_thread, &local_port) != 0) {
        perror("[Host Error] Failed to spawn background server thread");
        sgx_destroy_enclave(global_eid);
        return EXIT_FAILURE;
    }

    // Give the server thread a tiny fraction of a second to bind the port before printing the prompt
    usleep(100000); 
    print_banner();

    // 3. Interactive Command Loop
    char input_line[MAX_BUFFER_SIZE];
    char cmd[16], target_ip[64], message[1024];
    int target_port;

    while (1) {
        printf("p2p-node> ");
        if (!fgets(input_line, sizeof(input_line), stdin)) break;

        // Strip newline character
        input_line[strcspn(input_line, "\n")] = 0;

        if (strlen(input_line) == 0) continue;

        if (strcmp(input_line, "quit") == 0 || strcmp(input_line, "exit") == 0) {
            printf("[Host] Initiating node shutdown sequence...\n");
            break;
        }

        // Parse "send <ip> <port> <message>"
        if (sscanf(input_line, "%15s %63s %d %[^\n]", cmd, target_ip, &target_port, message) == 4) {
            if (strcmp(cmd, "send") == 0) {
                transmit_secure_message(target_ip, target_port, message);
            } else {
                printf("[Host] Unknown command. Use 'send <IP> <PORT> <MESSAGE>'.\n");
            }
        } else {
            printf("[Host] Invalid syntax. Example: send 127.0.0.1 8081 Secure Data Here\n");
        }
    }

    // 4. Safely scrub enclave context out of volatile memory
    if (global_eid != 0) {
        sgx_destroy_enclave(global_eid);
        printf("[Host] Enclave context scrubbed and destroyed cleanly.\n");
    }

    return EXIT_SUCCESS;
}
