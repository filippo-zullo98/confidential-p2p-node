#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

// Added for the malicious raw network injection
#include <sys/socket.h>
#include <arpa/inet.h>

#include "sgx_urts.h"
#include "enclave_u.h"
#include "p2p_network.h"

#define ENCLAVE_FILENAME "enclave.signed.so"

// Define the global Enclave ID declared in the header
sgx_enclave_id_t global_eid = 0;

// Global flag to control the insider threat behavior
int is_malicious = 0;

/*
 * OCALL Implementation: Enclave standard output proxy
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
 * Malicious Insider Threat Module: Bypasses SGX encryption 
 * and injects corrupted raw data to trigger receiver verification failures.
 */
void send_malicious_garbage(const char *ip, int port) {
    printf("\n[MALICIOUS INTERCEPT] Insider threat active! Bypassing SGX enclave protection...\n");
    printf("[MALICIOUS INTERCEPT] Injecting raw corrupted payload directly to %s:%d\n", ip, port);
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("[Host Error] Failed to open malicious raw socket.\n");
        return;
    }
    
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0) {
        printf("[Host Error] Invalid target IP address layout.\n");
        close(sock);
        return;
    }
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) {
        // Sending raw text without SGX structural encapsulation or valid cryptographic MAC
        const char *garbage_payload = "MALICIOUS_RAW_TAMPERED_DATA_NO_SGX_MAC";
        send(sock, garbage_payload, strlen(garbage_payload), 0);
        printf("[MALICIOUS INTERCEPT] Corrupted packet successfully injected into the network mesh.\n");
    } else {
        printf("[Host Error] Connection to target node failed. Unable to inject exploit.\n");
    }
    close(sock);
}

void print_banner() {
    printf("====================================================\n");
    printf("  ZERO-TRUST P2P NODE (SGX CONFIDENTIAL COMPUTING)  \n");
    printf("====================================================\n");
    printf("Commands:\n");
    printf("  send <IP> <PORT> <MESSAGE>   (e.g., send 127.0.0.1 8081 Hello!)\n");
    printf("  quit                         (Shutdown node safely)\n");
    printf("====================================================\n");
}

int main(int argc, char* argv[]) {
    if (argc != 3 || strcmp(argv[1], "--port") != 0) {
        printf("Usage: %s --port <listening_port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    int local_port = atoi(argv[2]);

    // Check if Docker injected the malicious behavior rule via environment variables
    char *behavior = getenv("NODE_BEHAVIOR");
    if (behavior != NULL && strcmp(behavior, "MALICIOUS") == 0) {
        is_malicious = 1;
        printf("\n====================================================\n");
        printf("[!] SECURITY WARNING: Node configured as MALICIOUS INSIDER!\n");
        printf("====================================================\n\n");
    } else {
        printf("[+] Node initialized in HONEST mode.\n");
    }

    // 1. Initialise Enclave TEE
    if (init_enclave() < 0) {
        return EXIT_FAILURE;
    }

    // 2. Launch the asynchronous network listener module
    pthread_t server_thread;
    if (start_p2p_listener(local_port, &server_thread) != 0) {
        printf("[Host Error] Failed to spawn background networking module.\n");
        sgx_destroy_enclave(global_eid);
        return EXIT_FAILURE;
    }

    usleep(100000); 
    print_banner();

    // 3. Interactive Command Loop
    char input_line[MAX_BUFFER_SIZE];
    char cmd[16], target_ip[64], message[1024];
    int target_port;

    while (1) {
        printf("p2p-node> ");
        if (!fgets(input_line, sizeof(input_line), stdin)) break;

        input_line[strcspn(input_line, "\n")] = 0;
        if (strlen(input_line) == 0) continue;

        if (strcmp(input_line, "quit") == 0 || strcmp(input_line, "exit") == 0) {
            printf("[Host] Initiating node shutdown sequence...\n");
            break;
        }

        if (sscanf(input_line, "%15s %63s %d %[^\n]", cmd, target_ip, &target_port, message) == 4) {
            if (strcmp(cmd, "send") == 0) {
                // Check if the attack toggle is active for this node instance
                if (is_malicious) {
                    send_malicious_garbage(target_ip, target_port);
                } else {
                    transmit_secure_message(target_ip, target_port, message);
                }
            } else {
                printf("[Host] Unknown command. Use 'send <IP> <PORT> <MESSAGE>'.\n");
            }
        } else {
            printf("[Host] Invalid syntax. Example: send 127.0.0.1 8081 Hello!\n");
        }
    }

    // 4. Teardown
    if (global_eid != 0) {
        sgx_destroy_enclave(global_eid);
        printf("[Host] Enclave context scrubbed cleanly.\n");
    }

    return EXIT_SUCCESS;
}
