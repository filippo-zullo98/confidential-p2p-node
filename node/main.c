#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "sgx_urts.h"
#include "enclave_u.h"
#include "p2p_network.h"

#define ENCLAVE_FILENAME "enclave.signed.so"

// Define the global Enclave ID declared in the header
sgx_enclave_id_t global_eid = 0;

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
                transmit_secure_message(target_ip, target_port, message);
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
