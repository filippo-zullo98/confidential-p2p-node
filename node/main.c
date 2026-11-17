#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
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
    printf("[Host] SGX Enclave initialized successfully. EID: %llu\n", (unsigned long long)global_eid);
    return 0;
}

void print_banner() {
    puts("====================================================");
    puts("  ZERO-TRUST P2P NODE (SGX CONFIDENTIAL COMPUTING)  ");
    puts("====================================================");
    puts("Commands:");
    puts("  send <IP> <PORT> <MESSAGE>   (e.g., send 127.0.0.1 8081 Hello!)");
    puts("  quit                         (Shutdown node safely)");
    puts("====================================================");
}

int compare_doubles(const void *a, const void *b){
	double diff = *(double *)a - *(double *)b;
	if (diff < 0) 
		return -1;
	if (diff > 0)
		return 1;
	return 0;
}

void run_crypto_benchmark(sgx_enclave_id_t eid) { 
	int nit = 1000;
	double *latencies = (double *)malloc(nit * sizeof(double));
	if (latencies == NULL) {
		perror("Perror");
		return;
	}

	struct timespec start, end;
	uint8_t test_payload[16] = "test_payload_16B";
	char ciphertext_buffer[64] = {0};
	size_t actual_crypto_len = 0;
	sgx_status_t status;
	
	int success_count = 0;

	printf("[Benchmark] Beginning of profilation for %d iterations of cryptographic ECALL\n", nit);
	
	for (int i = 0; i < nit; i++) {
		// Clean the buffer for all iteration
		memset(ciphertext_buffer, 0, sizeof(ciphertext_buffer));
		actual_crypto_len = 0;

		// 1. Capture start time (with nanosecond precision)
		clock_gettime(CLOCK_MONOTONIC, &start);

		// 2. Run ONLY cryptographyc operation inside the ENCLAVE
		sgx_status_t ecall_ret = SGX_SUCCESS;
		status = ecall_encrypt_payload(eid, &ecall_ret, (const char*)test_payload, ciphertext_buffer, sizeof(ciphertext_buffer), &actual_crypto_len);		
		
		// 3. Capture the final timestamp
		clock_gettime(CLOCK_MONOTONIC, &end);

		if (status != SGX_SUCCESS) {
			printf("[Benchmark Debug] ECALL failed with SGX Status: 0x%X\n", status);
			continue; // stop the iteration in case of anomalous error
		}
		
		// Compute the delta in microseconds
		double elapsed_us = (end.tv_sec - start.tv_sec) * 1e6 + (end.tv_nsec - start.tv_nsec) / 1e3;
		latencies[success_count++] = elapsed_us;
	}

	if (success_count == 0) {
		puts("[Benchmark Error] no one operation has been successfully completed");
		free(latencies);
		return;
	}
	
	// 4. Sorting the times for compute the median and the dispersion  
	qsort(latencies, success_count, sizeof(double), compare_doubles);

	double min_val = latencies[0];
	double max_val = latencies[success_count - 1];
	double median_val;

	if (success_count % 2 == 0) {
		median_val = (latencies[success_count / 2 - 1] + latencies[success_count / 2]) / 2.0;
	}
	else {
		median_val = latencies[success_count / 2];
	}
	
	puts("====================================================");
        printf(" BENCHMARK RESULTS OF CRYPTOGRAPHIC INTEL SGX (%d iter)\n", success_count);
    	puts("====================================================");
    	printf(" - Median (Latency) : %.2f µs\n", median_val);
    	printf(" - Min (Best case)  : %.2f µs\n", min_val);
    	printf(" - Max (Worst)      : %.2f µs\n", max_val);
    	puts("====================================================");

	free(latencies);
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
        puts("====================================================");
        puts("[!] SECURITY WARNING: Node configured as MALICIOUS INSIDER!");
        puts("====================================================");
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
        puts("[Host Error] Failed to spawn background networking module.");
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
            puts("[Host] Initiating node shutdown sequence...");
            break;
        }

        if (sscanf(input_line, "%15s %63s %d %1023[^\n]", cmd, target_ip, &target_port, message) == 4) {
            if (strcmp(cmd, "send") == 0) {
                // Check if the attack toggle is active for this node instance
                if (is_malicious) {
                    transmit_tampered_message(target_ip, target_port, message);
                } else {
                    transmit_secure_message(target_ip, target_port, message);
                }
            } 
	    else if (strcmp(cmd, "tamper") == 0) {
	    	printf("[Attacker] Starting payload injection with spoofed MAC...\n");
	    	transmit_tampered_message(target_ip, target_port, message);
	    }
	    else {
                printf("[Host] Unknown command. Use 'send' or 'tamper'.\n");
            }
        } 
	else if (strcmp(input_line, "benchmark") == 0) {
		// Run the benchmark procedure for 1000 times
		run_crypto_benchmark(global_eid); 
	}
	else {
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
