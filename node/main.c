#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include "sgx_urts.h"
#include "enclave_u.h"
#include "p2p_network.h"

#define ENCLAVE_FILENAME "enclave.signed.so"
#define BENCHMARK_ITERATIONS 1000
#define BENCHMARK_CSV_PATH "benchmark_results.csv"

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
 * Strict TCP port parser (1..65535) using strtol
 */
static int parse_valid_port(const char *str, int *out_port) {
    if (str == NULL || *str == '\0' || out_port == NULL) {
        return -1;
    }
    char *endptr = NULL;
    errno = 0;
    long val = strtol(str, &endptr, 10);
    if (errno != 0 || *endptr != '\0' || val < 1 || val > 65535) {
        return -1;
    }
    *out_port = (int)val;
    return 0;
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

void print_banner(void) {
    puts("====================================================");
    puts("  ZERO-TRUST P2P NODE (SGX CONFIDENTIAL COMPUTING)  ");
    puts("====================================================");
    puts("Commands:");
    puts("  send <IP> <PORT> <MESSAGE>     (Attested P2P send)");
    puts("  tamper <IP> <PORT> <MESSAGE>   (1-bit flip test)");
    puts("  benchmark                      (Run SGX profiling)");
    puts("  quit                           (Shutdown node)");
    puts("====================================================");
}

static int compare_doubles(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

static void print_stats_and_write_csv(
    FILE *csv_fp,
    const char *op_name,
    size_t payload_bytes,
    double *samples,
    int count
) {
    if (count <= 0) return;

    for (int i = 0; i < count; i++) {
        if (csv_fp != NULL) {
            fprintf(csv_fp, "%s,%zu,%d,%.4f\n", op_name, payload_bytes, i + 1, samples[i]);
        }
    }

    qsort(samples, (size_t)count, sizeof(double), compare_doubles);

    double min_val = samples[0];
    double max_val = samples[count - 1];
    double median_val = (count % 2 == 0)
        ? (samples[count / 2 - 1] + samples[count / 2]) / 2.0
        : samples[count / 2];

    printf(" %-24s | %6zu B | Median: %7.2f us | Min: %7.2f us | Max: %7.2f us\n",
           op_name, payload_bytes, median_val, min_val, max_val);
}

void run_crypto_benchmark(sgx_enclave_id_t eid) {
    const size_t payload_sizes[] = {16, 64, 256, 1024};
    const size_t num_sizes = sizeof(payload_sizes) / sizeof(payload_sizes[0]);

    double *latencies = (double *)malloc(BENCHMARK_ITERATIONS * sizeof(double));
    if (latencies == NULL) {
        perror("[Benchmark Error] malloc failed");
        return;
    }

    FILE *csv_fp = fopen(BENCHMARK_CSV_PATH, "w");
    if (csv_fp != NULL) {
        fprintf(csv_fp, "operation,payload_bytes,iteration,latency_us\n");
    } else {
        perror("[Benchmark Warning] Could not open CSV output file");
    }

    printf("\n[Benchmark] Starting profiling (%d iterations per metric)...\n", BENCHMARK_ITERATIONS);
    puts("====================================================================================");

    struct timespec start, end;
    sgx_status_t status = SGX_SUCCESS;
    sgx_status_t ecall_ret = SGX_SUCCESS;

    // 1. Measure full Attested ECDH Handshake latency (target_info + EREPORT + verify + KDF)
    int hs_success = 0;
    for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
        sgx_target_info_t ti = {0};
        sgx_report_t report = {0};

        clock_gettime(CLOCK_MONOTONIC, &start);

        status = ecall_get_target_info(eid, &ecall_ret, &ti);
        if (status == SGX_SUCCESS && ecall_ret == SGX_SUCCESS) {
            status = ecall_generate_attested_key(eid, &ecall_ret, &ti, &report);
        }
        if (status == SGX_SUCCESS && ecall_ret == SGX_SUCCESS) {
            status = ecall_verify_and_derive(eid, &ecall_ret, &report);
        }

        clock_gettime(CLOCK_MONOTONIC, &end);

        if (status == SGX_SUCCESS && ecall_ret == SGX_SUCCESS) {
            double elapsed_us = (end.tv_sec - start.tv_sec) * 1e6 + (end.tv_nsec - start.tv_nsec) / 1e3;
            latencies[hs_success++] = elapsed_us;
        }
    }
    print_stats_and_write_csv(csv_fp, "attested_handshake", 0, latencies, hs_success);

    // 2. Measure AES-GCM encryption ECALL latency across multiple payload sizes
    char ciphertext_buffer[2048];
    for (size_t s = 0; s < num_sizes; s++) {
        size_t p_len = payload_sizes[s];
        char *test_payload = (char *)malloc(p_len + 1);
        if (test_payload == NULL) continue;
        memset(test_payload, 'A', p_len);
        test_payload[p_len] = '\0';

        int enc_success = 0;
        for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
            // Provision a fresh single-use ephemeral session key outside the timed window
            sgx_target_info_t ti = {0};
            sgx_report_t report = {0};
            if (ecall_get_target_info(eid, &ecall_ret, &ti) != SGX_SUCCESS || ecall_ret != SGX_SUCCESS) continue;
            if (ecall_generate_attested_key(eid, &ecall_ret, &ti, &report) != SGX_SUCCESS || ecall_ret != SGX_SUCCESS) continue;
            if (ecall_verify_and_derive(eid, &ecall_ret, &report) != SGX_SUCCESS || ecall_ret != SGX_SUCCESS) continue;

            memset(ciphertext_buffer, 0, sizeof(ciphertext_buffer));
            size_t actual_crypto_len = 0;

            clock_gettime(CLOCK_MONOTONIC, &start);
            status = ecall_encrypt_payload(eid, &ecall_ret, test_payload, ciphertext_buffer, sizeof(ciphertext_buffer), &actual_crypto_len);
            clock_gettime(CLOCK_MONOTONIC, &end);

            if (status == SGX_SUCCESS && ecall_ret == SGX_SUCCESS && actual_crypto_len > 0) {
                double elapsed_us = (end.tv_sec - start.tv_sec) * 1e6 + (end.tv_nsec - start.tv_nsec) / 1e3;
                latencies[enc_success++] = elapsed_us;
            }
        }

        print_stats_and_write_csv(csv_fp, "aes_gcm_encrypt", p_len, latencies, enc_success);
        free(test_payload);
    }

    puts("====================================================================================");
    if (csv_fp != NULL) {
        fclose(csv_fp);
        printf("[Benchmark] Raw samples exported to %s\n\n", BENCHMARK_CSV_PATH);
    }
    free(latencies);
}

int main(int argc, char* argv[]) {
    int local_port = 0;
    if (argc != 3 || strcmp(argv[1], "--port") != 0 || parse_valid_port(argv[2], &local_port) != 0) {
        printf("Usage: %s --port <1-65535>\n", argv[0]);
        return EXIT_FAILURE;
    }

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
    char cmd[16], target_ip[64], port_str[16], message[1024];

    while (1) {
        printf("p2p-node> ");
        if (!fgets(input_line, sizeof(input_line), stdin)) break;

        input_line[strcspn(input_line, "\n")] = 0;
        if (strlen(input_line) == 0) continue;

        if (strcmp(input_line, "quit") == 0 || strcmp(input_line, "exit") == 0) {
            puts("[Host] Initiating node shutdown sequence...");
            break;
        }

        if (sscanf(input_line, "%15s %63s %15s %1023[^\n]", cmd, target_ip, port_str, message) == 4) {
            int target_port = 0;
            if (parse_valid_port(port_str, &target_port) != 0) {
                printf("[Host Error] Invalid port '%s'. Must be in range 1-65535.\n", port_str);
                continue;
            }

            if (strcmp(cmd, "send") == 0) {
                if (is_malicious) {
                    transmit_tampered_message(target_ip, target_port, message);
                } else {
                    transmit_secure_message(target_ip, target_port, message);
                }
            }
            else if (strcmp(cmd, "tamper") == 0) {
                printf("[Attacker] Injecting 1-bit flipped ciphertext to test AES-GCM tag verification...\n");
                transmit_tampered_message(target_ip, target_port, message);
            }
            else {
                printf("[Host] Unknown command. Use 'send', 'tamper', 'benchmark', or 'quit'.\n");
            }
        }
        else if (strcmp(input_line, "benchmark") == 0) {
            run_crypto_benchmark(global_eid);
        }
        else {
            printf("[Host] Invalid syntax. Example: send 172.20.0.11 8080 Hello!\n");
        }
    }

    // 4. Teardown
    if (global_eid != 0) {
        sgx_destroy_enclave(global_eid);
        printf("[Host] Enclave context scrubbed cleanly.\n");
    }

    return EXIT_SUCCESS;
}
