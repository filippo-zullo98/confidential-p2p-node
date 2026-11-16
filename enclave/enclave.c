#include "enclave_t.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "sgx_utils.h"
#include <string.h>
#include <stdlib.h>

/* * Global Enclave State for Cryptographic Session 
 * These variables reside ONLY in isolated EPC memory.
 */
static sgx_ec256_private_t g_priv_key;           // Our ephemeral private key
static sgx_aes_gcm_128bit_key_t g_session_key;   // The derived AES-128 session key
static int g_is_session_key_set = 0;             // State lock flag

/*
 * ECALL: ecall_ecdh_generate_keypair
 * Instantiates an ECC context and generates a NIST P-256 keypair.
 * The private key is kept globally inside the enclave, the public key is exported.
 */
void ecall_ecdh_generate_keypair(sgx_ec256_public_t* out_pub_key) {
    if (out_pub_key == NULL) {
        ocall_print_string("[Enclave Error] Null pointer for public key export.\n");
        return;
    }

    sgx_ecc_state_handle_t ecc_context;
    sgx_status_t status;

    // 1. Open ECC Context
    status = sgx_ecc256_open_context(&ecc_context);
    if (status != SGX_SUCCESS) {
        ocall_print_string("[Enclave Error] Failed to open hardware ECC context.\n");
        return;
    }

    // 2. Generate Keypair using hardware TRNG entropy
    status = sgx_ecc256_create_key_pair(&g_priv_key, out_pub_key, ecc_context);
    if (status != SGX_SUCCESS) {
        ocall_print_string("[Enclave Error] ECDH Keypair generation failed.\n");
        sgx_ecc256_close_context(ecc_context);
        return;
    }

    // 3. Clean up context
    sgx_ecc256_close_context(ecc_context);
    ocall_print_string("[Enclave] Ephemeral ECDH Keypair successfully generated. Public Key exported.\n");
}

/*
 * ECALL: ecall_ecdh_derive_shared_secret
 * Computes the DH shared secret using our private key and the remote peer's public key.
 * Derives a 128-bit AES-GCM key via SHA-256 hashing (KDF).
 */
void ecall_ecdh_derive_shared_secret(const sgx_ec256_public_t* remote_pub_key) {
    if (remote_pub_key == NULL) {
        ocall_print_string("[Enclave Error] Null pointer for remote public key.\n");
        return;
    }

    sgx_ecc_state_handle_t ecc_context;
    sgx_ec256_dh_shared_t shared_secret;
    sgx_status_t status;

    status = sgx_ecc256_open_context(&ecc_context);
    if (status != SGX_SUCCESS) return;

    // 1. Compute the raw DH Shared Secret (Mathematical intersection)
    status = sgx_ecc256_compute_shared_dhkey(&g_priv_key, (sgx_ec256_public_t*)remote_pub_key, &shared_secret, ecc_context);
    sgx_ecc256_close_context(ecc_context);

    if (status != SGX_SUCCESS) {
        ocall_print_string("[Enclave Error] Failed to compute DH shared secret. Curve point mismatch?\n");
        return;
    }

    // 2. Key Derivation Function (KDF): Hash the shared secret using SHA-256
    sgx_sha256_hash_t hash_output;
    status = sgx_sha256_msg((const uint8_t*)&shared_secret, sizeof(sgx_ec256_dh_shared_t), &hash_output);
    
    if (status != SGX_SUCCESS) {
        ocall_print_string("[Enclave Error] SHA-256 Key Derivation failed.\n");
        return;
    }

    // 3. Truncate SHA-256 (32 bytes) to AES-128 (16 bytes) and lock the state
    memcpy(&g_session_key, &hash_output, sizeof(sgx_aes_gcm_128bit_key_t));
    g_is_session_key_set = 1;

    // 4. Scrub the raw shared secret and full hash from memory to prevent leakage
    memset(&shared_secret, 0, sizeof(sgx_ec256_dh_shared_t));
    memset(&hash_output, 0, sizeof(sgx_sha256_hash_t));

    ocall_print_string("[Enclave] ECDH Handshake complete. AES-128 Session Key derived and locked safely.\n");
}

/*
 * ECALL: ecall_encrypt_payload (Updated for Dynamic Key)
 */
void ecall_encrypt_payload(const char* plaintext, char* ciphertext_buffer, size_t ciphertext_max_len, size_t* actual_ciphertext_len) {
    if (!g_is_session_key_set) {
        ocall_print_string("[Enclave Error] Cannot encrypt. ECDH session key is not derived yet!\n");
        *actual_ciphertext_len = 0;
        return;
    }

    if (plaintext == NULL || ciphertext_buffer == NULL || actual_ciphertext_len == NULL) return;

    uint32_t plaintext_len = (uint32_t)strlen(plaintext);
    uint32_t expected_total_len = SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + plaintext_len;

    if (ciphertext_max_len < expected_total_len) {
        *actual_ciphertext_len = 0;
        return;
    }

    uint8_t* p_iv  = (uint8_t*)ciphertext_buffer;
    uint8_t* p_tag = (uint8_t*)(ciphertext_buffer + SGX_AESGCM_IV_SIZE);
    uint8_t* p_crt = (uint8_t*)(ciphertext_buffer + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE);

    if (sgx_read_rand(p_iv, SGX_AESGCM_IV_SIZE) != SGX_SUCCESS) {
        ocall_print_string("[Enclave Error] TRNG failure.\n");
        *actual_ciphertext_len = 0;
        return;
    }     

    // Use the dynamically derived g_session_key
    sgx_status_t status = sgx_rijndael128GCM_encrypt(
        &g_session_key,
        (const uint8_t*)plaintext, plaintext_len,
        p_crt,
        p_iv, SGX_AESGCM_IV_SIZE,
        NULL, 0,
        (sgx_aes_gcm_128bit_tag_t*)p_tag
    );

    if (status != SGX_SUCCESS) {
        *actual_ciphertext_len = 0;
        return;
    }

    *actual_ciphertext_len = (size_t)expected_total_len;
}

/*
 * ECALL: ecall_decrypt_payload (Updated for Dynamic Key)
 */
void ecall_decrypt_payload(const char* ciphertext_buffer, size_t ciphertext_len) {
    if (!g_is_session_key_set) {
        ocall_print_string("[Enclave Error] Cannot decrypt. ECDH session key is not derived yet!\n");
        return;
    }

    if (ciphertext_buffer == NULL || ciphertext_len <= (SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE)) return;

    uint32_t plaintext_len = (uint32_t)(ciphertext_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE);
    char* decrypted_plaintext = (char*)malloc(plaintext_len + 1);
    if (decrypted_plaintext == NULL) return;

    const uint8_t* p_iv  = (const uint8_t*)ciphertext_buffer;
    const uint8_t* p_tag = (const uint8_t*)(ciphertext_buffer + SGX_AESGCM_IV_SIZE);
    const uint8_t* p_crt = (const uint8_t*)(ciphertext_buffer + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE);

    // Use the dynamically derived g_session_key
    sgx_status_t status = sgx_rijndael128GCM_decrypt(
        &g_session_key,
        p_crt, plaintext_len,
        (uint8_t*)decrypted_plaintext,
        p_iv, SGX_AESGCM_IV_SIZE,
        NULL, 0,
        (const sgx_aes_gcm_128bit_tag_t*)p_tag
    );

    if (status != SGX_SUCCESS) {
        ocall_print_string("[CRITICAL ATTACK DETECTED] MAC validation failed!\n");
        free(decrypted_plaintext);
        return;
    }

    decrypted_plaintext[plaintext_len] = '\0';
    ocall_print_string("[Enclave] Secure Payload: ");
    ocall_print_string(decrypted_plaintext);
    ocall_print_string("\n");

    memset(decrypted_plaintext, 0, plaintext_len);
    free(decrypted_plaintext);
}

/*
 * ECALL: ecall_generate_attestated_key
 * Generates an ephemeral NIST P-256 keypair inside EPC memory and binds the
 * 64-byte public key (X || Y) into the report_data field of an SGX Report.
 */
sgx_status_t ecall_generate_attestated_key(const sgx_target_info_t *p_qe_target_info, sgx_report_t *p_report) {
    if (p_qe_target_info == NULL || p_report == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_status_t ret = SGX_SUCCESS;
    sgx_ecc_state_handle_t ecc_handle = NULL;
    sgx_ec256_public_t pub_key;
    sgx_report_data_t report_data = {0};

    // 1. Open hardware ECC context
    ret = sgx_ecc256_open_context(&ecc_handle);
    if (ret != SGX_SUCCESS) {
        ocall_print_string("[Enclave Error] Failed to open ECC context for attestation.\n");
        return ret;
    }

    // 2. Generate ephemeral keypair storing the private key in global EPC state (g_priv_key)
    ret = sgx_ecc256_create_key_pair(&g_priv_key, &pub_key, ecc_handle);
    if (ret != SGX_SUCCESS) {
        ocall_print_string("[Enclave Error] Ephemeral keypair generation failed.\n");
        sgx_ecc256_close_context(ecc_handle);
        return ret;
    }

    // 3. Bind the 64-byte uncompressed public key (gx || gy) into report_data
    memcpy(&report_data.d[0],  pub_key.gx, SGX_ECP256_KEY_SIZE);
    memcpy(&report_data.d[32], pub_key.gy, SGX_ECP256_KEY_SIZE);

    // 4. Invoke EREPORT via sgx_create_report to cryptographically bind pub_key to MRENCLAVE
    ret = sgx_create_report(p_qe_target_info, &report_data, p_report);
    if (ret == SGX_SUCCESS) {
        ocall_print_string("[Enclave] Ephemeral ECDH key generated and bound to SGX Report.\n");
    }

    sgx_ecc256_close_context(ecc_handle);
    return ret;
}

/*
 * ECALL: ecall_verify_peer_report
 * Validates an incoming peer's SGX Report by checking that its MRSIGNER and
 * MRENCLAVE measurements match our trusted enclave identity policy.
 */
sgx_status_t ecall_verify_peer_report(const sgx_report_t *p_peer_report) {
    if (p_peer_report == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // Retrieve our own enclave identity (MRENCLAVE & MRSIGNER) via self-report
    sgx_report_t self_report;
    sgx_status_t ret = sgx_create_report(NULL, NULL, &self_report);
    if (ret != SGX_SUCCESS) {
        return ret;
    }

    // Verify that the peer enclave was signed by the same trusted authority (MRSIGNER)
    if (memcmp(&self_report.body.mr_signer, &p_peer_report->body.mr_signer, sizeof(sgx_measurement_t)) != 0) {
        ocall_print_string("[Enclave Security Alert] Peer MRSIGNER mismatch! Untrusted binary.\n");
        return SGX_ERROR_MAC_MISMATCH;
    }

    // Verify that the peer enclave executes the exact same approved binary code (MRENCLAVE)
    if (memcmp(&self_report.body.mr_enclave, &p_peer_report->body.mr_enclave, sizeof(sgx_measurement_t)) != 0) {
        ocall_print_string("[Enclave Security Alert] Peer MRENCLAVE mismatch! Code integrity violation.\n");
        return SGX_ERROR_MAC_MISMATCH;
    }

    ocall_print_string("[Enclave] Peer MRENCLAVE and MRSIGNER verified against Zero-Trust policy.\n");
    return SGX_SUCCESS;
}

