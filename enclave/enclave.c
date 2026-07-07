#include "enclave_t.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
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
