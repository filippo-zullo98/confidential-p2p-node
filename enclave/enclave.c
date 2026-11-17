#include "enclave_t.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "sgx_utils.h"
#include <string.h>
#include <stdlib.h>

/*
 * Global Enclave State for Cryptographic Session
 * Resides inside enclave memory (EPC on SGX hardware).
 */
static sgx_ec256_private_t g_priv_key;
static int g_is_priv_key_set = 0;

static sgx_aes_gcm_128bit_key_t g_session_key;
static int g_is_session_key_set = 0;

static void scrub_private_key(void) {
    memset(&g_priv_key, 0, sizeof(sgx_ec256_private_t));
    g_is_priv_key_set = 0;
}

static void scrub_session_key(void) {
    memset(&g_session_key, 0, sizeof(sgx_aes_gcm_128bit_key_t));
    g_is_session_key_set = 0;
}

/*
 * ECALL: ecall_get_target_info
 * Retrieves this enclave's target identity so a remote/local peer can generate
 * a cryptographic report verifiable exclusively by this enclave.
 */
sgx_status_t ecall_get_target_info(sgx_target_info_t* target_info) {
    if (target_info == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    return sgx_self_target(target_info);
}

/*
 * ECALL: ecall_generate_attested_key
 * Generates an ephemeral NIST P-256 keypair and binds the 64-byte public key
 * (gx || gy) into an SGX Report targeted at p_peer_target_info.
 */
sgx_status_t ecall_generate_attested_key(
    const sgx_target_info_t* p_peer_target_info,
    sgx_report_t* p_report
) {
    if (p_peer_target_info == NULL || p_report == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // Reset any stale cryptographic state before starting a new handshake
    scrub_private_key();
    scrub_session_key();

    sgx_status_t ret = SGX_SUCCESS;
    sgx_ecc_state_handle_t ecc_handle = NULL;
    sgx_ec256_public_t pub_key;
    sgx_report_data_t report_data = {0};

    ret = sgx_ecc256_open_context(&ecc_handle);
    if (ret != SGX_SUCCESS) {
        ocall_print_string("[Enclave Error] Failed to open ECC context.\n");
        return ret;
    }

    ret = sgx_ecc256_create_key_pair(&g_priv_key, &pub_key, ecc_handle);
    sgx_ecc256_close_context(ecc_handle);

    if (ret != SGX_SUCCESS) {
        scrub_private_key();
        ocall_print_string("[Enclave Error] Ephemeral keypair generation failed.\n");
        return ret;
    }
    g_is_priv_key_set = 1;

    // Bind the 64-byte uncompressed public key (gx || gy) into report_data
    memcpy(&report_data.d[0],  pub_key.gx, SGX_ECP256_KEY_SIZE);
    memcpy(&report_data.d[32], pub_key.gy, SGX_ECP256_KEY_SIZE);

    // Generate SGX Report authenticated with a MAC verifiable by p_peer_target_info
    ret = sgx_create_report(p_peer_target_info, &report_data, p_report);
    if (ret != SGX_SUCCESS) {
        scrub_private_key();
        ocall_print_string("[Enclave Error] sgx_create_report failed.\n");
        return ret;
    }

    ocall_print_string("[Enclave] Ephemeral ECDH key generated and bound to peer-targeted SGX Report.\n");
    return SGX_SUCCESS;
}

/*
 * ECALL: ecall_verify_and_derive
 * Authenticates the peer's SGX Report via sgx_verify_report(), validates
 * MRSIGNER and MRENCLAVE, extracts the bound public key inside the enclave,
 * and derives the ephemeral AES-128 session key.
 */
sgx_status_t ecall_verify_and_derive(const sgx_report_t* p_peer_report) {
    // Always invalidate previous session key immediately
    scrub_session_key();

    if (p_peer_report == NULL) {
        scrub_private_key();
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (!g_is_priv_key_set) {
        ocall_print_string("[Enclave Error] Ephemeral private key not initialized.\n");
        return SGX_ERROR_UNEXPECTED;
    }

    // 1. Cryptographically verify the Report MAC (detects any report_data tampering)
    sgx_status_t ret = sgx_verify_report(p_peer_report);
    if (ret != SGX_SUCCESS) {
        scrub_private_key();
        ocall_print_string("[Enclave Security Alert] sgx_verify_report failed! Report MAC invalid or tampered.\n");
        return ret;
    }

    // 2. Verify enclave identity measurements (MRSIGNER and MRENCLAVE)
    const sgx_report_t* self_report = sgx_self_report();
    if (self_report == NULL) {
        scrub_private_key();
        return SGX_ERROR_UNEXPECTED;
    }

    if (memcmp(&self_report->body.mr_signer, &p_peer_report->body.mr_signer, sizeof(sgx_measurement_t)) != 0) {
        scrub_private_key();
        ocall_print_string("[Enclave Security Alert] Peer MRSIGNER mismatch! Untrusted signer.\n");
        return SGX_ERROR_MAC_MISMATCH;
    }

    if (memcmp(&self_report->body.mr_enclave, &p_peer_report->body.mr_enclave, sizeof(sgx_measurement_t)) != 0) {
        scrub_private_key();
        ocall_print_string("[Enclave Security Alert] Peer MRENCLAVE mismatch! Code integrity violation.\n");
        return SGX_ERROR_MAC_MISMATCH;
    }

    ocall_print_string("[Enclave] Peer SGX Report MAC, MRENCLAVE, and MRSIGNER verified.\n");

    // 3. Extract the authenticated 64-byte public key strictly inside the enclave
    sgx_ec256_public_t peer_pub_key;
    memcpy(peer_pub_key.gx, &p_peer_report->body.report_data.d[0],  SGX_ECP256_KEY_SIZE);
    memcpy(peer_pub_key.gy, &p_peer_report->body.report_data.d[32], SGX_ECP256_KEY_SIZE);

    // 4. Compute ECDH shared secret
    sgx_ecc_state_handle_t ecc_context = NULL;
    sgx_ec256_dh_shared_t shared_secret;

    ret = sgx_ecc256_open_context(&ecc_context);
    if (ret != SGX_SUCCESS) {
        scrub_private_key();
        return ret;
    }

    ret = sgx_ecc256_compute_shared_dhkey(&g_priv_key, &peer_pub_key, &shared_secret, ecc_context);
    sgx_ecc256_close_context(ecc_context);

    // Ephemeral private key is no longer needed once DH computation completes
    scrub_private_key();

    if (ret != SGX_SUCCESS) {
        memset(&shared_secret, 0, sizeof(sgx_ec256_dh_shared_t));
        ocall_print_string("[Enclave Error] Failed to compute DH shared secret.\n");
        return ret;
    }

    // 5. Key Derivation Function (KDF): SHA-256 truncated to 128-bit AES key
    sgx_sha256_hash_t hash_output;
    ret = sgx_sha256_msg((const uint8_t*)&shared_secret, sizeof(sgx_ec256_dh_shared_t), &hash_output);
    memset(&shared_secret, 0, sizeof(sgx_ec256_dh_shared_t));

    if (ret != SGX_SUCCESS) {
        memset(&hash_output, 0, sizeof(sgx_sha256_hash_t));
        ocall_print_string("[Enclave Error] SHA-256 Key Derivation failed.\n");
        return ret;
    }

    memcpy(&g_session_key, &hash_output, sizeof(sgx_aes_gcm_128bit_key_t));
    memset(&hash_output, 0, sizeof(sgx_sha256_hash_t));
    g_is_session_key_set = 1;

    ocall_print_string("[Enclave] Attested ECDH complete. Ephemeral AES-128 Session Key derived.\n");
    return SGX_SUCCESS;
}

/*
 * ECALL: ecall_encrypt_payload
 * Encrypts plaintext with the ephemeral AES-128 session key and immediately
 * wipes the session key afterwards to enforce single-use forward secrecy.
 */
sgx_status_t ecall_encrypt_payload(
    const char* plaintext,
    char* ciphertext_buffer,
    size_t ciphertext_max_len,
    size_t* actual_ciphertext_len
) {
    if (actual_ciphertext_len == NULL) {
        scrub_session_key();
        return SGX_ERROR_INVALID_PARAMETER;
    }
    *actual_ciphertext_len = 0;

    if (!g_is_session_key_set) {
        ocall_print_string("[Enclave Error] Cannot encrypt. Attested session key is not active!\n");
        return SGX_ERROR_UNEXPECTED;
    }

    if (plaintext == NULL || ciphertext_buffer == NULL) {
        scrub_session_key();
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t plaintext_len = (uint32_t)strlen(plaintext);
    uint32_t expected_total_len = SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + plaintext_len;

    if (ciphertext_max_len < expected_total_len) {
        scrub_session_key();
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint8_t* p_iv  = (uint8_t*)ciphertext_buffer;
    uint8_t* p_tag = (uint8_t*)(ciphertext_buffer + SGX_AESGCM_IV_SIZE);
    uint8_t* p_crt = (uint8_t*)(ciphertext_buffer + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE);

    sgx_status_t status = sgx_read_rand(p_iv, SGX_AESGCM_IV_SIZE);
    if (status != SGX_SUCCESS) {
        scrub_session_key();
        ocall_print_string("[Enclave Error] Random IV generation failure.\n");
        return status;
    }

    status = sgx_rijndael128GCM_encrypt(
        &g_session_key,
        (const uint8_t*)plaintext, plaintext_len,
        p_crt,
        p_iv, SGX_AESGCM_IV_SIZE,
        NULL, 0,
        (sgx_aes_gcm_128bit_tag_t*)p_tag
    );

    // Wipe ephemeral session key immediately after use
    scrub_session_key();

    if (status != SGX_SUCCESS) {
        return status;
    }

    *actual_ciphertext_len = (size_t)expected_total_len;
    return SGX_SUCCESS;
}

/*
 * ECALL: ecall_decrypt_payload
 * Verifies the AES-GCM tag and decrypts the ciphertext, wiping the ephemeral
 * session key immediately upon completion or failure.
 */
sgx_status_t ecall_decrypt_payload(const char* ciphertext_buffer, size_t ciphertext_len) {
    if (!g_is_session_key_set) {
        ocall_print_string("[Enclave Error] Cannot decrypt. Attested session key is not active!\n");
        return SGX_ERROR_UNEXPECTED;
    }

    if (ciphertext_buffer == NULL || ciphertext_len <= (SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE)) {
        scrub_session_key();
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t plaintext_len = (uint32_t)(ciphertext_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE);
    char* decrypted_plaintext = (char*)malloc(plaintext_len + 1);
    if (decrypted_plaintext == NULL) {
        scrub_session_key();
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    const uint8_t* p_iv  = (const uint8_t*)ciphertext_buffer;
    const uint8_t* p_tag = (const uint8_t*)(ciphertext_buffer + SGX_AESGCM_IV_SIZE);
    const uint8_t* p_crt = (const uint8_t*)(ciphertext_buffer + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE);

    sgx_status_t status = sgx_rijndael128GCM_decrypt(
        &g_session_key,
        p_crt, plaintext_len,
        (uint8_t*)decrypted_plaintext,
        p_iv, SGX_AESGCM_IV_SIZE,
        NULL, 0,
        (const sgx_aes_gcm_128bit_tag_t*)p_tag
    );

    // Wipe ephemeral session key immediately after use
    scrub_session_key();

    if (status != SGX_SUCCESS) {
        ocall_print_string("[CRITICAL ATTACK DETECTED] AES-GCM MAC validation failed!\n");
        free(decrypted_plaintext);
        return status;
    }

    decrypted_plaintext[plaintext_len] = '\0';
    ocall_print_string("[Enclave] Secure Payload: ");
    ocall_print_string(decrypted_plaintext);
    ocall_print_string("\n");

    memset(decrypted_plaintext, 0, plaintext_len);
    free(decrypted_plaintext);
    return SGX_SUCCESS;
}
