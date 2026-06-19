#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* Contiene i tipi di dati base usati dal generatore di SGX */

#include "sgx_urts.h"    /* Richiesto per il tipo sgx_enclave_id_t */

#ifdef __cplusplus
extern "C" {
#endif

/* * PROTOTIPI DELLE OCALL (Riconosciute dall'Host)
 * Questa è la funzione che hai implementato nel main.c per stampare i log dell'enclave.
 */
#ifndef OCALL_PRINT_STRING_DEFINED
#define OCALL_PRINT_STRING_DEFINED
void ocall_print_string(const char* str);
#endif

/* * PROTOTIPI DELLE ECALL (I Proxy per l'Host)
 * Noti qualcosa di diverso rispetto al file .edl? 
 * 'sgx_edger8r' ha aggiunto due parametri fondamentali a tutte le tue funzioni:
 * 1. sgx_enclave_id_t eid: l'ID della cassaforte in cui saltare (generato da sgx_create_enclave).
 * 2. Il valore di ritorno 'sgx_status_t': serve a capire se il salto hardware è riuscito.
 */
sgx_status_t ecall_encrypt_block(sgx_enclave_id_t eid, const char* plaintext, size_t len, char* ciphertext);
sgx_status_t ecall_decrypt_block(sgx_enclave_id_t eid, const char* ciphertext, size_t len, char* decryptedtext);

#ifdef __cplusplus
}
#endif

#endif /* ENCLAVE_U_H__ */
