#include <stdio.h>
#include <string.h>
#include "sgx_urts.h"
#include "enclave_u.h" // Firme untrusted generate da sgx_edger8r

#define ENCLAVE_FILE "enclave.signed.so"

/* Implementazione della OCALL di debug richiesta dal file .edl */
void ocall_print_string(const char *str) {
    printf("%s", str);
}

int main(int argc, char const *argv[]) {
    sgx_enclave_id_t eid = 0;
    sgx_status_t ret = SGX_SUCCESS;
    sgx_launch_token_t token = {0};

    // 1. Inizializzazione dell'Enclave (passiamo NULL al posto di &updated)
    ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, NULL, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("Errore: Impossibile creare l'Enclave. Status code: 0x%X\n", ret);
        return 1;
    }
    printf("Enclave creata con successo! ID: %lu\n", eid);

    // 2. Dati di prova da cifrare
    const char *plaintext = "Messaggio segreto del Data Plane P2P!";
    size_t len = strlen(plaintext) + 1; // Includiamo il terminatore di stringa \0
    
    char ciphertext[128] = {0};
    char decryptedtext[128] = {0};

    printf("\n--- TEST CIFRATURA AES-CTR ---\n");
    printf("Testo in chiaro originale: %s\n", plaintext);

    // 3. Chiamata alla ECALL di cifratura
    ecall_encrypt_block(eid, plaintext, len, ciphertext);
    printf("Cifratura completata all'interno della memoria protetta EPC.\n");

    // Stampiamo il ciphertext in esadecimale
    printf("Testo cifrato (HEX): ");
    for(size_t i = 0; i < len; i++) {
        printf("%02x ", (unsigned char)ciphertext[i]);
    }
    printf("\n");

    // 4. Chiamata alla ECALL di decifratura
    ecall_decrypt_block(eid, ciphertext, len, decryptedtext);
    printf("Decifratura completata.\n");
    printf("Testo decifrato ottenuto: %s\n", decryptedtext);

    // 5. Distruzione dell'Enclave
    sgx_destroy_enclave(eid);
    printf("\nEnclave distrutta correttamente.\n");

    return 0;
}
