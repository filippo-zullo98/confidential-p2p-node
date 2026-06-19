#include "enclave_t.h"    // Header generato automaticamente dal compilatore EDL (lato trusted)
#include "sgx_tcrypto.h"  // Libreria crittografica fidata di Intel SGX (sostituisce OpenSSL/glibc)
#include <string.h>

/*
 * CHIAVE CRITTOGRAFICA DI SESSIONE (Simulata)
 * In una vera architettura Zero-Trust orientata alla rete P2P (stile Careful Whisper),
 * questa chiave AES a 128 bit (16 byte) NON è scritta fissa nel codice (hardcoded),
 * ma viene iniettata dinamicamente dentro la CPU solo DOPO che il nodo ha superato
 * con successo il processo di Attestazione Remota con gli altri peer della rete.
 */
static const sgx_aes_gcm_128bit_key_t p2p_session_key = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16
};

/*
 * IMPLEMENTAZIONE DELLA ECALL DI CIFRATURA
 * Questa funzione riceve il dato copiato in modo sicuro dall'hardware dentro la EPC.
 */
void ecall_encrypt_block(const char* plaintext, size_t len, char* ciphertext) {
    
    // Invochiamo la OCALL per fare un log all'esterno nell'Host.
    // Ricorda: la "printf" qui dentro è vietata, quindi deleghiamo l'Host.
    ocall_print_string("[ENCLAVE] Hardware encryption started...\n");

    /*
     * SCELTA ARCHITETTURALE: AES-CTR (Counter Mode)
     * Per il Data Plane di una rete P2P usiamo la modalità CTR perché:
     * 1. Non richiede Padding (il ciphertext ha la stessa identica lunghezza del plaintext).
     * 2. Permette il parallelismo hardware (accelerazione tramite istruzioni AES-NI della CPU).
     */
    
    // Il contatore (IV / Nonce) a 16 byte per la modalità CTR.
    // Deve essere sincrono tra chi cifra e chi decifra.
    uint8_t ctr[16] = {0}; 

    /*
     * Chiamata alla funzione crittografica hardware nativa di Intel SGX.
     * Parametri:
     * - &p2p_session_key: Puntatore alla chiave segreta custodita in RAM EPC.
     * - (const uint8_t*)plaintext: Il testo in chiaro (già copiato nella memoria fidata).
     * - (uint32_t)len: Lunghezza del blocco.
     * - ctr: Il vettore/contatore.
     * - 128: Gli bit del contatore da incrementare (tutto il blocco).
     * - (uint8_t*)ciphertext: Il buffer di destinazione in cui la CPU scriverà il risultato cifrato.
     */
    sgx_aes_ctr_encrypt(&p2p_session_key, 
                        (const uint8_t*)plaintext, 
                        (uint32_t)len, 
                        ctr, 
                        128, 
                        (uint8_t*)ciphertext);

    ocall_print_string("[ENCLAVE] Encryption completed successfully inside the CPU.\n");
}

/*
 * IMPLEMENTAZIONE DELLA ECALL DI DECIFRATURA
 * Sfrutta la natura simmetrica di AES-CTR.
 */
void ecall_decrypt_block(const char* ciphertext, size_t len, char* decryptedtext) {
    
    ocall_print_string("[ENCLAVE] Hardware decryption started...\n");

    // Re-inizializziamo lo stesso identico contatore usato per cifrare
    uint8_t ctr[16] = {0};

    /*
     * Nota di sicurezza: In modalità AES-CTR, l'operazione di decifratura 
     * sotto il cofano è matematicamente identica alla cifratura (è uno XOR con il keystream).
     * Per questo motivo l'SDK di Intel SGX mappa entrambe le operazioni 
     * sotto la stessa funzione 'sgx_aes_ctr_encrypt'.
     */
    sgx_aes_ctr_encrypt(&p2p_session_key, 
                        (const uint8_t*)ciphertext, 
                        (uint32_t)len, 
                        ctr, 
                        128, 
                        (uint8_t*)decryptedtext);

    // Ora 'decryptedtext' contiene il dato in chiaro, ma è ancora dentro l'enclave.
    // Appena questa funzione finisce, l'hardware prenderà questo blocco di memoria EPC
    // e lo copierà nel buffer dell'Host (per via del tag [out] definito nell'EDL).
    ocall_print_string("[ENCLAVE] Decryption completed. Data is about to be exposed to the Host.\n");
}
