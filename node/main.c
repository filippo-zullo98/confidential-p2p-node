#include <stdio.h>
#include <string.h>
#include "sgx_urts.h"     // Libreria Runtime di SGX per l'Host (contiene sgx_create_enclave, ecc.)
#include "enclave_u.h"    // Header generato automaticamente dal compilatore EDL (lato untrusted)

/* * DEFINIZIONE DELLA OCALL (Outbound Call)
 * Questa funzione è dichiarata nel file .edl sotto il blocco "untrusted".
 * Viene chiamata dall'interno dell'enclave quando il codice sicuro ha bisogno
 * di interagire con il mondo esterno (I/O). L'enclave non può fare "printf" 
 * direttamente perché non ha accesso alle chiamate di sistema (syscall) del Kernel.
 */
void ocall_print_string(const char *str) {
    // L'Host riceve la stringa dall'enclave e la stampa effettivamente a video
    printf("%s", str);
}

int main(int argc, char const *argv[]) {
    // 1. VARIABILI DI GESTIONE DELL'ENCLAVE
    sgx_enclave_id_t eid = 0;          // Identificatore univoco dell'enclave (Enclave ID)
    sgx_status_t ret = SGX_SUCCESS;    // Variabile per tracciare lo stato di ritorno delle funzioni SGX
    sgx_launch_token_t token = {0};    // Token di lancio (richiesto dall'hardware per verificare i permessi)
    int updated = 0;                   // Flag che indica se il token è stato aggiornato dall'hardware
    
    // Nome del file binario dell'enclave firmato che risiede sul disco
    const char* enclave_file = "enclave.signed.so";

    printf("[HOST] Initializing confidential P2P node...\n");

    /*
     * 2. CREAZIONE DELLA CASSAFORTE HARDWARE (Inizializzazione)
     * sgx_create_enclave prima fa una chiamata al microcodice della CPU. 
     * Il processore prende 'enclave.signed.so' dal disco, calcola l'hash crittografico 
     * del codice (MRENCLAVE), lo confronta con la firma del file e, se coincidono, 
     * alloca lo spazio isolato e cifrato nella RAM (la EPC - Enclave Page Cache).
     */
    ret = sgx_create_enclave(enclave_file, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("[HOST] CRITICAL ERROR: Could not create enclave. Error code: %#x\n", ret);
        return 1;
    }
    printf("[HOST] Enclave created successfully! Assigned ID (EID): %lu\n", eid);

    // 3. PREPARAZIONE DEI DATI PER IL DATA PLANE P2P
    // Simuliamo l'arrivo di un payload in chiaro che viaggia nel nostro sistema
    const char* plaintext = "Confidential P2P Data Plane Message";
    size_t len = strlen(plaintext) + 1; // Includiamo il terminatore null '\0'

    // Allochiamo i buffer nello spazio di memoria normale (RAM dell'Host)
    char ciphertext[128] = {0};
    char decryptedtext[128] = {0};

    printf("[HOST] Original plaintext: %s (Length: %zu bytes)\n", plaintext, len);

    /*
     * 4. CIFRATURA - ATTRAVERSAMENTO DEL CONFINE (ECALL)
     * Invochiamo la funzione sicura 'ecall_encrypt_block'.
     * Passiamo l'identificatore 'eid' per dire alla CPU in quale enclave saltare.
     * Sotto il cofano: la CPU interrompe l'esecuzione dell'Host, salva i registri,
     * copia il plaintext nella RAM protetta (EPC) e passa il controllo all'enclave.
     */
    printf("[HOST] Sending data to enclave for hardware encryption (AES-CTR)...\n");
    ret = ecall_encrypt_block(eid, plaintext, len, ciphertext);
    if (ret != SGX_SUCCESS) {
        printf("[HOST] Error during encryption ECALL: %#x\n", ret);
        sgx_destroy_enclave(eid);
        return 1;
    }
    
    // Ora il buffer 'ciphertext' contiene i dati cifrati restituiti dall'enclave
    printf("[HOST] Encryption completed. Ciphertext (simulated hex): %s\n", ciphertext);

    /*
     * 5. DECIFRATURA - SIMULAZIONE RICEZIONE DA UN PEER
     * Simuliamo che il nodo debba elaborare il pacchetto cifrato appena ricevuto.
     * Passiamo il ciphertext all'enclave tramite una nuova ECALL.
     */
    printf("[HOST] Sending ciphertext to enclave for decryption...\n");
    ret = ecall_decrypt_block(eid, ciphertext, len, decryptedtext);
    if (ret != SGX_SUCCESS) {
        printf("[HOST] Error during decryption ECALL: %#x\n", ret);
        sgx_destroy_enclave(eid);
        return 1;
    }

    printf("[HOST] Decryption completed. Restored data: %s\n", decryptedtext);

    /*
     * 6. DISTRUZIONE DEL NODO E WIPING DELLA MEMORIA
     * Quando il nodo si spegne, dobbiamo assicurarci di non lasciare tracce.
     * sgx_destroy_enclave dice alla CPU di invalidare le pagine di memoria EPC
     * associate a questo EID e di fare un "wipe" (azzeramento atomico) del silicio.
     */
    printf("[HOST] Closing node and destroying enclave...\n");
    sgx_destroy_enclave(eid);
    
    printf("[HOST] Node status: OFFLINE. EPC memory freed.\n");
    return 0;
}
