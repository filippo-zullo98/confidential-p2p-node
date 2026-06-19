#include "enclave_u.h"
#include <errno.h>

/* * 1. LE STRUTTURE DI MARSHALLING (Impacchettamento dei dati)
 * Per passare i parametri attraverso il muro di silicio, SGX li impacchetta in una struct.
 * Questa struttura specchia esattamente gli argomenti della tua ECALL.
 */
typedef struct ms_ecall_encrypt_block_t {
    const char* ms_plaintext;  // Puntatore al testo in chiaro nell'Host
    size_t ms_len;              // Lunghezza dei dati
    char* ms_ciphertext;       // Puntatore a dove l'enclave scriverà il risultato
} ms_ecall_encrypt_block_t;

typedef struct ms_ecall_decrypt_block_t {
    const char* ms_ciphertext;
    size_t ms_len;
    char* ms_decryptedtext;
} ms_ecall_decrypt_block_t;

/*
 * 2. LA TABELLA DELLE OCALL (L'Enclave Entry Table per uscire)
 * Come fa l'enclave a sapere dove si trova la tua 'ocall_print_string' nell'Host?
 * Viene creata una tabella di puntatori a funzione. L'enclave farà riferimento 
 * all'indice di questa tabella quando vorrà stampare qualcosa.
 */
static const struct {
    size_t nr_ocall; // Numero totale di OCALL registrate
    void * table[1]; // Array di puntatori alle funzioni OCALL
} ocall_table_enclave = {
    1,
    {
        (void*)ocall_print_string, // La tua funzione nel main.c è all'indice 0
    }
};

/*
 * 3. IL PROXY REALE DELLA ECALL (Quello chiamato dal tuo main.c)
 */
sgx_status_t ecall_encrypt_block(sgx_enclave_id_t eid, const char* plaintext, size_t len, char* ciphertext)
{
    sgx_status_t status;
    ms_ecall_encrypt_block_t ms; // Istanziamo la struttura di impacchettamento

    // Riempiamo la valigetta con i parametri passati dal main.c
    ms.ms_plaintext = plaintext;
    ms.ms_len = len;
    ms.ms_ciphertext = ciphertext;

    /*
     * LA CHIAMATA DI SISTEMA CRUCIALE: sgx_ecall
     * Questa è la funzione della libreria Runtime di Intel.
     * Parametri:
     * - eid: L'ID dell'enclave bersaglio.
     * - 0: L'indice della funzione dentro l'enclave (ecall_encrypt_block è la prima, quindi 0).
     * - &ocall_table_enclave: Mappa delle OCALL che l'enclave può usare mentre esegue questa ECALL.
     * - &ms: Il puntatore alla valigetta con i dati.
     * * Sotto il cofano, questa funzione esegue l'istruzione CPU assembler 'EENTER' 
     * che switcha il processore in modalità Enclave (Ring 3 protetto).
     */
    status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);

    // Ritorna lo stato dell'operazione hardware all'Host
    return status;
}

/* * Il proxy per la decifratura fa esattamente la stessa cosa, 
 * usando l'indice 1 della tabella delle ECALL.
 */
sgx_status_t ecall_decrypt_block(sgx_enclave_id_t eid, const char* ciphertext, size_t len, char* decryptedtext)
{
    sgx_status_t status;
    ms_ecall_decrypt_block_t ms;
    
    ms.ms_ciphertext = ciphertext;
    ms.ms_len = len;
    ms.ms_decryptedtext = decryptedtext;
    
    status = sgx_ecall(eid, 1, &ocall_table_enclave, &ms);
    
    return status;
}
