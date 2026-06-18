#include "enclave_t.h"
#include "sgx_tcrypto.h"
#include <string.h>

// Chiave simmetrica (provvisoria) fissa a 128 bit
static const sgx_aes_ctr_128bit_key_t key = {
	{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16}  
};

/**
 * Implementazione della ECALL di cifratura reale con AES-CTR 
 * */
void ecall_encrypt_block(const char* plaintext, size_t len, char* ciphertext) {
	// Il contatore (ctr) per AES-CTR deve essere di 16 byte
	uint8_t ctr[16] = {0};
	uint32_t ctr_inc_bits = 128; // Incrementa l'intero contatore a 128 bit
	
	// Chiamata alla funzione crittografica protetta dell'SDK
	sgx_aes_ctr_encrypt(
		&key,
		(const uint8_t*)plaintext,
		(uint32_t)len,
		ctr,
		ctr_inc_bits,
		(uint8_t*)ciphertext
	);
}

/**
 * Implementazione della ECALL di decifratura reale con AES-CTR
 * Nota: In modalità CTR, la decifratura usa la stessa identica funzione logica della cifratura
 * */
void ecall_decrypt_block(const char* ciphertext, size_t len, char* plaintext) {
	uint8_t ctr[16] = {0};
	uint32_t ctr_inc_bits = 128;

	sgx_aes_ctr_encrypt(
		&key,
		(const uint8_t*)ciphertext,
		(uint32_t)len,
		ctr,
		ctr_inc_bits,
		(uint8_t*)plaintext
	);
}
