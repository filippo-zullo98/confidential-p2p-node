#include "enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_encrypt_block_t {
	const char* ms_plaintext;
	size_t ms_len;
	char* ms_ciphertext;
} ms_ecall_encrypt_block_t;

typedef struct ms_ecall_decrypt_block_t {
	const char* ms_ciphertext;
	size_t ms_len;
	char* ms_plaintext;
} ms_ecall_decrypt_block_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_enclave = {
	1,
	{
		(void*)enclave_ocall_print_string,
	}
};
sgx_status_t ecall_encrypt_block(sgx_enclave_id_t eid, const char* plaintext, size_t len, char* ciphertext)
{
	sgx_status_t status;
	ms_ecall_encrypt_block_t ms;
	ms.ms_plaintext = plaintext;
	ms.ms_len = len;
	ms.ms_ciphertext = ciphertext;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_decrypt_block(sgx_enclave_id_t eid, const char* ciphertext, size_t len, char* plaintext)
{
	sgx_status_t status;
	ms_ecall_decrypt_block_t ms;
	ms.ms_ciphertext = ciphertext;
	ms.ms_len = len;
	ms.ms_plaintext = plaintext;
	status = sgx_ecall(eid, 1, &ocall_table_enclave, &ms);
	return status;
}

