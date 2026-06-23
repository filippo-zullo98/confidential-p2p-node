SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW

# 1. Scegliamo le librerie giuste in base alla modalità (Simulazione o Hardware)
ifeq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
else
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
endif

SGX_INCLUDE := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc

# 2. Flag di linking obbligatori per il linker di Intel SGX (Magia Nera di basso livello)
Enclave_Link_Flags := -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_SDK)/lib64 \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcrypto -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
	-Wl,--defsym,__ImageBase=0

# Il nuovo target finale che l'Host si aspetta
all: enclave.signed.so

enclave.o: enclave.c
	gcc -c enclave.c $(SGX_INCLUDE) -nostdinc -fvisibility=hidden -fpie -fstack-protector -o enclave.o

enclave_t.o: enclave_t.c
	gcc -c enclave_t.c $(SGX_INCLUDE) -nostdinc -fvisibility=hidden -fpie -fstack-protector -o enclave_t.o

# 3. Fase di LINKING: unisce i file .o nella libreria enclave.so
enclave.so: enclave.o enclave_t.o
	gcc enclave.o enclave_t.o -o enclave.so $(Enclave_Link_Flags)

# 4. Fase di FIRMA: genera l'hash e firma la libreria usando la chiave privata generata prima
enclave.signed.so: enclave.so
	$(SGX_SDK)/bin/x64/sgx_sign sign -key enclave_private.pem -enclave enclave.so -out enclave.signed.so

clean:
	rm -f *.o enclave.so enclave.signed.so
