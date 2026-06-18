SGX_SDK ?= /opt/intel/sgxsdk
SGX_INCLUDE := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc

# Compilazione dell'enclave (libreria fidata)
all: enclave.o enclave_t.o

enclave.o: enclave.c
	gcc -c enclave.c $(SGX_INCLUDE) -nostdinc -fvisibility=hidden -fpie -fstack-protector -o enclave.o

enclave_t.o: enclave_t.c
	gcc -c enclave_t.c $(SGX_INCLUDE) -nostdinc -fvisibility=hidden -fpie -fstack-protector -o enclave_t.o

clean:
	rm -f *.o
