SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

App_Include_Paths := -I$(SGX_SDK)/include -Inode
App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)
App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread

ifneq ($(SGX_DEBUG), 1)
	App_C_Flags += -O2
else
	App_C_Flags += -g -O0
endif

.PHONY: all clean run

all: app enclave.signed.so

######## Generazione dei file ponte tramite Edger8r ########
node/enclave_u.c node/enclave_u.h: enclave/enclave.edl
	@cd node && $(SGX_EDGER8R) --untrusted ../enclave/enclave.edl --search-path $(SGX_SDK)/include

######## Compilazione dell'Host App ########
node/enclave_u.o: node/enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@

node/main.o: node/main.c node/enclave_u.h
	@$(CC) $(App_C_Flags) -c $< -o $@

app: node/enclave_u.o node/main.o
	@$(CC) $^ -o $@ $(App_Link_Flags)
	@echo "-> Creato l'eseguibile dell'Host: app"

######## Compilazione e Firma dell'Enclave ########
enclave.signed.so:
	@$(MAKE) -C enclave
	@cp enclave/enclave.signed.so .
	@echo "-> Enclave compilata e firmata con successo!"

######## Pulizia ########
clean:
	@$(MAKE) -C enclave clean
	@rm -f app node/main.o node/enclave_u.o node/enclave_u.c node/enclave_u.h enclave.signed.so
	@echo "Pulizia completata."
