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

######## Bridge Files Generation via Edger8r ########
# Crucial: This target now generates BOTH untrusted and trusted bridge files 
# before any compilation rule takes place.
node/enclave_u.c node/enclave_u.h enclave/enclave_t.c enclave/enclave_t.h: enclave/enclave.edl
	@mkdir -p node
	@$(SGX_EDGER8R) --untrusted enclave/enclave.edl --search-path $(SGX_SDK)/include --untrusted-dir node
	@$(SGX_EDGER8R) --trusted enclave/enclave.edl --search-path $(SGX_SDK)/include --trusted-dir enclave
	@echo "-> Edge generated bridge files successfully (Host & Enclave targets)."

######## Host App Compilation ########
node/enclave_u.o: node/enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@

node/main.o: node/main.c node/enclave_u.h
	@$(CC) $(App_C_Flags) -c $< -o $@

app: node/enclave_u.o node/main.o
	@$(CC) $^ -o $@ $(App_Link_Flags)
	@echo "-> Host executable compiled successfully: app"

######## Enclave Compilation and Signing ########
# We enforce that enclave_t.h must exist before calling the inner Makefile
enclave.signed.so: enclave/enclave_t.c enclave/enclave_t.h
	@$(MAKE) -C enclave SGX_DEBUG=$(SGX_DEBUG) SGX_MODE=$(SGX_MODE)
	@cp enclave/enclave.signed.so .
	@echo "-> Enclave compiled and signed successfully!"

######## Cleanup ########
clean:
	@$(MAKE) -C enclave clean
	@rm -f app node/main.o node/enclave_u.o node/enclave_u.c node/enclave_u.h
	@rm -f enclave/enclave_t.c enclave/enclave_t.h enclave.signed.so
	@echo "Cleanup completed successfully."
