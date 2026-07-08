#ifndef P2P_NETWORK_H
#define P2P_NETWORK_H

#include "sgx_urts.h"
#include <pthread.h>

#define MAX_BUFFER_SIZE 2048

// Share the global Enclave ID across modules
extern sgx_enclave_id_t global_eid;

/*
 * Spawns the background server worker thread to listen for incoming 
 * P2P connections and handle ECDH handshakes.
 */
int start_p2p_listener(int port, pthread_t* thread_id);

/*
 * Connects to a remote peer, performs the live ECDH handshake, 
 * encrypts the message via AES-GCM within the TEE, and transmits it.
 */
void transmit_secure_message(const char* target_ip, int target_port, const char* plaintext_message);

#endif // P2P_NETWORK_H
