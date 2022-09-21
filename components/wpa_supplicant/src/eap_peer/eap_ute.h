/*
 * EAP server/peer: EAP-UTE (draft-rieckers-emu-eap-ute-00)
 */

#include "mbedtls/md.h"

#ifndef EAP_UTE_H
#define EAP_UTE_H

typedef enum {
    EAP_UTE_STATE_UNREGISTERED = 0,
    EAP_UTE_STATE_WAITING_FOR_OOB = 1,
    EAP_UTE_STATE_OOB_RECEIVED = 2,
    EAP_UTE_STATE_REGISTERED = 3
} eap_ute_state_machine_t;

typedef struct esp_eap_ute_oob_msg_node {
    struct esp_eap_ute_oob_msg *value;
    struct esp_eap_ute_oob_msg_node *next;
} esp_eap_ute_oob_msg_node_t;

struct eap_ute_ephemeral_state_info {
    u8 initial_hash[32];
    u8 nonce_peer[32];
    u8 nonce_server[32];
    u8 *ecdhe_shared_secret;
    size_t ecdhe_shared_secret_length;
    esp_eap_ute_oob_msg_node_t *oobMessages;
    mbedtls_md_context_t hash_context;
};

struct eap_ute_state {
    bool active;
    bool persistent;
    u8 supported_dir;
    eap_ute_state_machine_t ute_state;
    int version;
    int ecdhe_curve;
    int hash_algo;
    u8 peerid[16];
    u8 shared_secret[32];
    int version_prev;
    int ecdhe_curve_prev;
    int hash_algo_prev;
    u8 shared_secret_prev[32];
    bool prev_active;
    struct eap_ute_ephemeral_state_info *ephemeral_state;
    esp_eap_ute_oob_msg_t *oobMsg;
};

bool eap_ute_receive_oob_msg(esp_eap_ute_oob_msg_t *oobMsg);
esp_eap_ute_oob_msg_t *eap_ute_generate_oob_msg(void);

#endif /* EAP_UTE_H */
