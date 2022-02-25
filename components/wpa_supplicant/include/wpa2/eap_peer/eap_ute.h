/*
 * EAP server/peer: EAP-UTE (draft-rieckers-emu-eap-ute-00)
 */

#ifndef EAP_UTE_H
#define EAP_UTE_H

struct eap_ute_persistent_state {
    u8 *nai;
    int nai_length;
    u8 *peer_id;
    int peer_id_length;
    int version;
    int cryptosuite;
    u8 assoc_key[32];
    u8 assoc_key_prev[32];
};

struct eap_ute_ephemeral_state {
    u8 *nai;
    int nai_length;
    u8 *peer_id;
    int peer_id_length;
    int version;
    int cryptosuite;
    u8 *shared_key;
    int shared_key_length;
};

#endif /* EAP_UTE_H */
