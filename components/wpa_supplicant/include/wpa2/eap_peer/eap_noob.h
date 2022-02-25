/*
 * EAP server/peer: EAP-NOOB (RFC 9140)
 */

#ifndef EAP_NOOB_H
#define EAP_NOOB_H

struct eap_noob_persistent_state {
    u8 *peer_id;
    int peer_id_length;
    int version;
    int cryptosuite;
    int cryptosuite_prev;
    u8 *nai;
    int nai_length;
    u8 kz[32];
    u8 kz_prev[32];
};

struct eap_noob_ephemeral_state {
    u8 *peer_id;
    int peer_id_length;
    int version;
    int cryptosuite;
    u8 *nai;
    int nai_length;
    u8 *shared_key;
    int shared_key_length;
}

#endif /* EAP_NOOB_H */
