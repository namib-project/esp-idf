/*
 * EAP server/peer: EAP-NOOB (RFC 9140)
 */

#ifndef EAP_NOOB_H
#define EAP_NOOB_H

struct eap_noob_state {
    bool active;
    bool persistent;
    u8 noob_state;
    char *peer_id; //0-byte terminated!
    int version;
    int cryptosuite;
    int cryptosuite_prev;
    char *nai; // 0-byte terminated!
    int nai_length;
    u8 kz[32];
    u8 kz_prev[32];
    u8 *shared_key;
    int shared_key_length;
};

#endif /* EAP_NOOB_H */
