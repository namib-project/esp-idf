/*
 * EAP server/peer: EAP-NOOB (RFC 9140)
 */

#ifndef EAP_NOOB_H
#define EAP_NOOB_H

struct eap_noob_ephemeral_state_info {
    int verp;
    char *peer_id; //0-byte terminated
    int cryptosuitep;
    int dirp;
    char *nai; //0-byte terminated, simple string
    char *peer_info; //0-byte terminated, formatted as JSON map
    int keying_mode;
    u8 ns[32];
    u8 np[32];
    u8 noob[16];
    u8 *shared_secret;
    size_t shared_secret_length;
    u8 secret_key_base[320];
    u8 macp[32];
    u8 macs[32];
};

struct eap_noob_state {
    bool active;
    bool persistent;
    u8 noob_state;
    char *peer_id; //0-byte terminated!
    int version;
    int cryptosuite;
    int cryptosuite_prev;
    char *nai; // 0-byte terminated!
    u8 kz[32];
    u8 kz_prev[32];
    struct eap_noob_ephemeral_state_info *ephemeral_state;
};

#endif /* EAP_NOOB_H */
