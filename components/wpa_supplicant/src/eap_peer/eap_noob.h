/*
 * EAP server/peer: EAP-NOOB (RFC 9140)
 */

#ifndef EAP_NOOB_H
#define EAP_NOOB_H

struct eap_noob_ephemeral_state_info {
    char *vers; //0-byte terminated, formatted as JSON array of integers
    int verp;
    char *peer_id; //0-byte terminated
    char *cryptosuites; //0-byte terminated, formatted as JSON array of integers
    char *server_info; //0-byte terminated, formatted as JSON map
    int cryptosuitep;
    int dirp;
    char *nai; //0-byte terminated, simple string
    char *peer_info; //0-byte terminated, formatted as JSON map
    int keying_mode;
    char *pks; //0-byte terminated, formatted as JSON map
    u8 ns[32];
    char *pkp; //0-byte terminated, formatted as JSON map
    u8 np[32];
    u8 noob[16];
    u8 *shared_secret;
    size_t shared_secret_length;
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
