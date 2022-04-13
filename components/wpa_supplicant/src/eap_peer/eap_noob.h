/*
 * EAP server/peer: EAP-NOOB (RFC 9140)
 */

#ifndef EAP_NOOB_H
#define EAP_NOOB_H

typedef enum {
    EAP_NOOB_STATE_UNREGISTERED = 0,
    EAP_NOOB_STATE_WAITING_FOR_OOB = 1,
    EAP_NOOB_STATE_OOB_RECEIVED = 2,
    EAP_NOOB_STATE_RECONNECTING = 3,
    EAP_NOOB_STATE_REGISTERED = 4
} eap_noob_state;

enum {
    EAP_NOOB_OOB_DIRECTION_PEER_TO_SERVER = 1,
    EAP_NOOB_OOB_DIRECTION_SERVER_TO_PEER = 2,
    EAP_NOOB_OOB_DIRECTION_BOTH = EAP_NOOB_OOB_DIRECTION_PEER_TO_SERVER ^ EAP_NOOB_OOB_DIRECTION_SERVER_TO_PEER
};

typedef struct eap_noob_oob_msg {
    u8 noob[16];
    u8 noob_id[16];
    u8 hoob[16];
    u8 dir;
} eap_noob_oob_msg_t;

typedef struct eap_noob_oob_msg_node {
    struct eap_noob_oob_msg *value;
    struct eap_noob_oob_msg_node *next;
} eap_noob_oob_msg_node_t;

struct eap_noob_ephemeral_state_info {
    char *hash_base_string; // String, 0-byte terminated
    u8 *shared_secret;
    size_t shared_secret_length;
    u8 np[32];
    u8 ns[32];
    eap_noob_oob_msg_node_t *oobMessages;
};

struct eap_noob_state {
    bool active;
    bool persistent;
    u8 supported_dir; // 0x01 Peer->Server 0x02 Server->Peer, XOR
    eap_noob_state noob_state;
    char *peer_id; // String, 0-byte terminated!
    int version;
    int cryptosuite;
    int cryptosuite_prev;
    char *nai; // String, 0-byte terminated!
    u8 kz[32];
    u8 kz_prev[32];
    struct eap_noob_ephemeral_state_info *ephemeral_state;
};

static void *eap_noob_init(struct eap_sm *sm);
static void eap_noob_deinit(struct eap_sm *sm, void *priv);
static struct wpabuf *eap_noob_process(struct eap_sm *sm, void *priv, struct eap_method_ret *ret, const struct wpabuf *reqData);
static bool eap_noob_isKeyAvailable(struct eap_sm *sm, void *priv);
static u8 *eap_noob_getKey(struct eap_sm *sm, void *priv, size_t *len);
static u8 *eap_noob_get_emsk(struct eap_sm *sm, void *priv, size_t *len);

static bool eap_noob_receive_oob_msg(eap_noob_oob_msg_t *oobMsg);
static eap_noob_oob_msg_t *eap_noob_generate_oob_msg(void);

#endif /* EAP_NOOB_H */