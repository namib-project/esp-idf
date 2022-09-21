/*
 * EAP peer method: EAP-UTE (draft-rieckers-emu-eap-ute-00.txt)
 */

//#ifdef EAP_UTE


#include "utils/includes.h"
#include "utils/common.h"

#include "eap_peer/eap_i.h"
#include "eap_peer/eap_config.h"
#include "eap_peer/eap_methods.h"
#include "eap_peer/eap_ute.h"
#include "tinycbor/cbor.h"

#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"

struct eap_ute_state g_wpa_eap_ute_state;

enum eap_ute_error_codes {
    EAP_UTE_ERROR_INVALID_MESSAGE_STRUCTURE = 1,
    EAP_UTE_ERROR_UNEXPECTED_MESSAGE_TYPE = 2,
    EAP_UTE_ERROR_MISSING_MANDATORY_FIELD = 3,
    EAP_UTE_ERROR_VERSION_MISMATCH = 4,
    EAP_UTE_ERROR_CIPHER_MISMATCH = 5,
    EAP_UTE_ERROR_APPLICATION_SPECIFIC_ERROR = 6,
    EAP_UTE_ERROR_MAC_MISMATCH = 7,
};

enum eap_ute_internal_state {
    EAP_UTE_INTERNAL_STATE_INITIAL,
    EAP_UTE_INTERNAL_STATE_CLIENT_GREETING_SENT,
    EAP_UTE_INTERNAL_STATE_CLIENT_KEYSHARE_SENT,
    EAP_UTE_INTERNAL_STATE_CLIENT_COMPLETION_REQUEST_SENT,
    EAP_UTE_INTERNAL_STATE_CLIENT_FINISHED_SENT,
};

enum eap_ute_exchange_type {
    EAP_UTE_EXCHANGE_TYPE_NONE,
    EAP_UTE_EXCHANGE_TYPE_INITIAL,
    EAP_UTE_EXCHANGE_TYPE_COMPLETION,
    EAP_UTE_EXCHANGE_TYPE_RECONNECT_STATIC,
    EAP_UTE_EXCHANGE_TYPE_RECONNECT_PFS
};

enum eap_ute_msg_type {
    EAP_UTE_MSG_TYPE_ERROR = 0,
    EAP_UTE_MSG_TYPE_SERVER_GREETING = 1,
    EAP_UTE_MSG_TYPE_CLIENT_GREETING = 2,
    EAP_UTE_MSG_TYPE_SERVER_KEYSHARE = 3,
    EAP_UTE_MSG_TYPE_CLIENT_FINISHED = 4,
    EAP_UTE_MSG_TYPE_CLIENT_COMPLETION_REQUEST = 5,
    EAP_UTE_MSG_TYPE_SERVER_COMPLETION_RESPONSE = 6,
    EAP_UTE_MSG_TYPE_CLIENT_KEYSHARE = 7,
};

enum eap_ute_map_key_type {
    EAP_UTE_MAP_KEY_VERSIONS = 1,
    EAP_UTE_MAP_KEY_VERSION = 2,
    EAP_UTE_MAP_KEY_CIPHERS = 3,
    EAP_UTE_MAP_KEY_CIPHER = 4,
    EAP_UTE_MAP_KEY_DIRECTIONS = 5,
    EAP_UTE_MAP_KEY_DIRECTION = 6,
    EAP_UTE_MAP_KEY_SERVER_INFO = 7,
    EAP_UTE_MAP_KEY_PEER_INFO = 8,
    EAP_UTE_MAP_KEY_NONCE_PEER = 9,
    EAP_UTE_MAP_KEY_NONCE_SERVER = 10,
    EAP_UTE_MAP_KEY_KEY_PEER = 11,
    EAP_UTE_MAP_KEY_KEY_SERVER = 12,
    EAP_UTE_MAP_KEY_MAC_SERVER = 13,
    EAP_UTE_MAP_KEY_MAC_PEER = 14,
    EAP_UTE_MAP_KEY_PEER_ID = 15,
    EAP_UTE_MAP_KEY_OOB_ID = 16,
    EAP_UTE_MAP_KEY_RETRY_INTERVAL = 17,
    EAP_UTE_MAP_KEY_ADDITIONAL_SERVER_INFO = 18,
};

struct eap_ute_data {
    enum eap_ute_internal_state state;
    enum eap_ute_exchange_type exch_type;
    u8 *kdf_out;
    size_t kdf_out_len;
    u8 nonce_peer[32];
    u8 nonce_server[32];
    u8 *shared_key;
    size_t shared_key_length;
    mbedtls_ecdh_context mbed_ctx;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_md_context_t md_ctx;
    u8 messages_hash[32];
    u8 *msg_save;
    size_t msg_save_len;
    u8 mac_p[32];
    u8 mac_s[32];
    esp_eap_ute_oob_msg_t *oobMsg;
};

/**
 * @brief Calculate the cryptographic material
 * @param data
 * @param keying_mode 0 for completion, 1 for reconnect without ecdhe, 2 for reconnect with ecdhe, 3 for upgrade
 * @param oobMsg only needed for completion exchange, otherwise NULL
 */
static void eap_ute_calculate_kdf(struct eap_ute_data *data, int keying_mode, esp_eap_ute_oob_msg_t *oobMsg)
{
    if (keying_mode == 0 || keying_mode == 3) {
        data->kdf_out_len = 320;
    } else {
        data->kdf_out_len = 288;
    }

    if (keying_mode == 0 && oobMsg == NULL) {
        // Error condition
        return;
    }

    data->kdf_out = malloc(data->kdf_out_len);

    size_t kdf_input_size = 71;
    if (keying_mode == 0 || keying_mode == 2 || keying_mode == 3) {
        kdf_input_size += data->shared_key_length; // Z is ECDHE shared secret
    } else {
        kdf_input_size += 32; // Z is Association_Key
    }

    if (keying_mode == 0) {
        kdf_input_size += 32; // SuppPrivInfo is OOB-Nonce
    }
    if (keying_mode == 2 || keying_mode == 3) {
        kdf_input_size += 32; // SupPrivInfo is Association_key
    }

    u8 *kdf_input = malloc(kdf_input_size + 4);

    size_t cur_ptr = 4;

    // KDF Z
    if (keying_mode == 0 || keying_mode == 2 || keying_mode == 3) {
        memcpy(kdf_input + cur_ptr, data->shared_key, data->shared_key_length);
        cur_ptr += data->shared_key_length;
    } else {
        memcpy(kdf_input + cur_ptr, g_wpa_eap_ute_state.shared_secret, 32);
        cur_ptr += 32;
    }
    // KDF AlgorithmId
    char *alg_id = "EAP-UTE";
    memcpy(kdf_input + cur_ptr, alg_id, 7);
    cur_ptr += 7;
    // KDF PartyUInfo
    memcpy(kdf_input + cur_ptr, data->nonce_peer, 32);
    cur_ptr += 32;
    // KDF PartyVInfo
    memcpy(kdf_input + cur_ptr, data->nonce_server, 32);
    cur_ptr += 32;
    // KDF SuppPrivInfo
    if (keying_mode == 0) {
        memcpy(kdf_input + cur_ptr, oobMsg->nonce, 32);
        cur_ptr += 32;
    }
    if (keying_mode == 2 || keying_mode == 3) {
        memcpy(kdf_input + cur_ptr, g_wpa_eap_ute_state.shared_secret, 32);
        cur_ptr += 32;
    }

    cur_ptr = 0;
    u32 id = 1;
    u8 kdf_out[32];
    while (cur_ptr < data->kdf_out_len) {
        kdf_input[0] = id >> 24;
        kdf_input[1] = id >> 16;
        kdf_input[2] = id >> 8;
        kdf_input[3] = id;

        mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), kdf_input, kdf_input_size, kdf_out);

        if (cur_ptr + 32 <= data->kdf_out_len) {
            memcpy(data->kdf_out + cur_ptr, kdf_out, 32);
            cur_ptr += 32;
        } else {
            memcpy(data->kdf_out + cur_ptr, kdf_out, data->kdf_out_len - cur_ptr);
            cur_ptr = data->kdf_out_len;
        }
    }
}

/**
 * @brief Calculate the Message Authentication Codes for peer and server
 * @param data
 * @param keying_mode
 */
static void eap_ute_calculate_crypto_material(struct eap_ute_data *data, int keying_mode)
{
    u8 *mac_input;
    mbedtls_md_context_t md;

    size_t cur_pos = 1;
    if (keying_mode == 0) {
        mac_input = os_zalloc(1 + 32 + 32 + 32);

        mbedtls_md_init( &md );
        mbedtls_md_setup( &md, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
        mbedtls_md_clone( &md, &g_wpa_eap_ute_state.ephemeral_state->hash_context);
        mbedtls_md_finish( &md, mac_input + cur_pos);
        cur_pos += 32;
        mbedtls_md_free( &md );

        mbedtls_md_init( &md );
        mbedtls_md_setup( &md, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
        mbedtls_md_clone( &md, &data->md_ctx );
        mbedtls_md_finish( &md, mac_input + cur_pos);
        cur_pos += 32;
        mbedtls_md_free( &md );
    } else {
        mac_input = os_zalloc(1 + 32);
        mbedtls_md_init( &md );
        mbedtls_md_setup( &md, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
        mbedtls_md_clone( &md, &data->md_ctx );
        mbedtls_md_finish( &md, mac_input + cur_pos);
        cur_pos += 32;
        mbedtls_md_free( &md );
    }
    mac_input[0] = EAP_UTE_OOB_DIRECTION_SERVER_TO_PEER;
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), data->kdf_out + 224, 32, mac_input, cur_pos, data->mac_s);
    mac_input[0] = EAP_UTE_OOB_DIRECTION_PEER_TO_SERVER;
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), data->kdf_out + 256, 32, mac_input, cur_pos, data->mac_p);
    free(mac_input);
}
/**
 * Calculate OOB-Auth value of the given OOB Message
 */
void eap_ute_calculate_oob_auth(struct esp_eap_ute_oob_msg *oobMsg)
{
    mbedtls_md_context_t auth_ctx;
    mbedtls_md_init( &auth_ctx );
    mbedtls_md_setup(&auth_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
    mbedtls_md_clone (&auth_ctx, &g_wpa_eap_ute_state.ephemeral_state->hash_context);

    mbedtls_md_update(&auth_ctx, oobMsg->nonce, 32);

    u8 dir = oobMsg->oob_dir;
    mbedtls_md_update(&auth_ctx, &dir, 1);

    mbedtls_md_finish(&auth_ctx, oobMsg->auth);
    mbedtls_md_free(&auth_ctx);

    u8 tmp_auth[32];
    mbedtls_md_init( &auth_ctx );
    mbedtls_md_setup(&auth_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
    mbedtls_md_update(&auth_ctx, (unsigned char *)"OOB-Id", strlen("OOB-Id"));
    mbedtls_md_update(&auth_ctx, oobMsg->auth, 32);
    mbedtls_md_finish(&auth_ctx, tmp_auth);
    mbedtls_md_free(&auth_ctx);
}

esp_eap_ute_oob_msg_t *eap_ute_generate_oob_msg(void)
{
    if (g_wpa_eap_ute_state.ephemeral_state == NULL) {
        return NULL;
    }

    esp_eap_ute_oob_msg_node_t *oobMsgNode = os_zalloc(sizeof(esp_eap_ute_oob_msg_node_t));

    if (oobMsgNode == NULL) {
        return NULL;
    }

    struct esp_eap_ute_oob_msg *oobMsg = os_zalloc(sizeof(struct esp_eap_ute_oob_msg));
    if (oobMsg == NULL) {
        return NULL;
    }

    oobMsgNode->value = oobMsg;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );

    int ret_val;
    const char *mbed_seed = "EAP-UTE-Nonce";
    ret_val = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *)mbed_seed, 13);
    if (ret_val != 0) {
        free(oobMsg);
        free(oobMsgNode);
        return NULL;
    }

    mbedtls_ctr_drbg_random(&ctr_drbg, oobMsg->nonce, 32);

    struct eap_ute_ephemeral_state_info *eph = g_wpa_eap_ute_state.ephemeral_state;

    oobMsg->oob_dir = EAP_UTE_OOB_DIRECTION_PEER_TO_SERVER;

    eap_ute_calculate_oob_auth(oobMsg);

    if (eph->oobMessages == NULL) {
        eph->oobMessages = oobMsgNode;
    } else {
        esp_eap_ute_oob_msg_node_t *cur = eph->oobMessages;
        for ( ; cur->next != NULL ; cur = cur->next);
        cur->next = oobMsgNode;
    }

    return oobMsg;
}

/**
 * Receives a new EAP-UTE out-of-band message.
 * If returned `false`, the caller has to free the oobMsg structure, if returned `true`, the freeing is handled by EAP-UTE
 * @param oobMsg
 * @return `true` if the OOB message had the correct auth
 */
bool eap_ute_receive_oob_msg(esp_eap_ute_oob_msg_t *oobMsg)
{
    if (g_wpa_eap_ute_state.ute_state == EAP_UTE_STATE_UNREGISTERED ||
            g_wpa_eap_ute_state.ute_state == EAP_UTE_STATE_REGISTERED) {
        return false;
    }

    mbedtls_md_context_t auth_ctx;
    mbedtls_md_init( &auth_ctx );
    mbedtls_md_setup( &auth_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
    mbedtls_md_clone( &auth_ctx, &g_wpa_eap_ute_state.ephemeral_state->hash_context);

    mbedtls_md_update(&auth_ctx, oobMsg->nonce, 32);

    u8 dir = oobMsg->oob_dir;
    mbedtls_md_update(&auth_ctx, &dir, 1);

    u8 auth_to_check[32];
    mbedtls_md_finish(&auth_ctx, auth_to_check);
    mbedtls_md_free(&auth_ctx);

    // Check the Auth value of the OOB Message
    u8 res = 0;
    for (int i = 0; i < 32; i++) {
        res |= auth_to_check[i] ^ oobMsg->auth[i];
    }

    if (res != 0) {
        wpa_printf(MSG_INFO, "Auth value was wrong.");
        return false;
    }

    u8 tmp_id[32];
    mbedtls_md_init( &auth_ctx);
    mbedtls_md_setup(&auth_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
    mbedtls_md_update(&auth_ctx, (unsigned char *)"OOB-Id", strlen("OOB-Id"));
    mbedtls_md_update(&auth_ctx, oobMsg->auth, 32);
    mbedtls_md_finish(&auth_ctx, tmp_id);
    mbedtls_md_free(&auth_ctx);

    memcpy( oobMsg->oob_id, tmp_id, 16);

    struct eap_ute_ephemeral_state_info *eph = g_wpa_eap_ute_state.ephemeral_state;
    if (eph == NULL) {
        wpa_printf(MSG_INFO, "EAP-UTE: No ephemeral state. Aborting.");
        return false;
    }

    esp_eap_ute_oob_msg_node_t *newNode = os_zalloc(sizeof(esp_eap_ute_oob_msg_node_t));
    newNode->value = oobMsg;

    esp_eap_ute_oob_msg_node_t *oobMsgNode = eph->oobMessages;

    if (oobMsgNode == NULL) {
        eph->oobMessages = newNode;
    } else {
        for ( ; oobMsgNode->next != NULL; oobMsgNode = oobMsgNode->next);
        oobMsgNode->next = newNode;
    }

    g_wpa_eap_ute_state.ute_state = EAP_UTE_STATE_OOB_RECEIVED;

    return true;
}

static void eap_ute_free_ephemeral_state()
{
    if (g_wpa_eap_ute_state.ephemeral_state == NULL) {
        return;
    }

    struct eap_ute_ephemeral_state_info *eph = g_wpa_eap_ute_state.ephemeral_state;
    if (eph->ecdhe_shared_secret != NULL && eph->ecdhe_shared_secret_length != 0) {
        free(eph->ecdhe_shared_secret);
    }

    esp_eap_ute_oob_msg_node_t *cur = eph->oobMessages;
    esp_eap_ute_oob_msg_node_t *next;
    while (cur->next != NULL) {
        next = cur->next;
        free(cur->value);
        free(cur);
        cur = next;
    }

    mbedtls_md_free(&eph->hash_context);

    free(eph);

    g_wpa_eap_ute_state.ephemeral_state = NULL;
}

static void eap_ute_save_ephemeral_state(struct eap_ute_data *data)
{
    eap_ute_free_ephemeral_state();

    g_wpa_eap_ute_state.ephemeral_state = os_zalloc(sizeof(struct eap_ute_ephemeral_state_info));
    struct eap_ute_ephemeral_state_info *eph = g_wpa_eap_ute_state.ephemeral_state;

    if (data->shared_key != NULL) {
        eph->ecdhe_shared_secret = os_zalloc(data->shared_key_length);
        eph->ecdhe_shared_secret_length = data->shared_key_length;
        memcpy(eph->ecdhe_shared_secret, data->shared_key, data->shared_key_length);
    }

    memcpy(eph->initial_hash, data->messages_hash, 32);
    memcpy(eph->nonce_peer, data->nonce_peer, 32);
    memcpy(eph->nonce_server, data->nonce_server, 32);

    mbedtls_md_init(&eph->hash_context);
    mbedtls_md_setup(&eph->hash_context, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);

    mbedtls_md_clone(&eph->hash_context, &data->md_ctx);
}

static void *eap_ute_init(struct eap_sm *sm)
{
    struct eap_ute_data *data;
    data = (struct eap_ute_data *)os_zalloc(sizeof(*data));
    if (data == NULL) {
        return NULL;
    }
    data->state = EAP_UTE_INTERNAL_STATE_INITIAL;
    data->exch_type = EAP_UTE_EXCHANGE_TYPE_NONE;
    mbedtls_md_init(&data->md_ctx);
    mbedtls_md_setup(&data->md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
    return data;
}

static void eap_ute_deinit(struct eap_sm *sm, void *priv)
{
    struct eap_ute_data *data = priv;
    if (data == NULL) {
        return;
    }

    if (data->kdf_out_len != 0 && data->kdf_out != NULL) {
        os_free(data->kdf_out);
    }

    if (data->shared_key_length != 0 && data->shared_key != NULL) {
        os_free(data->shared_key);
    }

    mbedtls_md_free(&data->md_ctx);

    os_free(data);
}

static bool check_array_for_value(CborValue *arr, int to_check)
{
    CborValue inner_val;
    CborError err;
    int val;

    wpa_printf(MSG_INFO, "EAP-UTE: Array check: Initialize");
    err = cbor_value_enter_container(arr, &inner_val);
    if (err != CborNoError) {
        wpa_printf(MSG_INFO, "EAP-UTE: Array check: Error in entering container");
        return false;
    }
    while (!cbor_value_at_end(&inner_val)) {
        if (!cbor_value_is_integer(&inner_val)) {
            wpa_printf(MSG_INFO, "EAP-UTE: Array check: value is not an integer");
            err = cbor_value_advance(&inner_val);
            if (err != CborNoError) {
                wpa_printf(MSG_INFO, "EAP-UTE: Array check: error advancing");
                return false;
            }
        }
        err = cbor_value_get_int_checked(&inner_val, &val);
        if (err == CborNoError && val == to_check) {
            while (!cbor_value_at_end(&inner_val)) {
                err = cbor_value_advance(&inner_val);
                if (err != CborNoError) {
                    wpa_printf(MSG_INFO, "EAP-UTE: Array check: error advancing");
                    return false;
                }
            }
            return true;
        } else {
            wpa_printf(MSG_INFO, "EAP-UTE: Array check: error in getting ");
        }
        err = cbor_value_advance(&inner_val);
        if (err != CborNoError) {
            wpa_printf(MSG_INFO, "EAP-UTE: Array check: error advancing");
            return false;
        }
    }
    wpa_printf(MSG_INFO, "EAP-UTE: Array check: item not found.");
    return false;
}

/**
 * Generate a Nonce
 * @param out buffer to store the generated nonce (needs to be allocated before
 * @param len length of buffer
 * @return 0 on OK, 1 on error
 * @todo Correct error code needs to be returned
 */
static int eap_ute_generate_nonce(u8 *out, size_t len)
{
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init( &ctr_drbg );

    const char *mbed_seed = "nonce_seed";

    int ret_val = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *)mbed_seed, 10);
    if (ret_val != 0) {
        // todo return correct error code
        return 1;
    }
    ret_val = mbedtls_ctr_drbg_random(&ctr_drbg, out, len);
    if (ret_val != 0 ) {
        // todo return correct error code
        return 1;
    }
    return 0;
}

/**
 * Generate an ECDHE key
 * @param data struct where the mbed context should be saved
 * @param keyout buffer (32 byte) to store the public key in
 * @return 0 on OK, 1 on error
 */
static int eap_ute_generate_ecdhe_key(struct eap_ute_data *data, u8 *keyout)
{
    mbedtls_ecdh_context *x25519_ctx = &data->mbed_ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context *ctr_drbg = &data->ctr_drbg;
    mbedtls_ecdh_init( x25519_ctx );
    mbedtls_ctr_drbg_init( ctr_drbg );
    mbedtls_entropy_init( &entropy );
    int result;
    const char *mbed_seed = "ecdh";
    mbedtls_ecdh_context_mbed *x25519_ctx_m = &x25519_ctx->MBEDTLS_PRIVATE(ctx).MBEDTLS_PRIVATE(mbed_ecdh);
    result = mbedtls_ctr_drbg_seed( ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *)mbed_seed, 4);
    if (result != 0) {
        return 1;
    }
    result = mbedtls_ecp_group_load( &x25519_ctx_m->MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_CURVE25519);
    if (result != 0) {
        return 1;
    }
    result = mbedtls_ecdh_gen_public( &x25519_ctx_m->MBEDTLS_PRIVATE(grp), &x25519_ctx_m->MBEDTLS_PRIVATE(d), &x25519_ctx_m->MBEDTLS_PRIVATE(Q), mbedtls_ctr_drbg_random, ctr_drbg );
    if (result != 0) {
        return 1;
    }
    result = mbedtls_mpi_write_binary_le( &x25519_ctx_m->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X), keyout, 32);
    if (result != 0) {
        return 1;
    }
    return 0;
}

static esp_eap_ute_oob_msg_t *eap_ute_check_for_usable_oob_msg()
{
    if (g_wpa_eap_ute_state.ute_state == EAP_UTE_STATE_UNREGISTERED ||
            g_wpa_eap_ute_state.ute_state == EAP_UTE_STATE_REGISTERED) {
        return NULL;
    }

    struct eap_ute_ephemeral_state_info *eph = g_wpa_eap_ute_state.ephemeral_state;
    if (eph == NULL) {
        return NULL;
    }

    esp_eap_ute_oob_msg_node_t *cur = eph->oobMessages;
    for ( ; cur != NULL; cur = cur->next) {
        if (cur->value->oob_dir == EAP_UTE_OOB_DIRECTION_SERVER_TO_PEER) {
            return cur->value;
        }
    }

    return NULL;
}

static esp_eap_ute_oob_msg_t *eap_ute_get_oob_msg_by_id(u8 *oob_id)
{
    if (g_wpa_eap_ute_state.ute_state == EAP_UTE_STATE_UNREGISTERED ||
            g_wpa_eap_ute_state.ute_state == EAP_UTE_STATE_REGISTERED) {
        return NULL;
    }

    struct eap_ute_ephemeral_state_info *eph = g_wpa_eap_ute_state.ephemeral_state;
    if (eph == NULL) {
        return NULL;
    }

    esp_eap_ute_oob_msg_node_t *cur = eph->oobMessages;
    for ( ; cur != NULL; cur = cur->next) {
        if (cur->value->oob_dir == EAP_UTE_OOB_DIRECTION_PEER_TO_SERVER) {
            if (memcmp(cur->value->oob_id, oob_id, 16)) {
                return cur->value;
            }
        }
    }
    return NULL;
}

/**
 * Build en error message
 * @param reqData
 * @param errorcode
 * @return wpabuf to send to the server
 */
static struct wpabuf *build_error_msg(const struct wpabuf *reqData, int errorcode)
{
    wpa_printf(MSG_INFO, "EAP-UTE: Sending Error message!");
    // TODO not yet implemented
    return NULL;
}

static struct wpabuf *eap_ute_send_client_greeting(struct eap_sm *sm, struct eap_ute_data *data, struct eap_method_ret *ret, const struct wpabuf *reqData)
{
    // Generate a new nonce
    int nonce_stat = eap_ute_generate_nonce(data->nonce_peer, 32);
    if (nonce_stat != 0) {
        wpa_printf(MSG_INFO, "EAP-UTE: Error in nonce generation");
        // todo correct error code
        return build_error_msg(reqData, 11);
    }

    // Calculate X25519 key
    u8 mykey[32];
    int result = eap_ute_generate_ecdhe_key(data, mykey);
    if (result != 0) {
        wpa_printf(MSG_INFO, "EAP-UTE: Error in ECHDE key generation");
        // todo correct error code
        return build_error_msg(reqData, 12);
    }

    // Build CBOR return values
    u8 cbor_buf[1500];
    CborEncoder encoder, mapEncoder, cipherEncoder, peerInfoEncoder, keyEncoder;
    cbor_encoder_init(&encoder, cbor_buf, sizeof(cbor_buf), 0);
    cbor_encoder_create_map(&encoder, &mapEncoder, 6);

    cbor_encode_int(&mapEncoder, EAP_UTE_MAP_KEY_VERSION);
    cbor_encode_int(&mapEncoder, 1);

    cbor_encode_int(&mapEncoder, EAP_UTE_MAP_KEY_CIPHER);
    cbor_encoder_create_array(&mapEncoder, &cipherEncoder, 2);
    cbor_encode_int(&cipherEncoder, 4);
    cbor_encode_int(&cipherEncoder, -16);
    cbor_encoder_close_container(&mapEncoder, &cipherEncoder);

    cbor_encode_int(&mapEncoder, EAP_UTE_MAP_KEY_PEER_INFO);
    cbor_encoder_create_map(&mapEncoder, &peerInfoEncoder, 0);
    cbor_encoder_close_container(&mapEncoder, &peerInfoEncoder);

    if (g_wpa_eap_ute_state.ute_state == EAP_UTE_STATE_REGISTERED) {
        // If we are registered, this is a Upgrade Exchange.
        cbor_encode_int(&mapEncoder, EAP_UTE_MAP_KEY_PEER_ID);
        cbor_encode_byte_string(&mapEncoder, g_wpa_eap_ute_state.peerid, 16);
    } else {
        // If we are not registered, this is an Initial Exchange.
        cbor_encode_int(&mapEncoder, EAP_UTE_MAP_KEY_DIRECTION);
        cbor_encode_int(&mapEncoder, 1);
    }

    cbor_encode_int(&mapEncoder, EAP_UTE_MAP_KEY_NONCE_PEER);
    cbor_encode_byte_string(&mapEncoder, data->nonce_peer, 32);

    cbor_encode_int(&mapEncoder, EAP_UTE_MAP_KEY_KEY_PEER);
    cbor_encoder_create_map(&mapEncoder, &keyEncoder, 2);
    cbor_encode_int(&keyEncoder, -1);
    cbor_encode_int(&keyEncoder, 4);
    cbor_encode_int(&keyEncoder, -2);
    cbor_encode_byte_string(&keyEncoder, mykey, 32);
    cbor_encoder_close_container(&mapEncoder, &keyEncoder);

    cbor_encoder_close_container(&encoder, &mapEncoder);

    size_t cbor_len = cbor_encoder_get_buffer_size(&encoder, cbor_buf);

    u8 final_cbor[1500];
    cbor_encoder_init(&encoder, final_cbor, sizeof(final_cbor), 0);
    cbor_encode_int(&encoder, EAP_UTE_MSG_TYPE_CLIENT_GREETING);
    size_t prelude_len = cbor_encoder_get_buffer_size(&encoder, final_cbor);
    cbor_encoder_init(&encoder, final_cbor + prelude_len, sizeof(final_cbor) - prelude_len, 0);
    cbor_encode_byte_string(&encoder, cbor_buf, cbor_len);

    cbor_len = cbor_encoder_get_buffer_size(&encoder, final_cbor + prelude_len);

    mbedtls_md_update(&data->md_ctx, final_cbor, prelude_len + cbor_len);

    struct wpabuf *to_return = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_UTE, prelude_len + cbor_len, EAP_CODE_RESPONSE, eap_get_id(reqData));

    wpabuf_put_data(to_return, final_cbor, prelude_len + cbor_len);

    data->state = EAP_UTE_INTERNAL_STATE_CLIENT_GREETING_SENT;

    return to_return;
}

static struct wpabuf *eap_ute_send_client_completion_request(struct eap_sm *sm, struct eap_ute_data *data, struct eap_method_ret *ret, const struct wpabuf *reqData)
{
    int nonce_stat = eap_ute_generate_nonce(data->nonce_peer, 32);
    if (nonce_stat != 0) {
        wpa_printf(MSG_INFO, "EAP-UTE: error in nonce generation");
        return build_error_msg(reqData, EAP_UTE_ERROR_APPLICATION_SPECIFIC_ERROR);
    }


    if (g_wpa_eap_ute_state.ute_state != EAP_UTE_STATE_REGISTERED) {
        data->oobMsg = eap_ute_check_for_usable_oob_msg();
    }

    u8 cbor_buf[1500];
    CborEncoder encoder, mapEncoder;
    cbor_encoder_init(&encoder, cbor_buf, sizeof(cbor_buf), 0);
    cbor_encoder_create_map(&encoder, &mapEncoder, data->oobMsg == NULL ? 2 : 3);

    cbor_encode_int(&mapEncoder, EAP_UTE_MAP_KEY_PEER_ID);
    cbor_encode_byte_string(&mapEncoder, g_wpa_eap_ute_state.peerid, 16);

    cbor_encode_int(&mapEncoder, EAP_UTE_MAP_KEY_NONCE_PEER);
    cbor_encode_byte_string(&mapEncoder, data->nonce_peer, 32);

    if (data->oobMsg != NULL) {
        cbor_encode_int(&mapEncoder, EAP_UTE_MAP_KEY_OOB_ID);
        cbor_encode_byte_string(&mapEncoder, data->oobMsg->oob_id, 16);
    }

    cbor_encoder_close_container(&encoder, &mapEncoder);

    size_t cbor_len = cbor_encoder_get_buffer_size(&encoder, cbor_buf);

    u8 final_cbor[1500];
    cbor_encoder_init(&encoder, final_cbor, sizeof(final_cbor), 0);
    cbor_encode_int(&encoder, EAP_UTE_MSG_TYPE_CLIENT_COMPLETION_REQUEST);
    size_t prelude_len = cbor_encoder_get_buffer_size(&encoder, final_cbor);
    cbor_encoder_init(&encoder, final_cbor + prelude_len, sizeof(final_cbor) - prelude_len, 0);
    cbor_encode_byte_string(&encoder, cbor_buf, cbor_len);

    cbor_len = cbor_encoder_get_buffer_size(&encoder, final_cbor + prelude_len);

    mbedtls_md_update(&data->md_ctx, final_cbor, prelude_len + cbor_len);

    struct wpabuf *to_return = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_UTE, prelude_len + cbor_len, EAP_CODE_RESPONSE, eap_get_id(reqData));

    wpabuf_put_data(to_return, final_cbor, prelude_len + cbor_len);

    data->state = EAP_UTE_INTERNAL_STATE_CLIENT_COMPLETION_REQUEST_SENT;

    return to_return;
}

static struct wpabuf *eap_ute_send_client_finished(struct eap_sm *sm, struct eap_ute_data *data, struct eap_method_ret *ret, const struct wpabuf *reqData, bool include_mac)
{
    u8 cbor_buf[1500];
    u8 additional_buf[1500];
    size_t cbor_len;
    size_t additional_len = 0;
    CborEncoder encoder, mapEncoder;
    cbor_encoder_init(&encoder, cbor_buf, sizeof(cbor_buf), 0);
    cbor_encoder_create_map(&encoder, &mapEncoder, include_mac ? 1 : 0);

    if (include_mac) {
        cbor_encode_int(&mapEncoder, EAP_UTE_MAP_KEY_MAC_PEER);
        cbor_encode_null(&mapEncoder);
    }

    cbor_encoder_close_container(&encoder, &mapEncoder);
    cbor_len = cbor_encoder_get_buffer_size(&encoder, cbor_buf);

    if (include_mac) {
        cbor_encoder_init(&encoder, additional_buf, sizeof(additional_buf), 0);
        cbor_encoder_create_map(&encoder, &mapEncoder, 1);

        cbor_encode_int(&mapEncoder, EAP_UTE_MAP_KEY_MAC_PEER);
        cbor_encode_byte_string(&mapEncoder, data->mac_p, 32);

        cbor_encoder_close_container(&encoder, &mapEncoder);
        additional_len = cbor_encoder_get_buffer_size(&encoder, additional_buf);
    }

    u8 final_cbor[1500];
    cbor_encoder_init(&encoder, final_cbor, sizeof(final_cbor), 0);
    cbor_encode_int(&encoder, EAP_UTE_MSG_TYPE_CLIENT_FINISHED);
    size_t prelude_len = cbor_encoder_get_buffer_size(&encoder, final_cbor);

    cbor_encoder_init(&encoder, final_cbor + prelude_len, sizeof(final_cbor) - prelude_len, 0);
    cbor_encode_byte_string(&encoder, cbor_buf, cbor_len);
    cbor_len = cbor_encoder_get_buffer_size(&encoder, final_cbor + prelude_len);

    if (include_mac) {
        cbor_encoder_init(&encoder, final_cbor + prelude_len + cbor_len, sizeof(final_cbor) - prelude_len - cbor_len, 0);
        cbor_encode_byte_string(&encoder, additional_buf, additional_len);
        additional_len = cbor_encoder_get_buffer_size(&encoder, final_cbor + prelude_len + cbor_len);
    }

    struct wpabuf *to_return = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_UTE, prelude_len + cbor_len + additional_len, EAP_CODE_RESPONSE, eap_get_id(reqData));
    wpabuf_put_data(to_return, final_cbor, prelude_len + cbor_len + additional_len);

    u8 hash_out[32];
    mbedtls_md_context_t hash_final;
    mbedtls_md_init(&hash_final);
    mbedtls_md_setup(&hash_final, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);

    mbedtls_md_clone(&hash_final, &data->md_ctx);

    mbedtls_md_finish(&hash_final, data->messages_hash);
    mbedtls_md_free(&hash_final);

    wpa_hexdump(MSG_INFO, "EAP-UTE: hash output", hash_out, 32);

    data->state = EAP_UTE_INTERNAL_STATE_CLIENT_FINISHED_SENT;

    eap_ute_save_ephemeral_state(data);

    return to_return;
}

static struct wpabuf *eap_ute_handle_server_greeting(struct eap_sm *sm, struct eap_ute_data *data, struct eap_method_ret *ret, const struct wpabuf *reqData, const u8 *payload, size_t payload_len, const u8 *additional, size_t additional_len)
{
    CborParser parser;
    CborValue value;
    CborValue map_value;
    CborError err;

    wpa_printf(MSG_INFO, "EAP-UTE: Handling server greeting");

    err = cbor_parser_init(payload, payload_len, 0, &parser, &value);
    if (err != CborNoError) {
        wpa_printf(MSG_INFO, "EAP-UTE: Error initializing CBOR parser");
        return build_error_msg(reqData, EAP_UTE_ERROR_APPLICATION_SPECIFIC_ERROR);
    }
    if (!cbor_value_is_map(&value)) {
        wpa_printf(MSG_INFO, "EAP-UTE: CBOR payload was not a map");
        return build_error_msg(reqData, EAP_UTE_ERROR_INVALID_MESSAGE_STRUCTURE);
    }
    err = cbor_value_enter_container(&value, &map_value);
    if (err != CborNoError) {
        wpa_printf(MSG_INFO, "EAP-UTE: CBOR Parsing error");
        return build_error_msg(reqData, EAP_UTE_ERROR_APPLICATION_SPECIFIC_ERROR);
    }

    int map_key;
    uint8_t versions_seen = 0;
    uint8_t ciphers_seen = 0;
    uint8_t directions_seen = 0;

    while (!cbor_value_at_end(&map_value)) {
        if (!cbor_value_is_integer(&map_value)) {
            wpa_printf(MSG_INFO, "EAP-UTE: Map key was no integer");
            // TODO correct error code
            return build_error_msg(reqData, 2);
        }
        err = cbor_value_get_int_checked(&map_value, &map_key);
        // TODO: check for other error here, large ints may be used for extensions
        if (err != CborNoError) {
            wpa_printf(MSG_INFO, "EAP-UTE: Map key get int failed");
            //todo correct error code
            return build_error_msg(reqData, 3);
        }
        err = cbor_value_advance(&map_value);
        if (err != CborNoError) {
            wpa_printf(MSG_INFO, "EAP-UTE: Advancing failed");
            //todo correct error code
            return build_error_msg(reqData, 4);
        }


        switch (map_key) {
        case EAP_UTE_MAP_KEY_VERSIONS:
            wpa_printf(MSG_INFO, "EAP-UTE: Seen key for Versions");
            if (versions_seen != 0) {
                wpa_printf(MSG_INFO, "EAP-UTE: Double version key in cbor map");
                // todo correct error code
                return build_error_msg(reqData, 0);
            }
            versions_seen = 1;
            if (!cbor_value_is_array(&map_value)) {
                wpa_printf(MSG_INFO, "EAP-UTE: Versions value was not an array");
                // todo correct error code
                return build_error_msg(reqData, 5);
            }
            if (!check_array_for_value(&map_value, 1)) {
                wpa_printf(MSG_INFO, "EAP-UTE: No compatible version found");
                // todo correct error code
                return build_error_msg(reqData, 6);
            }
            break;
        case EAP_UTE_MAP_KEY_CIPHERS:
            wpa_printf(MSG_INFO, "EAP-UTE: Seen key for ciphers");
            if (ciphers_seen != 0) {
                wpa_printf(MSG_INFO, "EAP-UTE: Double ciphers key in cbor map");
                // todo correct error code
                return build_error_msg(reqData, 0);
            }
            ciphers_seen = 1;

            if (!cbor_value_is_array(&map_value)) {
                wpa_printf(MSG_INFO, "EAP-UTE: Ciphers value was not an array");
                // todo correct error code
                return build_error_msg(reqData, 7);
            }
            CborValue cipher_inner;
            err = cbor_value_enter_container(&map_value, &cipher_inner);
            if (err != CborNoError) {
                wpa_printf(MSG_INFO, "EAP-UTE: Error entering inner value");
                // todo correct error code
                return build_error_msg(reqData, 0);
            }

            if (!cbor_value_is_array(&cipher_inner)) {
                wpa_printf(MSG_INFO, "EAP-UTE: Supported ECDHE curves was not an array");
                // todo correct error code
                return build_error_msg(reqData, 0);
            }
            if (!check_array_for_value(&cipher_inner, 4)) {
                wpa_printf(MSG_INFO, "EAP-UTE: No compatible ECDHE curve found");
                // todo correct error code
                return build_error_msg(reqData, 8);
            }

            err = cbor_value_advance(&cipher_inner);
            if ( err != CborNoError) {
                wpa_printf(MSG_INFO, "EAP-UTE: Error in advancing");
                // todo correct error code
                return build_error_msg(reqData, 0);
            }

            if (!cbor_value_is_array(&cipher_inner)) {
                wpa_printf(MSG_INFO, "EAP-UTE: Supported Hash algorithms was not an array");
                // todo correct error code
                return build_error_msg(reqData, 0);
            }
            if (!check_array_for_value(&cipher_inner, -16)) {
                wpa_printf(MSG_INFO, "EAP-UTE: No compatible Hash algorithm found");
                // todo correct error code
                return build_error_msg(reqData, 0);
            }
            break;
        case EAP_UTE_MAP_KEY_DIRECTIONS:
            if (directions_seen != 0) {
                wpa_printf(MSG_INFO, "EAP-UTE: Double directions key in cbor map");
                // todo correct error code
                return build_error_msg(reqData, 0);
            }
            directions_seen = 1;
            wpa_printf(MSG_INFO, "EAP-UTE: seen key for directions");

            if (!cbor_value_is_integer(&map_value)) {
                wpa_printf(MSG_INFO, "EAP-UTE: Directions was not an integer");
                // todo correct error code
                return build_error_msg(reqData, 9);
            }
            int directions_tmp;
            err = cbor_value_get_int_checked(&map_value, &directions_tmp);
            if (err != CborNoError) {
                wpa_printf(MSG_INFO, "EAP-UTE: Directions could not be retrieved");
                // todo correct error code
                return build_error_msg(reqData, 0);
            }
            break;
        default:
            wpa_printf(MSG_INFO, "EAP-UTE: seen unknown key");
        }

        err = cbor_value_advance(&map_value);
        if (err != CborNoError) {
            wpa_printf(MSG_INFO, "EAP-UTE: CBOR Advancing failed");
            // todo correct error code
            return build_error_msg(reqData, 10);
        }

    }

    if (!versions_seen) {
        wpa_printf(MSG_INFO, "EAP-UTE: No Versions seen.");
        // todo correct error code
        return build_error_msg(reqData, 0);
    }
    if (!ciphers_seen) {
        wpa_printf(MSG_INFO, "EAP-UTE: No Versions seen.");
        // todo correct error code
        return build_error_msg(reqData, 0);
    }
    if (!directions_seen) {
        wpa_printf(MSG_INFO, "EAP-UTE: No Versions seen.");
        // todo correct error code
        return build_error_msg(reqData, 0);
    }

    // Depending on the current state, we send different messages
    switch (g_wpa_eap_ute_state.ute_state) {
    case EAP_UTE_STATE_UNREGISTERED:
        // Initial exchange, send Client Greeting
        return eap_ute_send_client_greeting(sm, data, ret, reqData);
    case EAP_UTE_STATE_WAITING_FOR_OOB:
    case EAP_UTE_STATE_OOB_RECEIVED:
        // Intentional Fallthrough
        // Waiting exchange, send Client Completion Request
        return eap_ute_send_client_completion_request(sm, data, ret, reqData);
        return NULL;
    case EAP_UTE_STATE_REGISTERED:
        // Reconnect exchange.
        // Depending on the chosen exchange (w. ecdhe, w/o ecdhe, upgrade)
        //  different messages will be sent
        //  Reconnect w/o ECDHE: Client Completion Request
        //  Reconnect w. ECDHE: Client Keyshare
        //  Version Upgrade: Client Greeting
        return NULL;
    default:
        // TODO invalid situation
        return NULL;
    }
}

static struct wpabuf *eap_ute_handle_server_keyshare(struct eap_sm *sm, struct eap_ute_data *data, struct eap_method_ret *ret, const struct wpabuf *reqData, const u8 *payload, size_t payload_len, const u8 *additional, size_t additional_len)
{
    CborParser parser;
    CborValue value;
    CborValue map_value;
    CborError err;

    wpa_printf(MSG_INFO, "EAP-UTE: Handling Server Keyshare");

    err = cbor_parser_init(payload, payload_len, 0, &parser, &value);
    if (err != CborNoError) {
        wpa_printf(MSG_INFO, "EAP-UTE: Error initializing CBOR parser");
        // todo correct error code
        return build_error_msg(reqData, 0);
    }
    if (!cbor_value_is_map(&value)) {
        wpa_printf(MSG_INFO, "EAP-UTE: CBOR payload was not a map");
        // TODO correct error code
        return build_error_msg(reqData, 0);
    }
    err = cbor_value_enter_container(&value, &map_value);
    if (err != CborNoError) {
        wpa_printf(MSG_INFO, "EAP-UTE: CBOR Parsing error");
        // TODO correct error code
        return build_error_msg(reqData, 1);
    }

    int map_key;
    uint8_t server_key_seen = 0, nonce_server_seen = 0;
    u8 serverkey[32];

    while (!cbor_value_at_end(&map_value)) {
        if (!cbor_value_is_integer(&map_value)) {
            wpa_printf(MSG_INFO, "EAP-UTE: Map key was no integer");
            // TODO correct error code
            return build_error_msg(reqData, 2);
        }
        err = cbor_value_get_int_checked(&map_value, &map_key);
        // TODO: check for other error here, large ints may be used for extensions
        if (err != CborNoError) {
            wpa_printf(MSG_INFO, "EAP-UTE: Map key get int failed");
            //todo correct error code
            return build_error_msg(reqData, 3);
        }
        err = cbor_value_advance(&map_value);
        if (err != CborNoError) {
            wpa_printf(MSG_INFO, "EAP-UTE: Advancing failed");
            //todo correct error code
            return build_error_msg(reqData, 4);
        }

        switch (map_key) {
        case EAP_UTE_MAP_KEY_KEY_SERVER:
            wpa_printf(MSG_INFO, "EAP-UTE: Seen Key for Server Key");
            if (server_key_seen != 0) {
                wpa_printf(MSG_INFO, "EAP-UTE: Double Server Key in cbor map");
                // todo correct error code
                return build_error_msg(reqData, 0);
            }

            server_key_seen = 1;

            if (!cbor_value_is_map(&map_value)) {
                wpa_printf(MSG_INFO, "EAP-UTE: server key was not a map");
                // todo correct error code
                return build_error_msg(reqData, 0);
            }

            CborValue key_inner;
            err = cbor_value_enter_container(&map_value, &key_inner);
            if (err != CborNoError) {
                wpa_printf(MSG_INFO, "EAP-UTE: error entering map for ecdhe key");
                // todo correct error code
                return build_error_msg(reqData, 0);
            }

            uint8_t type_seen = 0, key_seen = 0;
            while (!cbor_value_at_end(&key_inner)) {
                if (!cbor_value_is_integer(&key_inner)) {
                    wpa_printf(MSG_INFO, "EAP-UTE: ecdhe map key was not an integer");
                    //todo correct error code
                    return build_error_msg(reqData, 0);
                }
                int ecdhe_map_key;
                err = cbor_value_get_int_checked(&key_inner, &ecdhe_map_key);
                if (err != CborNoError) {
                    wpa_printf(MSG_INFO, "EAP-UTE: ecdhe map key get int failed");
                    // todo correct error code
                    return build_error_msg(reqData, 0);
                }
                err = cbor_value_advance(&key_inner);
                if (err != CborNoError) {
                    wpa_printf(MSG_INFO, "EAP-UTE: ecdhe map advancing failed");
                    // todo correct error code
                    return build_error_msg(reqData, 0);
                }

                switch (ecdhe_map_key) {
                case -1: // key type
                    if (type_seen != 0) {
                        wpa_printf(MSG_INFO, "EAP-UTE: double key type in map");
                        // todo correct error code
                        return build_error_msg(reqData, 0);
                    }
                    type_seen = 1;
                    if (!cbor_value_is_integer(&key_inner)) {
                        wpa_printf(MSG_INFO, "EAP-UTE: Key type was not an integer");
                        // todo correct error code
                        return build_error_msg(reqData, 0);
                    }
                    int keytype;
                    err = cbor_value_get_int_checked(&key_inner, &keytype);
                    if (err != CborNoError) {
                        wpa_printf(MSG_INFO, "EAP-UTE: Key type get int failed");
                        // todo correct error code
                        return build_error_msg(reqData, 0);
                    }
                    if (keytype != 4) {
                        wpa_printf(MSG_INFO, "EAP-UTE: Key type was not 4 (X25519)");
                        // todo correct error code
                        return build_error_msg(reqData, 0);
                    }
                    break;
                case -2: // key bytes
                    if (key_seen != 0) {
                        wpa_printf(MSG_INFO, "EAP-UTE: double key type in map");
                        // todo correct error code
                        return build_error_msg(reqData, 0);
                    }
                    if (!cbor_value_is_byte_string(&key_inner)) {
                        wpa_printf(MSG_INFO, "EAP-UTE: Key was not a byte string");
                        // todo correct error code
                        return build_error_msg(reqData, 0);
                    }
                    size_t server_key_length;
                    err = cbor_value_get_string_length(&key_inner, &server_key_length);
                    if (err != CborNoError) {
                        wpa_printf(MSG_INFO, "EAP-UTE: Error getting server key length");
                        // todo correct error code
                        return build_error_msg(reqData, 0);
                    }
                    if (server_key_length != 32) {
                        wpa_printf(MSG_INFO, "EAP-UTE: Key length is not valid");
                        // todo correct error code
                        return build_error_msg(reqData, 0);
                    }
                    err = cbor_value_copy_byte_string(&key_inner, serverkey, &server_key_length, NULL);
                    if (err != CborNoError) {
                        wpa_printf(MSG_INFO, "EAP-UTE: Error getting server key bytes");
                        // todo correct error code
                        return build_error_msg(reqData, 0);
                    }
                    break;
                default:
                    wpa_printf(MSG_INFO, "EAP-UTE: Unknown map key %i", ecdhe_map_key);
                }
                err = cbor_value_advance(&key_inner);
                if (err != CborNoError) {
                    wpa_printf(MSG_INFO, "EAP-UTE: ecdhe map advancing failed");
                    // todo correct error code
                    return build_error_msg(reqData, 0);
                }
            }

            break;
        case EAP_UTE_MAP_KEY_NONCE_SERVER:
            wpa_printf(MSG_INFO, "EAP-UTE: Seen Key for Server Nonce");
            if (nonce_server_seen != 0) {
                wpa_printf(MSG_INFO, "EAP-UTE: Double Server Nonce in cbor map");
                // todo correct error code
                return build_error_msg(reqData, 0);
            }
            nonce_server_seen = 1;
            if (!cbor_value_is_byte_string(&map_value)) {
                wpa_printf(MSG_INFO, "EAP-UTE: Nonce was not a bytes string");
                // todo correct error code
                return build_error_msg(reqData, 0);
            }
            size_t nonce_size = 32;
            err = cbor_value_copy_byte_string(&map_value, data->nonce_server, &nonce_size, NULL);
            if (err != CborNoError) {
                wpa_printf(MSG_INFO, "EAP-UTE: Error in getting server nonce");
                // todo correct error code
                return build_error_msg(reqData, 0);
            }
            if (nonce_size != 32) {
                wpa_printf(MSG_INFO, "EAP-UTE: Nonce size was not 32 bytes");
                // todo correct error code
                return build_error_msg(reqData, 0);
            }
            break;
        default:
            wpa_printf(MSG_INFO, "EAP-UTE: seen unknown key");
        }

        err = cbor_value_advance(&map_value);
        if (err != CborNoError) {
            wpa_printf(MSG_INFO, "EAP-UTE: CBOR Advancing failed");
            // todo correct error code
            return build_error_msg(reqData, 0);
        }
    }

    if (server_key_seen == 0) {
        wpa_printf(MSG_INFO, "EAP-UTE: No server key seen.");
        return build_error_msg(reqData, EAP_UTE_ERROR_MISSING_MANDATORY_FIELD);
    }
    if (nonce_server_seen == 0) {
        wpa_printf(MSG_INFO, "EAP-UTE: No server nonce seen.");
        return build_error_msg(reqData, EAP_UTE_ERROR_MISSING_MANDATORY_FIELD);
    }

    // Load public key of the server
    mbedtls_ecdh_context_mbed *ctxm = &data->mbed_ctx.MBEDTLS_PRIVATE(ctx).MBEDTLS_PRIVATE(mbed_ecdh);
    mbedtls_mpi_lset(&ctxm->MBEDTLS_PRIVATE(Qp).MBEDTLS_PRIVATE(Z), 1);
    int ret_val = mbedtls_mpi_read_binary_le(&ctxm->MBEDTLS_PRIVATE(Qp).MBEDTLS_PRIVATE(X), serverkey, 32);
    if (ret_val != 0) {
        wpa_printf(MSG_INFO, "EAP-UTE: Error in writing server ECDHE key");
        return build_error_msg(reqData, EAP_UTE_ERROR_APPLICATION_SPECIFIC_ERROR);
    }
    data->shared_key = malloc(32);
    data->shared_key_length = 32;

    ret_val = mbedtls_ecdh_compute_shared(&ctxm->MBEDTLS_PRIVATE(grp), &ctxm->MBEDTLS_PRIVATE(z), &ctxm->MBEDTLS_PRIVATE(Qp), &ctxm->MBEDTLS_PRIVATE(d),
                                          mbedtls_ctr_drbg_random, &data->ctr_drbg);
    if (ret_val != 0) {
        wpa_printf(MSG_INFO, "EAP-UTE: Error in calculating ECDHE shared secret. Error code %i %i", ret_val, -0x0020);
        return build_error_msg(reqData, EAP_UTE_ERROR_APPLICATION_SPECIFIC_ERROR);
    }

    ret_val = mbedtls_mpi_write_binary_le(&ctxm->MBEDTLS_PRIVATE(z), data->shared_key, 32);
    if (ret_val != 0) {
        wpa_printf(MSG_INFO, "EAP-UTE: Error in getting shared secret. Error code %i", ret_val);
        return build_error_msg(reqData, EAP_UTE_ERROR_APPLICATION_SPECIFIC_ERROR);
    }

    wpa_hexdump(MSG_INFO, "EAP-UTE: shared key", data->shared_key, 32);

    return eap_ute_send_client_finished(sm, data, ret, reqData, false);
}

static struct wpabuf *eap_ute_handle_server_completion_response(struct eap_sm *sm, struct eap_ute_data *data, struct eap_method_ret *ret, const struct wpabuf *reqData, const u8 *payload, size_t payload_len, const u8 *additional, size_t additional_len)
{
    CborParser parser;
    CborValue value;
    CborValue map_value;
    CborError err;

    wpa_printf(MSG_INFO, "EAP-UTE: Handling server completion response");

    err = cbor_parser_init(payload, payload_len, 0, &parser, &value);
    if (err != CborNoError) {
        wpa_printf(MSG_INFO, "EAP-UTE: Error initializing CBOR parser");
        return build_error_msg(reqData, EAP_UTE_ERROR_APPLICATION_SPECIFIC_ERROR);
    }
    if (!cbor_value_is_map(&value)) {
        wpa_printf(MSG_INFO, "EAP-UTE: CBOR payload was not a map");
        return build_error_msg(reqData, EAP_UTE_ERROR_INVALID_MESSAGE_STRUCTURE);
    }
    err = cbor_value_enter_container(&value, &map_value);
    if (err != CborNoError) {
        wpa_printf(MSG_INFO, "EAP-UTE: CBOR Parsing error");
        return build_error_msg(reqData, EAP_UTE_ERROR_APPLICATION_SPECIFIC_ERROR);
    }

    int map_key;
    u8 nonce_server_seen = 0;
    u8 mac_server_seen = 0;
    u8 oob_id_seen = 0;
    u8 oob_id[16];

    while (!cbor_value_at_end(&map_value)) {
        if (!cbor_value_is_integer(&map_value)) {
            wpa_printf(MSG_INFO, "EAP-UTE: Map key was no integer");
            return build_error_msg(reqData, EAP_UTE_ERROR_INVALID_MESSAGE_STRUCTURE);
        }
        err = cbor_value_get_int_checked(&map_value, &map_key);
        if (err != CborNoError) {
            wpa_printf(MSG_INFO, "EAP-UTE: Map key get int failed");
            return build_error_msg(reqData, EAP_UTE_ERROR_APPLICATION_SPECIFIC_ERROR);
        }
        err = cbor_value_advance(&map_value);
        if (err != CborNoError) {
            wpa_printf(MSG_INFO, "EAP-UTE: Advancing failed");
            return build_error_msg(reqData, EAP_UTE_ERROR_APPLICATION_SPECIFIC_ERROR);
        }

        switch (map_key) {
        case EAP_UTE_MAP_KEY_NONCE_SERVER:
            wpa_printf(MSG_INFO, "EAP-UTE: Seen Key for Server Nonce");
            if (nonce_server_seen != 0) {
                wpa_printf(MSG_INFO, "EAP-UTE: Double Server Nonce in cbor map");
                return build_error_msg(reqData, EAP_UTE_ERROR_INVALID_MESSAGE_STRUCTURE);
            }
            nonce_server_seen = 1;
            if (!cbor_value_is_byte_string(&map_value)) {
                wpa_printf(MSG_INFO, "EAP-UTE: Nonce was not a bytes string");
                return build_error_msg(reqData, EAP_UTE_ERROR_INVALID_MESSAGE_STRUCTURE);
            }
            size_t nonce_size = 32;
            err = cbor_value_copy_byte_string(&map_value, data->nonce_server, &nonce_size, NULL);
            if (err != CborNoError) {
                wpa_printf(MSG_INFO, "EAP-UTE: Error in getting server nonce");
                return build_error_msg(reqData, EAP_UTE_ERROR_APPLICATION_SPECIFIC_ERROR);
            }
            if (nonce_size != 32) {
                wpa_printf(MSG_INFO, "EAP-UTE: Nonce size was not 32 bytes");
                return build_error_msg(reqData, EAP_UTE_ERROR_INVALID_MESSAGE_STRUCTURE);
            }
            break;
        case EAP_UTE_MAP_KEY_OOB_ID:
            wpa_printf(MSG_INFO, "EAP-UTE: Seen Key for OOB ID");
            if (oob_id_seen != 0) {
                wpa_printf(MSG_INFO, "EAP-UTE: Double OOB Id in cbor map");
                return build_error_msg(reqData, EAP_UTE_ERROR_INVALID_MESSAGE_STRUCTURE);
            }
            oob_id_seen = 1;
            if (!cbor_value_is_byte_string(&map_value)) {
                wpa_printf(MSG_INFO, "EAP-UTE: OOB ID was not a bytes string");
                return build_error_msg(reqData, EAP_UTE_ERROR_INVALID_MESSAGE_STRUCTURE);
            }
            size_t oob_size = 16;
            err = cbor_value_copy_byte_string(&map_value, oob_id, &oob_size, NULL);
            if (err != CborNoError) {
                wpa_printf(MSG_INFO, "EAP-UTE: Error in getting oob id");
                return build_error_msg(reqData, EAP_UTE_ERROR_APPLICATION_SPECIFIC_ERROR);
            }
            if (oob_size != 16) {
                wpa_printf(MSG_INFO, "EAP-UTE: OOB-ID size was not 16 bytes");
                return build_error_msg(reqData, EAP_UTE_ERROR_INVALID_MESSAGE_STRUCTURE);
            }
            break;
        case EAP_UTE_MAP_KEY_MAC_SERVER:
            wpa_printf(MSG_INFO, "EAP_UTE: Seen Key for MAC Server");
            if (mac_server_seen != 0) {
                wpa_printf(MSG_INFO, "EAP-UTE: Double MAC server in cbor map");
                return build_error_msg(reqData, EAP_UTE_ERROR_INVALID_MESSAGE_STRUCTURE);
            }
            mac_server_seen = 1;
            if (!cbor_value_is_null(&map_value)) {
                wpa_printf(MSG_INFO, "EAP-UTE: MAC server was not nil");
                return build_error_msg(reqData, EAP_UTE_ERROR_INVALID_MESSAGE_STRUCTURE);
            }
            break;
        default:
            wpa_printf(MSG_INFO, "EAP-UTE: Seen unknown key %i", map_key);
        }

        err = cbor_value_advance(&map_value);
        if (err != CborNoError) {
            wpa_printf(MSG_INFO, "EAP-UTE: CBOR Advancing failed");
            return build_error_msg(reqData, EAP_UTE_ERROR_APPLICATION_SPECIFIC_ERROR);
        }
    }

    if (mac_server_seen == 0) {
        wpa_printf(MSG_INFO, "EAP-UTE: No MAC Server seen");
        return build_error_msg(reqData, EAP_UTE_ERROR_MISSING_MANDATORY_FIELD);
    }
    if (nonce_server_seen == 0) {
        wpa_printf(MSG_INFO, "EAP-UTE: No Nonce Server seen");
        return build_error_msg(reqData, EAP_UTE_ERROR_MISSING_MANDATORY_FIELD);
    }
    if (data->oobMsg == NULL) {
        if (oob_id_seen == 0) {
            wpa_printf(MSG_INFO, "EAP-UTE: No OOB Id seen and no sent my myself");
            return build_error_msg(reqData, EAP_UTE_ERROR_MISSING_MANDATORY_FIELD);
        }

        data->oobMsg = eap_ute_get_oob_msg_by_id(oob_id);
        if (data->oobMsg == NULL) {
            wpa_printf(MSG_INFO, "EAP-UTE: No usable OOB-MSG found");
            return build_error_msg(reqData, EAP_UTE_ERROR_APPLICATION_SPECIFIC_ERROR);
        }
    }

    err = cbor_parser_init(additional, additional_len, 0, &parser, &value);
    if (err != CborNoError) {
        wpa_printf(MSG_INFO, "EAP-UTE: Error initializing CBOR parser");
        return build_error_msg(reqData, EAP_UTE_ERROR_APPLICATION_SPECIFIC_ERROR);
    }
    if (!cbor_value_is_map(&value)) {
        wpa_printf(MSG_INFO, "EAP-UTE: CBOR payload was not a map");
        return build_error_msg(reqData, EAP_UTE_ERROR_INVALID_MESSAGE_STRUCTURE);
    }
    err = cbor_value_enter_container(&value, &map_value);
    if (err != CborNoError) {
        wpa_printf(MSG_INFO, "EAP-UTE: CBOR Parsing error");
        return build_error_msg(reqData, EAP_UTE_ERROR_APPLICATION_SPECIFIC_ERROR);
    }
    mac_server_seen = 0;
    u8 mac_server[32];
    while (!cbor_value_at_end(&map_value)) {
        if (!cbor_value_is_integer(&map_value)) {
            wpa_printf(MSG_INFO, "EAP-UTE: Map key was no integer");
            return build_error_msg(reqData, EAP_UTE_ERROR_INVALID_MESSAGE_STRUCTURE);
        }
        err = cbor_value_get_int_checked(&map_value, &map_key);
        if (err != CborNoError) {
            wpa_printf(MSG_INFO, "EAP-UTE: Map key get int failed");
            return build_error_msg(reqData, EAP_UTE_ERROR_APPLICATION_SPECIFIC_ERROR);
        }
        err = cbor_value_advance(&map_value);
        if (err != CborNoError) {
            wpa_printf(MSG_INFO, "EAP-UTE: Advancing failed");
            return build_error_msg(reqData, EAP_UTE_ERROR_APPLICATION_SPECIFIC_ERROR);
        }

        switch (map_key) {
        case EAP_UTE_MAP_KEY_MAC_SERVER:
            wpa_printf(MSG_INFO, "EAP-UTE: Seen Key for Server MAC (additional)");
            if (mac_server_seen != 0) {
                wpa_printf(MSG_INFO, "EAP-UTE: Double MAC server in cbor map");
                return build_error_msg(reqData, EAP_UTE_ERROR_INVALID_MESSAGE_STRUCTURE);
            }
            mac_server_seen = 1;
            if (!cbor_value_is_byte_string(&map_value)) {
                wpa_printf(MSG_INFO, "EAP-UTE: MAC server (additional) was not a byte string");
                return build_error_msg(reqData, EAP_UTE_ERROR_INVALID_MESSAGE_STRUCTURE);
            }
            size_t mac_len = 32;
            err = cbor_value_copy_byte_string(&map_value, mac_server, &mac_len, NULL);
            if (err != CborNoError) {
                wpa_printf(MSG_INFO, "EAP-UTE: Error in getting server MAC");
                return build_error_msg(reqData, EAP_UTE_ERROR_APPLICATION_SPECIFIC_ERROR);
            }
            if (mac_len != 32) {
                wpa_printf(MSG_INFO, "EAP-UTE: server MAC was not 32 bytes");
                return build_error_msg(reqData, EAP_UTE_ERROR_INVALID_MESSAGE_STRUCTURE);
            }
            break;
        default:
            wpa_printf(MSG_INFO, "EAP-UTE: Seen unknown key %i", map_key);
        }
        err = cbor_value_advance(&map_value);
        if (err != CborNoError) {
            wpa_printf(MSG_INFO, "EAP-UTE: CBOR Advancing failed");
            return build_error_msg(reqData, EAP_UTE_ERROR_APPLICATION_SPECIFIC_ERROR);
        }

    }
    if (mac_server_seen == 0) {
        wpa_printf(MSG_INFO, "EAP-UTE: No MAC Server seen in additional");
        return build_error_msg(reqData, EAP_UTE_ERROR_MISSING_MANDATORY_FIELD);
    }

    // TODO:
    eap_ute_calculate_kdf(data, 0, data->oobMsg);

    eap_ute_calculate_crypto_material(data, 0);

    u8 mac_c = 0;
    for (int i = 0; i < 32; i++) {
        mac_c |= data->mac_s[i] ^ mac_server[i];
    }
    if (mac_c != 0) {
        wpa_printf(MSG_INFO, "EAP-UTE: MAC did not match");
        return build_error_msg(reqData, EAP_UTE_ERROR_MAC_MISMATCH);
    }

    return eap_ute_send_client_finished(sm, data, ret, reqData, true);
}

static struct wpabuf *eap_ute_process(struct eap_sm *sm, void *priv, struct eap_method_ret *ret, const struct wpabuf *reqData)
{
    size_t len;
    struct eap_ute_data *data = priv;
    struct wpabuf *to_return = NULL;
    const u8 *eap_pkt = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_UTE, reqData, &len);

    if (eap_pkt == NULL) {
        goto ignore;
    }

    CborParser parser;
    CborValue value;
    CborError error;

    size_t cur_pos = 0;

    // <editor-fold desc="Parse message type" >
    error = cbor_parser_init(eap_pkt, len, 0, &parser, &value);
    if (error != CborNoError) {
        // TODO Log error message (cbor parser error)
        // TODO send error
        goto send_wpabuf;
    }

    if (!cbor_value_is_integer(&value)) {
        // TODO Log error message (invalid cbor structure)
        // TODO send error
        goto send_wpabuf;
    }

    int msg_type;
    error = cbor_value_get_int_checked(&value, &msg_type);
    if (error != CborNoError) {
        // TODO Log error message (cbor parser error)
        // TODO send error
        goto send_wpabuf;
    }

    error = cbor_value_advance(&value);
    if (error != CborNoError) {
        // TODO log error message (cbor parser error)
        // todo send error
        goto send_wpabuf;
    }

    if (!cbor_value_at_end(&value)) {
        // todo log error message (cbor parser error)
        // todo send error
        goto send_wpabuf;
    }


    // </editor-fold>

    const uint8_t *msg2 = cbor_value_get_next_byte(&value);
    int diff = msg2 - eap_pkt;

    cur_pos += diff;

    // <editor-fold desc="Parse message payload" >
    error = cbor_parser_init(eap_pkt + cur_pos, len - cur_pos, 0, &parser, &value);
    if (error != CborNoError) {
        // TODO Log error message (cbor parser error)
        // TODO send error
        goto send_wpabuf;
    }

    if (!cbor_value_is_byte_string(&value)) {
        // todo log error message (invalid cbor structure)
        // todo send error
        goto send_wpabuf;
    }

    size_t payload_len;
    error = cbor_value_get_string_length(&value, &payload_len);
    if (error != CborNoError) {
        // todo log error message (cbor parser error)
        // todo send error
        goto send_wpabuf;
    }

    uint8_t *payload = malloc(payload_len);
    if (!payload) {
        // todo log error message (failed malloc)
        // todo send error
        goto send_wpabuf;
    }

    error = cbor_value_copy_byte_string(&value, payload, &payload_len, NULL);
    if (error != CborNoError) {
        // todo log error message (cbor parser error)
        // todo send error
        goto send_wpabuf;
    }

    error = cbor_value_advance(&value);
    if (error != CborNoError) {
        // todo log error message (cbor parser error)
        // todo send error
        goto send_wpabuf;
    }

    if (!cbor_value_at_end(&value)) {
        // todo log error message (cbor parser error)
        // todo send error
    }
    // </editor-fold>

    const uint8_t *msg3 = cbor_value_get_next_byte(&value);
    diff = msg3 - msg2;

    int total_hash = msg3 - eap_pkt;

    mbedtls_md_update(&data->md_ctx, eap_pkt, total_hash);

    cur_pos += diff;


    size_t additional_len = 0;
    uint8_t *additional = NULL;
    if (cur_pos < len) {
        // <editor-fold desc="Parse additional payload">
        error = cbor_parser_init(eap_pkt + cur_pos, len - cur_pos, 0, &parser, &value);
        if (error != CborNoError) {
            // TODO Log error message (cbor parser error)
            // TODO send error
            goto send_wpabuf;
        }

        if (!cbor_value_is_byte_string(&value)) {
            // todo log error message (invalid cbor structure)
            // todo send error
            goto send_wpabuf;
        }

        error = cbor_value_get_string_length(&value, &additional_len);
        if (error != CborNoError) {
            // todo log error message (cbor parser error)
            // todo send error
            goto send_wpabuf;
        }

        additional = malloc(additional_len);
        if (!additional) {
            // todo log error message (failed malloc)
            // todo send error
            goto send_wpabuf;
        }

        error = cbor_value_copy_byte_string(&value, additional, &additional_len, NULL);
        if (error != CborNoError) {
            // todo log error message (cbor parser error)
            // todo send error
            goto send_wpabuf;
        }

        error = cbor_value_advance(&value);
        if (error != CborNoError) {
            // todo log error message (cbor parser error)
            // todo send error
            goto send_wpabuf;
        }

        if (!cbor_value_at_end(&value)) {
            // todo log error message (cbor parser error)
            // todo send error
            goto send_wpabuf;
        }
        // </editor-fold>
    }

    // todo maybe check that this is all? Or leave it so EAP-UTE is even more extensible?

    switch (msg_type) {
    case EAP_UTE_MSG_TYPE_ERROR:
        // TODO log message
        // todo maybe acknowledge error msg so server can send an EAP failure? not sure.
        goto ignore;
    case EAP_UTE_MSG_TYPE_SERVER_GREETING:
        // This is always the first message from the server and only otherwise if
        //   the client requested a renegotiation using a different EAP-UTE version.
        if (data->state != EAP_UTE_INTERNAL_STATE_INITIAL) {
            // todo log error message (unexpected message)
            // todo send error
            goto send_wpabuf;
        }
        to_return = eap_ute_handle_server_greeting(sm, data, ret, reqData, payload, payload_len, additional, additional_len);
        break;
    case EAP_UTE_MSG_TYPE_SERVER_KEYSHARE:
        // With this message the server sends us its ECDHE public key.
        //   This could occur:
        //   * after the Client greeting in the initial exchange
        //   * after the client keyshare in the reconnect-with-ECDHE exchange
        if (data->state != EAP_UTE_INTERNAL_STATE_CLIENT_GREETING_SENT &&
                data->state != EAP_UTE_INTERNAL_STATE_CLIENT_KEYSHARE_SENT) {
            // todo log error message (unexpected message)
            // todo send error
            goto send_wpabuf;
        }
        to_return = eap_ute_handle_server_keyshare(sm, data, ret, reqData, payload, payload_len, additional, additional_len);
        break;
    case EAP_UTE_MSG_TYPE_SERVER_COMPLETION_RESPONSE:
        // With this message the server acknowledges our completion
        //   This is part of
        //   * the completion exchange after the Client Completion Request
        //   * the reconnect exchange without ECDHE after the Client Completion Request
        //   * the upgrade exchange after the client greeting
        if (data->state != EAP_UTE_INTERNAL_STATE_CLIENT_COMPLETION_REQUEST_SENT &&
                data->state != EAP_UTE_INTERNAL_STATE_CLIENT_GREETING_SENT) {
            // todo log error message (unexpected message)
            // todo send error
            goto send_wpabuf;
        }
        to_return = eap_ute_handle_server_completion_response(sm, data, ret, reqData, payload, payload_len, additional, additional_len);
        break;
    }
send_wpabuf:
    return to_return;
ignore:
    ret->ignore = true;
    return NULL;
}

static bool eap_ute_isKeyAvailable(struct eap_sm *sm, void *priv)
{
    return false;
}

static u8 *eap_ute_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
    struct eap_ute_data *data = priv;
    u8 *key;

    if (data->kdf_out == NULL) {
        return NULL;
    }
    key = os_malloc(64);
    if (key == NULL) {
        return NULL;
    }

    *len = 64;
    os_memcpy(key, data->kdf_out, 64);

    return key;
}

static u8 *eap_ute_get_emsk(struct eap_sm *sm, void *priv, size_t *len)
{
    struct eap_ute_data *data = priv;
    u8 *key;

    if (data->kdf_out == NULL) {
        return NULL;
    }

    key = os_malloc(64);
    if (key == NULL) {
        return NULL;
    }

    *len = 64;
    os_memcpy(key, &(data->kdf_out[64]), 64);

    return key;
}

int eap_peer_ute_register(void)
{
    struct eap_method *eap;
    int ret;

    eap = eap_peer_method_alloc(EAP_VENDOR_IETF, EAP_TYPE_UTE, "UTE");
    if (eap == NULL) {
        return -1;
    }

    eap->init = eap_ute_init;
    eap->deinit = eap_ute_deinit;
    eap->process = eap_ute_process;
    eap->isKeyAvailable = eap_ute_isKeyAvailable;
    eap->getKey = eap_ute_getKey;
    eap->get_emsk = eap_ute_get_emsk;

    ret = eap_peer_method_register(eap);
    if (ret) {
        eap_peer_method_free(eap);
    }
    return ret;
}
//#endif /* EAP_UTE */
