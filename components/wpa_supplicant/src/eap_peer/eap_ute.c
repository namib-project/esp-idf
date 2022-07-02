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
#include "eap_peer/cbor.h"

#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"

enum eap_ute_internal_state {
    EAP_UTE_INTERNAL_STATE_INITIAL,
    EAP_UTE_INTERNAL_STATE_CLIENT_GREETING_SENT
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
    mbedtls_ecdh_context mbed_ctx;
};

static void * eap_ute_init(struct eap_sm *sm){
    struct eap_ute_data *data;
    data = (struct eap_ute_data *)os_zalloc(sizeof(*data));
    if (data == NULL)
        return NULL;
    data->state = EAP_UTE_INTERNAL_STATE_INITIAL;
    data->exch_type = EAP_UTE_EXCHANGE_TYPE_NONE;
    return data;
}
static void eap_ute_deinit(struct eap_sm *sm, void *priv)
{
    struct eap_ute_data *data = priv;
    if (data == NULL)
        return;

    if (data->kdf_out_len != 0 && data->kdf_out != NULL)
        os_free(data->kdf_out);

    os_free(data);
}

static bool check_array_for_value(CborValue *arr, int to_check){
    CborValue inner_val;
    CborError err;
    int val;

    err = cbor_value_enter_container(arr, &inner_val);
    if(err != CborNoError){
        return false;
    }
    while(!cbor_value_at_end(&inner_val)){
        if(!cbor_value_is_integer(&inner_val)){
            err = cbor_value_advance(&inner_val);
            if(err != CborNoError)
                return false;
        }
        err = cbor_value_get_int_checked(&inner_val, &val);
        if(err == CborNoError && val == to_check){
            cbor_value_leave_container(arr, &inner_val);
            return true;
        }
        err = cbor_value_advance(&inner_val);
        if(err != CborNoError){
            return false;
        }
    }
    cbor_value_leave_container(arr, &inner_val);
    return false;
}

static int eap_ute_generate_nonce(u8 *out, size_t len){
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init( &ctr_drbg );

    const char *mbed_seed = "nonce_seed";

    int ret_val = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *)mbed_seed, 10);
    if(ret_val != 0) {
        // todo return correct error code
        return 1;
    }
    ret_val = mbedtls_ctr_drbg_random(&ctr_drbg, out, len);
    if(ret_val != 0 ) {
        // todo return correct error code
        return 1;
    }
    return 0;
}
static int eap_ute_generate_ecdhe_key(struct eap_ute_data *data, u8 *keyout){
    mbedtls_ecdh_context *x25519_ctx = &data->mbed_ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ecdh_init( x25519_ctx );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
    int result;
    const char *mbed_seed = "ecdh";
    mbedtls_ecdh_context_mbed *x25519_ctx_m = &x25519_ctx->MBEDTLS_PRIVATE(ctx).MBEDTLS_PRIVATE(mbed_ecdh);
    result = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *)mbed_seed, 4);
    if(result != 0) {
        return 1;
    }
    result = mbedtls_ecp_group_load( &x25519_ctx_m->MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_CURVE25519);
    if(result != 0) {
        return 1;
    }
    result = mbedtls_ecdh_gen_public( &x25519_ctx_m->MBEDTLS_PRIVATE(grp), &x25519_ctx_m->MBEDTLS_PRIVATE(d), &x25519_ctx_m->MBEDTLS_PRIVATE(Q), mbedtls_ctr_drbg_random, &ctr_drbg );
    if(result != 0) {
        return 1;
    }
    result = mbedtls_mpi_write_binary_le( &x25519_ctx_m->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X), keyout, 32);
    if(result != 0) {
        return 1;
    }
    return 0;
}

static struct wpabuf * build_error_msg(const struct wpabuf *reqData, int errorcode){ return NULL; }

static struct wpabuf *eap_ute_handle_server_greeting(struct eap_sm *sm, struct eap_ute_data *data, struct eap_method_ret *ret, const struct wpabuf *reqData, const u8 *payload, size_t payload_len, const u8 *additional, size_t additional_len){
    CborParser parser;
    CborValue value;
    CborValue map_value;
    CborError err;
    int result;

    cbor_parser_init(payload, payload_len, 0, &parser, &value);
    if(!cbor_value_is_map(&value)){
        wpa_printf(MSG_INFO, "EAP-UTE: CBOR payload was not a map");
        // TODO correct error code
        return build_error_msg(reqData, 0);
    }
    err = cbor_value_enter_container(&value, &map_value);
    if(err != CborNoError){
        wpa_printf(MSG_INFO, "EAP-UTE: CBOR Parsing error");
        // TODO correct error code
        return build_error_msg(reqData, 0);
    }

    int map_key;

    while(!cbor_value_at_end(&map_value)){
        if(!cbor_value_is_integer(&map_value)){
            wpa_printf(MSG_INFO, "EAP-UTE: Map key was no integer");
            // TODO correct error code
            return build_error_msg(reqData, 0);
        }
        err = cbor_value_get_int_checked(&map_value, &map_key);
        if(err != CborNoError){
            wpa_printf(MSG_INFO, "EAP-UTE: Map key get int failed");
            //todo correct error code
            return build_error_msg(reqData, 0);
        }
        err = cbor_value_advance(&map_value);
        if(err != CborNoError){
            wpa_printf(MSG_INFO, "EAP-UTE: Advancing failed");
            //todo correct error code
            return build_error_msg(reqData, 0);
        }
        switch (map_key) {
            case EAP_UTE_MAP_KEY_VERSIONS:
                if(!cbor_value_is_array(&map_value)){
                    wpa_printf(MSG_INFO, "EAP-UTE: Versions value was not an array");
                    // todo correct error code
                    return build_error_msg(reqData, 0);
                }
                if(!check_array_for_value(&map_value, 1)){
                    wpa_printf(MSG_INFO, "EAP-UTE: No compatible version found");
                    // todo correct error code
                    return build_error_msg(reqData, 0);
                }
                break;
            case EAP_UTE_MAP_KEY_CIPHERS:
                if(!cbor_value_is_array(&map_value)){
                    wpa_printf(MSG_INFO, "EAP-UTE: Ciphers value was not an array");
                    // todo correct error code
                    return build_error_msg(reqData, 0);
                }
                if(!check_array_for_value(&map_value, 4)){
                    wpa_printf(MSG_INFO, "EAP-UTE: No compatible cipher found");
                    // todo correct error code
                    return build_error_msg(reqData, 0);
                }
                break;
            case EAP_UTE_MAP_KEY_DIRECTIONS:
                if(!cbor_value_is_integer(&map_value)){
                    wpa_printf(MSG_INFO, "EAP-UTE: Directions was not an integer");
                    // todo correct error code
                    return build_error_msg(reqData, 0);
                }
                // TODO check for correct directions
        }

        err = cbor_value_advance(&map_value);
        if(err != CborNoError) {
            wpa_printf(MSG_INFO, "EAP-UTE: CBOR Advancing failed");
            // todo correct error code
            return build_error_msg(reqData, 0);
        }
    }

    // Generate a new nonce

    int nonce_stat = eap_ute_generate_nonce(data->nonce_peer, 32);
    if (nonce_stat != 0){
        wpa_printf(MSG_INFO, "EAP-UTE: Error in nonce generation");
        // todo correct error code
        return build_error_msg(reqData, 0);
    }

    // Calculate X25519 key
    u8 mykey[32];
    result = eap_ute_generate_ecdhe_key(data, mykey);
    if(result != 0){
        wpa_printf(MSG_INFO, "EAP-UTE: Error in ECHDE key generation");
        // todo correct error code
        return build_error_msg(reqData, 0);
    }


    // Build CBOR return values
    u8 cbor_buf[1500];
    CborEncoder encoder, mapEncoder, peerInfoEncoder, keyEncoder;
    cbor_encoder_init(&encoder, cbor_buf, sizeof(cbor_buf), 0);
    cbor_encoder_create_map(&encoder, &mapEncoder, 6);

    cbor_encode_int(&mapEncoder, EAP_UTE_MAP_KEY_VERSION);
    cbor_encode_int(&mapEncoder, 1);

    cbor_encode_int(&mapEncoder, EAP_UTE_MAP_KEY_CIPHER);
    cbor_encode_int(&mapEncoder, 4);

    cbor_encode_int(&mapEncoder, EAP_UTE_MAP_KEY_PEER_INFO);
    cbor_encoder_create_map(&mapEncoder, &peerInfoEncoder, 0);
    cbor_encoder_close_container(&mapEncoder, &peerInfoEncoder);

    cbor_encode_int(&mapEncoder, EAP_UTE_MAP_KEY_DIRECTION);
    cbor_encode_int(&mapEncoder, 1);

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
    struct wpabuf *to_return = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_UTE, cbor_len + 3, EAP_CODE_RESPONSE, eap_get_id(reqData));
    u8 prelude[3];
    prelude[0] = EAP_UTE_MSG_TYPE_CLIENT_GREETING;
    prelude[1] = cbor_len >> 8 & 0xFF;
    prelude[2] = cbor_len & 0xFF;
    wpabuf_put_data(to_return, prelude, 3);
    wpabuf_put_data(to_return, cbor_buf, cbor_len);

    data->state = EAP_UTE_INTERNAL_STATE_CLIENT_GREETING_SENT;

    return to_return;
}

static struct wpabuf * eap_ute_process(struct eap_sm *sm, void *priv, struct eap_method_ret *ret, const struct wpabuf *reqData)
{
    size_t len;
    struct eap_ute_data *data = priv;
    struct wpabuf *to_return = NULL;
    const u8 *eap_pkt = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_UTE, reqData, &len);

    if(eap_pkt == NULL)
        goto ignore;


    // Length must be at least 3 (1 byte type, 2 byte length)
    if(len < 3)
        goto ignore;

    u8 msgtype = eap_pkt[0];
    size_t msglen = eap_pkt[1]*256 + eap_pkt[2];
    const u8 *payload = eap_pkt + 3;

    if (len < msglen + 3) {
        // Invalid Message format.
        // TODO Change error code
        to_return = build_error_msg(reqData, 0);
    }
    const u8 *additional = NULL;
    size_t additional_len = 0;
    if(len > msglen +1 ){
        additional = eap_pkt + 3 + msglen;
        additional_len = len - (3 + msglen);
    }

    switch(msgtype) {
        case EAP_UTE_MSG_TYPE_ERROR:
            // Error message.
            // TODO: Should be logged, maybe even mirrored back to the application
            goto ignore;
        case EAP_UTE_MSG_TYPE_SERVER_GREETING:
            if(data->state != EAP_UTE_INTERNAL_STATE_INITIAL) {
                // TODO change error code
                to_return = build_error_msg(reqData, 0);
            }
            to_return = eap_ute_handle_server_greeting(sm, data, ret, reqData, payload, msglen, additional, additional_len);
    }

//send_wpabuf:
    return to_return;
ignore:
    ret->ignore = true;
    return NULL;
}
static bool eap_ute_isKeyAvailable(struct eap_sm *sm, void *priv)
{
    return false;
}
static u8 * eap_ute_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
    struct eap_ute_data *data = priv;
    u8 *key;

    if (data->kdf_out == NULL)
        return NULL;
    key = os_malloc(64);
    if (key == NULL)
        return NULL;

    *len = 64;
    os_memcpy(key, data->kdf_out, 64);

    return key;
}
static u8 * eap_ute_get_emsk(struct eap_sm *sm, void *priv, size_t *len)
{
    struct eap_ute_data *data = priv;
    u8 *key;

    if (data->kdf_out == NULL)
        return NULL;

    key = os_malloc(64);
    if (key == NULL)
        return NULL;

    *len = 64;
    os_memcpy(key, &(data->kdf_out[64]), 64);

    return key;
}


int eap_peer_ute_register(void)
{
    struct eap_method *eap;
    int ret;

    eap = eap_peer_method_alloc(EAP_VENDOR_IETF, EAP_TYPE_UTE, "UTE");
    if (eap == NULL)
        return -1;

    eap->init = eap_ute_init;
    eap->deinit = eap_ute_deinit;
    eap->process = eap_ute_process;
    eap->isKeyAvailable = eap_ute_isKeyAvailable;
    eap->getKey = eap_ute_getKey;
    eap->get_emsk = eap_ute_get_emsk;

    ret = eap_peer_method_register(eap);
    if (ret)
        eap_peer_method_free(eap);
    return ret;
}
//#endif /* EAP_UTE */
