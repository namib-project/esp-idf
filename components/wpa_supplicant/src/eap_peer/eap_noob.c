/*
 * EAP peer method: EAP-NOOB (RFC 9140)
 */

#include "utils/includes.h"

# TODO: removed ifdef EAP_NOOB. Maybe put it back.
#include "utils/common.h"
#include "eap_peer/eap_i.h"
#include "eap_peer/eap_config.h"
#include "eap_peer/eap_methods.h"
#include "eap_peer/eap_noob.h"
#include "utils/base64.h"
#include "cJSON.h"

struct eap_noob_state g_wpa_eap_noob_state;

typedef enum {
        EAP_NOOB_STATE_IDENTITY_SENT,
        EAP_NOOB_STATE_PEERID_SENT
    } eap_noob_state;

struct eap_noob_data {
    u8 *vers;
    size_t vers_length;
    u8 peer_state;
    eap_noob_state state;
    u8 verp;
    char *peer_id;
    size_t peer_id_length;
    u8 *cryptosuites;
    size_t cryptosuites_length;
    u8 dirs;
    u8 *server_info;
    size_t server_info_length;
    u8 cryptosuitep;
    u8 dirp;
    char *nai;
    size_t nai_length;
    u8 *peer_info;
    size_t peer_info_length;
    u8 keying_mode;
    u8 *pks;
    size_t pks_length;
    u8 *pkp;
    size_t pkp_length;
    u8 ns[32];
    u8 np[32];
    u8 kz[32];
    u8 *kdf_out;
    size_t kdf_out_length;
};

static void eap_noob_deinit(struct eap_sm *sm, void *priv);

static void *
eap_noob_init(struct eap_sm *sm){


    if(!g_wpa_eap_noob_state.active)
        return NULL;

    struct eap_noob_data *data;
    data = (struct eap_noob_data *)os_zalloc(sizeof(*data));
    if (data == NULL)
        return NULL;

    data->state = EAP_NOOB_STATE_IDENTITY_SENT;
    data->peer_state = g_wpa_eap_noob_state.noob_state;
    if(g_wpa_eap_noob_state.peer_id != NULL){
        size_t pid_len = strlen(g_wpa_eap_noob_state.peer_id)+1;
        data->peer_id = os_zalloc(pid_len);
        if(data->peer_id == NULL){
            eap_noob_deinit(sm, data);
            return NULL;
        }
        memcpy(data->peer_id, g_wpa_eap_noob_state.peer_id, pid_len);
        data->peer_id_length = pid_len;
    }
    return data;
}

static void
eap_noob_deinit(struct eap_sm *sm, void *priv)
{
    struct eap_noob_data *data = priv;
    if (data == NULL)
        return;

    if (data->vers != NULL && data->vers_length > 0)
        os_free(data->vers);
    if (data->peer_id != NULL && data->peer_id_length > 0)
        os_free(data->peer_id);
    if (data->cryptosuites != NULL && data->cryptosuites_length > 0)
        os_free(data->cryptosuites);
    if (data->server_info != NULL && data->server_info_length > 0)
        os_free(data->server_info);
    if (data->peer_info != NULL && data->peer_info_length > 0)
        os_free(data->peer_info);
    if (data->pks != NULL && data->pks_length > 0)
        os_free(data->pks);
    if (data->pkp != NULL && data->pkp_length > 0)
        os_free(data->pkp);
    if (data->kdf_out != NULL && data->kdf_out_length > 0)
        os_free(data->kdf_out);

    os_free(data);
}

static struct wpabuf * eap_noob_handle_type_1(struct eap_sm *sm, struct eap_noob_data *data, struct eap_method_ret *ret, const struct wpabuf *reqData, cJSON *json){
    // Reply with Type 1
    cJSON *ret_json = cJSON_CreateObject();
    cJSON_AddItemToObject(ret_json, "Type", cJSON_CreateNumber(1));
    cJSON_AddItemToObject(ret_json, "PeerState", cJSON_CreateNumber(data->peer_state));
    if(data->peer_id != NULL) {
        cJSON_AddItemToObject(ret_json, "PeerId", cJSON_CreateStringReference(data->peer_id));
    }

    char *return_json = cJSON_Print(ret_json);
    size_t payload_len = strlen(return_json);
    u8 *return_bytes = os_zalloc(payload_len + 5);
    return_bytes[0] = 2; // EAP Response
    return_bytes[1] = 0; // TODO: EAP-ID. fetch from reqData.
    return_bytes[2] = (payload_len + 5) >> 8;
    return_bytes[3] = payload_len + 5;
    return_bytes[4] = EAP_TYPE_NOOB;
    memcpy(&return_bytes[5], (u8 *)return_json, payload_len);
    return wpabuf_alloc_ext_data(return_bytes, payload_len+5);
}
static struct wpabuf * eap_noob_handle_type_2(struct eap_sm *sm, struct eap_noob_data *data, struct eap_method_ret *ret, const struct wpabuf *reqData, cJSON *json){ return NULL; }
static struct wpabuf * eap_noob_handle_type_3(struct eap_sm *sm, struct eap_noob_data *data, struct eap_method_ret *ret, const struct wpabuf *reqData, cJSON *json){ return NULL; }
static struct wpabuf * eap_noob_handle_type_4(struct eap_sm *sm, struct eap_noob_data *data, struct eap_method_ret *ret, const struct wpabuf *reqData, cJSON *json){ return NULL; }
static struct wpabuf * eap_noob_handle_type_5(struct eap_sm *sm, struct eap_noob_data *data, struct eap_method_ret *ret, const struct wpabuf *reqData, cJSON *json){ return NULL; }
static struct wpabuf * eap_noob_handle_type_6(struct eap_sm *sm, struct eap_noob_data *data, struct eap_method_ret *ret, const struct wpabuf *reqData, cJSON *json){ return NULL; }
static struct wpabuf * eap_noob_handle_type_7(struct eap_sm *sm, struct eap_noob_data *data, struct eap_method_ret *ret, const struct wpabuf *reqData, cJSON *json){ return NULL; }
static struct wpabuf * eap_noob_handle_type_8(struct eap_sm *sm, struct eap_noob_data *data, struct eap_method_ret *ret, const struct wpabuf *reqData, cJSON *json){ return NULL; }
static struct wpabuf * eap_noob_handle_type_9(struct eap_sm *sm, struct eap_noob_data *data, struct eap_method_ret *ret, const struct wpabuf *reqData, cJSON *json){ return NULL; }

static struct wpabuf *
eap_noob_process(struct eap_sm *sm, void *priv, struct eap_method_ret *ret, const struct wpabuf *reqData)
{
    size_t len;
    struct eap_noob_data *data = priv;
    const u8 *pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_NOOB, reqData, &len);

    if (pos == NULL) {
        // No content in the EAP Packet, so ignore it.
        ret->ignore = true;
        return NULL;
    }

    cJSON *content = cJSON_ParseWithLength((char *)pos, len);
    if (content == NULL){
        // Invalid JSON
        // TODO: Send out error message
        ret->ignore = true;
        return NULL;
    }

    cJSON *parsed_type = cJSON_GetObjectItemCaseSensitive(content, "Type");
    if (!cJSON_IsNumber(parsed_type)) {
        // Type is not a number
        // TODO: Send out error message
        ret->ignore = true;
        return NULL;
    }

    int type = parsed_type->valueint;
    switch(type){
        case 1:
            // PeerId and PeerState discovery
            return eap_noob_handle_type_1(sm, data, ret, reqData, content);
        case 2:
            // Version, cryptosuite, and parameter negotiation
            return eap_noob_handle_type_2(sm, data, ret, reqData, content);
        case 3:
            // Exchange of ECDHE keys and nonces
            return eap_noob_handle_type_3(sm, data, ret, reqData, content);
        case 4:
            // Indication to the peer that the server has not yet received an OOB message
            return eap_noob_handle_type_4(sm, data, ret, reqData, content);
        case 5:
            // NoobId discovery
            return eap_noob_handle_type_5(sm, data, ret, reqData, content);
        case 6:
            // Authentication and key confirmation with HMAC
            return eap_noob_handle_type_6(sm, data, ret, reqData, content);
        case 7:
            // Version, cryptosuite, and parameter negotiation
            return eap_noob_handle_type_7(sm, data, ret, reqData, content);
        case 8:
            // Exchange of ECDHE keys and nonces
            return eap_noob_handle_type_8(sm, data, ret, reqData, content);
        case 9:
            // Authentication and key confirmation with HMAC
            return eap_noob_handle_type_9(sm, data, ret, reqData, content);
        default:
            // Unknown message type.
            // TODO: Send out error message
            ret->ignore = true;
            return NULL;
    }
}

static bool
eap_noob_isKeyAvailable(struct eap_sm *sm, void *priv)
{
    return false; // TODO STUB
}

static u8 *
eap_noob_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
    return NULL; // TODO STUB
}

static u8 *
eap_noob_get_emsk(struct eap_sm *sm, void *priv, size_t *len)
{
    return NULL; // TODO STUB
}

static u8 *
eap_noob_getSessionId(struct eap_sm *sm, void *priv, size_t *len)
{
    return NULL; // TODO STUB
}

int
eap_peer_noob_register(void)
{
    struct eap_method *eap;
    int ret;

    eap = eap_peer_method_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, "NOOB");
    if (eap == NULL)
        return -1;

    eap->init = eap_noob_init;
    eap->deinit = eap_noob_deinit;
    eap->process = eap_noob_process;
    eap->isKeyAvailable = eap_noob_isKeyAvailable;
    eap->getKey = eap_noob_getKey;
    eap->get_emsk = eap_noob_get_emsk;
    eap->getSessionId = eap_noob_getSessionId;

    ret = eap_peer_method_register(eap);
    if (ret)
        eap_peer_method_free(eap);
    return ret;
}
# TODO: add endif if ifdef comes back (ifdef EAP_NOOB)
