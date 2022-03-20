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
        EAP_NOOB_STATE_PEERID_SENT,
        EAP_NOOB_STATE_VERSION_NEGOTIATION_SENT
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
    struct wpabuf * to_return = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, payload_len, EAP_CODE_RESPONSE, eap_get_id(reqData));
    wpabuf_put_data(to_return, return_json, payload_len);
    data->state = EAP_NOOB_STATE_PEERID_SENT;
    return to_return;
}
static struct wpabuf * eap_noob_handle_type_2(struct eap_sm *sm, struct eap_noob_data *data, struct eap_method_ret *ret, const struct wpabuf *reqData, cJSON *json){
    cJSON *parsed_vers = cJSON_GetObjectItemCaseSensitive(json, "Vers");
    if(!cJSON_IsArray(parsed_vers)){
        wpa_printf(MSG_INFO, "EAP-NOOB: Vers was not an array");
        // TODO send out error.
        ret->ignore = true;
        return NULL;
    }
    data->vers = (u8 *)cJSON_Print(parsed_vers);
    data->vers_length = strlen((char *)data->vers);
    // TODO: Check that version 1 is included

    cJSON *parsed_peerid = cJSON_GetObjectItemCaseSensitive(json, "PeerId");
    if(!cJSON_IsString(parsed_peerid)){
        wpa_printf(MSG_INFO, "EAP-NOOB: PeerID was not a string");
        // TODO send out error
        ret->ignore = true;
        return NULL;
    }
    size_t len = strlen(parsed_peerid->valuestring);
    if(data->peer_id == NULL) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: New PeerID allocated");
        data->peer_id = os_zalloc(len+1);
        memcpy(data->peer_id, parsed_peerid->valuestring, len+1);
        data->peer_id_length = len;
    } else {
        // We already have a PeerId. Check if it matches.
        if(data->peer_id_length != len || !memcmp(data->peer_id, parsed_peerid->valuestring, len)){
            wpa_printf(MSG_INFO, "EAP-NOOB: PeerID did not match!");
            // TODO send out error
            ret->ignore = true;
            return NULL;
        }
    }

    cJSON *parsed_newnai = cJSON_GetObjectItemCaseSensitive(json, "NewNAI");
    if(parsed_newnai == NULL){
        wpa_printf(MSG_DEBUG, "EAP-NOOB: No NewNAI.");
    } else {
        if(!cJSON_IsString(parsed_newnai)){
            wpa_printf(MSG_INFO, "EAP-NOOB: NewNAI was not a string");
            // TODO send out error
            ret->ignore = true;
            return NULL;
        }

        wpa_printf(MSG_DEBUG, "EAP-NOOB: NewNAI is set. Updating.");
        if(data->nai)
          os_free(data->nai);
        len = strlen(parsed_newnai->valuestring);
        data->nai = os_zalloc(len+1);
        memcpy(data->nai, parsed_newnai->valuestring, len+1);
        data->nai_length = len;
        // TODO: Update the outer Username for EAP.
    }

    cJSON *parsed_cryptosuites = cJSON_GetObjectItemCaseSensitive(json, "Cryptosuites");
    if(!cJSON_IsArray(parsed_cryptosuites)){
        wpa_printf(MSG_INFO, "EAP-NOOB: Cryptosuites was not an array");
        // TODO send out error
        ret->ignore = true;
        return NULL;
    }
    data->cryptosuites = (u8 *)cJSON_Print(parsed_cryptosuites);
    data->cryptosuites_length = strlen((char *)data->cryptosuites);
    // TODO: Check the cryptosuites values.

    cJSON *parsed_dirs = cJSON_GetObjectItemCaseSensitive(json, "Dirs");
    if(!cJSON_IsNumber(parsed_dirs)){
        wpa_printf(MSG_INFO, "EAP-NOOB: Dirs was not a number");
        // TODO send out error
        ret->ignore = true;
        return NULL;
    }
    data->dirs = parsed_dirs->valueint;
    // TODO: Check if dirs is compatible with our directions.

    cJSON *parsed_serverinfo = cJSON_GetObjectItemCaseSensitive(json, "ServerInfo");
    if(parsed_serverinfo == NULL){
        wpa_printf(MSG_INFO, "EAP-NOOB: No ServerInfo supplied");
        // TODO send out error
        ret->ignore = true;
        return NULL;
    }
    data->server_info = (u8 *)cJSON_Print(parsed_serverinfo);
    data->server_info_length = strlen((char *)data->server_info);
    // TODO: Actually parse ServerInfo.

    cJSON *ret_json = cJSON_CreateObject();
    cJSON_AddItemToObject(ret_json, "Type", cJSON_CreateNumber(2));
    cJSON_AddItemToObject(ret_json, "Verp", cJSON_CreateNumber(1));
    cJSON_AddItemToObject(ret_json, "PeerId", cJSON_CreateStringReference(data->peer_id));
    cJSON_AddItemToObject(ret_json, "Cryptosuitep", cJSON_CreateNumber(1));
    cJSON_AddItemToObject(ret_json, "Dirp", cJSON_CreateNumber(1)); // Peer-to-server
    cJSON_AddItemToObject(ret_json, "PeerInfo", cJSON_CreateObject()); // For now PeerInfo is empty. Need to fill it at some point

    char *return_json = cJSON_Print(ret_json);
    size_t payload_len = strlen(return_json);
    struct wpabuf *to_return = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, payload_len, EAP_CODE_RESPONSE, eap_get_id(reqData));
    wpabuf_put_data(to_return, return_json, payload_len);
    data->state = EAP_NOOB_STATE_VERSION_NEGOTIATION_SENT;
    return to_return;
}
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
            // TODO: check if the current state is actually "Identity sent"
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
