/*
 * EAP peer method: EAP-NOOB (RFC 9140)
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "eap_peer/eap_i.h"
#include "eap_peer/eap_config.h"
#include "eap_peer/eap_methods.h"
#include "eap_peer/eap_noob.h"
#include "utils/base64.h"
#include "cJSON.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/sha256.h"
#include "mbedtls/md.h"

struct eap_noob_state g_wpa_eap_noob_state;

typedef enum {
        EAP_NOOB_STATE_IDENTITY_SENT,
        EAP_NOOB_STATE_PEERID_SENT,
        EAP_NOOB_STATE_VERSION_NEGOTIATION_SENT,
        EAP_NOOB_STATE_PUBKEY_SENT,
        EAP_NOOB_STATE_MACP_SENT
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
    u8 *ns_b64;
    size_t ns_b64_length;
    u8 np[32];
    u8 *np_b64;
    size_t np_b64_length;
    u8 noob[16];
    u8 *noob_b64;
    size_t noob_b64_length;
    u8 *shared_key;
    size_t shared_key_length;
    u8 kz[32];
    u8 *kdf_out;
    size_t kdf_out_length;
    u8 macp[32];
    u8 macs[32];
};

static void eap_noob_deinit(struct eap_sm *sm, void *priv);

static char *
eap_noob_generate_hash_src(
        u8 dir,
        u8 *vers,
        u8 verp,
        char *peer_id,
        u8 *cryptosuites,
        u8 dirs,
        u8 *server_info,
        u8 cryptosuitep,
        u8 dirp,
        char *nai,
        u8 *peer_info,
        u8 keying_mode,
        u8 *pks,
        u8 *ns_b,
        u8 *pkp,
        u8 *np_b,
        u8 *noob
){
    u8 dir_s[8];
    snprintf((char *)dir_s,8,"%i", dir);
    u8 verp_s[8];
    snprintf((char *)verp_s,8,"%i",verp);
    u8 dirs_s[8];
    snprintf((char *)dirs_s,8,"%i", dirs);
    u8 cryptosuitep_s[8];
    snprintf((char *)cryptosuitep_s, 8, "%i", cryptosuitep);
    u8 dirp_s[8];
    snprintf((char *)dirp_s,8,"%i", dirp);
    u8 keying_mode_s[8];
    snprintf((char *)keying_mode_s,8,"%i", keying_mode);

    size_t dir_s_len = strlen((char *)dir_s);
    size_t vers_len = strlen((char *)vers);
    size_t verp_s_len = strlen((char *)verp_s);
    size_t peer_id_len = strlen(peer_id);
    size_t cryptosuites_len = strlen((char *)cryptosuites);
    size_t dirs_s_len = strlen((char *)dirs_s);
    size_t server_info_len = strlen((char *)server_info);
    size_t cryptosuitep_s_len = strlen((char *)cryptosuitep_s);
    size_t dirp_s_len = strlen((char *)dirp_s);
    size_t nai_len = strlen(nai);
    size_t peer_info_len = strlen((char *)peer_info);
    size_t keying_mode_s_len = strlen((char *)keying_mode_s);
    size_t pks_len = strlen((char *)pks);
    size_t ns_len = strlen((char *)ns_b);
    size_t pkp_len = strlen((char *)pkp);
    size_t np_len = strlen((char *)np_b);
    size_t noob_len = strlen((char *)noob);

    size_t total_length = 28 + dir_s_len + vers_len + verp_s_len + peer_id_len +
                          cryptosuites_len + dirs_s_len + server_info_len + cryptosuitep_s_len +
                          dirp_s_len + nai_len + peer_info_len + keying_mode_s_len + pks_len + ns_len +
                          pkp_len + np_len + noob_len;

    char *to_return = os_zalloc(total_length+1);

    snprintf(to_return, total_length+1,
             "[%s,%s,%s,\"%s\",%s,%s,%s,%s,%s,\"%s\",%s,%s,%s,\"%s\",%s,\"%s\",\"%s\"]",
             dir_s,
             vers,
             verp_s,
             peer_id,
             cryptosuites,
             dirs_s,
             server_info,
             cryptosuitep_s,
             dirp_s,
             nai,
             peer_info,
             keying_mode_s,
             pks,
             ns_b,
             pkp,
             np_b,
             noob
    );


    return to_return;
}

static void eap_noob_calculate_mac(struct eap_noob_data *data){
    char *macp_src = eap_noob_generate_hash_src(
            1,
            data->vers,
            data->verp,
            data->peer_id,
            data->cryptosuites,
            data->dirs,
            data->server_info,
            data->cryptosuitep,
            data->dirp,
            data->nai,
            data->peer_info,
            0,
            data->pks,
            data->ns_b64,
            data->pkp,
            data->np_b64,
            data->noob_b64
    );
    char *macs_src = eap_noob_generate_hash_src(
            2,
            data->vers,
            data->verp,
            data->peer_id,
            data->cryptosuites,
            data->dirs,
            data->server_info,
            data->cryptosuitep,
            data->dirp,
            data->nai,
            data->peer_info,
            0,
            data->pks,
            data->ns_b64,
            data->pkp,
            data->np_b64,
            data->noob_b64
    );

    mbedtls_md_context_t macs_ctx;
    mbedtls_md_context_t macp_ctx;

    mbedtls_md_init(&macs_ctx);
    mbedtls_md_init(&macp_ctx);

    mbedtls_md_setup(&macs_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_setup(&macp_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);

    mbedtls_md_hmac_starts(&macs_ctx, data->kdf_out+224, 32);
    mbedtls_md_hmac_starts(&macp_ctx, data->kdf_out+256, 32);

    mbedtls_md_hmac_update(&macs_ctx, (u8 *)macs_src, strlen(macs_src));
    mbedtls_md_hmac_update(&macp_ctx, (u8 *)macp_src, strlen(macp_src));

    mbedtls_md_hmac_finish(&macp_ctx, data->macp);
    mbedtls_md_hmac_finish(&macs_ctx, data->macs);

    wpa_hexdump(MSG_MSGDUMP, "EAP-NOOB: MACp", data->macp, 32);
    wpa_hexdump(MSG_MSGDUMP, "EAP-NOOB: MACs", data->macs, 32);
}

static void eap_noob_calculate_kdf(u8 *out, size_t len, u8 *z, size_t z_len, u8 *party_u_info, u8 *party_v_info, u8 *supp_priv_info, size_t supp_priv_info_len){
    char *alg_id = "EAP-NOOB";
    size_t kdf_len = 4 + z_len + 8 + 64 + supp_priv_info_len;
    u8 *kdf_input = os_zalloc(kdf_len);
    memcpy(kdf_input+4, z, z_len);
    memcpy(kdf_input+4+z_len, alg_id, 8);
    memcpy(kdf_input+4+z_len+8, party_u_info, 32);
    memcpy(kdf_input+4+z_len+8+32, party_v_info, 32);
    memcpy(kdf_input+4+z_len+8+64, supp_priv_info, supp_priv_info_len);


    size_t curptr = 0;
    u32 id = 1;
    u8 kdf_out[32];
    while(curptr < len){
        kdf_input[0] = id >> 24;
        kdf_input[1] = id >> 16;
        kdf_input[2] = id >> 8;
        kdf_input[3] = id;
        id++;

        wpa_hexdump(MSG_MSGDUMP, "EAP-NOOB: KDF Input", kdf_input, kdf_len);

        mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), kdf_input, kdf_len, kdf_out);

        wpa_hexdump(MSG_MSGDUMP, "EAP-NOOB: KDF Output", kdf_out, 32);

        if(curptr+32<=len){
            memcpy(out + curptr, kdf_out, 32);
            curptr += 32;
        } else {
            memcpy(out + curptr, kdf_out, len-curptr);
            curptr = len;
        }
    }
    wpa_hexdump(MSG_MSGDUMP, "EAP-NOOB: KDF concat out", out, len);
}
static void eap_noob_save_persistent_state(struct eap_noob_data *data){
    // TODO NOT YET IMPLEMENTED
}
static void eap_noob_save_ephemeral_state(struct eap_noob_data *data){
    if(g_wpa_eap_noob_state.ephemeral_state)
        free(g_wpa_eap_noob_state.ephemeral_state);
    g_wpa_eap_noob_state.ephemeral_state = os_zalloc(sizeof(struct eap_noob_ephemeral_state_info));

    struct eap_noob_ephemeral_state_info *ephemeral =g_wpa_eap_noob_state.ephemeral_state;
    ephemeral->verp = data->verp;

    if(ephemeral->peer_id)
        free(ephemeral->peer_id);
    ephemeral->peer_id = os_zalloc(data->peer_id_length + 1);
    memcpy(ephemeral->peer_id, data->peer_id, data->peer_id_length + 1);

    ephemeral->cryptosuitep = data->cryptosuitep;

    if(ephemeral->nai)
        free(ephemeral->nai);
    ephemeral->nai = os_zalloc(data->nai_length + 1);
    memcpy(ephemeral->nai, data->nai, data->nai_length + 1);

    memcpy(ephemeral->ns, data->ns, 32);
    memcpy(ephemeral->np, data->np, 32);

    if(ephemeral->shared_secret)
        free(ephemeral->shared_secret);
    ephemeral->shared_secret = os_zalloc(data->shared_key_length);
    memcpy(ephemeral->shared_secret, data->shared_key, data->shared_key_length);

    memcpy(ephemeral->secret_key_base, data->kdf_out, data->kdf_out_length);

    memcpy(ephemeral->macp, data->macp, 32);
    memcpy(ephemeral->macs, data->macs, 32);

    g_wpa_eap_noob_state.noob_state = 1;
}

static void eap_noob_calculate_noob(struct eap_noob_data *data){
    // TODO: Actually use random for noob
    for(int i = 0; i<16; i++)
        data->noob[i] = i;

    if(data->noob_b64)
        free(data->noob_b64);
    data->noob_b64 = (unsigned char *)base64_url_encode(data->noob, 16, &data->noob_b64_length);

    char *hoob_src = eap_noob_generate_hash_src(
            1,
            data->vers,
            data->verp,
            data->peer_id,
            data->cryptosuites,
            data->dirs,
            data->server_info,
            data->cryptosuitep,
            data->dirp,
            data->nai,
            data->peer_info,
            0,
            data->pks,
            data->ns_b64,
            data->pkp,
            data->np_b64,
            data->noob_b64
            );

    wpa_printf(MSG_INFO, "EAP-NOOB: HOOB source: %s", hoob_src);


    u8 hoob[32];
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (u8 *)hoob_src, strlen(hoob_src), hoob);
    free(hoob_src);

    char noobid_input[14+data->noob_b64_length];
    snprintf(noobid_input, 14+data->noob_b64_length, "[\"NoobId\",\"%s\"]", data->noob_b64);

    u8 noobid[32];
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (u8 *)noobid_input, strlen(noobid_input), noobid);

    size_t hoob_length, noobid_length;
    char *hoob_b = base64_url_encode(hoob, 16, &hoob_length);
    char *noobid_b = base64_url_encode(noobid, 16, &noobid_length);

    wpa_printf(MSG_INFO, "EAP-NOOB: Hoob: %s", hoob_b);
    wpa_printf(MSG_INFO, "EAP-NOOB: Noob: %s", data->noob_b64);
    wpa_printf(MSG_INFO, "EAP-NOOB: PeerId: %s", data->peer_id);
    wpa_printf(MSG_INFO, "EAP-NOOB: NoobId: %s", noobid_b);
    wpa_printf(MSG_INFO, "EAP-NOOB: {\"hoob\"=>\"%s\", \"noob\"=>\"%s\", \"peer_id\"=>\"%s\", \"noob_id\"=>\"%s\"}",
               hoob_b, data->noob_b64, data->peer_id, noobid_b);

    free(hoob_b);
    free(noobid_b);
}

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

    if(g_wpa_eap_noob_state.ephemeral_state && g_wpa_eap_noob_state.ephemeral_state->nai){
        size_t nailen = strlen(g_wpa_eap_noob_state.ephemeral_state->nai);
        data->nai = os_zalloc(nailen+1);
        memcpy(data->nai, g_wpa_eap_noob_state.ephemeral_state->nai, nailen+1);
        data->nai_length = nailen;
    } else if (g_wpa_eap_noob_state.nai) {
        size_t nailen = strlen(g_wpa_eap_noob_state.nai);
        data->nai = os_zalloc(nailen+1);
        memcpy(data->nai, g_wpa_eap_noob_state.nai, nailen + 1);
        data->nai_length = nailen;
    } else {
        data->nai = os_zalloc(g_wpa_anonymous_identity_len+1);
        memcpy(data->nai, g_wpa_anonymous_identity, g_wpa_anonymous_identity_len);
        data->nai[g_wpa_anonymous_identity_len] = 0;
        data->nai_length = g_wpa_anonymous_identity_len;
    }

    if(g_wpa_eap_noob_state.ephemeral_state){
        if(g_wpa_eap_noob_state.ephemeral_state->peer_id != NULL) {
            size_t pid_len = strlen(g_wpa_eap_noob_state.ephemeral_state->peer_id);
            data->peer_id = os_zalloc(pid_len+1);
            if(data->peer_id == NULL){
                eap_noob_deinit(sm, data);
                return NULL;
            }
            memcpy(data->peer_id, g_wpa_eap_noob_state.ephemeral_state->peer_id, pid_len+1);
            data->peer_id_length = pid_len;
        }

        memcpy(data->macp, g_wpa_eap_noob_state.ephemeral_state->macp, 32);
        memcpy(data->macs, g_wpa_eap_noob_state.ephemeral_state->macs, 32);

        data->kdf_out = os_zalloc(320);
        data->kdf_out_length = 320;
        memcpy(data->kdf_out, g_wpa_eap_noob_state.ephemeral_state->secret_key_base, 320);
    }
    else if(g_wpa_eap_noob_state.peer_id != NULL){
        size_t pid_len = strlen(g_wpa_eap_noob_state.peer_id);
        data->peer_id = os_zalloc(pid_len+1);
        if(data->peer_id == NULL){
            eap_noob_deinit(sm, data);
            return NULL;
        }
        memcpy(data->peer_id, g_wpa_eap_noob_state.peer_id, pid_len+1);
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
    if (data->shared_key != NULL && data->shared_key_length > 0)
        os_free(data->shared_key);
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

    char *return_json = cJSON_PrintUnformatted(ret_json);
    size_t payload_len = strlen(return_json);
    struct wpabuf * to_return = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, payload_len, EAP_CODE_RESPONSE, eap_get_id(reqData));
    wpabuf_put_data(to_return, return_json, payload_len);
    data->state = EAP_NOOB_STATE_PEERID_SENT;
    return to_return;
}
static struct wpabuf * eap_noob_handle_type_2(struct eap_sm *sm, struct eap_noob_data *data, struct eap_method_ret *ret, const struct wpabuf *reqData, cJSON *json){
    // Parse Type 2 data
    cJSON *parsed_vers = cJSON_GetObjectItemCaseSensitive(json, "Vers");
    if(!cJSON_IsArray(parsed_vers)){
        wpa_printf(MSG_INFO, "EAP-NOOB: Vers was not an array");
        // TODO send out error.
        ret->ignore = true;
        return NULL;
    }
    data->vers = (u8 *)cJSON_PrintUnformatted(parsed_vers);
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
    data->cryptosuites = (u8 *)cJSON_PrintUnformatted(parsed_cryptosuites);
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
    data->server_info = (u8 *)cJSON_PrintUnformatted(parsed_serverinfo);
    data->server_info_length = strlen((char *)data->server_info);
    // TODO: Actually parse ServerInfo.

    // Build Reply Type 2
    cJSON *peerinfo_json = cJSON_CreateObject();

    cJSON *ret_json = cJSON_CreateObject();
    cJSON_AddItemToObject(ret_json, "Type", cJSON_CreateNumber(2));
    cJSON_AddItemToObject(ret_json, "Verp", cJSON_CreateNumber(1));
    cJSON_AddItemToObject(ret_json, "PeerId", cJSON_CreateStringReference(data->peer_id));
    cJSON_AddItemToObject(ret_json, "Cryptosuitep", cJSON_CreateNumber(1));
    cJSON_AddItemToObject(ret_json, "Dirp", cJSON_CreateNumber(1)); // Peer-to-server
    cJSON_AddItemToObject(ret_json, "PeerInfo", peerinfo_json); // For now PeerInfo is empty. Need to fill it at some point

    data->peer_info = (u8 *) cJSON_PrintUnformatted(peerinfo_json);
    data->peer_info_length = strlen((char *)data->peer_info);
    data->verp = 1;
    data->cryptosuitep = 1;
    data->dirp = 1;

    char *return_json = cJSON_PrintUnformatted(ret_json);
    size_t payload_len = strlen(return_json);
    struct wpabuf *to_return = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, payload_len, EAP_CODE_RESPONSE, eap_get_id(reqData));
    wpabuf_put_data(to_return, return_json, payload_len);
    data->state = EAP_NOOB_STATE_VERSION_NEGOTIATION_SENT;
    return to_return;
}
static struct wpabuf * eap_noob_handle_type_3(struct eap_sm *sm, struct eap_noob_data *data, struct eap_method_ret *ret, const struct wpabuf *reqData, cJSON *json){
    // Parse Type 3 data
    cJSON *parsed_peerid = cJSON_GetObjectItemCaseSensitive(json, "PeerId");
    if(!cJSON_IsString(parsed_peerid)){
        wpa_printf(MSG_INFO, "EAP-NOOB: PeerID was not a string");
        // TODO send out error
        ret->ignore = true;
        return NULL;
    }
    size_t len = strlen(parsed_peerid->valuestring);
    // We already have a PeerId. Check if it matches.
    if(data->peer_id_length != len || memcmp(data->peer_id, parsed_peerid->valuestring, len) != 0){
        wpa_printf(MSG_INFO, "EAP-NOOB: PeerID did not match!");
        // TODO send out error
        ret->ignore = true;
        return NULL;
    }

    cJSON *parsed_pks = cJSON_GetObjectItemCaseSensitive(json, "PKs");
    if(!cJSON_IsObject(parsed_pks)){
        wpa_printf(MSG_INFO, "EAP-NOOB: PKs was not an object");
        // TODO send out error
        ret->ignore = true;
        return NULL;
    }
    // TODO: actually parse the PKs
    cJSON *parsed_pks_x = cJSON_GetObjectItemCaseSensitive(parsed_pks, "x");
    if(!cJSON_IsString(parsed_pks_x)){
        wpa_printf(MSG_INFO, "EAP-NOOB: PKs.x was not a string");
        // TODO send out error
        ret->ignore = true;
        return NULL;
    }
    size_t otherpubkey_len;
    unsigned char *otherpubkey = base64_url_decode(parsed_pks_x->valuestring, strlen(parsed_pks_x->valuestring), &otherpubkey_len);
    if(otherpubkey_len != 32){
        wpa_printf(MSG_INFO, "EAP-NOOB: PKs.x was not a 32-byte encoded ");
        // TODO send out error
        ret->ignore = true;
        return NULL;
    }

    if(data->pks)
        os_free(data->pks);
    data->pks = (u8 *) cJSON_PrintUnformatted(parsed_pks);
    data->pks_length = strlen((char *) data->pks);

    cJSON *parsed_ns = cJSON_GetObjectItemCaseSensitive(json, "Ns");
    if(!cJSON_IsString(parsed_ns)){
        wpa_printf(MSG_INFO, "EAP-NOOB: Ns was not a string");
        // TODO send out error
        ret->ignore = true;
        return NULL;
    }
    size_t ns_len;
    len = strlen(parsed_ns->valuestring);
    u8 *l = base64_url_decode(parsed_ns->valuestring, len, &ns_len);
    if(ns_len != 32){
        wpa_printf(MSG_INFO, "EAP-NOOB: Decoded Ns was not exactly 32 bytes long");
        // TODO send out error
        ret->ignore = true;
        return NULL;
    }

    memcpy(data->ns, l, 32);
    free(l);

    if(data->ns_b64)
        os_free(data->ns_b64);
    data->ns_b64 = os_zalloc(len+1);
    memcpy(data->ns_b64, parsed_ns->valuestring, len+1);
    data->ns_b64_length = len;

    cJSON *parsed_sleeptime = cJSON_GetObjectItemCaseSensitive(json, "SleepTime");
    // TODO: actually parse SleepTime


    // Calculate X25519
    mbedtls_ecdh_context x25519_ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ecdh_init( &x25519_ctx );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
    int ret_val = 1;

    unsigned char mykey[32];
    unsigned char sharedkey[32];

    const char *mbed_seed = "ecdh";

    ret_val = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *)mbed_seed, 4);
    ret_val = mbedtls_ecp_group_load( &x25519_ctx.grp, MBEDTLS_ECP_DP_CURVE25519 );
    ret_val = mbedtls_ecdh_gen_public( &x25519_ctx.grp, &x25519_ctx.d, &x25519_ctx.Q, mbedtls_ctr_drbg_random, &ctr_drbg );
    ret_val = mbedtls_mpi_write_binary_le( &x25519_ctx.Q.X, mykey, 32);

    size_t mykey_b64_len;
    char *mykey_b64 = base64_url_encode(mykey, 32, &mykey_b64_len);

    mbedtls_mpi_lset(&x25519_ctx.Qp.Z, 1);
    ret_val = mbedtls_mpi_read_binary_le( &x25519_ctx.Qp.X, otherpubkey, 32);
    free(otherpubkey);
    ret_val = mbedtls_ecdh_compute_shared( &x25519_ctx.grp, &x25519_ctx.z, &x25519_ctx.Qp, &x25519_ctx.d, mbedtls_ctr_drbg_random, &ctr_drbg );
    ret_val = mbedtls_mpi_write_binary_le( &x25519_ctx.z, sharedkey, 32);

    if(data->shared_key)
        free(data->shared_key);
    data->shared_key = os_zalloc(32);
    memcpy(data->shared_key, sharedkey, 32);
    data->shared_key_length = 32;

    wpa_hexdump(MSG_MSGDUMP, "EAP-NOOB: ECHDE Output:", sharedkey, 32);

    // TODO Actually use a random nonce.
    for(int i = 0; i<32; i++){
        data->np[i] = i;
    }
    l = (unsigned char *)base64_url_encode(data->np, 32, &len);
    if (data->np_b64)
        free(data->np_b64);
    data->np_b64 = l;
    data->np_b64_length = len;


    cJSON *pkp = cJSON_CreateObject();
    cJSON_AddItemToObject(pkp, "kty", cJSON_CreateString("OKP"));
    cJSON_AddItemToObject(pkp, "crv", cJSON_CreateString("X25519"));
    cJSON_AddItemToObject(pkp, "x", cJSON_CreateString(mykey_b64));

    if(data->pkp)
        free(data->pkp);
    data->pkp = (u8 *)cJSON_PrintUnformatted(pkp);
    data->pkp_length = strlen((char *)data->pkp);

    // Build Reply Type 3
    cJSON *ret_json = cJSON_CreateObject();
    cJSON_AddItemToObject(ret_json, "Type", cJSON_CreateNumber(3));
    cJSON_AddItemToObject(ret_json, "PeerId", cJSON_CreateStringReference(data->peer_id));
    cJSON_AddItemToObject(ret_json, "PKp", pkp);
    cJSON_AddItemToObject(ret_json, "Np", cJSON_CreateStringReference((char *)l));

    char *return_json = cJSON_PrintUnformatted(ret_json);
    size_t payload_len = strlen(return_json);
    struct wpabuf *to_return = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, payload_len, EAP_CODE_RESPONSE, eap_get_id(reqData));
    wpabuf_put_data(to_return, return_json, payload_len);
    data->state = EAP_NOOB_STATE_PUBKEY_SENT;

    // Here we have completed the initial exchange.
    // We now calculate an OOB-Message, save our ephemeral state, so we just do reconnect exchanges from now on.
    eap_noob_calculate_noob(data);

    // With the noob value we also have everything to calculate the secret keys
    if(data->kdf_out)
        free(data->kdf_out);
    data->kdf_out = os_zalloc(320);
    data->kdf_out_length = 320;
    eap_noob_calculate_kdf(data->kdf_out, 320, sharedkey, 32, data->np, data->ns, data->noob, 16);

    // And with the secret keys we can calculate the MAC values
    eap_noob_calculate_mac(data);

    eap_noob_save_ephemeral_state(data);
    return to_return;
}
static struct wpabuf * eap_noob_handle_type_4(struct eap_sm *sm, struct eap_noob_data *data, struct eap_method_ret *ret, const struct wpabuf *reqData, cJSON *json){ return NULL; }
static struct wpabuf * eap_noob_handle_type_5(struct eap_sm *sm, struct eap_noob_data *data, struct eap_method_ret *ret, const struct wpabuf *reqData, cJSON *json){ return NULL; }
static struct wpabuf * eap_noob_handle_type_6(struct eap_sm *sm, struct eap_noob_data *data, struct eap_method_ret *ret, const struct wpabuf *reqData, cJSON *json){
    cJSON *parsed_peerid = cJSON_GetObjectItemCaseSensitive(json, "PeerId");
    if(!cJSON_IsString(parsed_peerid)){
        wpa_printf(MSG_INFO, "EAP-NOOB: PeerID was not a string");
        // TODO send out error
        ret->ignore = true;
        return NULL;
    }
    size_t len = strlen(parsed_peerid->valuestring);
    // We already have a PeerId. Check if it matches.
    if(data->peer_id_length != len || memcmp(data->peer_id, parsed_peerid->valuestring, len) != 0){
        wpa_printf(MSG_INFO, "EAP-NOOB: PeerID did not match!");
        wpa_printf(MSG_INFO, "EAP-NOOB: My PeerId: %s %i, sent PeerId: %s %i", data->peer_id, data->peer_id_length, parsed_peerid->valuestring, len);
        // TODO send out error
        ret->ignore = true;
        return NULL;
    }

    cJSON *parsed_noobid = cJSON_GetObjectItemCaseSensitive(json, "NoobId");
    if(!cJSON_IsString(parsed_noobid)){
        wpa_printf(MSG_INFO, "EAP-NOOB: NoobId was not a string");
        // TODO send out error
        ret->ignore = true;
        return NULL;
    }
    // TODO check for the correct noob id. For now we just assume the correct noobid was transmitted

    cJSON *parsed_macs = cJSON_GetObjectItemCaseSensitive(json, "MACs");
    if(!cJSON_IsString(parsed_macs)){
        wpa_printf(MSG_INFO, "EAP-NOOB: MACs was not a string");
        // TODO send out error
        ret->ignore = true;
        return NULL;
    }
    len = strlen(parsed_macs->valuestring);
    size_t mac_len;
    u8 *macs = base64_url_decode(parsed_macs->valuestring, len, &mac_len);

    if(mac_len != 32){
        wpa_printf(MSG_INFO, "EAP-NOOB: MACs decoded length did not match");
        // TODO send out error
        ret->ignore = true;
        return NULL;
    }
    u8 equal = 0;
    for(int i = 0; i< 32; i++)
        equal = equal | (data->macs[i] ^ macs[i]);
    if(equal != 0){
        wpa_printf(MSG_INFO, "EAP-NOOB: MACs did not match.");
        wpa_hexdump(MSG_MSGDUMP, "EAP-NOOB: sent MACs", macs, 32);
        wpa_hexdump(MSG_MSGDUMP, "EAP-NOOB: my MACs", data->macs, 32);
        // TODO send out error
        ret->ignore = true;
        return NULL;
    }

    char *macp = base64_url_encode(data->macp, 32, &mac_len);

    cJSON *ret_json = cJSON_CreateObject();
    cJSON_AddItemToObject(ret_json, "Type", cJSON_CreateNumber(6));
    cJSON_AddItemToObject(ret_json, "PeerId", cJSON_CreateStringReference(data->peer_id));
    cJSON_AddItemToObject(ret_json, "MACp", cJSON_CreateStringReference(macp));

    char *return_json = cJSON_PrintUnformatted(ret_json);
    size_t payload_len = strlen(return_json);
    struct wpabuf *to_return = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, payload_len, EAP_CODE_RESPONSE, eap_get_id(reqData));
    wpabuf_put_data(to_return, return_json, payload_len);

    eap_noob_save_persistent_state(data);

    data->state = EAP_NOOB_STATE_MACP_SENT;
    return to_return;
}
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
    struct eap_noob_data *data = priv;
    return data->state == EAP_NOOB_STATE_MACP_SENT;
}

static u8 *
eap_noob_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
    if(!eap_noob_isKeyAvailable(sm, priv)){
        return NULL;
    }
    struct eap_noob_data *data = priv;
    u8 *msk = malloc(64);
    memcpy(msk, data->kdf_out, 64);
    wpa_printf(MSG_INFO, "========================================");
    wpa_hexdump(MSG_MSGDUMP, "EAP-NOOB: getKey called", data->kdf_out, 64);
    wpa_printf(MSG_INFO, "========================================");
    *len = 64;
    return msk;
}

static u8 *
eap_noob_get_emsk(struct eap_sm *sm, void *priv, size_t *len)
{
    if(!eap_noob_isKeyAvailable(sm, priv)){
        return NULL;
    }
    struct eap_noob_data *data = priv;
    u8 *emsk = malloc(64);
    memcpy(emsk, data->kdf_out + 64, 64);
    *len = 64;
    return emsk;
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
