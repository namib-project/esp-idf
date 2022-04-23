/*
 * EAP peer method: EAP-UTE (draft-rieckers-emu-eap-ute-00.txt)
 */

#ifdef EAP_UTE

#include "eap_peer/eap_i.h"
#include "eap_peer/eap_config.h"
#include "eap_peer/eap_methods.h"
#include "eap_peer/eap_ute.h"

enum eap_ute_internal_state {
    EAP_UTE_INTERNAL_STATE_INITIAL
}
enum eap_ute_exchange_type {
    EAP_UTE_EXCHANGE_TYPE_NONE,
    EAP_UTE_EXCHANGE_TYPE_INITIAL,
    EAP_UTE_EXCHANGE_TYPE_COMPLETION,
    EAP_UTE_EXCHANGE_TYPE_RECONNECT_STATIC,
    EAP_UTE_EXCHANGE_TYPE_RECONNECT_PFS
};

struct eap_ute_data {
    enum eap_ute_state state;
    enum eap_ute_exchange_type exch_type;
    u8 *kdf_out;
    size_t kdf_out_len;
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
static void * eap_ute_deinit(struct eap_sm *sm, void *priv)
{
    struct eap_ute_data *data = priv;
    if (data == NULL)
        return;

    if (data->kdf_out_len != 0 && data->kdf_out != NULL)
        os_free(data->kdf_out);

    os_free(data);
}
static struct wpabuf * eap_ute_process(struct eap_sm *sm, void *priv, struct eap_method_ret *ret, const struct wpabuf *reqData)
{
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
#endif /* EAP_UTE */