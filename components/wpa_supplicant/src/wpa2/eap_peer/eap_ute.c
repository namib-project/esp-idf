/*
 * EAP peer method: EAP-UTE (draft-rieckers-emu-eap-ute-00.txt)
 */

#ifdef EAP_UTE

static void eap_ute_deinit(struct eap_sm *sm, void *priv);


static void *
eap_ute_init(struct eap_sm *sm){
}

static void
eap_ute_deinit(struct eap_sm *sm, void *priv)
{
}

static struct wpabuf *
eap_ute_process(struct eap_sm *sm, void *priv,
        struct eap_method_ret *ret,
        const struct wpabuf *reqData)
{
}

static bool
eap_ute_isKeyAvailable(struct eap_sm *sm, void *priv)
{
}

static u8 *
eap_ute_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
}

static int
eap_ute_get_status(struct eap_sm *sm, void *priv, char *buf,
        size_t buflen, int verbose)
{
}

static bool
eap_ute_has_reauth_data(struct eap_sm *sm, void *priv)
{
}

static void
eap_ute_deinit_for_reauth(struct eap_sm *sm, void *priv)
{
}

static void *
eap_ute_init_for_reauth(struct eap_sm *sm, void *priv)
{
}

static void *
eap_ute_get_session_id(struct eap_sm *sm, void *priv, size_t *len)
{
}

int
eap_peer_ute_register(void)
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
    eap->get_status = eap_ute_get_status;
    eap->has_reauth_data = eap_ute_has_reauth_data;
    eap->deinit_for_reauth = eap_ute_deinit_for_reauth;
    eap->init_for_reauth = eap_ute_init_for_reauth;
    eap->getSessionId = eap_ute_get_session_id;

    ret = eap_peer_method_register(eap);
    if (ret)
        eap_peer_method_free(eap);
    return ret;
}

#endif /* EAP_UTE */
