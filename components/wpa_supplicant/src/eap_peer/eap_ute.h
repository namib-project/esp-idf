/*
 * EAP server/peer: EAP-UTE (draft-rieckers-emu-eap-ute-00)
 */

#ifndef EAP_UTE_H
#define EAP_UTE_H

typedef enum {
    EAP_UTE_STATE_UNREGISTERED = 0,
    EAP_UTE_STATE_WAITING_FOR_OOB = 1,
    EAP_UTE_STATE_OOB_RECEIVED = 2,
    EAP_UTE_STATE_REGISTERED = 3
} eap_ute_state_machine;

#endif /* EAP_UTE_H */