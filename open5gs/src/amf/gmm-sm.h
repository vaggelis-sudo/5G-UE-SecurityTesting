#ifndef AMF_NAS_5GS_GMM_SM_H
#define AMF_NAS_5GS_GMM_SM_H

#ifdef __cplusplus
extern "C" {
#endif

bool hijack_registration_request; // Hijack Registration Request
bool hijack_service_request; // Hijack Service Request
bool hijack_identity_response; // Hijack Identity Response
bool hijack_gmm_status; // Hijack GMM Status
bool hijack_de_registration_request; // Hijack Deregistration Request
bool hijack_de_registration_accept; // Hijack Deregistration Accept
bool hijack_configuration_update_complete; // Hijack Configuration Update Complete
bool hijack_registration_complete; // Hijack Registration Complete
bool hijack_authentication_response; // Hijack Authentication Response 
bool hijack_authentication_failure; // Hijack Authentication Failure
bool hijack_security_mode_complete; // Hijack Security Mode Complete
bool hijack_security_mode_reject; //Hijack Security Mode Reject
bool hijack_timer; //Hijack Timer
bool hijack_ul_nas_transport; //Hijack Ul NAS Transport

#ifdef __cplusplus
}
#endif

#endif /* AMF_NAS_5GS_GMM_SM_H */
