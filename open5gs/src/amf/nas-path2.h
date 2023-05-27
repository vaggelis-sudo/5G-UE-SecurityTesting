#ifndef AMF_NAS_5GS_PATH2_H
#define AMF_NAS_5GS_PATH2_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

bool deregistration_security; //Deregistration Message Security
bool deregistration_accept_security; //Deregistration Accept Message Security
bool gmm_status_security; //GMM Status Message Security
bool security_mode_command_security; //Security Mode Command Security
bool configuration_update_command_security; //Configuration Update Command Security
bool service_accept_security; //Service Accept Security
bool registration_accept_security; //Registration Accept Security
bool authentication_result_security; //Authentication Result Security

typedef struct{
 char* ue_ul_handle;
 char* dl_reply;
 char* command_mode;
 char** dl_params;
 int dl_size;
} nas_command;
 
typedef struct{
 nas_command nas_commands_aka;
 int aka_size;
 nas_command nas_commands_after_aka;
 int after_aka_size;
} nas_testset;

//nas_command n_command;
nas_testset n_testset; 

int user_nas_5gs_send_registration_accept(amf_ue_t *amf_ue, char** parameters, int size);
int user_nas_5gs_send_registration_reject(amf_ue_t *amf_ue, char** parameters, int size);
int user_nas_5gs_send_service_accept(amf_ue_t *amf_ue, char** parameters, int size);
int user_nas_5gs_send_service_reject(amf_ue_t *amf_ue, char** parameters, int size);
int user_nas_5gs_send_de_registration_accept(amf_ue_t *amf_ue, char** parameters, int size);
int user_nas_5gs_send_de_registration_request(amf_ue_t *amf_ue, char** parameters, int size);
int user_nas_5gs_send_identity_request(amf_ue_t *amf_ue, char** parameters, int size);
int user_nas_5gs_send_authentication_request(amf_ue_t *amf_ue, char** parameters, int size);
int user_nas_5gs_send_authentication_result(amf_ue_t* amf_ue, char** parameters, int size);
int user_nas_5gs_send_authentication_reject(amf_ue_t *amf_ue, char** parameters, int size);
int user_nas_5gs_send_security_mode_command(amf_ue_t *amf_ue, char** parameters, int size);
int user_nas_5gs_send_configuration_update_command(amf_ue_t *amf_ue, char** parameters, int size);
//int user_nas_send_pdu_session_modification_command(amf_sess_t *sess, char** parameters, int size);
//int user_nas_send_pdu_session_release_command(amf_sess_t *sess, char** parameters, int size);
int user_nas_5gs_send_gmm_status(amf_ue_t *amf_ue, char** parameters, int size);
//int user_nas_5gs_send_gmm_reject(amf_ue_t *amf_ue, char** parameters, int size);
//int user_nas_5gs_send_gmm_reject_from_sbi(amf_ue_t *amf_ue, char** parameters, int size);
//int user_ngap_send_paging(amf_ue_t *amf_ue, char** parameters, int size);

void user_dl_handle(char* downlink_message, amf_ue_t *amf_ue, char** parameters, int size);
void execute_flow(nas_command command_temp, amf_ue_t* amf_ue);
ogs_pkbuf_t *user_nas_5gs_security_encode(amf_ue_t *amf_ue, ogs_nas_5gs_message_t *message, uint8_t initial_security_header);

uint8_t stringToInt8(char* parameter);
uint16_t stringToInt16(char* parameter);
void stringToInt8pointer(uint8_t* data, char* parameter);

#ifdef __cplusplus
}
#endif

#endif /* AMF_NAS_5GS_PATH2_H */
