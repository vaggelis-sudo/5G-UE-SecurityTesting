/*
 * Copyright (C) 2019,2020 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef AMF_NAS_5GS_PATH_H
#define AMF_NAS_5GS_PATH_H

#include "gmm-build.h"
//#include "gmm-build.c"
#include "nas-security.h"
#include "amf-sm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//#include "/lib/nas/5gs/type.h"
//#include "open5gs/lib/nas/common/type.h"
//#include "open5gs/lib/sbi/openapi/model/deregistration_reason.h"
//#include "open5gs/lib/proto/types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AMF_NAS_BACKOFF_TIME  6    /* 6 seconds */

int nas_5gs_send_to_gnb(amf_ue_t *amf_ue, ogs_pkbuf_t *pkbuf);
int nas_5gs_send_to_downlink_nas_transport(
        amf_ue_t *amf_ue, ogs_pkbuf_t *pkbuf);

int nas_5gs_send_registration_accept(amf_ue_t *amf_ue);
int nas_5gs_send_registration_reject(
        amf_ue_t *amf_ue, ogs_nas_5gmm_cause_t gmm_cause);

int nas_5gs_send_service_accept(amf_ue_t *amf_ue);
int nas_5gs_send_service_reject(
        amf_ue_t *amf_ue, ogs_nas_5gmm_cause_t gmm_cause);

int nas_5gs_send_de_registration_accept(amf_ue_t *amf_ue);
int nas_5gs_send_de_registration_request(amf_ue_t *amf_ue,
        OpenAPI_deregistration_reason_e dereg_reason);

int nas_5gs_send_identity_request(amf_ue_t *amf_ue);

int nas_5gs_send_authentication_request(amf_ue_t *amf_ue);
int nas_5gs_send_authentication_reject(amf_ue_t *amf_ue);

int nas_5gs_send_security_mode_command(amf_ue_t *amf_ue);

int nas_5gs_send_configuration_update_command(
        amf_ue_t *amf_ue, gmm_configuration_update_command_param_t *param);

int nas_send_pdu_session_modification_command(amf_sess_t *sess,
        ogs_pkbuf_t *n1smbuf, ogs_pkbuf_t *n2smbuf);

int nas_send_pdu_session_release_command(amf_sess_t *sess,
        ogs_pkbuf_t *n1smbuf, ogs_pkbuf_t *n2smbuf);

int nas_5gs_send_gmm_status(amf_ue_t *amf_ue, ogs_nas_5gmm_cause_t cause);

int nas_5gs_send_gmm_reject(
        amf_ue_t *amf_ue, ogs_nas_5gmm_cause_t gmm_cause);
int nas_5gs_send_gmm_reject_from_sbi(amf_ue_t *amf_ue, int status);

int nas_5gs_send_dl_nas_transport(amf_sess_t *sess,
        uint8_t payload_container_type, ogs_pkbuf_t *payload_container,
        ogs_nas_5gmm_cause_t cause, uint8_t backoff_time);

int nas_5gs_send_gsm_reject(amf_sess_t *sess,
        uint8_t payload_container_type, ogs_pkbuf_t *payload_container);
int nas_5gs_send_back_gsm_message(
        amf_sess_t *sess, ogs_nas_5gmm_cause_t cause, uint8_t backoff_time);

///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////

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

bool deregistration_security; //Deregistration Message Security
bool deregistration_accept_security; //Deregistration Accept Message Security
bool gmm_status_security; //GMM Status Message Security
bool security_mode_command_security; //Security Mode Command Security
bool configuration_update_command_security; //Configuration Update Command Security
bool service_accept_security; //Service Accept Security
bool registration_accept_security; //Registration Accept Security
bool authentication_result_security; //Authentication Result Security

//const char* registration_request = "registration_request";
//const char* registration_complete = "registration_complete";
//const char* deregistration_request = "deregistration_request";
//const char* service_request = "service_request";
//const char* security_mode_reject = "security_mode_reject";
//const char* notification = "notification";
//const char* authentication_response = "authentication_response";
//const char* authentication_failure = "authentication_failure";
//const char* authentication_result = "authentication_result";
//const char* identity_response = "identity_response";
//const char* security_mode_complete = "security_mode_complete";
//const char* notification_response = "notification_response";
//const char* configuration_update_complete = "configuration_update_complete";
//const char* gmm_status = "gmm_status";
//const char* deregistration_accept = "deregistration_accept";

//const char* timer_t3560 = "timer_t3560";
//const char* timer_t3550 = "timer_t3550";
//const char* timer_t3570 = "timer_t3570";
//const char* timer_t3555 = "timer_t3555";
//const char* timer_t3513 = "timer_t3513";
//const char* timer_t3522 = "timer_t3522";

//const char* send_message = "send";
//const char* replay_message = "replay";

///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////

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

///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////

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
int user_nas_send_pdu_session_modification_command(amf_sess_t *sess, char** parameters, int size);
int user_nas_send_pdu_session_release_command(amf_sess_t *sess, char** parameters, int size);
int user_nas_5gs_send_gmm_status(amf_ue_t *amf_ue, char** parameters, int size);
int user_nas_5gs_send_gmm_reject(amf_ue_t *amf_ue, char** parameters, int size);
int user_nas_5gs_send_gmm_reject_from_sbi(amf_ue_t *amf_ue, char** parameters, int size);
int user_ngap_send_paging(amf_ue_t *amf_ue, char** parameters, int size);

void user_ul_handle(const char* uplink_message, amf_ue_t *amf_ue, amf_sess_t *sess);
void user_dl_handle(char* downlink_message, amf_ue_t *amf_ue, amf_sess_t *sess, char** parameters, int size);
void execute_flow(nas_command command_temp, amf_ue_t* amf_ue, amf_sess_t* sess);

uint8_t stringToInt8(char* parameter);
uint16_t stringToInt16(char* parameter);
void stringToInt8pointer(uint8_t* data, char* parameter);

#ifdef __cplusplus
}
#endif

#endif /* AMF_NAS_5GS_PATH_H */
