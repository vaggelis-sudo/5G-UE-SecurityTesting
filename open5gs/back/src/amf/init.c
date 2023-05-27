/*
 * Copyright (C) 2019-2022 by Sukchan Lee <acetcom@gmail.com>
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

#include "sbi-path.h"
#include "ngap-path.h"
#include "metrics.h"

#include "nas-path.h" //added
#include <json-c/json.h>  //added
#include <stdio.h>  //added
#include <stdlib.h>  //added
#include <string.h>  //added

static ogs_thread_t *thread;
int initialize_testcase(void); //added
bool check_testcase(void); //added
void parse(struct json_object* obj, int iteration); //added
void parse_params(char* params, int iteration); //added
static void amf_main(void *data);
static int initialized = 0;

void parse_params(char* params, int iteration){ //added
    int i, token_counter = 0;
    char* param_token;

    for(i=0; params[i]; i++) token_counter  += (params[i] == ':');

    if(iteration == 1){
     n_testset.nas_commands_aka.dl_params = (char**) malloc((token_counter*2)*sizeof(char*));
     n_testset.nas_commands_aka.dl_size = token_counter*2;
    } else if(iteration == 2){
     n_testset.nas_commands_after_aka.dl_params = (char**) malloc((token_counter*2)*sizeof(char*));
     n_testset.nas_commands_after_aka.dl_size = token_counter*2;
    }
    
    for(i=0; i < (token_counter*2); i++){
    	if(iteration == 1){
    	 n_testset.nas_commands_aka.dl_params[i] = (char*) malloc(100*sizeof(char));//careful here
    	 memset(n_testset.nas_commands_aka.dl_params[i], 0, 100);
    	 }else if(iteration == 2){
    	 n_testset.nas_commands_after_aka.dl_params[i] = (char*) malloc(100*sizeof(char));//careful here
    	 memset(n_testset.nas_commands_after_aka.dl_params[i], 0, 100);
    	}
    }

    token_counter = 0;
    param_token = strtok(params, "\"{,:");
    while(param_token != NULL){
        if(strcmp(param_token, " ") != 0 && strcmp(param_token, "null") != 0){
            //enable flags
            if(strcmp(param_token, "deregistration_security") == 0) deregistration_security = false;
            else if(strcmp(param_token, "deregistration_accept_security") == 0) deregistration_accept_security = false;
            else if(strcmp(param_token, "gmm_status_security") == 0) gmm_status_security = false;
            else if(strcmp(param_token, "authentication_result_security") == 0) authentication_result_security = false;
            else if(strcmp(param_token, "security_mode_command_security") == 0) security_mode_command_security = false;
            else if(strcmp(param_token, "configuration_update_command_security") == 0) configuration_update_command_security = false; 
            else if(strcmp(param_token, "service_accept_security") == 0) service_accept_security = false;
            else if(strcmp(param_token, "registration_accept_security") == 0) registration_accept_security = false;
            else{ //add to dl_params
                if(iteration == 1 && !strcmp(param_token, "disabled") == 0) strncpy(n_testset.nas_commands_aka.dl_params[token_counter], (const char*)param_token, (size_t)strlen(param_token));
                else if(iteration == 2 && !strcmp(param_token, "disabled") == 0) strncpy(n_testset.nas_commands_after_aka.dl_params[token_counter], (const char*)param_token, (size_t)strlen(param_token));
            }
            ++token_counter;
        } 
        param_token = strtok(NULL, ",:}\"");
    }
}

void parse(struct json_object* obj, int iteration){ //added
    struct json_object* ue_ul_handle = NULL;
    struct json_object* dl_reply = NULL;
    struct json_object* command_mode = NULL;
    struct json_object* dl_params = NULL;

    char* ue_ul_handle_str;
    char* dl_reply_str;
    char* command_mode_str;
    char* dl_params_str;

    if(!json_object_object_get_ex(obj, "ue_ul_handle", &ue_ul_handle))
        printf("Not exists");
    else{
        ue_ul_handle_str = (char*) json_object_get_string(ue_ul_handle);
        if(!strcmp(ue_ul_handle_str, "null") == 0){
            //add to testcase
            //printf("Handle: %s\n", ue_ul_handle_str);
            if(iteration == 1){
                n_testset.nas_commands_aka.ue_ul_handle = ue_ul_handle_str;
                n_testset.aka_size++;
            }else if(iteration == 2){
                n_testset.nas_commands_after_aka.ue_ul_handle = ue_ul_handle_str;
                n_testset.after_aka_size++;
            } 

            //enable flags
            if(strcmp(ue_ul_handle_str, "registration_request") == 0) hijack_registration_request = true;
            else if(strcmp(ue_ul_handle_str, "registration_complete") == 0) hijack_registration_complete = true;
            else if(strcmp(ue_ul_handle_str, "deregistration_request") == 0) hijack_de_registration_request = true;
            else if(strcmp(ue_ul_handle_str, "service_request") == 0) hijack_service_request = true;
            else if(strcmp(ue_ul_handle_str, "security_mode_reject") == 0) hijack_security_mode_reject = true;
            else if(strcmp(ue_ul_handle_str, "authentication_response") == 0) hijack_authentication_response = true;
            else if(strcmp(ue_ul_handle_str, "authentication_failure") == 0) hijack_authentication_failure = true;
            else if(strcmp(ue_ul_handle_str, "identity_response") == 0) hijack_identity_response = true;
            else if(strcmp(ue_ul_handle_str, "ul_nas_transport") == 0) hijack_ul_nas_transport = true;
            else if(strcmp(ue_ul_handle_str, "security_mode_complete") == 0) hijack_security_mode_complete = true;
            else if(strcmp(ue_ul_handle_str, "configuration_update_complete") == 0) hijack_configuration_update_complete = true;
            else if(strcmp(ue_ul_handle_str, "gmm_status") == 0) hijack_gmm_status = true;
            else if(strcmp(ue_ul_handle_str, "deregistration_accept") == 0) hijack_de_registration_accept = true;
            else if(strcmp(ue_ul_handle_str, "timer_t3560") == 0 || strcmp(ue_ul_handle_str, "timer_t3550") == 0 || strcmp(ue_ul_handle_str, "timer_t3570") == 0 || strcmp(ue_ul_handle_str, "timer_t3555") == 0 || strcmp(ue_ul_handle_str, "timer_t3513") == 0 || strcmp(ue_ul_handle_str, "timer_t3522") == 0) hijack_timer = true;
        }
    }
 
    if(!json_object_object_get_ex(obj, "dl_reply", &dl_reply))
        printf("Not exists");
    else{
        dl_reply_str = (char*) json_object_get_string(dl_reply);
        if(!strcmp(dl_reply_str, "null") == 0){
            //printf("%s\n", dl_reply_str);
            //add to testcase
            if(iteration == 1) n_testset.nas_commands_aka.dl_reply = dl_reply_str;
            else if(iteration == 2) n_testset.nas_commands_after_aka.dl_reply = dl_reply_str;
        }
    }
 
    if(!json_object_object_get_ex(obj, "command_mode", &command_mode))
        printf("Not exists");
    else{
        command_mode_str = (char*) json_object_get_string(command_mode);
        if(!strcmp(command_mode_str, "null") == 0){
            //printf("%s\n", command_mode_str);
            //add to testcase
            if(iteration == 1) n_testset.nas_commands_aka.command_mode = command_mode_str;
            else if(iteration == 2) n_testset.nas_commands_after_aka.command_mode = command_mode_str;
        }
    }

    if(!json_object_object_get_ex(obj, "dl_params", &dl_params))
        printf("Not exists");
    else{
        dl_params_str = (char*) json_object_get_string(dl_params);
        if(!strcmp(dl_params_str, "null") == 0) parse_params(dl_params_str, iteration);
        //else{
        //    if(iteration == 1) n_testset.nas_commands_aka->dl_params[0] = "null";
        //    else if(iteration == 2) n_testset.nas_commands_after_aka->dl_params[0] = "null";
        //}  
    }
}

int initialize_testcase(void){ //added
    FILE* fp;
    char* buffer;
    long lSize;
    size_t i;

    struct json_object* parsed_json;

    fp = fopen("/home/cp105/Testcase/test.json", "r");
    if(fp == NULL) printf("File not found\n");
    fseek(fp, 0, SEEK_END);
    lSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    //printf("Size: %ld", lSize);
 
    buffer = (char*) malloc(sizeof(char)*lSize);
    fread(buffer, lSize, 1, fp);
    fclose(fp);
    
    printf("Buffer: %s", buffer);

    parsed_json = json_tokener_parse(buffer);
    
    hijack_registration_request = false;
    hijack_service_request = false;
    hijack_identity_response = false;
    hijack_gmm_status = false;
    hijack_de_registration_request = false;
    hijack_de_registration_accept = false;
    hijack_configuration_update_complete = false;
    hijack_registration_complete = false;
    hijack_authentication_response = false;
    hijack_authentication_failure = false;
    hijack_security_mode_complete = false;
    hijack_security_mode_reject = false;
    hijack_ul_nas_transport = false;
    hijack_timer = false;

    deregistration_security = true;
    deregistration_accept_security = true;
    gmm_status_security = true;
    authentication_result_security = true;
    security_mode_command_security = true;
    configuration_update_command_security = true; 
    service_accept_security = true;
    registration_accept_security = true;
 
    for(i = 0; i < json_object_array_length(parsed_json); i++){
        json_object* obj = json_object_array_get_idx(parsed_json, i);
        parse(obj, i);
    }
    
    printf("UE_UL_HANDLE set to: %s\n", n_testset.nas_commands_aka.ue_ul_handle);
    printf("DL_MESSAGE set to: %s\n", n_testset.nas_commands_aka.dl_reply);
    printf("COMMAND_MODE set to: %s\n", n_testset.nas_commands_aka.command_mode);
    //printf("dl params2: %s %s\n", n_testset.nas_commands_aka.dl_params[0], n_testset.nas_commands_aka.dl_params[1]);
 
    free(buffer);
    
    return OGS_OK;
}

bool check_testcase(void){ //added
    if(n_testset.aka_size == 0 && n_testset.after_aka_size == 0) return true;
    else return false;
}

int amf_initialize()
{
    int rv;

    ogs_metrics_context_init();
    ogs_sbi_context_init();

    amf_context_init();

    rv = ogs_sbi_context_parse_config("amf", "nrf", "scp");
    if (rv != OGS_OK) return rv;

    rv = ogs_metrics_context_parse_config("amf");
    if (rv != OGS_OK) return rv;

    rv = amf_context_parse_config();
    if (rv != OGS_OK) return rv;

    rv = amf_context_nf_info();
    if (rv != OGS_OK) return rv;

    rv = amf_m_tmsi_pool_generate();
    if (rv != OGS_OK) return rv;

    rv = amf_metrics_open();
    if (rv != 0) return OGS_ERROR;

    rv = ogs_log_config_domain(ogs_app()->logger.domain, ogs_app()->logger.level);
    if (rv != OGS_OK) return rv;

    rv = amf_sbi_open();
    if (rv != OGS_OK) return rv;

    rv = ngap_open();
    if (rv != OGS_OK) return rv;

    rv = initialize_testcase(); //added
    if (rv != OGS_OK) return rv;

    thread = ogs_thread_create(amf_main, NULL);
    if (!thread) return OGS_ERROR;

    initialized = 1;

    return OGS_OK;
}

static ogs_timer_t *t_termination_holding = NULL;

static void event_termination(void)
{
    ogs_sbi_nf_instance_t *nf_instance = NULL;

    /* Sending NF Instance De-registeration to NRF */
    ogs_list_for_each(&ogs_sbi_self()->nf_instance_list, nf_instance);
    ogs_sbi_nf_fsm_fini(nf_instance);

    /* Starting holding timer */
    t_termination_holding = ogs_timer_add(ogs_app()->timer_mgr, NULL, NULL);
    ogs_assert(t_termination_holding);
    #define TERMINATION_HOLDING_TIME ogs_time_from_msec(300)
    ogs_timer_start(t_termination_holding, TERMINATION_HOLDING_TIME);

    /* Sending termination event to the queue */
    ogs_queue_term(ogs_app()->queue);
    ogs_pollset_notify(ogs_app()->pollset);
}

void amf_terminate(void)
{
    if (!initialized) return;

    /* Daemon terminating */
    event_termination();
    ogs_thread_destroy(thread);
    ogs_timer_delete(t_termination_holding);

    ngap_close();
    amf_sbi_close();
    amf_metrics_close();

    amf_context_final();
    ogs_sbi_context_final();
    ogs_metrics_context_final();
}

static void amf_main(void *data)
{
    ogs_fsm_t amf_sm;
    int rv;

    ogs_fsm_init(&amf_sm, amf_state_initial, amf_state_final, 0);

    for ( ;; ) {
        ogs_pollset_poll(ogs_app()->pollset, ogs_timer_mgr_next(ogs_app()->timer_mgr));

        /*
         * After ogs_pollset_poll(), ogs_timer_mgr_expire() must be called.
         *
         * The reason is why ogs_timer_mgr_next() can get the corrent value
         * when ogs_timer_stop() is called internally in ogs_timer_mgr_expire().
         *
         * You should not use event-queue before ogs_timer_mgr_expire().
         * In this case, ogs_timer_mgr_expire() does not work
         * because 'if rv == OGS_DONE' statement is exiting and
         * not calling ogs_timer_mgr_expire().
         */
        ogs_timer_mgr_expire(ogs_app()->timer_mgr);

        for ( ;; ) {
            amf_event_t *e = NULL;

            rv = ogs_queue_trypop(ogs_app()->queue, (void**)&e);
            ogs_assert(rv != OGS_ERROR);

            if(check_testcase()) //added
                goto done;

            if (rv == OGS_DONE)
                goto done;

            if (rv == OGS_RETRY)
                break;

            ogs_assert(e);
            ogs_fsm_dispatch(&amf_sm, e);
            ogs_event_free(e);
        }
    }
done:

    ogs_fsm_fini(&amf_sm, 0);
}
