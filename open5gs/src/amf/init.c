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

#include "nas-path.c" //added
#include "gmm-sm.c"
#include <stdio.h>  //added
#include <stdlib.h>  //added
#include <string.h>  //added
#include "cjson/cJSON.h" //added

#define MAX_JSON_SIZE 1024
#define MAX_PARAMS 10 // maximum number of parameters in dl_params

static ogs_thread_t *thread;
int parse(const char* const*); //added
bool check_testcase(void); //added
static void amf_main(void *data);
static int initialized = 0;

int parse(const char* const argv[]){ //added
    FILE *fp;
    char* file_name;
    char *json = NULL;
    cJSON *root = NULL, *item = NULL, *dl_params = NULL;
    int i, j, count = 0;
    int num_params1 = 0, num_params2 = 0; // number of parameters found in the current object
    char *params_arr1[MAX_PARAMS], *params_arr2[MAX_PARAMS]; // dynamic array of parameter strings

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

    if(strcmp(argv[1], "-n") == 0) file_name = (char*) argv[2]; //It is already checked in main.c
    else return OGS_ERROR;

    // Open the file
    fp = fopen(file_name, "r");
    if (!fp) {
        fprintf(stderr, "Failed to open file\n");
        return OGS_ERROR;
    }

    // Read the JSON data into a string
    json = (char *) malloc(MAX_JSON_SIZE * sizeof(char));
    if (!json) {
        fprintf(stderr, "Failed to allocate memory\n");
        fclose(fp);
        return OGS_ERROR;
    }
    size_t num_read = fread(json, sizeof(char), MAX_JSON_SIZE - 1, fp);
    json[num_read] = '\0';

    // Close the file
    fclose(fp);

    // Parse the JSON data
    root = cJSON_Parse(json);
    if (!root) {
        fprintf(stderr, "JSON parsing error\n");
        free(json);
        return OGS_ERROR;
    }

    char* ue_ul_handle_str;
    char* dl_reply_str;
    char* command_mode_str;

    // Iterate over all the objects in the array
    cJSON_ArrayForEach(item, root) {
        dl_params = cJSON_GetObjectItemCaseSensitive(item, "dl_params");

        // Check that the object has the expected members
        if (!cJSON_IsString(cJSON_GetObjectItemCaseSensitive(item, "ue_ul_handle")) ||
            !cJSON_IsString(cJSON_GetObjectItemCaseSensitive(item, "dl_reply")) ||
            !cJSON_IsString(cJSON_GetObjectItemCaseSensitive(item, "command_mode"))) {
            fprintf(stderr, "JSON object has missing or invalid members\n");
            continue;
        }
        
        if(!strcmp(cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(item, "ue_ul_handle")), "null") == 0 && !strcmp(cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(item, "dl_reply")), "null") == 0 && !strcmp(cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(item, "command_mode")), "null") == 0){
          ue_ul_handle_str = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(item, "ue_ul_handle"));
          dl_reply_str = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(item, "dl_reply"));
          command_mode_str = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(item, "command_mode"));
       
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
                
          if(count == 1){
            n_testset.nas_commands_aka.ue_ul_handle = ue_ul_handle_str;
            n_testset.aka_size++;
            n_testset.nas_commands_aka.dl_reply = dl_reply_str;
            n_testset.nas_commands_aka.command_mode = command_mode_str;    
          }else if (count == 2){
            n_testset.nas_commands_after_aka.ue_ul_handle = ue_ul_handle_str;
            n_testset.after_aka_size++;
            n_testset.nas_commands_after_aka.dl_reply = dl_reply_str;
            n_testset.nas_commands_after_aka.command_mode = command_mode_str;
          }         
         }
        
        // Check if dl_params is an object or a string
        if (dl_params) {
            if (cJSON_IsObject(dl_params)) {
		      // Iterate over all the members of dl_params and output their names and values
              cJSON *item = dl_params->child;
              i = j = 0;
    		  while (item != NULL) {
        	    if (item->type == cJSON_String) {
            	    //flags
                    if(strcmp(item->string, "deregistration_security") == 0 && strcmp(item->valuestring, "disabled") == 0) deregistration_security = false;
                    else if(strcmp(item->string, "deregistration_accept_security") == 0 && strcmp(item->valuestring, "disabled") == 0) deregistration_accept_security = false;
                    else if(strcmp(item->string, "gmm_status_security") == 0 && strcmp(item->valuestring, "disabled") == 0) gmm_status_security = false;
                    else if(strcmp(item->string, "authentication_result_security") == 0 && strcmp(item->valuestring, "disabled") == 0) authentication_result_security = false;
                    else if(strcmp(item->string, "security_mode_command_security") == 0 && strcmp(item->valuestring, "disabled") == 0) security_mode_command_security = false;
                    else if(strcmp(item->string, "configuration_update_command_security") == 0 && strcmp(item->valuestring, "disabled") == 0) configuration_update_command_security = false; 
                    else if(strcmp(item->string, "service_accept_security") == 0 && strcmp(item->valuestring, "disabled") == 0) service_accept_security = false;
                    else if(strcmp(item->string, "registration_accept_security") == 0 && strcmp(item->valuestring, "disabled") == 0) registration_accept_security = false;
                    else{
            	      if(count == 1){
                        // Store the strings in the array
                        params_arr1[i] = (char*) strdup(item->string);
                        i++;
                        params_arr1[i] = (char*) strdup(item->valuestring);
                        i++; 
                      }else if(count == 2){
                        // Store the strings in the array
                        params_arr2[j] = (char*) strdup(item->string);
                        j++;
                        params_arr2[j] = (char*) strdup(item->valuestring);
                        j++; 
                      }
                    }
                  } else {
                    fprintf(stderr, "dl_params contains invalid value type for key '%s'\n", item->string);
                  }
                  item = item->next;
                }
                num_params1 = i;
                num_params2 = j;
             }
        }
        ++count;
    }

    n_testset.nas_commands_aka.dl_params = (char**) malloc(num_params1 * sizeof(char*));
    if (!n_testset.nas_commands_aka.dl_params) {
      fprintf(stderr, "Error: failed to allocate memory for params_ptr_arr\n");
      return OGS_ERROR;
    }else n_testset.nas_commands_aka.dl_size = num_params1;

    n_testset.nas_commands_after_aka.dl_params = (char**) malloc(num_params2 * sizeof(char*));
    if (!n_testset.nas_commands_after_aka.dl_params) {
      fprintf(stderr, "Error: failed to allocate memory for params_ptr_arr\n");
      return OGS_ERROR;
    }else n_testset.nas_commands_after_aka.dl_size = num_params2;

    // Copy strings from params_arr1 into the test array
    for (i = 0; i < num_params1; i++) {
      n_testset.nas_commands_aka.dl_params[i] = strdup(params_arr1[i]);
      if (!n_testset.nas_commands_aka.dl_params[i]) {
        fprintf(stderr, "Error: failed to copy string %d to params_ptr_arr\n", i + 1);
        return OGS_ERROR;
      }
    }

    // Copy strings from params_arr2 into the test array
    for (j = 0; j < num_params2; j++) {
      n_testset.nas_commands_after_aka.dl_params[j] = strdup(params_arr2[j]);
      if (!n_testset.nas_commands_after_aka.dl_params[j]) {
        fprintf(stderr, "Error: failed to copy string %d to params_ptr_arr\n", j + 1);
        return OGS_ERROR;
      }
    }

    if(n_testset.nas_commands_aka.ue_ul_handle != NULL && n_testset.nas_commands_aka.dl_reply != NULL && n_testset.nas_commands_aka.command_mode != NULL){

      //Print content
      ogs_info("Testcase Content AKA:");
      ogs_info("%s", n_testset.nas_commands_aka.ue_ul_handle);
      ogs_info("%s", n_testset.nas_commands_aka.dl_reply);
      ogs_info("%s", n_testset.nas_commands_aka.command_mode);
      
      if(num_params1 != 0){   
        ogs_info("DL Params:");
        for (i = 0; i < num_params1; i++) {
          ogs_info("%s", n_testset.nas_commands_aka.dl_params[i]);
        }
      }
     }
      
    if(n_testset.nas_commands_after_aka.ue_ul_handle != NULL && n_testset.nas_commands_after_aka.dl_reply != NULL && n_testset.nas_commands_after_aka.command_mode != NULL){

      ogs_info("Testcase Content Post-AKA:");
      ogs_info("%s", n_testset.nas_commands_after_aka.ue_ul_handle);
      ogs_info("%s", n_testset.nas_commands_after_aka.dl_reply);
      ogs_info("%s", n_testset.nas_commands_after_aka.command_mode);
      
      if(num_params2 != 0) {
        ogs_info("DL Params:");
        for (j = 0; i < num_params2; i++) {
          ogs_info("%s", n_testset.nas_commands_after_aka.dl_params[j]);
        }
      }  
    }

   // Free memory when done
   for (i = 0; i < num_params1; i++) {
    free(params_arr1[i]);
   }
   //free(params_arr1);

   for (i = 0; i < num_params2; i++) {
    free(params_arr2[i]);
   }
   //free(params_arr2);

   // Clean up
   cJSON_Delete(root);
   free(json);

   ogs_info("Parsing finished!");

   return OGS_OK;
}

bool check_testcase(void){
   if(n_testset.aka_size == 0 && n_testset.after_aka_size == 0) return true;
   return false;
}

int amf_initialize(const char* const argv[])
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

    rv = parse(argv); //added
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
    int i;
    if (!initialized) return;

    // Free memory when done
    for (i = 0; i < n_testset.nas_commands_aka.dl_size; i++) {
      free(n_testset.nas_commands_aka.dl_params[i]);
    }
    free(n_testset.nas_commands_aka.dl_params);

    for (i = 0; i < n_testset.nas_commands_after_aka.dl_size; i++) {
      free(n_testset.nas_commands_after_aka.dl_params[i]);
    }
    free(n_testset.nas_commands_after_aka.dl_params);

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

            if(check_testcase()) ogs_info("Testing finished!");
            //    goto done;

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
