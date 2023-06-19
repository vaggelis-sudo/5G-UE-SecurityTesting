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

#include "ngap-path.h"
#include "ngap-build.h"
#include "nas-path.h"
#include "nas-path2.h"
#include "ul-handler.h"

int nas_5gs_send_to_gnb(amf_ue_t *amf_ue, ogs_pkbuf_t *pkbuf)
{
    ogs_assert(pkbuf);

    amf_ue = amf_ue_cycle(amf_ue);
    if (!amf_ue) {
        ogs_warn("UE(amf-ue) context has already been removed");
        ogs_pkbuf_free(pkbuf);
        return OGS_ERROR;
    }
    
    return ngap_send_to_ran_ue(amf_ue->ran_ue, pkbuf);
}

int nas_5gs_send_to_downlink_nas_transport(amf_ue_t *amf_ue, ogs_pkbuf_t *pkbuf)
{
    int rv;
    ogs_pkbuf_t *ngapbuf = NULL;
    ran_ue_t *ran_ue = NULL;

    ogs_assert(pkbuf);

    amf_ue = amf_ue_cycle(amf_ue);
    if (!amf_ue) {
        ogs_warn("UE(amf-ue) context has already been removed");
        ogs_pkbuf_free(pkbuf);
        return OGS_ERROR;
    }

    ran_ue = ran_ue_cycle(amf_ue->ran_ue);
    if (!ran_ue) {
        ogs_warn("NG context has already been removed");
        ogs_pkbuf_free(pkbuf);
        return OGS_ERROR;
    }

    ngapbuf = ngap_build_downlink_nas_transport(
            ran_ue, pkbuf, false, false);
    ogs_expect_or_return_val(ngapbuf, OGS_ERROR);

    rv = nas_5gs_send_to_gnb(amf_ue, ngapbuf);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int nas_5gs_send_registration_accept(amf_ue_t *amf_ue)
{
    int rv;
    bool transfer_needed = false;

    ran_ue_t *ran_ue = NULL;

    ogs_pkbuf_t *ngapbuf = NULL;
    ogs_pkbuf_t *gmmbuf = NULL;

    ogs_assert(amf_ue);
    ran_ue = ran_ue_cycle(amf_ue->ran_ue);
    ogs_expect_or_return_val(ran_ue, OGS_ERROR);

    ogs_debug("[%s] Registration accept", amf_ue->supi);

    if (amf_ue->next.m_tmsi) {
        if (amf_ue->t3550.pkbuf) {
            gmmbuf = amf_ue->t3550.pkbuf;
            ogs_expect_or_return_val(gmmbuf, OGS_ERROR);
        } else {
            gmmbuf = gmm_build_registration_accept(amf_ue);
            ogs_expect_or_return_val(gmmbuf, OGS_ERROR);
        }

        amf_ue->t3550.pkbuf = ogs_pkbuf_copy(gmmbuf);
        ogs_expect_or_return_val(amf_ue->t3550.pkbuf, OGS_ERROR);
        ogs_timer_start(amf_ue->t3550.timer,
                amf_timer_cfg(AMF_TIMER_T3550)->duration);
    } else {
        gmmbuf = gmm_build_registration_accept(amf_ue);
        ogs_expect_or_return_val(gmmbuf, OGS_ERROR);
    }

    /*
     * Previously, AMF would sends PDUSessionResourceSetupRequest
     * when the following conditions were met:
     * - gNB didn't send UE Context Request IE of InitialUEMessage
     * - AMF should send SMF generated TRANSFER message(PDU_RES_SETUP_REQ)
     *   to the gNB
     *
     * However, in issues #771, the gNB did not accept
     * PDUSessionResourceSetupRequest. Perhaps the gNB engineer thought
     * that if gNB needs to send data traffic to the UE, AMF should send
     * an InitialContextSetupRequest regardless of UE Context Request IE.
     * This is because gNB requires the kgNB security context
     * for data connection.
     *
     * So, in this case, Open5GS-AMF decided to send
     * an InitialContexSetupRequest regardless of
     * whether it received UE Context Request IE of InitialUEMessage.
     */
    transfer_needed = PDU_RES_SETUP_REQ_TRANSFER_NEEDED(amf_ue);

    if (ran_ue->initial_context_setup_request_sent == false &&
        (ran_ue->ue_context_requested == true || transfer_needed == true)) {
        ngapbuf = ngap_ue_build_initial_context_setup_request(amf_ue, gmmbuf);
        ogs_expect_or_return_val(ngapbuf, OGS_ERROR);

        rv = nas_5gs_send_to_gnb(amf_ue, ngapbuf);
        ogs_expect_or_return_val(rv == OGS_OK, OGS_ERROR);

        ran_ue->initial_context_setup_request_sent = true;
    } else {
        if (transfer_needed == true) {
            ngapbuf = ngap_ue_build_pdu_session_resource_setup_request(
                    amf_ue, gmmbuf);
            ogs_expect_or_return_val(ngapbuf, OGS_ERROR);

            rv = nas_5gs_send_to_gnb(amf_ue, ngapbuf);
            ogs_expect_or_return_val(rv == OGS_OK, OGS_ERROR);
        } else {
            ngapbuf = ngap_build_downlink_nas_transport(
                    ran_ue, gmmbuf, true, true);
            ogs_expect_or_return_val(ngapbuf, OGS_ERROR);

            rv = nas_5gs_send_to_gnb(amf_ue, ngapbuf);
            ogs_expect_or_return_val(rv == OGS_OK, OGS_ERROR);
        }
    }

    return OGS_OK;
}

int nas_5gs_send_registration_reject(
        amf_ue_t *amf_ue, ogs_nas_5gmm_cause_t gmm_cause)
{
    int rv;
    ogs_pkbuf_t *gmmbuf = NULL;

    ogs_assert(amf_ue);

    ogs_warn("[%s] Registration reject [%d]", amf_ue->suci, gmm_cause);

    gmmbuf = gmm_build_registration_reject(gmm_cause);
    ogs_expect_or_return_val(gmmbuf, OGS_ERROR);

    rv = nas_5gs_send_to_downlink_nas_transport(amf_ue, gmmbuf);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int nas_5gs_send_service_accept(amf_ue_t *amf_ue)
{
    int rv;
    bool transfer_needed = false;
    ran_ue_t *ran_ue = NULL;

    ogs_pkbuf_t *gmmbuf = NULL;
    ogs_pkbuf_t *ngapbuf = NULL;

    ogs_assert(amf_ue);
    ran_ue = ran_ue_cycle(amf_ue->ran_ue);
    ogs_expect_or_return_val(ran_ue, OGS_ERROR);

    ogs_debug("[%s] Service accept", amf_ue->supi);

    gmmbuf = gmm_build_service_accept(amf_ue);
    ogs_expect_or_return_val(gmmbuf, OGS_ERROR);

    /*
     * Previously, AMF would sends PDUSessionResourceSetupRequest
     * when the following conditions were met:
     * - gNB didn't send UE Context Request IE of InitialUEMessage
     * - AMF should send SMF generated TRANSFER message(PDU_RES_SETUP_REQ)
     *   to the gNB
     *
     * However, in issues #771, the gNB did not accept
     * PDUSessionResourceSetupRequest. Perhaps the gNB engineer thought
     * that if gNB needs to send data traffic to the UE, AMF should send
     * an InitialContextSetupRequest regardless of UE Context Request IE.
     * This is because gNB requires the kgNB security context
     * for data connection.
     *
     * So, in this case, Open5GS-AMF decided to send
     * an InitialContexSetupRequest regardless of
     * whether it received UE Context Request IE of InitialUEMessage.
     */
    transfer_needed = PDU_RES_SETUP_REQ_TRANSFER_NEEDED(amf_ue);

    if (ran_ue->initial_context_setup_request_sent == false &&
        (ran_ue->ue_context_requested == true || transfer_needed == true)) {
        ngapbuf = ngap_ue_build_initial_context_setup_request(amf_ue, gmmbuf);
        ogs_expect_or_return_val(ngapbuf, OGS_ERROR);

        rv = nas_5gs_send_to_gnb(amf_ue, ngapbuf);
        ogs_expect_or_return_val(rv == OGS_OK, OGS_ERROR);

        ran_ue->initial_context_setup_request_sent = true;
    } else {
        if (transfer_needed == true) {
            ngapbuf = ngap_ue_build_pdu_session_resource_setup_request(
                    amf_ue, gmmbuf);
            ogs_expect_or_return_val(ngapbuf, OGS_ERROR);

            rv = nas_5gs_send_to_gnb(amf_ue, ngapbuf);
            ogs_expect_or_return_val(rv == OGS_OK, OGS_ERROR);
        } else {
            rv = nas_5gs_send_to_downlink_nas_transport(amf_ue, gmmbuf);
            ogs_expect_or_return_val(rv == OGS_OK, OGS_ERROR);
        }
    }

    return OGS_OK;
}

int nas_5gs_send_service_reject(
        amf_ue_t *amf_ue, ogs_nas_5gmm_cause_t gmm_cause)
{
    int rv;
    ogs_pkbuf_t *gmmbuf = NULL;

    ogs_assert(amf_ue);

    ogs_debug("[%s] Service reject", amf_ue->supi);

    gmmbuf = gmm_build_service_reject(amf_ue, gmm_cause);
    ogs_expect_or_return_val(gmmbuf, OGS_ERROR);

    rv = nas_5gs_send_to_downlink_nas_transport(amf_ue, gmmbuf);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int nas_5gs_send_de_registration_accept(amf_ue_t *amf_ue)
{
    int rv;

    ran_ue_t *ran_ue = NULL;
    ogs_pkbuf_t *gmmbuf = NULL;

    ogs_assert(amf_ue);
    ran_ue = ran_ue_cycle(amf_ue->ran_ue);
    ogs_expect_or_return_val(ran_ue, OGS_ERROR);

    ogs_debug("[%s] De-registration accept", amf_ue->supi);

    if (amf_ue->nas.de_registration.switch_off == 0) {
        int rv;

        gmmbuf = gmm_build_de_registration_accept(amf_ue);
        ogs_expect_or_return_val(gmmbuf, OGS_ERROR);

        rv = nas_5gs_send_to_downlink_nas_transport(amf_ue, gmmbuf);
        ogs_expect_or_return_val(rv == OGS_OK, OGS_ERROR);
    }

    rv = ngap_send_ran_ue_context_release_command(ran_ue,
            NGAP_Cause_PR_nas, NGAP_CauseNas_deregister,
            NGAP_UE_CTX_REL_NG_REMOVE_AND_UNLINK, 0);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int nas_5gs_send_de_registration_request(amf_ue_t *amf_ue,
        OpenAPI_deregistration_reason_e dereg_reason)
{
    int rv;

    ran_ue_t *ran_ue = NULL;
    ogs_pkbuf_t *gmmbuf = NULL;

    ogs_assert(amf_ue);
    ran_ue = ran_ue_cycle(amf_ue->ran_ue);
    ogs_expect_or_return_val(ran_ue, OGS_ERROR);

    ogs_debug("[%s] De-registration request", amf_ue->supi);

    if (amf_ue->t3522.pkbuf) {
        gmmbuf = amf_ue->t3522.pkbuf;
        ogs_expect_or_return_val(gmmbuf, OGS_ERROR);
    } else {
        gmmbuf = gmm_build_de_registration_request(amf_ue, dereg_reason);
        ogs_expect_or_return_val(gmmbuf, OGS_ERROR);
    }

    amf_ue->t3522.pkbuf = ogs_pkbuf_copy(gmmbuf);
    ogs_expect_or_return_val(amf_ue->t3522.pkbuf, OGS_ERROR);
    ogs_timer_start(amf_ue->t3522.timer,
            amf_timer_cfg(AMF_TIMER_T3522)->duration);

    rv = nas_5gs_send_to_downlink_nas_transport(amf_ue, gmmbuf);
    ogs_expect_or_return_val(rv == OGS_OK, OGS_ERROR);

    return rv;
}

int nas_5gs_send_identity_request(amf_ue_t *amf_ue)
{
    int rv;
    ogs_pkbuf_t *gmmbuf = NULL;

    ogs_assert(amf_ue);

    ogs_debug("Identity request");

    if (amf_ue->t3570.pkbuf) {
        gmmbuf = amf_ue->t3570.pkbuf;
        ogs_expect_or_return_val(gmmbuf, OGS_ERROR);
    } else {
        gmmbuf = gmm_build_identity_request(amf_ue);
        ogs_expect_or_return_val(gmmbuf, OGS_ERROR);
    }

    amf_ue->t3570.pkbuf = ogs_pkbuf_copy(gmmbuf);
    ogs_expect_or_return_val(amf_ue->t3570.pkbuf, OGS_ERROR);
    ogs_timer_start(amf_ue->t3570.timer,
            amf_timer_cfg(AMF_TIMER_T3570)->duration);

    rv = nas_5gs_send_to_downlink_nas_transport(amf_ue, gmmbuf);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int nas_5gs_send_authentication_request(amf_ue_t *amf_ue)
{
    int rv;
    ogs_pkbuf_t *gmmbuf = NULL;

    ogs_assert(amf_ue);

    ogs_debug("[%s] Authentication request", amf_ue->suci);

    if (amf_ue->t3560.pkbuf) {
        gmmbuf = amf_ue->t3560.pkbuf;
        ogs_expect_or_return_val(gmmbuf, OGS_ERROR);
    } else {
        gmmbuf = gmm_build_authentication_request(amf_ue);
        ogs_expect_or_return_val(gmmbuf, OGS_ERROR);
    }

    amf_ue->t3560.pkbuf = ogs_pkbuf_copy(gmmbuf);
    ogs_expect_or_return_val(amf_ue->t3560.pkbuf, OGS_ERROR);
    ogs_timer_start(amf_ue->t3560.timer,
            amf_timer_cfg(AMF_TIMER_T3560)->duration);

    rv = nas_5gs_send_to_downlink_nas_transport(amf_ue, gmmbuf);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int nas_5gs_send_authentication_reject(amf_ue_t *amf_ue)
{
    int rv;
    ogs_pkbuf_t *gmmbuf = NULL;

    ogs_assert(amf_ue);

    ogs_warn("[%s] Authentication reject", amf_ue->suci);

    gmmbuf = gmm_build_authentication_reject();
    ogs_expect_or_return_val(gmmbuf, OGS_ERROR);

    rv = nas_5gs_send_to_downlink_nas_transport(amf_ue, gmmbuf);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int nas_5gs_send_security_mode_command(amf_ue_t *amf_ue)
{
    int rv;
    ogs_pkbuf_t *gmmbuf = NULL;

    ogs_assert(amf_ue);

    ogs_debug("[%s] Security mode command", amf_ue->supi);

    if (amf_ue->t3560.pkbuf) {
        gmmbuf = amf_ue->t3560.pkbuf;
        ogs_expect_or_return_val(gmmbuf, OGS_ERROR);
    } else {
        gmmbuf = gmm_build_security_mode_command(amf_ue);
        ogs_expect_or_return_val(gmmbuf, OGS_ERROR);
    }

    amf_ue->t3560.pkbuf = ogs_pkbuf_copy(gmmbuf);
    ogs_expect_or_return_val(amf_ue->t3560.pkbuf, OGS_ERROR);
    ogs_timer_start(amf_ue->t3560.timer,
            amf_timer_cfg(AMF_TIMER_T3560)->duration);

    rv = nas_5gs_send_to_downlink_nas_transport(amf_ue, gmmbuf);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int nas_5gs_send_configuration_update_command(
        amf_ue_t *amf_ue, gmm_configuration_update_command_param_t *param)
{
    int rv;
    ogs_pkbuf_t *gmmbuf = NULL;

    ogs_assert(amf_ue);

    ogs_info("[%s] Configuration update command", amf_ue->supi);

    if (amf_ue->t3555.pkbuf) {
        gmmbuf = amf_ue->t3555.pkbuf;
        ogs_expect_or_return_val(gmmbuf, OGS_ERROR);

        amf_ue->t3555.pkbuf = ogs_pkbuf_copy(gmmbuf);
        ogs_expect_or_return_val(amf_ue->t3555.pkbuf, OGS_ERROR);
        ogs_timer_start(amf_ue->t3555.timer,
                amf_timer_cfg(AMF_TIMER_T3555)->duration);

    } else {
        ogs_expect_or_return_val(param, OGS_ERROR);
        gmmbuf = gmm_build_configuration_update_command(amf_ue, param);
        ogs_expect_or_return_val(gmmbuf, OGS_ERROR);

        if (param->acknowledgement_requested) {
            amf_ue->t3555.pkbuf = ogs_pkbuf_copy(gmmbuf);
            ogs_expect_or_return_val(amf_ue->t3555.pkbuf, OGS_ERROR);
            ogs_timer_start(amf_ue->t3555.timer,
                    amf_timer_cfg(AMF_TIMER_T3555)->duration);
        }
    }

    rv = nas_5gs_send_to_downlink_nas_transport(amf_ue, gmmbuf);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int nas_send_pdu_session_modification_command(amf_sess_t *sess,
        ogs_pkbuf_t *n1smbuf, ogs_pkbuf_t *n2smbuf)
{
    int rv;

    amf_ue_t *amf_ue = NULL;

    ogs_pkbuf_t *gmmbuf = NULL;
    ogs_pkbuf_t *ngapbuf = NULL;

    ogs_assert(sess);
    amf_ue = sess->amf_ue;
    ogs_assert(amf_ue);
    ogs_assert(n1smbuf);
    ogs_assert(n2smbuf);

    gmmbuf = gmm_build_dl_nas_transport(sess,
            OGS_NAS_PAYLOAD_CONTAINER_N1_SM_INFORMATION, n1smbuf, 0, 0);
    ogs_expect_or_return_val(gmmbuf, OGS_ERROR);

    ngapbuf = ngap_build_pdu_session_resource_modify_request(
            sess, gmmbuf, n2smbuf);
    ogs_expect_or_return_val(ngapbuf, OGS_ERROR);

    rv = nas_5gs_send_to_gnb(amf_ue, ngapbuf);
    ogs_expect(rv == OGS_OK);

    return rv;
}


int nas_send_pdu_session_release_command(amf_sess_t *sess,
        ogs_pkbuf_t *n1smbuf, ogs_pkbuf_t *n2smbuf)
{
    int rv;

    amf_ue_t *amf_ue = NULL;

    ogs_pkbuf_t *gmmbuf = NULL;
    ogs_pkbuf_t *ngapbuf = NULL;

    ogs_assert(sess);
    amf_ue = sess->amf_ue;
    ogs_assert(amf_ue);
    ogs_assert(n1smbuf);
    ogs_assert(n2smbuf);

    gmmbuf = gmm_build_dl_nas_transport(sess,
            OGS_NAS_PAYLOAD_CONTAINER_N1_SM_INFORMATION, n1smbuf, 0, 0);
    ogs_expect_or_return_val(gmmbuf, OGS_ERROR);

    ngapbuf = ngap_build_pdu_session_resource_release_command(
            sess, gmmbuf, n2smbuf);
    ogs_expect_or_return_val(ngapbuf, OGS_ERROR);

    rv = nas_5gs_send_to_gnb(amf_ue, ngapbuf);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int nas_5gs_send_gmm_status(amf_ue_t *amf_ue, ogs_nas_5gmm_cause_t cause)
{
    int rv;
    ogs_pkbuf_t *gmmbuf = NULL;

    ogs_assert(amf_ue);

    ogs_debug("[%s] 5GMM status", amf_ue->supi);

    gmmbuf = gmm_build_status(amf_ue, cause);
    ogs_expect_or_return_val(gmmbuf, OGS_ERROR);

    rv = nas_5gs_send_to_downlink_nas_transport(amf_ue, gmmbuf);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int nas_5gs_send_gmm_reject(
        amf_ue_t *amf_ue, ogs_nas_5gmm_cause_t gmm_cause)
{
    int rv;
    ogs_assert(amf_ue);

    switch(amf_ue->nas.message_type) {
    case OGS_NAS_5GS_REGISTRATION_REQUEST:
        rv = nas_5gs_send_registration_reject(amf_ue, gmm_cause);
        ogs_expect(rv == OGS_OK);
        break;
    case OGS_NAS_5GS_SERVICE_REQUEST:
        rv = nas_5gs_send_service_reject(amf_ue, gmm_cause);
        ogs_expect(rv == OGS_OK);
        break;
    default:
        ogs_error("Unknown message type [%d]", amf_ue->nas.message_type);
        rv = OGS_ERROR;
    }

    return rv;
}

static ogs_nas_5gmm_cause_t gmm_cause_from_sbi(int status)
{
    ogs_nas_5gmm_cause_t gmm_cause;

    switch(status) {
    case OGS_SBI_HTTP_STATUS_NOT_FOUND:
        gmm_cause = OGS_5GMM_CAUSE_PLMN_NOT_ALLOWED;
        break;
    case OGS_SBI_HTTP_STATUS_GATEWAY_TIMEOUT:
        gmm_cause = OGS_5GMM_CAUSE_PAYLOAD_WAS_NOT_FORWARDED;
        break;
    case OGS_SBI_HTTP_STATUS_BAD_REQUEST:
        gmm_cause = OGS_5GMM_CAUSE_SEMANTICALLY_INCORRECT_MESSAGE;
        break;
    case OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR:
        gmm_cause =
            OGS_5GMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK;
        break;
    default:
        gmm_cause = OGS_5GMM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED;
    }

    return gmm_cause;
}

int nas_5gs_send_gmm_reject_from_sbi(amf_ue_t *amf_ue, int status)
{
    int rv;

    ogs_assert(amf_ue);
    rv = nas_5gs_send_gmm_reject(amf_ue, gmm_cause_from_sbi(status));
    ogs_expect(rv == OGS_OK);

    return rv;
}

int nas_5gs_send_dl_nas_transport(amf_sess_t *sess,
        uint8_t payload_container_type, ogs_pkbuf_t *payload_container,
        ogs_nas_5gmm_cause_t cause, uint8_t backoff_time)
{
    int rv;

    ogs_pkbuf_t *gmmbuf = NULL;
    amf_ue_t *amf_ue = NULL;

    ogs_assert(sess);
    amf_ue = sess->amf_ue;
    ogs_assert(amf_ue);

    ogs_assert(payload_container_type);
    ogs_assert(payload_container);

    ogs_warn("[%s] DL NAS transport", amf_ue->suci);

    gmmbuf = gmm_build_dl_nas_transport(sess,
            payload_container_type, payload_container, cause, backoff_time);
    ogs_expect_or_return_val(gmmbuf, OGS_ERROR);
    rv = nas_5gs_send_to_downlink_nas_transport(amf_ue, gmmbuf);
    ogs_expect_or_return_val(rv == OGS_OK, OGS_ERROR);

    return rv;
}

/*
 * TS24.501
 * 8.2.11 DL NAS transport
 * 8.2.11.4 5GMM cause
 *
 * The AMF shall include this IE when the Payload container IE
 * contains an uplink payload which was not forwarded and
 * the Payload container type IE is not set to "Multiple payloads".
 *
 * -0-
 * As such, this function 'nas_5gs_send_gsm_reject()' must be used
 * only when an N1 SM message has been forwarded to the SMF.
 */
int nas_5gs_send_gsm_reject(amf_sess_t *sess,
        uint8_t payload_container_type, ogs_pkbuf_t *payload_container)
{
    int rv;

    ogs_assert(sess);
    ogs_assert(payload_container_type);
    ogs_assert(payload_container);

    rv = nas_5gs_send_dl_nas_transport(
            sess, payload_container_type, payload_container, 0, 0);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int nas_5gs_send_back_gsm_message(
        amf_sess_t *sess, ogs_nas_5gmm_cause_t cause, uint8_t backoff_time)
{
    int rv;
    ogs_pkbuf_t *pbuf = NULL;

    ogs_assert(sess);
    ogs_assert(sess->payload_container_type);
    ogs_assert(sess->payload_container);

    pbuf = ogs_pkbuf_copy(sess->payload_container);
    ogs_expect_or_return_val(pbuf, OGS_ERROR);

    rv = nas_5gs_send_dl_nas_transport(sess, sess->payload_container_type, pbuf,
            cause, backoff_time);
    ogs_expect(rv == OGS_OK);

    return rv;
}

void user_ul_handle(const char* uplink_message, amf_ue_t* amf_ue){

    nas_command command_temp = n_testset.nas_commands_aka;
    nas_command command_temp_after = n_testset.nas_commands_after_aka;

    if(strcmp(uplink_message, "registration_request") == 0 && n_testset.aka_size != 0){
            ogs_info("UL Handler 1!!!");
            if(strcmp(command_temp.ue_ul_handle, "registration_request") == 0){
                ogs_info("UL Handler 2!!!");
                execute_flow(command_temp, amf_ue);
                n_testset.aka_size--;
            }
    }else if(strcmp(uplink_message, "registration_complete") == 0 && n_testset.aka_size != 0){
            ogs_info("UL Handler 1!!!");
            if(strcmp(command_temp.ue_ul_handle, "registration_complete") == 0){
                ogs_info("UL Handler 2!!!");
                execute_flow(command_temp, amf_ue);
                n_testset.aka_size--;
            }
    }else if(strcmp(uplink_message, "ul_nas_transport") == 0 && n_testset.aka_size != 0){
            ogs_info("UL Handler 1!!!");
            if(strcmp(command_temp.ue_ul_handle, "ul_nas_transport") == 0){
                ogs_info("UL Handler 2!!!");
                execute_flow(command_temp, amf_ue);
                n_testset.aka_size--;
            }
    }else if(strcmp(uplink_message, "deregistration_request") == 0 && n_testset.after_aka_size != 0){
            ogs_info("UL Handler 1!!!");
            if(strcmp(command_temp_after.ue_ul_handle, "deregistration_request") == 0){
                ogs_info("UL Handler 2!!!");
                execute_flow(command_temp_after, amf_ue);
                n_testset.after_aka_size--;
            }
    }else if(strcmp(uplink_message, "service_request") == 0 && n_testset.after_aka_size != 0){
            ogs_info("UL Handler 1!!!");
            if(strcmp(command_temp_after.ue_ul_handle, "service_request") == 0){
                ogs_info("UL Handler 2!!!");
                execute_flow(command_temp_after, amf_ue);
                n_testset.after_aka_size--;
            }
    }else if(strcmp(uplink_message, "security_mode_reject") == 0 && n_testset.aka_size != 0){
            ogs_info("UL Handler 1!!!");
            if(strcmp(command_temp.ue_ul_handle, "security_mode_reject") == 0){
                ogs_info("UL Handler 2!!!");
                execute_flow(command_temp, amf_ue);
                n_testset.aka_size--;
            }
    }else if(strcmp(uplink_message, "authentication_response") == 0 && n_testset.aka_size != 0){
            ogs_info("UL Handler 1!!!");
            if(strcmp(command_temp.ue_ul_handle, "authentication_response") == 0){
                ogs_info("UL Handler 2!!!");
                execute_flow(command_temp, amf_ue);
                n_testset.aka_size--;
            }
    }else if(strcmp(uplink_message, "authentication_failure") == 0 && n_testset.aka_size != 0){
            ogs_info("UL Handler 1!!!");
            if(strcmp(command_temp.ue_ul_handle, "authentication_failure") == 0){
                ogs_info("UL Handler 2!!!");
                execute_flow(command_temp, amf_ue);
                n_testset.aka_size--;
            }
    }else if(strcmp(uplink_message, "identity_response") == 0 && n_testset.aka_size != 0){
            ogs_info("UL Handler 1!!!");
            if(strcmp(command_temp.ue_ul_handle, "identity_response") == 0){
                ogs_info("UL Handler 2!!!");
                execute_flow(command_temp, amf_ue);
                n_testset.aka_size--;
            }
    }else if(strcmp(uplink_message, "security_mode_complete") == 0 && n_testset.aka_size != 0){
            ogs_info("UL Handler 1!!!");
            if(strcmp(command_temp.ue_ul_handle, "security_mode_complete") == 0){
                ogs_info("UL Handler 2!!!");
                execute_flow(command_temp, amf_ue);
                n_testset.aka_size--;
            }
    }else if(strcmp(uplink_message, "configuration_update_complete") == 0 && n_testset.after_aka_size != 0){
            ogs_info("UL Handler 1!!!");
            if(strcmp(command_temp_after.ue_ul_handle, "configuration_update_complete") == 0){
                ogs_info("UL Handler 2!!!");
                execute_flow(command_temp_after, amf_ue);
                n_testset.after_aka_size--;
            }
    }else if(strcmp(uplink_message, "gmm_status") == 0 && n_testset.after_aka_size != 0){
            ogs_info("UL Handler 1!!!");
            if(strcmp(command_temp_after.ue_ul_handle, "gmm_status") == 0){
                ogs_info("UL Handler 2!!!");
                execute_flow(command_temp_after, amf_ue);
                n_testset.after_aka_size--;
            }
    }else if(strcmp(uplink_message, "deregistration_accept") == 0 || n_testset.after_aka_size != 0){
            ogs_info("UL Handler 1!!!");
            if(strcmp(command_temp_after.ue_ul_handle, "deregistration_accept") == 0){
                ogs_info("UL Handler 2!!!");
                execute_flow(command_temp_after, amf_ue);
                n_testset.after_aka_size--;
            }
    }else if(((strcmp(uplink_message, "timer_t3570") == 0) || (strcmp(uplink_message, "timer_t3560") == 0) || (strcmp(uplink_message, "timer_t3555") == 0) || (strcmp(uplink_message, "timer_t3550") == 0) || (strcmp(uplink_message, "timer_t3513") == 0) || (strcmp(uplink_message, "timer_t3522") == 0)) && n_testset.after_aka_size != 0){
            ogs_info("UL Handler 1!!!");
            if((strcmp(command_temp_after.ue_ul_handle, "timer_t3570") == 0) || (strcmp(command_temp_after.ue_ul_handle, "timer_t3560") == 0) || (strcmp(command_temp_after.ue_ul_handle, "timer_t3550") == 0) || (strcmp(command_temp_after.ue_ul_handle, "timer_t3555") == 0) || (strcmp(command_temp_after.ue_ul_handle, "timer_t3513") == 0) || (strcmp(command_temp_after.ue_ul_handle, "timer_t3522") == 0)){
                ogs_info("UL Handler 2!!!");
                execute_flow(command_temp_after, amf_ue);
                n_testset.after_aka_size--;
            }
    }else{
        printf("Invalid UP Selection or Empty List\n" );
    }
    ogs_info("Done!");
}

void execute_flow(nas_command command_temp, amf_ue_t* amf_ue){
    if(strcmp(command_temp.command_mode, "send") == 0){
        //send the dl_message
        ogs_info("Modified Flow 1!!!");
        user_dl_handle(command_temp.dl_reply, amf_ue, command_temp.dl_params, command_temp.dl_size);
    }else if(strcmp(command_temp.command_mode, "replay") == 0){
        //replay the dl_message
        ogs_info("Modified Flow 2!!!");
        user_dl_handle(command_temp.dl_reply, amf_ue, command_temp.dl_params, command_temp.dl_size);
        user_dl_handle(command_temp.dl_reply, amf_ue, command_temp.dl_params, command_temp.dl_size);
    }else{
        printf("Invalid Mode Selection\n" );              
    } 
}

void user_dl_handle(char* downlink_message, amf_ue_t* amf_ue, char** parameters, int size){
   ogs_info("DL Handler!!!");
   if(strcmp(downlink_message, "registration_accept") == 0) ogs_assert(OGS_OK == user_nas_5gs_send_registration_accept(amf_ue, parameters, size));
   else if(strcmp(downlink_message, "registration_reject") == 0) ogs_assert(OGS_OK == user_nas_5gs_send_registration_reject(amf_ue, parameters, size));
   else if(strcmp(downlink_message, "deregistration_request") == 0) ogs_assert(OGS_OK == user_nas_5gs_send_de_registration_request(amf_ue, parameters, size));
   else if(strcmp(downlink_message, "service_reject") == 0) ogs_assert(OGS_OK == user_nas_5gs_send_service_reject(amf_ue, parameters, size));
   else if(strcmp(downlink_message, "service_accept") == 0) ogs_assert(OGS_OK == user_nas_5gs_send_service_accept(amf_ue, parameters, size));
   else if(strcmp(downlink_message, "gmm_status") == 0) ogs_assert(OGS_OK == user_nas_5gs_send_gmm_status(amf_ue, parameters, size));
   else if(strcmp(downlink_message, "authentication_result") == 0) ogs_assert(OGS_OK == user_nas_5gs_send_authentication_result(amf_ue, parameters, size));
   else if(strcmp(downlink_message, "configuration_update_command") == 0) ogs_assert(OGS_OK == user_nas_5gs_send_configuration_update_command(amf_ue, parameters, size));
   else if(strcmp(downlink_message, "authentication_request") == 0) ogs_assert(OGS_OK == user_nas_5gs_send_authentication_request(amf_ue, parameters, size));
   else if(strcmp(downlink_message, "authentication_reject") == 0) ogs_assert(OGS_OK == user_nas_5gs_send_authentication_reject(amf_ue, parameters, size));
   else if(strcmp(downlink_message, "identity_request") == 0) ogs_assert(OGS_OK == user_nas_5gs_send_identity_request(amf_ue, parameters, size));
   else if(strcmp(downlink_message, "security_mode_command") == 0) ogs_assert(OGS_OK == user_nas_5gs_send_security_mode_command(amf_ue, parameters, size));
   else if(strcmp(downlink_message, "deregistration_accept") == 0) ogs_assert(OGS_OK == user_nas_5gs_send_de_registration_accept(amf_ue, parameters, size));
   else printf("Invalid DL Selection\n" );      
}

int user_nas_5gs_send_registration_reject(amf_ue_t* amf_ue, char** parameters, int size)
{
    int rv, i;
    ogs_pkbuf_t *gmmbuf = NULL;
    ogs_nas_5gs_message_t message;
    ogs_nas_5gs_registration_reject_t *registration_reject = &message.gmm.registration_reject;

    ogs_assert(amf_ue);
    ogs_info("Modified Registration Reject!!!");

    memset(&message, 0, sizeof(message));
    registration_reject->gmm_cause = OGS_5GMM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED; //default value
    message.gmm.h.extended_protocol_discriminator = OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM;
    message.gmm.h.message_type = OGS_NAS_5GS_REGISTRATION_REJECT;

    if(parameters != NULL){
     for(i = 0; i < size; i+=2){
        if(strcmp(parameters[i], "gmm_cause") == 0){
            if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_ILLEGAL_UE") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_ILLEGAL_UE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_ILLEGAL_ME") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_ILLEGAL_ME;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_IMPLICITLY_DE_REGISTERED") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_IMPLICITLY_DE_REGISTERED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_PEI_NOT_ACCEPTED") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_PEI_NOT_ACCEPTED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_5GS_SERVICES_NOT_ALLOWED") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_5GS_SERVICES_NOT_ALLOWED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_PLMN_NOT_ALLOWED") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_PLMN_NOT_ALLOWED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_TRACKING_AREA_NOT_ALLOWED") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_TRACKING_AREA_NOT_ALLOWED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_ROAMING_NOT_ALLOWED_IN_THIS_TRACKING_AREA") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_ROAMING_NOT_ALLOWED_IN_THIS_TRACKING_AREA;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_NO_SUITABLE_CELLS_IN_TRACKING_AREA") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_NO_SUITABLE_CELLS_IN_TRACKING_AREA;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_N1_MODE_NOT_ALLOWED") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_N1_MODE_NOT_ALLOWED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_REDIRECTION_TO_EPC_REQUIRED") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_REDIRECTION_TO_EPC_REQUIRED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_NON_3GPP_ACCESS_TO_5GCN_NOT_ALLOWED") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_NON_3GPP_ACCESS_TO_5GCN_NOT_ALLOWED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_TEMPORARILY_NOT_AUTHORIZED_FOR_THIS_SNPN") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_TEMPORARILY_NOT_AUTHORIZED_FOR_THIS_SNPN;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_PERMANENTLY_NOT_AUTHORIZED_FOR_THIS_SNPN") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_PERMANENTLY_NOT_AUTHORIZED_FOR_THIS_SNPN;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_NOT_AUTHORIZED_FOR_THIS_CAG_OR_AUITHORIZED_FOR_CAG_CELLS_ONLY") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_NOT_AUTHORIZED_FOR_THIS_CAG_OR_AUITHORIZED_FOR_CAG_CELLS_ONLY;
            }else if(strcmp(parameters[i+1], "WIRELESS_ACCESS_AREA_NOT_ALLOWED") == 0){
                registration_reject->gmm_cause = WIRELESS_ACCESS_AREA_NOT_ALLOWED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_MAC_FAILURE") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_MAC_FAILURE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_SYNCH_FAILURE") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_SYNCH_FAILURE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_CONGESTION") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_CONGESTION;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_UE_SECURITY_CAPABILITIES_MISMATCH") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_UE_SECURITY_CAPABILITIES_MISMATCH;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_SECURITY_MODE_REJECTED_UNSPECIFIED") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_SECURITY_MODE_REJECTED_UNSPECIFIED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_NON_5G_AUTHENTICATION_UNACCEPTABLE") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_NON_5G_AUTHENTICATION_UNACCEPTABLE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_RESTRICTED_SERVICE_AREA") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_RESTRICTED_SERVICE_AREA;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_LADN_NOT_AVAILABLE") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_LADN_NOT_AVAILABLE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_NO_NETWORK_SLICES_AVAILABLE") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_NO_NETWORK_SLICES_AVAILABLE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_MAXIMUM_NUMBER_OF_PDU_SESSIONS_REACHED") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_MAXIMUM_NUMBER_OF_PDU_SESSIONS_REACHED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_INSUFFICIENT_RESOURCES_FOR_SPECIFIC_SLICE_AND_DNN") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_INSUFFICIENT_RESOURCES_FOR_SPECIFIC_SLICE_AND_DNN;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_INSUFFICIENT_RESOURCES_FOR_SPECIFIC_SLICE") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_INSUFFICIENT_RESOURCES_FOR_SPECIFIC_SLICE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_NGKSI_ALREADY_IN_USE") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_NGKSI_ALREADY_IN_USE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_SERVING_NETWORK_NOT_AUTHORIZED") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_SERVING_NETWORK_NOT_AUTHORIZED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_PAYLOAD_WAS_NOT_FORWARDED") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_PAYLOAD_WAS_NOT_FORWARDED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_DNN_NOT_SUPPORTED_OR_NOT_SUBSCRIBED_IN_THE_SLICE") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_DNN_NOT_SUPPORTED_OR_NOT_SUBSCRIBED_IN_THE_SLICE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_INSUFFICIENT_USER_PLANE_RESOURCES_FOR_THE_PDU_SESSION") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_INSUFFICIENT_USER_PLANE_RESOURCES_FOR_THE_PDU_SESSION;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_SEMANTICALLY_INCORRECT_MESSAGE") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_SEMANTICALLY_INCORRECT_MESSAGE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_INVALID_MANDATORY_INFORMATION") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_INVALID_MANDATORY_INFORMATION;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_MESSAGE_TYPE_NON_EXISTENT_OR_NOT_IMPLEMENTED") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_MESSAGE_TYPE_NON_EXISTENT_OR_NOT_IMPLEMENTED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_MESSAGE_TYPE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_MESSAGE_TYPE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_INFORMATION_ELEMENT_NON_EXISTENT_OR_NOT_IMPLEMENTED") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_INFORMATION_ELEMENT_NON_EXISTENT_OR_NOT_IMPLEMENTED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_CONDITIONAL_IE_ERROR") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_CONDITIONAL_IE_ERROR;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_MESSAGE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE") == 0){
                registration_reject->gmm_cause = OGS_5GMM_CAUSE_MESSAGE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE;
            }
        }else if(strcmp(parameters[i], "t3346_value") == 0){
            registration_reject->presencemask = OGS_NAS_5GS_REGISTRATION_REJECT_T3346_VALUE_PRESENT;
            registration_reject->t3346_value.value = stringToInt8(parameters[i+1]);
            registration_reject->t3346_value.length = 1;
        }else if(strcmp(parameters[i], "t3502_value") == 0){
            registration_reject->presencemask = OGS_NAS_5GS_REGISTRATION_REJECT_T3502_VALUE_PRESENT;
            registration_reject->t3502_value.value = stringToInt8(parameters[i+1]);
            registration_reject->t3502_value.length = 1;
        }else if(strcmp(parameters[i], "eap_message") == 0){
            registration_reject->presencemask = OGS_NAS_5GS_REGISTRATION_REJECT_EAP_MESSAGE_PRESENT;
            registration_reject->eap_message.buffer = malloc(strlen(parameters[i+1]) + 1);
            memcpy(registration_reject->eap_message.buffer, (void*)parameters[i+1], strlen(parameters[i+1]));
            ((char*) registration_reject->eap_message.buffer)[strlen(parameters[i+1])] = '\0';
            registration_reject->eap_message.length = strlen(parameters[i+1]) + 1;
        }else if(strcmp(parameters[i], "rejected_nssai") == 0){
            registration_reject->presencemask = OGS_NAS_5GS_REGISTRATION_REJECT_REJECTED_NSSAI_PRESENT;
            if(OGS_NAS_MAX_REJECTED_NSSAI_LEN > strlen(parameters[i+1])){
                memcpy(registration_reject->rejected_nssai.buffer, parameters[i+1], strlen(parameters[i+1]));
                size_t i;
                for (i = strlen(parameters[i+1]); i < OGS_NAS_MAX_REJECTED_NSSAI_LEN; i++) { // add null characters to fill remaining space in output_buffer
                    registration_reject->rejected_nssai.buffer[i] = '\0';
                }
                registration_reject->rejected_nssai.length = strlen(parameters[i+1]);
            }else{
                memcpy(registration_reject->rejected_nssai.buffer, parameters[i+1], OGS_NAS_MAX_REJECTED_NSSAI_LEN);
                registration_reject->rejected_nssai.buffer[OGS_NAS_MAX_REJECTED_NSSAI_LEN] = '\0';
                registration_reject->rejected_nssai.length = OGS_NAS_MAX_REJECTED_NSSAI_LEN;
            }
        }else if(strcmp(parameters[i], "security_header_type") == 0){
            if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_PARTICALLY_CIPHTERD") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_PARTICALLY_CIPHTERD;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
            }
        }
    }
   }

   gmmbuf = ogs_nas_5gs_plain_encode(&message);
   ogs_expect_or_return_val(gmmbuf, OGS_ERROR);

   rv = nas_5gs_send_to_downlink_nas_transport(amf_ue, gmmbuf);
   ogs_expect(rv == OGS_OK);

   return rv;
}

int user_nas_5gs_send_service_reject(amf_ue_t* amf_ue, char** parameters, int size)
{
    int rv, i;
    ogs_pkbuf_t *gmmbuf = NULL;
    ogs_nas_5gs_message_t message;
    ogs_nas_5gs_service_reject_t *service_reject = &message.gmm.service_reject;
    ogs_nas_pdu_session_status_t *pdu_session_status = NULL;

    ogs_assert(amf_ue);
    ogs_info("Modified Service Reject!!!");
    memset(&message, 0, sizeof(message));

    pdu_session_status = &service_reject->pdu_session_status;
    message.gmm.h.extended_protocol_discriminator = OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM;
    message.gmm.h.message_type = OGS_NAS_5GS_SERVICE_REJECT;
    service_reject->gmm_cause = OGS_5GMM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED; //default value

    if(parameters != NULL){
     for(i = 0; i < size; i+=2){
        if(strcmp(parameters[i], "gmm_cause")){
            if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_ILLEGAL_UE") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_ILLEGAL_UE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_ILLEGAL_ME") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_ILLEGAL_ME;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_IMPLICITLY_DE_REGISTERED") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_IMPLICITLY_DE_REGISTERED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_PEI_NOT_ACCEPTED") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_PEI_NOT_ACCEPTED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_5GS_SERVICES_NOT_ALLOWED") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_5GS_SERVICES_NOT_ALLOWED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_PLMN_NOT_ALLOWED") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_PLMN_NOT_ALLOWED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_TRACKING_AREA_NOT_ALLOWED") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_TRACKING_AREA_NOT_ALLOWED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_ROAMING_NOT_ALLOWED_IN_THIS_TRACKING_AREA") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_ROAMING_NOT_ALLOWED_IN_THIS_TRACKING_AREA;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_NO_SUITABLE_CELLS_IN_TRACKING_AREA") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_NO_SUITABLE_CELLS_IN_TRACKING_AREA;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_N1_MODE_NOT_ALLOWED") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_N1_MODE_NOT_ALLOWED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_REDIRECTION_TO_EPC_REQUIRED") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_REDIRECTION_TO_EPC_REQUIRED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_NON_3GPP_ACCESS_TO_5GCN_NOT_ALLOWED") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_NON_3GPP_ACCESS_TO_5GCN_NOT_ALLOWED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_TEMPORARILY_NOT_AUTHORIZED_FOR_THIS_SNPN") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_TEMPORARILY_NOT_AUTHORIZED_FOR_THIS_SNPN;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_PERMANENTLY_NOT_AUTHORIZED_FOR_THIS_SNPN") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_PERMANENTLY_NOT_AUTHORIZED_FOR_THIS_SNPN;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_NOT_AUTHORIZED_FOR_THIS_CAG_OR_AUITHORIZED_FOR_CAG_CELLS_ONLY") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_NOT_AUTHORIZED_FOR_THIS_CAG_OR_AUITHORIZED_FOR_CAG_CELLS_ONLY;
            }else if(strcmp(parameters[i+1], "WIRELESS_ACCESS_AREA_NOT_ALLOWED") == 0){
                service_reject->gmm_cause = WIRELESS_ACCESS_AREA_NOT_ALLOWED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_MAC_FAILURE") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_MAC_FAILURE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_SYNCH_FAILURE") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_SYNCH_FAILURE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_CONGESTION") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_CONGESTION;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_UE_SECURITY_CAPABILITIES_MISMATCH") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_UE_SECURITY_CAPABILITIES_MISMATCH;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_SECURITY_MODE_REJECTED_UNSPECIFIED") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_SECURITY_MODE_REJECTED_UNSPECIFIED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_NON_5G_AUTHENTICATION_UNACCEPTABLE") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_NON_5G_AUTHENTICATION_UNACCEPTABLE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_RESTRICTED_SERVICE_AREA") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_RESTRICTED_SERVICE_AREA;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_LADN_NOT_AVAILABLE") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_LADN_NOT_AVAILABLE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_NO_NETWORK_SLICES_AVAILABLE") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_NO_NETWORK_SLICES_AVAILABLE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_MAXIMUM_NUMBER_OF_PDU_SESSIONS_REACHED") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_MAXIMUM_NUMBER_OF_PDU_SESSIONS_REACHED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_INSUFFICIENT_RESOURCES_FOR_SPECIFIC_SLICE_AND_DNN") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_INSUFFICIENT_RESOURCES_FOR_SPECIFIC_SLICE_AND_DNN;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_INSUFFICIENT_RESOURCES_FOR_SPECIFIC_SLICE") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_INSUFFICIENT_RESOURCES_FOR_SPECIFIC_SLICE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_NGKSI_ALREADY_IN_USE") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_NGKSI_ALREADY_IN_USE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_SERVING_NETWORK_NOT_AUTHORIZED") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_SERVING_NETWORK_NOT_AUTHORIZED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_PAYLOAD_WAS_NOT_FORWARDED") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_PAYLOAD_WAS_NOT_FORWARDED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_DNN_NOT_SUPPORTED_OR_NOT_SUBSCRIBED_IN_THE_SLICE") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_DNN_NOT_SUPPORTED_OR_NOT_SUBSCRIBED_IN_THE_SLICE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_INSUFFICIENT_USER_PLANE_RESOURCES_FOR_THE_PDU_SESSION") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_INSUFFICIENT_USER_PLANE_RESOURCES_FOR_THE_PDU_SESSION;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_SEMANTICALLY_INCORRECT_MESSAGE")== 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_SEMANTICALLY_INCORRECT_MESSAGE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_INVALID_MANDATORY_INFORMATION") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_INVALID_MANDATORY_INFORMATION;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_MESSAGE_TYPE_NON_EXISTENT_OR_NOT_IMPLEMENTED") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_MESSAGE_TYPE_NON_EXISTENT_OR_NOT_IMPLEMENTED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_MESSAGE_TYPE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_MESSAGE_TYPE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_INFORMATION_ELEMENT_NON_EXISTENT_OR_NOT_IMPLEMENTED") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_INFORMATION_ELEMENT_NON_EXISTENT_OR_NOT_IMPLEMENTED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_CONDITIONAL_IE_ERROR") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_CONDITIONAL_IE_ERROR;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_MESSAGE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE") == 0){
                service_reject->gmm_cause = OGS_5GMM_CAUSE_MESSAGE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE;
            }
        }else if(strcmp(parameters[i], "t3346_value") == 0){
            service_reject->presencemask = OGS_NAS_5GS_SERVICE_REJECT_T3346_VALUE_PRESENT;
            service_reject->t3346_value.value = stringToInt8(parameters[i+1]);
            service_reject->t3346_value.length = 1;
        }else if(strcmp(parameters[i], "t3448_value") == 0){
            service_reject->presencemask |= OGS_NAS_5GS_SERVICE_REJECT_T3448_VALUE_PRESENT;
            service_reject->t3448_value.value = stringToInt8(parameters[i+1]);
            service_reject->t3448_value.length = 1;
        }else if(strcmp(parameters[i], "eap_message") == 0){
            service_reject->presencemask |= OGS_NAS_5GS_SERVICE_REJECT_EAP_MESSAGE_PRESENT;
            service_reject->eap_message.buffer = malloc(strlen(parameters[i+1]) + 1);
            memcpy(service_reject->eap_message.buffer, (void*)parameters[i+1], strlen(parameters[i+1]));
            ((char*) service_reject->eap_message.buffer)[strlen(parameters[i+1])] = '\0';
            service_reject->eap_message.length = strlen(parameters[i+1]) + 1;
        }else if(strcmp(parameters[i], "pdu_session_status") == 0){
            service_reject->presencemask |= OGS_NAS_5GS_SERVICE_REJECT_PDU_SESSION_STATUS_PRESENT;
            pdu_session_status->psi = stringToInt16(parameters[i+1]);
            pdu_session_status->length = 2;
        }else if(strcmp(parameters[i], "security_header_type") == 0){
            if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_PARTICALLY_CIPHTERD") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_PARTICALLY_CIPHTERD;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
            }
        }
    }
   }

   gmmbuf = ogs_nas_5gs_plain_encode(&message);
   ogs_expect_or_return_val(gmmbuf, OGS_ERROR);

   rv = nas_5gs_send_to_downlink_nas_transport(amf_ue, gmmbuf);
   ogs_expect(rv == OGS_OK);

   return rv;
}

int user_nas_5gs_send_de_registration_request(amf_ue_t* amf_ue, char** parameters, int size)
{
    int rv, i;
    ran_ue_t *ran_ue = NULL;
    ogs_pkbuf_t *gmmbuf = NULL;
    ogs_nas_5gs_message_t message;
    ogs_nas_5gs_deregistration_request_to_ue_t *dereg_req = &message.gmm.deregistration_request_to_ue;

    ogs_assert(amf_ue);
    ran_ue = ran_ue_cycle(amf_ue->ran_ue);
    ogs_expect_or_return_val(ran_ue, OGS_ERROR);
    ogs_info("Modified Deregistration Request!!!");
    memset(&message, 0, sizeof(message));

    message.gmm.h.extended_protocol_discriminator = OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM;
    message.gmm.h.message_type = OGS_NAS_5GS_DEREGISTRATION_REQUEST_TO_UE;
    message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
    uint8_t initial_security_header = message.h.security_header_type;
    message.h.extended_protocol_discriminator = OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM;
    dereg_req->de_registration_type.switch_off = 1;
    dereg_req->de_registration_type.re_registration_required = OpenAPI_deregistration_reason_NULL == OpenAPI_deregistration_reason_REREGISTRATION_REQUIRED;
    dereg_req->de_registration_type.access_type = OGS_ACCESS_TYPE_3GPP;
    dereg_req->presencemask |= OGS_NAS_5GS_DEREGISTRATION_REQUEST_TO_UE_5GMM_CAUSE_PRESENT;

   if(parameters != NULL){
    for(i = 0; i < size; i+=2){
        if(strcmp(parameters[i], "gmm_cause") == 0){
            if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_ILLEGAL_UE") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_ILLEGAL_UE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_ILLEGAL_ME") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_ILLEGAL_ME;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_IMPLICITLY_DE_REGISTERED") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_IMPLICITLY_DE_REGISTERED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_PEI_NOT_ACCEPTED") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_PEI_NOT_ACCEPTED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_5GS_SERVICES_NOT_ALLOWED") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_5GS_SERVICES_NOT_ALLOWED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_PLMN_NOT_ALLOWED") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_PLMN_NOT_ALLOWED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_TRACKING_AREA_NOT_ALLOWED") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_TRACKING_AREA_NOT_ALLOWED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_ROAMING_NOT_ALLOWED_IN_THIS_TRACKING_AREA") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_ROAMING_NOT_ALLOWED_IN_THIS_TRACKING_AREA;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_NO_SUITABLE_CELLS_IN_TRACKING_AREA") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_NO_SUITABLE_CELLS_IN_TRACKING_AREA;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_N1_MODE_NOT_ALLOWED") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_N1_MODE_NOT_ALLOWED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_REDIRECTION_TO_EPC_REQUIRED") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_REDIRECTION_TO_EPC_REQUIRED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_NON_3GPP_ACCESS_TO_5GCN_NOT_ALLOWED") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_NON_3GPP_ACCESS_TO_5GCN_NOT_ALLOWED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_TEMPORARILY_NOT_AUTHORIZED_FOR_THIS_SNPN") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_TEMPORARILY_NOT_AUTHORIZED_FOR_THIS_SNPN;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_PERMANENTLY_NOT_AUTHORIZED_FOR_THIS_SNPN") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_PERMANENTLY_NOT_AUTHORIZED_FOR_THIS_SNPN;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_NOT_AUTHORIZED_FOR_THIS_CAG_OR_AUITHORIZED_FOR_CAG_CELLS_ONLY") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_NOT_AUTHORIZED_FOR_THIS_CAG_OR_AUITHORIZED_FOR_CAG_CELLS_ONLY;
            }else if(strcmp(parameters[i+1], "WIRELESS_ACCESS_AREA_NOT_ALLOWED") == 0){
                dereg_req->gmm_cause = WIRELESS_ACCESS_AREA_NOT_ALLOWED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_MAC_FAILURE") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_MAC_FAILURE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_SYNCH_FAILURE") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_SYNCH_FAILURE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_CONGESTION") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_CONGESTION;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_UE_SECURITY_CAPABILITIES_MISMATCH") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_UE_SECURITY_CAPABILITIES_MISMATCH;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_SECURITY_MODE_REJECTED_UNSPECIFIED") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_SECURITY_MODE_REJECTED_UNSPECIFIED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_NON_5G_AUTHENTICATION_UNACCEPTABLE") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_NON_5G_AUTHENTICATION_UNACCEPTABLE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_RESTRICTED_SERVICE_AREA") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_RESTRICTED_SERVICE_AREA;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_LADN_NOT_AVAILABLE") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_LADN_NOT_AVAILABLE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_NO_NETWORK_SLICES_AVAILABLE") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_NO_NETWORK_SLICES_AVAILABLE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_MAXIMUM_NUMBER_OF_PDU_SESSIONS_REACHED") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_MAXIMUM_NUMBER_OF_PDU_SESSIONS_REACHED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_INSUFFICIENT_RESOURCES_FOR_SPECIFIC_SLICE_AND_DNN") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_INSUFFICIENT_RESOURCES_FOR_SPECIFIC_SLICE_AND_DNN;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_INSUFFICIENT_RESOURCES_FOR_SPECIFIC_SLICE") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_INSUFFICIENT_RESOURCES_FOR_SPECIFIC_SLICE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_NGKSI_ALREADY_IN_USE") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_NGKSI_ALREADY_IN_USE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_SERVING_NETWORK_NOT_AUTHORIZED") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_SERVING_NETWORK_NOT_AUTHORIZED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_PAYLOAD_WAS_NOT_FORWARDED") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_PAYLOAD_WAS_NOT_FORWARDED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_DNN_NOT_SUPPORTED_OR_NOT_SUBSCRIBED_IN_THE_SLICE") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_DNN_NOT_SUPPORTED_OR_NOT_SUBSCRIBED_IN_THE_SLICE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_INSUFFICIENT_USER_PLANE_RESOURCES_FOR_THE_PDU_SESSION") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_INSUFFICIENT_USER_PLANE_RESOURCES_FOR_THE_PDU_SESSION;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_SEMANTICALLY_INCORRECT_MESSAGE") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_SEMANTICALLY_INCORRECT_MESSAGE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_INVALID_MANDATORY_INFORMATION") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_INVALID_MANDATORY_INFORMATION;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_MESSAGE_TYPE_NON_EXISTENT_OR_NOT_IMPLEMENTED") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_MESSAGE_TYPE_NON_EXISTENT_OR_NOT_IMPLEMENTED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_MESSAGE_TYPE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_MESSAGE_TYPE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_INFORMATION_ELEMENT_NON_EXISTENT_OR_NOT_IMPLEMENTED") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_INFORMATION_ELEMENT_NON_EXISTENT_OR_NOT_IMPLEMENTED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_CONDITIONAL_IE_ERROR") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_CONDITIONAL_IE_ERROR;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_MESSAGE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE") == 0){
                dereg_req->gmm_cause = OGS_5GMM_CAUSE_MESSAGE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE;
            }
        }else if(strcmp(parameters[i], "t3346_value") == 0){
            dereg_req->presencemask |= OGS_NAS_5GS_DEREGISTRATION_REQUEST_TO_UE_T3346_VALUE_PRESENT;
            dereg_req->t3346_value.value = stringToInt8(parameters[i+1]);
            dereg_req->t3346_value.length = 1;
        }else if(strcmp(parameters[i], "rejected_nssai") == 0){
            dereg_req->presencemask |= OGS_NAS_5GS_DEREGISTRATION_REQUEST_TO_UE_REJECTED_NSSAI_PRESENT;
            if(OGS_NAS_MAX_REJECTED_NSSAI_LEN > strlen(parameters[i+1])){
                memcpy(dereg_req->rejected_nssai.buffer, parameters[i+1], strlen(parameters[i+1]));
                size_t i;
                for (i = strlen(parameters[i+1]); i < OGS_NAS_MAX_REJECTED_NSSAI_LEN; i++) { // add null characters to fill remaining space in output_buffer
                    dereg_req->rejected_nssai.buffer[i] = '\0';
                }
                dereg_req->rejected_nssai.length = strlen(parameters[i+1]);
            }else{
                memcpy(dereg_req->rejected_nssai.buffer, parameters[i+1], OGS_NAS_MAX_REJECTED_NSSAI_LEN);
                dereg_req->rejected_nssai.buffer[OGS_NAS_MAX_REJECTED_NSSAI_LEN] = '\0';
                dereg_req->rejected_nssai.length = OGS_NAS_MAX_REJECTED_NSSAI_LEN;
            }
        }else if(strcmp(parameters[i], "de_registration_type.switch_off") == 0){
            dereg_req->de_registration_type.switch_off = stringToInt8(parameters[i+1]);
        }else if(strcmp(parameters[i], "de_registration_type.tsc") == 0){
            dereg_req->de_registration_type.tsc = stringToInt8(parameters[i+1]);
        }else if(strcmp(parameters[i], "de_registration_type.ksi") == 0){
            dereg_req->de_registration_type.ksi = stringToInt8(parameters[i+1]);
        }else if(strcmp(parameters[i], "de_registration_type.re_registration_required") == 0){
            if(strcmp(parameters[i+1], "OpenAPI_deregistration_reason_NULL") == 0){
                dereg_req->de_registration_type.re_registration_required = OpenAPI_deregistration_reason_NULL == OpenAPI_deregistration_reason_NULL; 
            }else if(strcmp(parameters[i+1], "OpenAPI_deregistration_reason_UE_INITIAL_REGISTRATION") == 0){
                dereg_req->de_registration_type.re_registration_required = OpenAPI_deregistration_reason_NULL == OpenAPI_deregistration_reason_UE_INITIAL_REGISTRATION; 
            }else if(strcmp(parameters[i+1], "OpenAPI_deregistration_reason_UE_REGISTRATION_AREA_CHANGE") == 0){
                dereg_req->de_registration_type.re_registration_required = OpenAPI_deregistration_reason_NULL == OpenAPI_deregistration_reason_UE_REGISTRATION_AREA_CHANGE; 
            }else if(strcmp(parameters[i+1], "OpenAPI_deregistration_reason_SUBSCRIPTION_WITHDRAWN") == 0){
                dereg_req->de_registration_type.re_registration_required = OpenAPI_deregistration_reason_NULL == OpenAPI_deregistration_reason_SUBSCRIPTION_WITHDRAWN; 
            }else if(strcmp(parameters[i+1], "OpenAPI_deregistration_reason__5GS_TO_EPS_MOBILITY") == 0){
                dereg_req->de_registration_type.re_registration_required = OpenAPI_deregistration_reason_NULL == OpenAPI_deregistration_reason__5GS_TO_EPS_MOBILITY; 
            }else if(strcmp(parameters[i+1], "OpenAPI_deregistration_reason__5GS_TO_EPS_MOBILITY_UE_INITIAL_REGISTRATION") == 0){
                dereg_req->de_registration_type.re_registration_required = OpenAPI_deregistration_reason_NULL == OpenAPI_deregistration_reason__5GS_TO_EPS_MOBILITY_UE_INITIAL_REGISTRATION; 
            }else if(strcmp(parameters[i+1], "OpenAPI_deregistration_reason_SMF_CONTEXT_TRANSFERRED") == 0){
                dereg_req->de_registration_type.re_registration_required = OpenAPI_deregistration_reason_NULL == OpenAPI_deregistration_reason_SMF_CONTEXT_TRANSFERRED; 
            }
        }else if(strcmp(parameters[i], "de_registration_type.access_type") == 0){
            if(strcmp(parameters[i+1], "OGS_ACCESS_TYPE_NON_3GPP") == 0){
                dereg_req->de_registration_type.access_type = OGS_ACCESS_TYPE_NON_3GPP;
            }else if(strcmp(parameters[i+1], "OGS_ACCESS_TYPE_BOTH_3GPP_AND_NON_3GPP") == 0){
                dereg_req->de_registration_type.access_type = OGS_ACCESS_TYPE_BOTH_3GPP_AND_NON_3GPP;
            }
        }else if(strcmp(parameters[i], "security_header_type") == 0){
            if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_PARTICALLY_CIPHTERD") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_PARTICALLY_CIPHTERD;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT;
            }
        }
    }
   }

   if(deregistration_security) gmmbuf = user_nas_5gs_security_encode(amf_ue, &message, initial_security_header);
   else gmmbuf = ogs_nas_5gs_plain_encode(&message);

   rv = nas_5gs_send_to_downlink_nas_transport(amf_ue, gmmbuf);
   ogs_expect_or_return_val(rv == OGS_OK, OGS_ERROR);

   return rv;
}

int user_nas_5gs_send_authentication_reject(amf_ue_t* amf_ue, char** parameters, int size)
{
    int rv, i;
    ogs_pkbuf_t *gmmbuf = NULL;
    ogs_nas_5gs_message_t message;

    ogs_assert(amf_ue);
    ogs_info("Modified Authentication Reject!!!");
    memset(&message, 0, sizeof(message));

    message.gmm.h.extended_protocol_discriminator = OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM;
    message.gmm.h.message_type = OGS_NAS_5GS_AUTHENTICATION_REJECT;

    if(parameters != NULL){
     for(i = 0; i < size; i+=2){
        if(strcmp(parameters[i], "security_header_type") == 0){
            if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_PARTICALLY_CIPHTERD") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_PARTICALLY_CIPHTERD;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
            }
        }
     }
    }

    gmmbuf = ogs_nas_5gs_plain_encode(&message);
    ogs_expect_or_return_val(gmmbuf, OGS_ERROR);

    rv = nas_5gs_send_to_downlink_nas_transport(amf_ue, gmmbuf);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int user_nas_5gs_send_de_registration_accept(amf_ue_t* amf_ue, char** parameters, int size)
{
    int rv, i;
    ran_ue_t *ran_ue = NULL;
    ogs_pkbuf_t *gmmbuf = NULL;
    ogs_nas_5gs_message_t message;

    ogs_assert(amf_ue);
    ran_ue = ran_ue_cycle(amf_ue->ran_ue);
    ogs_expect_or_return_val(ran_ue, OGS_ERROR);
    ogs_info("Modified Deregistration Accept!!!");;

    memset(&message, 0, sizeof(message));

    message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
    uint8_t initial_security_header = message.h.security_header_type;
    message.h.extended_protocol_discriminator = OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM;

    message.gmm.h.extended_protocol_discriminator = OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM;
    message.gmm.h.message_type = OGS_NAS_5GS_DEREGISTRATION_ACCEPT_TO_UE;

    if(parameters != NULL){
     for(i = 0; i < size; i+=2){
        if(strcmp(parameters[i], "security_header_type") == 0){
            if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_PARTICALLY_CIPHTERD") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_PARTICALLY_CIPHTERD;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT;
            }
        }
      }
    }

    if(deregistration_accept_security) gmmbuf = user_nas_5gs_security_encode(amf_ue, &message, initial_security_header);
    else gmmbuf = ogs_nas_5gs_plain_encode(&message);
    ogs_expect_or_return_val(gmmbuf, OGS_ERROR);

    rv = nas_5gs_send_to_downlink_nas_transport(amf_ue, gmmbuf);
    ogs_expect_or_return_val(rv == OGS_OK, OGS_ERROR);

    rv = ngap_send_ran_ue_context_release_command(ran_ue, NGAP_Cause_PR_nas, NGAP_CauseNas_deregister, NGAP_UE_CTX_REL_NG_REMOVE_AND_UNLINK, 0); //?
    //ogs_expect(rv == OGS_OK);

    return rv;
}

int user_nas_5gs_send_identity_request(amf_ue_t* amf_ue, char** parameters, int size)
{
    int rv, i;
    ogs_pkbuf_t *gmmbuf = NULL;
    ogs_nas_5gs_message_t message;
    ogs_nas_5gs_identity_request_t *identity_request = &message.gmm.identity_request;

    ogs_assert(amf_ue);
    ogs_info("Modified Identity Request!!!");

    memset(&message, 0, sizeof(message));
    message.gmm.h.extended_protocol_discriminator = OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM;
    message.gmm.h.message_type = OGS_NAS_5GS_IDENTITY_REQUEST;

    ogs_debug("Identity Type 2: SUCI");
    identity_request->identity_type.value = OGS_NAS_5GS_MOBILE_IDENTITY_SUCI;

    if(parameters != NULL){
     for(i = 0; i < size; i+=2){
        if(strcmp(parameters[i], "identity_type") == 0){
            if(strcmp(parameters[i+1], "OGS_NAS_5GS_MOBILE_IDENTITY_IS_NOT_AVAILABLE") == 0){
                identity_request->identity_type.value = OGS_NAS_5GS_MOBILE_IDENTITY_IS_NOT_AVAILABLE;
            }else if(strcmp(parameters[i+1], "OGS_NAS_5GS_MOBILE_IDENTITY_GUTI") == 0){
                identity_request->identity_type.value = OGS_NAS_5GS_MOBILE_IDENTITY_GUTI;
            }else if(strcmp(parameters[i+1], "OGS_NAS_5GS_MOBILE_IDENTITY_IMEI") == 0){
                identity_request->identity_type.value = OGS_NAS_5GS_MOBILE_IDENTITY_IMEI;
            }else if(strcmp(parameters[i+1], "OGS_NAS_5GS_MOBILE_IDENTITY_S_TMSI") == 0){
                identity_request->identity_type.value = OGS_NAS_5GS_MOBILE_IDENTITY_S_TMSI;
            }else if(strcmp(parameters[i+1], "OGS_NAS_5GS_MOBILE_IDENTITY_IMEISV") == 0){
                identity_request->identity_type.value = OGS_NAS_5GS_MOBILE_IDENTITY_IMEISV;
            }
        }else if(strcmp(parameters[i], "security_header_type") == 0){
            if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_PARTICALLY_CIPHTERD") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_PARTICALLY_CIPHTERD;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
            }
        }
      }
    }

    gmmbuf = ogs_nas_5gs_plain_encode(&message);
    ogs_expect_or_return_val(gmmbuf, OGS_ERROR);

    rv = nas_5gs_send_to_downlink_nas_transport(amf_ue, gmmbuf);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int user_nas_5gs_send_gmm_status(amf_ue_t* amf_ue, char** parameters, int size)
{
    int rv, i;
    ogs_pkbuf_t *gmmbuf = NULL;
    ogs_nas_5gs_message_t message;
    ogs_nas_5gs_5gmm_status_t *gmm_status = &message.gmm.gmm_status;

    ogs_assert(amf_ue);
    ogs_info("Modified GMM Status!!!");

    memset(&message, 0, sizeof(message));
    message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
    uint8_t initial_security_header = message.h.security_header_type;
    message.h.extended_protocol_discriminator = OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM;
    message.gmm.h.extended_protocol_discriminator = OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM;
    message.gmm.h.message_type = OGS_NAS_5GS_5GMM_STATUS;

    if(parameters != NULL){
     for(i = 0; i < size; i+=2){
        if(strcmp(parameters[i], "gmm_cause") == 0){
            if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_ILLEGAL_UE") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_ILLEGAL_UE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_ILLEGAL_ME") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_ILLEGAL_ME;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_IMPLICITLY_DE_REGISTERED") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_IMPLICITLY_DE_REGISTERED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_PEI_NOT_ACCEPTED") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_PEI_NOT_ACCEPTED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_5GS_SERVICES_NOT_ALLOWED") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_5GS_SERVICES_NOT_ALLOWED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_PLMN_NOT_ALLOWED") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_PLMN_NOT_ALLOWED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_TRACKING_AREA_NOT_ALLOWED") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_TRACKING_AREA_NOT_ALLOWED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_ROAMING_NOT_ALLOWED_IN_THIS_TRACKING_AREA") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_ROAMING_NOT_ALLOWED_IN_THIS_TRACKING_AREA;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_NO_SUITABLE_CELLS_IN_TRACKING_AREA") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_NO_SUITABLE_CELLS_IN_TRACKING_AREA;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_N1_MODE_NOT_ALLOWED") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_N1_MODE_NOT_ALLOWED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_REDIRECTION_TO_EPC_REQUIRED") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_REDIRECTION_TO_EPC_REQUIRED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_NON_3GPP_ACCESS_TO_5GCN_NOT_ALLOWED") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_NON_3GPP_ACCESS_TO_5GCN_NOT_ALLOWED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_TEMPORARILY_NOT_AUTHORIZED_FOR_THIS_SNPN") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_TEMPORARILY_NOT_AUTHORIZED_FOR_THIS_SNPN;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_PERMANENTLY_NOT_AUTHORIZED_FOR_THIS_SNPN") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_PERMANENTLY_NOT_AUTHORIZED_FOR_THIS_SNPN;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_NOT_AUTHORIZED_FOR_THIS_CAG_OR_AUITHORIZED_FOR_CAG_CELLS_ONLY") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_NOT_AUTHORIZED_FOR_THIS_CAG_OR_AUITHORIZED_FOR_CAG_CELLS_ONLY;
            }else if(strcmp(parameters[i+1], "WIRELESS_ACCESS_AREA_NOT_ALLOWED") == 0){
                gmm_status->gmm_cause = WIRELESS_ACCESS_AREA_NOT_ALLOWED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_MAC_FAILURE") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_MAC_FAILURE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_SYNCH_FAILURE") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_SYNCH_FAILURE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_CONGESTION") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_CONGESTION;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_UE_SECURITY_CAPABILITIES_MISMATCH") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_UE_SECURITY_CAPABILITIES_MISMATCH;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_SECURITY_MODE_REJECTED_UNSPECIFIED") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_SECURITY_MODE_REJECTED_UNSPECIFIED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_NON_5G_AUTHENTICATION_UNACCEPTABLE") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_NON_5G_AUTHENTICATION_UNACCEPTABLE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_RESTRICTED_SERVICE_AREA") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_RESTRICTED_SERVICE_AREA;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_LADN_NOT_AVAILABLE") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_LADN_NOT_AVAILABLE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_NO_NETWORK_SLICES_AVAILABLE") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_NO_NETWORK_SLICES_AVAILABLE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_MAXIMUM_NUMBER_OF_PDU_SESSIONS_REACHED") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_MAXIMUM_NUMBER_OF_PDU_SESSIONS_REACHED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_INSUFFICIENT_RESOURCES_FOR_SPECIFIC_SLICE_AND_DNN") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_INSUFFICIENT_RESOURCES_FOR_SPECIFIC_SLICE_AND_DNN;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_INSUFFICIENT_RESOURCES_FOR_SPECIFIC_SLICE") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_INSUFFICIENT_RESOURCES_FOR_SPECIFIC_SLICE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_NGKSI_ALREADY_IN_USE") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_NGKSI_ALREADY_IN_USE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_SERVING_NETWORK_NOT_AUTHORIZED") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_SERVING_NETWORK_NOT_AUTHORIZED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_PAYLOAD_WAS_NOT_FORWARDED") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_PAYLOAD_WAS_NOT_FORWARDED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_DNN_NOT_SUPPORTED_OR_NOT_SUBSCRIBED_IN_THE_SLICE") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_DNN_NOT_SUPPORTED_OR_NOT_SUBSCRIBED_IN_THE_SLICE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_INSUFFICIENT_USER_PLANE_RESOURCES_FOR_THE_PDU_SESSION") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_INSUFFICIENT_USER_PLANE_RESOURCES_FOR_THE_PDU_SESSION;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_SEMANTICALLY_INCORRECT_MESSAGE") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_SEMANTICALLY_INCORRECT_MESSAGE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_INVALID_MANDATORY_INFORMATION") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_INVALID_MANDATORY_INFORMATION;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_MESSAGE_TYPE_NON_EXISTENT_OR_NOT_IMPLEMENTED") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_MESSAGE_TYPE_NON_EXISTENT_OR_NOT_IMPLEMENTED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_MESSAGE_TYPE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_MESSAGE_TYPE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_INFORMATION_ELEMENT_NON_EXISTENT_OR_NOT_IMPLEMENTED") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_INFORMATION_ELEMENT_NON_EXISTENT_OR_NOT_IMPLEMENTED;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_CONDITIONAL_IE_ERROR") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_CONDITIONAL_IE_ERROR;
            }else if(strcmp(parameters[i+1], "OGS_5GMM_CAUSE_MESSAGE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE") == 0){
                gmm_status->gmm_cause = OGS_5GMM_CAUSE_MESSAGE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE;
            }
        }else if(strcmp(parameters[i], "security_header_type") == 0){
            if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_PARTICALLY_CIPHTERD") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_PARTICALLY_CIPHTERD;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT;
            }
        }
     }
    }

    if(gmm_status_security) gmmbuf = user_nas_5gs_security_encode(amf_ue, &message, initial_security_header);
    else gmmbuf = ogs_nas_5gs_plain_encode(&message);

    rv = nas_5gs_send_to_downlink_nas_transport(amf_ue, gmmbuf);

    return rv;
}

int user_nas_5gs_send_authentication_request(amf_ue_t* amf_ue, char** parameters, int size)
{
    int rv, i;
    ogs_pkbuf_t *gmmbuf = NULL;
    ogs_nas_5gs_message_t message;
    ogs_nas_5gs_authentication_request_t *authentication_request = &message.gmm.authentication_request;

    ogs_assert(amf_ue);
    ogs_info("Modified Authentication Request!!!");

    memset(&message, 0, sizeof(message));
    message.gmm.h.extended_protocol_discriminator = OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM;
    message.gmm.h.message_type = OGS_NAS_5GS_AUTHENTICATION_REQUEST;

    authentication_request->ngksi.tsc = amf_ue->nas.amf.tsc;
    authentication_request->ngksi.value = amf_ue->nas.amf.ksi;
    authentication_request->abba.length = amf_ue->abba_len;
    memcpy(authentication_request->abba.value, amf_ue->abba, amf_ue->abba_len);

    authentication_request->presencemask |= OGS_NAS_5GS_AUTHENTICATION_REQUEST_AUTHENTICATION_PARAMETER_RAND_PRESENT;
    authentication_request->presencemask |= OGS_NAS_5GS_AUTHENTICATION_REQUEST_AUTHENTICATION_PARAMETER_AUTN_PRESENT;

    memcpy(authentication_request->authentication_parameter_rand.rand, amf_ue->rand, OGS_RAND_LEN);
    memcpy(authentication_request->authentication_parameter_autn.autn, amf_ue->autn, OGS_AUTN_LEN);
    authentication_request->authentication_parameter_autn.length = OGS_AUTN_LEN;

    if(parameters != NULL){
     for(i = 0; i < size; i+=2){
      if(strcmp(parameters[i], "ngksi_tsc") == 0){
        authentication_request->ngksi.tsc = stringToInt8(parameters[i+1]);
      }else if(strcmp(parameters[i], "ngksi_ksi") == 0){
        authentication_request->ngksi.value = stringToInt8(parameters[i+1]);
      }else if(strcmp(parameters[i], "abba") == 0){
        uint8_t data[strlen(parameters[i+1]) + 1];
        stringToInt8pointer(data, parameters[i+1]);
        memcpy(authentication_request->abba.value, data, 2);
        authentication_request->abba.length = 2;
      }else if(strcmp(parameters[i], "authentication_parameter_rand") == 0){
        uint8_t data[strlen(parameters[i+1]) + 1];
        stringToInt8pointer(data, parameters[i+1]);
        memcpy(authentication_request->authentication_parameter_rand.rand, data, OGS_RAND_LEN);
        //authentication_request->authentication_parameter_rand.length = OGS_RAND_LEN;
      }else if(strcmp(parameters[i], "authentication_parameter_autn") == 0){
        uint8_t data[strlen(parameters[i+1]) + 1];
        stringToInt8pointer(data, parameters[i+1]);
        memcpy(authentication_request->authentication_parameter_autn.autn, data, OGS_AUTN_LEN);
        authentication_request->authentication_parameter_autn.length = OGS_AUTN_LEN;
      }else if(strcmp(parameters[i], "eap_message") == 0){ 
        authentication_request->presencemask |= OGS_NAS_5GS_AUTHENTICATION_REQUEST_EAP_MESSAGE_PRESENT;
        authentication_request->eap_message.buffer = malloc(strlen(parameters[i+1]) + 1);
        memcpy(authentication_request->eap_message.buffer, (void*)parameters[i+1], strlen(parameters[i+1]));
        ((char*) authentication_request->eap_message.buffer)[strlen(parameters[i+1])] = '\0';
        authentication_request->eap_message.length = strlen(parameters[i+1]) + 1;
      }else if(strcmp(parameters[i], "security_header_type") == 0){
            if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_PARTICALLY_CIPHTERD") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_PARTICALLY_CIPHTERD;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
            }
        }
     }
    }

    gmmbuf =  ogs_nas_5gs_plain_encode(&message);
    ogs_expect_or_return_val(gmmbuf, OGS_ERROR);

    rv = nas_5gs_send_to_downlink_nas_transport(amf_ue, gmmbuf);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int user_nas_5gs_send_authentication_result(amf_ue_t* amf_ue, char** parameters, int size)
{
    int rv, i;
    ogs_pkbuf_t *gmmbuf = NULL;
    ogs_nas_5gs_message_t message;
    ogs_nas_5gs_authentication_result_t *authentication_result = &message.gmm.authentication_result;

    ogs_assert(amf_ue);
    ogs_info("Modified Authentication Result!!!");

    memset(&message, 0, sizeof(message));
    message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
    uint8_t initial_security_header = message.h.security_header_type;
    message.h.extended_protocol_discriminator = OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM;
    message.gmm.h.extended_protocol_discriminator = OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM;
    message.gmm.h.message_type = OGS_NAS_5GS_AUTHENTICATION_RESULT;

    if(parameters != NULL){
     for(i = 0; i < size; i+=2){
      if(strcmp(parameters[i], "ngksi_tsc") == 0){
        authentication_result->ngksi.tsc = stringToInt8(parameters[i+1]);
      }else if(strcmp(parameters[i], "ngksi_ksi") == 0){
        authentication_result->ngksi.value = stringToInt8(parameters[i+1]);
      }else if(strcmp(parameters[i], "abba") == 0){
        authentication_result->presencemask |= OGS_NAS_5GS_AUTHENTICATION_RESULT_ABBA_PRESENT;   
        uint8_t data[strlen(parameters[i+1]) + 1];
        stringToInt8pointer(data, parameters[i+1]);
        memcpy(authentication_result->abba.value, data, 2);
        authentication_result->abba.length = 2;
      }else if(strcmp(parameters[i], "eap_message") == 0){ 
        authentication_result->eap_message.buffer = malloc(strlen(parameters[i+1]) + 1);
        memcpy(authentication_result->eap_message.buffer, (void*)parameters[i+1], strlen(parameters[i+1]));
        ((char*) authentication_result->eap_message.buffer)[strlen(parameters[i+1])] = '\0';
        authentication_result->eap_message.length = strlen(parameters[i+1]) + 1;
      }else if(strcmp(parameters[i], "security_header_type") == 0){
        if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE") == 0){
            message.h.security_header_type = OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED") == 0){
            message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT") == 0){
            message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_PARTICALLY_CIPHTERD") == 0){
            message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_PARTICALLY_CIPHTERD;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE") == 0){
            message.h.security_header_type = OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT") == 0){
            message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT;
        }
      }
     }
    }

    if(authentication_result_security) gmmbuf = user_nas_5gs_security_encode(amf_ue, &message, initial_security_header);
    else gmmbuf = ogs_nas_5gs_plain_encode(&message);
    ogs_expect_or_return_val(gmmbuf, OGS_ERROR);

    rv = nas_5gs_send_to_downlink_nas_transport(amf_ue, gmmbuf);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int user_nas_5gs_send_security_mode_command(amf_ue_t* amf_ue, char** parameters, int size)
{
    int rv, i;
    ogs_pkbuf_t *gmmbuf = NULL;
    ogs_nas_5gs_message_t message;
    ogs_nas_5gs_security_mode_command_t *security_mode_command = &message.gmm.security_mode_command;
    ogs_nas_security_algorithms_t *selected_nas_security_algorithms = &security_mode_command->selected_nas_security_algorithms;
    ogs_nas_key_set_identifier_t *ngksi = &security_mode_command->ngksi;
    ogs_nas_ue_security_capability_t *replayed_ue_security_capabilities = &security_mode_command->replayed_ue_security_capabilities;
    ogs_nas_s1_ue_security_capability_t *replayed_s1_ue_security_capabilities = &security_mode_command->replayed_s1_ue_security_capabilities;
    ogs_nas_imeisv_request_t *imeisv_request = &security_mode_command->imeisv_request;
    ogs_nas_additional_5g_security_information_t *additional_security_information = &security_mode_command->additional_security_information;
    ogs_nas_eps_nas_security_algorithms_t *selected_eps_nas_security_algorithms = &security_mode_command->selected_eps_nas_security_algorithms;

    ogs_assert(amf_ue);
    ogs_info("Modified Security Mode Command!!!");

    memset(&message, 0, sizeof(message));
    message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT;
    uint8_t initial_security_header = message.h.security_header_type;
    message.h.extended_protocol_discriminator = OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM;
    message.gmm.h.extended_protocol_discriminator = OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM;
    message.gmm.h.message_type = OGS_NAS_5GS_SECURITY_MODE_COMMAND;

    amf_ue->selected_int_algorithm = amf_selected_int_algorithm(amf_ue);
    amf_ue->selected_enc_algorithm = amf_selected_enc_algorithm(amf_ue);
    selected_nas_security_algorithms->type_of_integrity_protection_algorithm = amf_ue->selected_int_algorithm;
    selected_nas_security_algorithms->type_of_ciphering_algorithm = amf_ue->selected_enc_algorithm;

    ngksi->tsc = amf_ue->nas.amf.tsc;
    ngksi->value = amf_ue->nas.amf.ksi;

    replayed_ue_security_capabilities->nr_ea = amf_ue->ue_security_capability.nr_ea;
    replayed_ue_security_capabilities->nr_ia = amf_ue->ue_security_capability.nr_ia;
    replayed_ue_security_capabilities->eutra_ea = amf_ue->ue_security_capability.eutra_ea;
    replayed_ue_security_capabilities->eutra_ia = amf_ue->ue_security_capability.eutra_ia;

    security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_IMEISV_REQUEST_PRESENT;
    imeisv_request->type = OGS_NAS_IMEISV_TYPE;
    imeisv_request->value = OGS_NAS_IMEISV_REQUESTED;

    security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_ADDITIONAL_5G_SECURITY_INFORMATION_PRESENT;
    additional_security_information->length = 1;
    additional_security_information->retransmission_of_initial_nas_message_request = 1;

    ogs_kdf_nas_5gs(OGS_KDF_NAS_INT_ALG, amf_ue->selected_int_algorithm, amf_ue->kamf, amf_ue->knas_int);
    ogs_kdf_nas_5gs(OGS_KDF_NAS_ENC_ALG, amf_ue->selected_enc_algorithm, amf_ue->kamf, amf_ue->knas_enc);

    if(parameters != NULL){
     for(i = 0; i < size; i+=2){
      if(strcmp(parameters[i], "nas_security_encryption") == 0){
        if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_NEA0") == 0){
            amf_ue->selected_enc_algorithm = OGS_NAS_SECURITY_ALGORITHMS_NEA0;
            selected_nas_security_algorithms->type_of_ciphering_algorithm = OGS_NAS_SECURITY_ALGORITHMS_NEA0;
            ogs_kdf_nas_5gs(OGS_KDF_NAS_ENC_ALG, amf_ue->selected_enc_algorithm, amf_ue->kamf, amf_ue->knas_enc);
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_128_NEA1") == 0){
            amf_ue->selected_enc_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_NEA1;
            selected_nas_security_algorithms->type_of_ciphering_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_NEA1;
            ogs_kdf_nas_5gs(OGS_KDF_NAS_ENC_ALG, amf_ue->selected_enc_algorithm, amf_ue->kamf, amf_ue->knas_enc);
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_128_NEA2") == 0){
            amf_ue->selected_enc_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_NEA2;
            selected_nas_security_algorithms->type_of_ciphering_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_NEA2;
            ogs_kdf_nas_5gs(OGS_KDF_NAS_ENC_ALG, amf_ue->selected_enc_algorithm, amf_ue->kamf, amf_ue->knas_enc);
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_128_NEA3") == 0){
            amf_ue->selected_enc_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_NEA3;
            selected_nas_security_algorithms->type_of_ciphering_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_NEA3;
            ogs_kdf_nas_5gs(OGS_KDF_NAS_ENC_ALG, amf_ue->selected_enc_algorithm, amf_ue->kamf, amf_ue->knas_enc);
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_NEA4") == 0){
            amf_ue->selected_enc_algorithm = OGS_NAS_SECURITY_ALGORITHMS_NEA4;
            selected_nas_security_algorithms->type_of_ciphering_algorithm = OGS_NAS_SECURITY_ALGORITHMS_NEA4;
            ogs_kdf_nas_5gs(OGS_KDF_NAS_ENC_ALG, amf_ue->selected_enc_algorithm, amf_ue->kamf, amf_ue->knas_enc);
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_NEA5") == 0){
            amf_ue->selected_enc_algorithm = OGS_NAS_SECURITY_ALGORITHMS_NEA5;
            selected_nas_security_algorithms->type_of_ciphering_algorithm = OGS_NAS_SECURITY_ALGORITHMS_NEA5;
            ogs_kdf_nas_5gs(OGS_KDF_NAS_ENC_ALG, amf_ue->selected_enc_algorithm, amf_ue->kamf, amf_ue->knas_enc);
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_NEA6") == 0){
            amf_ue->selected_enc_algorithm = OGS_NAS_SECURITY_ALGORITHMS_NEA6;
            selected_nas_security_algorithms->type_of_ciphering_algorithm = OGS_NAS_SECURITY_ALGORITHMS_NEA6;
            ogs_kdf_nas_5gs(OGS_KDF_NAS_ENC_ALG, amf_ue->selected_enc_algorithm, amf_ue->kamf, amf_ue->knas_enc);
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_NEA7") == 0){
            amf_ue->selected_enc_algorithm = OGS_NAS_SECURITY_ALGORITHMS_NEA7;
            selected_nas_security_algorithms->type_of_ciphering_algorithm = OGS_NAS_SECURITY_ALGORITHMS_NEA7;
            ogs_kdf_nas_5gs(OGS_KDF_NAS_ENC_ALG, amf_ue->selected_enc_algorithm, amf_ue->kamf, amf_ue->knas_enc);
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_EEA0") == 0){
            amf_ue->selected_enc_algorithm = OGS_NAS_SECURITY_ALGORITHMS_EEA0;
            selected_nas_security_algorithms->type_of_ciphering_algorithm = OGS_NAS_SECURITY_ALGORITHMS_EEA0;
            ogs_kdf_nas_5gs(OGS_KDF_NAS_ENC_ALG, amf_ue->selected_enc_algorithm, amf_ue->kamf, amf_ue->knas_enc);
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_128_EEA1") == 0){
            amf_ue->selected_enc_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_EEA1;
            selected_nas_security_algorithms->type_of_ciphering_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_EEA1;
            ogs_kdf_nas_5gs(OGS_KDF_NAS_ENC_ALG, amf_ue->selected_enc_algorithm, amf_ue->kamf, amf_ue->knas_enc);
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_128_EEA2") == 0){
            amf_ue->selected_enc_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_EEA2;
            selected_nas_security_algorithms->type_of_ciphering_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_EEA2;
            ogs_kdf_nas_5gs(OGS_KDF_NAS_ENC_ALG, amf_ue->selected_enc_algorithm, amf_ue->kamf, amf_ue->knas_enc);
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_128_EEA3") == 0){
            amf_ue->selected_enc_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_EEA3;
            selected_nas_security_algorithms->type_of_ciphering_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_EEA3;
            ogs_kdf_nas_5gs(OGS_KDF_NAS_ENC_ALG, amf_ue->selected_enc_algorithm, amf_ue->kamf, amf_ue->knas_enc);
        }
      }else if(strcmp(parameters[i], "nas_security_integrity") == 0){
        if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_NIA0") == 0){
            amf_ue->selected_int_algorithm = OGS_NAS_SECURITY_ALGORITHMS_NIA0;
            selected_nas_security_algorithms->type_of_integrity_protection_algorithm = OGS_NAS_SECURITY_ALGORITHMS_NIA0;  
            ogs_kdf_nas_5gs(OGS_KDF_NAS_INT_ALG, amf_ue->selected_int_algorithm, amf_ue->kamf, amf_ue->knas_int); 
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_128_NIA1") == 0){
            amf_ue->selected_int_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_NIA1;
            selected_nas_security_algorithms->type_of_integrity_protection_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_NIA1;  
            ogs_kdf_nas_5gs(OGS_KDF_NAS_INT_ALG, amf_ue->selected_int_algorithm, amf_ue->kamf, amf_ue->knas_int); 
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_128_NIA2") == 0){
            amf_ue->selected_int_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_NIA2;
            selected_nas_security_algorithms->type_of_integrity_protection_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_NIA2;  
            ogs_kdf_nas_5gs(OGS_KDF_NAS_INT_ALG, amf_ue->selected_int_algorithm, amf_ue->kamf, amf_ue->knas_int); 
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_128_NIA3") == 0){
            amf_ue->selected_int_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_NIA3;
            selected_nas_security_algorithms->type_of_integrity_protection_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_NIA3;  
            ogs_kdf_nas_5gs(OGS_KDF_NAS_INT_ALG, amf_ue->selected_int_algorithm, amf_ue->kamf, amf_ue->knas_int); 
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_NIA4") == 0){
            amf_ue->selected_int_algorithm = OGS_NAS_SECURITY_ALGORITHMS_NIA4;
            selected_nas_security_algorithms->type_of_integrity_protection_algorithm = OGS_NAS_SECURITY_ALGORITHMS_NIA4;  
            ogs_kdf_nas_5gs(OGS_KDF_NAS_INT_ALG, amf_ue->selected_int_algorithm, amf_ue->kamf, amf_ue->knas_int); 
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_NIA5") == 0){
            amf_ue->selected_int_algorithm = OGS_NAS_SECURITY_ALGORITHMS_NIA5;
            selected_nas_security_algorithms->type_of_integrity_protection_algorithm = OGS_NAS_SECURITY_ALGORITHMS_NIA5;  
            ogs_kdf_nas_5gs(OGS_KDF_NAS_INT_ALG, amf_ue->selected_int_algorithm, amf_ue->kamf, amf_ue->knas_int); 
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_NIA6") == 0){
            amf_ue->selected_int_algorithm = OGS_NAS_SECURITY_ALGORITHMS_NIA6;
            selected_nas_security_algorithms->type_of_integrity_protection_algorithm = OGS_NAS_SECURITY_ALGORITHMS_NIA6;  
            ogs_kdf_nas_5gs(OGS_KDF_NAS_INT_ALG, amf_ue->selected_int_algorithm, amf_ue->kamf, amf_ue->knas_int); 
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_NIA7") == 0){
            amf_ue->selected_int_algorithm = OGS_NAS_SECURITY_ALGORITHMS_NIA7;
            selected_nas_security_algorithms->type_of_integrity_protection_algorithm = OGS_NAS_SECURITY_ALGORITHMS_NIA7;  
            ogs_kdf_nas_5gs(OGS_KDF_NAS_INT_ALG, amf_ue->selected_int_algorithm, amf_ue->kamf, amf_ue->knas_int); 
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_EIA0") == 0){
            amf_ue->selected_int_algorithm = OGS_NAS_SECURITY_ALGORITHMS_EIA0;
            selected_nas_security_algorithms->type_of_integrity_protection_algorithm = OGS_NAS_SECURITY_ALGORITHMS_EIA0;  
            ogs_kdf_nas_5gs(OGS_KDF_NAS_INT_ALG, amf_ue->selected_int_algorithm, amf_ue->kamf, amf_ue->knas_int); 
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_128_EIA1") == 0){
            amf_ue->selected_int_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_EIA1;
            selected_nas_security_algorithms->type_of_integrity_protection_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_EIA1;  
            ogs_kdf_nas_5gs(OGS_KDF_NAS_INT_ALG, amf_ue->selected_int_algorithm, amf_ue->kamf, amf_ue->knas_int); 
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_128_EIA2") == 0){
            amf_ue->selected_int_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_EIA2;
            selected_nas_security_algorithms->type_of_integrity_protection_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_EIA2;  
            ogs_kdf_nas_5gs(OGS_KDF_NAS_INT_ALG, amf_ue->selected_int_algorithm, amf_ue->kamf, amf_ue->knas_int); 
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_128_EIA3") == 0){
            amf_ue->selected_int_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_EIA3;
            selected_nas_security_algorithms->type_of_integrity_protection_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_EIA3;  
            ogs_kdf_nas_5gs(OGS_KDF_NAS_INT_ALG, amf_ue->selected_int_algorithm, amf_ue->kamf, amf_ue->knas_int); 
        }
      }else if(strcmp(parameters[i], "ngksi_tsc") == 0){
        security_mode_command->ngksi.tsc = stringToInt8(parameters[i+1]);
      }else if(strcmp(parameters[i], "ngksi_ksi") == 0){
        security_mode_command->ngksi.value = stringToInt8(parameters[i+1]);
      }else if(strcmp(parameters[i], "replayed_ue_security_capabilities_nr_ea") == 0){ 
        replayed_ue_security_capabilities->nr_ea = stringToInt8(parameters[i+1]);
      }else if(strcmp(parameters[i], "replayed_ue_security_capabilities_nr_ia") == 0){
        replayed_ue_security_capabilities->nr_ia = stringToInt8(parameters[i+1]);
      }else if(strcmp(parameters[i], "replayed_ue_security_capabilities_eutra_ea") == 0){
        replayed_ue_security_capabilities->eutra_ea = stringToInt8(parameters[i+1]);
      }else if(strcmp(parameters[i], "replayed_ue_security_capabilities_eutra_ia") == 0){
        replayed_ue_security_capabilities->eutra_ia = stringToInt8(parameters[i+1]);
      }else if(strcmp(parameters[i], "replayed_ue_security_capabilities_gea") == 0){
        replayed_ue_security_capabilities->gea = stringToInt8(parameters[i+1]);
      }else if(strcmp(parameters[i], "imeisv_request") == 0){
        if(strcmp(parameters[i], "OGS_NAS_IMEISV_NOT_REQUESTED") == 0) imeisv_request->value = OGS_NAS_IMEISV_NOT_REQUESTED;
      }else if(strcmp(parameters[i], "selected_eps_nas_security_algorithms") == 0){
        if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_NEA0") == 0){
            security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_SELECTED_EPS_NAS_SECURITY_ALGORITHMS_PRESENT;
            selected_eps_nas_security_algorithms->type_of_ciphering_algorithm = OGS_NAS_SECURITY_ALGORITHMS_NEA0;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_128_NEA1") == 0){
            security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_SELECTED_EPS_NAS_SECURITY_ALGORITHMS_PRESENT;
            selected_eps_nas_security_algorithms->type_of_ciphering_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_NEA1;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_128_NEA2") == 0){
            security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_SELECTED_EPS_NAS_SECURITY_ALGORITHMS_PRESENT;
            selected_eps_nas_security_algorithms->type_of_ciphering_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_NEA2;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_128_NEA3") == 0){
            security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_SELECTED_EPS_NAS_SECURITY_ALGORITHMS_PRESENT;
            selected_eps_nas_security_algorithms->type_of_ciphering_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_NEA3;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_NEA4") == 0){
            security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_SELECTED_EPS_NAS_SECURITY_ALGORITHMS_PRESENT;
            selected_eps_nas_security_algorithms->type_of_ciphering_algorithm = OGS_NAS_SECURITY_ALGORITHMS_NEA4;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_NEA5") == 0){
            security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_SELECTED_EPS_NAS_SECURITY_ALGORITHMS_PRESENT;
            selected_eps_nas_security_algorithms->type_of_ciphering_algorithm = OGS_NAS_SECURITY_ALGORITHMS_NEA5;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_NEA6") == 0){
            security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_SELECTED_EPS_NAS_SECURITY_ALGORITHMS_PRESENT;
            selected_eps_nas_security_algorithms->type_of_ciphering_algorithm = OGS_NAS_SECURITY_ALGORITHMS_NEA6;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_NEA7") == 0){
            security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_SELECTED_EPS_NAS_SECURITY_ALGORITHMS_PRESENT;
            selected_eps_nas_security_algorithms->type_of_ciphering_algorithm = OGS_NAS_SECURITY_ALGORITHMS_NEA7;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_EEA0") == 0){
            security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_SELECTED_EPS_NAS_SECURITY_ALGORITHMS_PRESENT;
            selected_eps_nas_security_algorithms->type_of_ciphering_algorithm = OGS_NAS_SECURITY_ALGORITHMS_EEA0;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_128_EEA1") == 0){
            security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_SELECTED_EPS_NAS_SECURITY_ALGORITHMS_PRESENT;
            selected_eps_nas_security_algorithms->type_of_ciphering_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_EEA1;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_128_EEA2") == 0){
            security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_SELECTED_EPS_NAS_SECURITY_ALGORITHMS_PRESENT;
            selected_eps_nas_security_algorithms->type_of_ciphering_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_EEA2;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_128_EEA3") == 0){
            security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_SELECTED_EPS_NAS_SECURITY_ALGORITHMS_PRESENT;
            selected_eps_nas_security_algorithms->type_of_ciphering_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_EEA3;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_NIA0") == 0){
            security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_SELECTED_EPS_NAS_SECURITY_ALGORITHMS_PRESENT;
            selected_eps_nas_security_algorithms->type_of_integrity_protection_algorithm = OGS_NAS_SECURITY_ALGORITHMS_NIA0;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_128_NIA1") == 0){
            security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_SELECTED_EPS_NAS_SECURITY_ALGORITHMS_PRESENT;
            selected_eps_nas_security_algorithms->type_of_integrity_protection_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_NIA1;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_128_NIA2") == 0){
            security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_SELECTED_EPS_NAS_SECURITY_ALGORITHMS_PRESENT;
            selected_eps_nas_security_algorithms->type_of_integrity_protection_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_NIA2;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_128_NIA3") == 0){
            security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_SELECTED_EPS_NAS_SECURITY_ALGORITHMS_PRESENT;
            selected_eps_nas_security_algorithms->type_of_integrity_protection_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_NIA3;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_NIA4") == 0){
            security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_SELECTED_EPS_NAS_SECURITY_ALGORITHMS_PRESENT;
            selected_eps_nas_security_algorithms->type_of_integrity_protection_algorithm = OGS_NAS_SECURITY_ALGORITHMS_NIA4;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_NIA5") == 0){
            security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_SELECTED_EPS_NAS_SECURITY_ALGORITHMS_PRESENT;
            selected_eps_nas_security_algorithms->type_of_integrity_protection_algorithm = OGS_NAS_SECURITY_ALGORITHMS_NIA5;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_NIA6") == 0){
            security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_SELECTED_EPS_NAS_SECURITY_ALGORITHMS_PRESENT;
            selected_eps_nas_security_algorithms->type_of_integrity_protection_algorithm = OGS_NAS_SECURITY_ALGORITHMS_NIA6;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_NIA7") == 0){
            security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_SELECTED_EPS_NAS_SECURITY_ALGORITHMS_PRESENT;
            selected_eps_nas_security_algorithms->type_of_integrity_protection_algorithm = OGS_NAS_SECURITY_ALGORITHMS_NIA7;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_EIA0") == 0){
            security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_SELECTED_EPS_NAS_SECURITY_ALGORITHMS_PRESENT;
            selected_eps_nas_security_algorithms->type_of_integrity_protection_algorithm = OGS_NAS_SECURITY_ALGORITHMS_EIA0;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_128_EIA1") == 0){
            security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_SELECTED_EPS_NAS_SECURITY_ALGORITHMS_PRESENT;
            selected_eps_nas_security_algorithms->type_of_integrity_protection_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_EIA1;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_128_EIA2") == 0){
            security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_SELECTED_EPS_NAS_SECURITY_ALGORITHMS_PRESENT;
            selected_eps_nas_security_algorithms->type_of_integrity_protection_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_EIA2;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_ALGORITHMS_128_EIA3") == 0){
            security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_SELECTED_EPS_NAS_SECURITY_ALGORITHMS_PRESENT;
            selected_eps_nas_security_algorithms->type_of_integrity_protection_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_EIA3;
        }
      }else if(strcmp(parameters[i], "additional_security_information_retransmission") == 0){
        additional_security_information->retransmission_of_initial_nas_message_request = stringToInt8(parameters[i+1]);
      }else if(strcmp(parameters[i], "additional_security_information_derivation") == 0){
        additional_security_information->horizontal_derivation_parameter = stringToInt8(parameters[i+1]);
      }else if(strcmp(parameters[i], "abba") == 0){
        security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_ABBA_PRESENT;
        uint8_t data[strlen(parameters[i+1]) + 1];
        stringToInt8pointer(data, parameters[i+1]); 
        memcpy(security_mode_command->abba.value, data, 2);
        security_mode_command->abba.length = 2;
      }else if(strcmp(parameters[i], "eap_message") == 0){
        security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_EAP_MESSAGE_PRESENT;
        security_mode_command->eap_message.buffer = malloc(strlen(parameters[i+1]) + 1);
        memcpy(security_mode_command->eap_message.buffer, (void*)parameters[i+1], strlen(parameters[i+1]));
        ((char*) security_mode_command->eap_message.buffer)[strlen(parameters[i+1])] = '\0';
        security_mode_command->eap_message.length = strlen(parameters[i+1]) + 1;
      }else if(strcmp(parameters[i], "replayed_s1_ue_security_capabilities_nr_ea") == 0){ 
        security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_REPLAYED_S1_UE_SECURITY_CAPABILITIES_PRESENT;
        replayed_s1_ue_security_capabilities->nr_ea = stringToInt8(parameters[i+1]);
      }else if(strcmp(parameters[i], "replayed_s1_ue_security_capabilities_nr_ia") == 0){
        security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_REPLAYED_S1_UE_SECURITY_CAPABILITIES_PRESENT;
        replayed_s1_ue_security_capabilities->nr_ia = stringToInt8(parameters[i+1]);
      }else if(strcmp(parameters[i], "replayed_s1_ue_security_capabilities_eutra_ea") == 0){
        security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_REPLAYED_S1_UE_SECURITY_CAPABILITIES_PRESENT;
        replayed_s1_ue_security_capabilities->eutra_ea = stringToInt8(parameters[i+1]);
      }else if(strcmp(parameters[i], "replayed_s1_ue_security_capabilities_eutra_ia") == 0){
        security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_REPLAYED_S1_UE_SECURITY_CAPABILITIES_PRESENT;
        replayed_s1_ue_security_capabilities->eutra_ia = stringToInt8(parameters[i+1]);
      }else if(strcmp(parameters[i], "security_header_type") == 0){
            if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_PARTICALLY_CIPHTERD") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_PARTICALLY_CIPHTERD;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT;
            }
        }
     }
    }

    replayed_ue_security_capabilities->length = sizeof(replayed_ue_security_capabilities->nr_ea) + sizeof(replayed_ue_security_capabilities->nr_ia);
    if ((replayed_ue_security_capabilities->eutra_ea || replayed_ue_security_capabilities->eutra_ia) && replayed_ue_security_capabilities->gea) replayed_ue_security_capabilities->length = sizeof(replayed_ue_security_capabilities->nr_ea) + sizeof(replayed_ue_security_capabilities->nr_ia) + sizeof(replayed_ue_security_capabilities->eutra_ea) + sizeof(replayed_ue_security_capabilities->eutra_ia) + sizeof(replayed_ue_security_capabilities->gea);
    else if (replayed_ue_security_capabilities->eutra_ea || replayed_ue_security_capabilities->eutra_ia) replayed_ue_security_capabilities->length = sizeof(replayed_ue_security_capabilities->nr_ea) + sizeof(replayed_ue_security_capabilities->nr_ia) + sizeof(replayed_ue_security_capabilities->eutra_ea) + sizeof(replayed_ue_security_capabilities->eutra_ia);

    replayed_s1_ue_security_capabilities->length = sizeof(replayed_s1_ue_security_capabilities->nr_ea) + sizeof(replayed_s1_ue_security_capabilities->nr_ia);
    if (replayed_s1_ue_security_capabilities->eutra_ea || replayed_s1_ue_security_capabilities->eutra_ia) replayed_s1_ue_security_capabilities->length = sizeof(replayed_s1_ue_security_capabilities->nr_ea) + sizeof(replayed_s1_ue_security_capabilities->nr_ia) + sizeof(replayed_s1_ue_security_capabilities->eutra_ea) + sizeof(replayed_s1_ue_security_capabilities->eutra_ia);

    if(security_mode_command_security) gmmbuf = user_nas_5gs_security_encode(amf_ue, &message, initial_security_header);
    else gmmbuf = ogs_nas_5gs_plain_encode(&message);
    ogs_expect_or_return_val(gmmbuf, OGS_ERROR);

    rv = nas_5gs_send_to_downlink_nas_transport(amf_ue, gmmbuf);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int user_nas_5gs_send_service_accept(amf_ue_t* amf_ue, char** parameters, int size)
{
    int rv, i;
    ran_ue_t *ran_ue = NULL;
    ogs_pkbuf_t *gmmbuf = NULL;
    ogs_nas_5gs_message_t message;
    ogs_nas_5gs_service_accept_t *service_accept = &message.gmm.service_accept;
    ogs_nas_pdu_session_status_t *pdu_session_status = NULL;
    ogs_nas_pdu_session_reactivation_result_t *pdu_session_reactivation_result;

    ran_ue = ran_ue_cycle(amf_ue->ran_ue);
    ogs_expect_or_return_val(ran_ue, OGS_ERROR);
    ogs_info("Modified Service Accept!!!");
    ogs_assert(amf_ue);

    pdu_session_status = &service_accept->pdu_session_status;
    ogs_assert(pdu_session_status);
    pdu_session_reactivation_result = &service_accept->pdu_session_reactivation_result;
    ogs_assert(pdu_session_reactivation_result);

    memset(&message, 0, sizeof(message));
    message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
    uint8_t initial_security_header = message.h.security_header_type;
    message.h.extended_protocol_discriminator = OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM;
    message.gmm.h.extended_protocol_discriminator = OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM;
    message.gmm.h.message_type = OGS_NAS_5GS_SERVICE_ACCEPT;

    //if (amf_ue->nas.present.pdu_session_status) {
    //    service_accept->presencemask |= OGS_NAS_5GS_SERVICE_ACCEPT_PDU_SESSION_STATUS_PRESENT;
    //    pdu_session_status->length = 2;
    //    pdu_session_status->psi = get_pdu_session_status(amf_ue);
    //}

    //if (amf_ue->nas.present.uplink_data_status) {
    //    service_accept->presencemask |= OGS_NAS_5GS_SERVICE_ACCEPT_PDU_SESSION_REACTIVATION_RESULT_PRESENT;
    //    pdu_session_reactivation_result->length = 2;
    //    pdu_session_reactivation_result->psi = get_pdu_session_reactivation_result(amf_ue);
    //}

    if(parameters != NULL){
        for(i = 0; i < size; i+=2){
            if(strcmp(parameters[i], "pdu_session_status_psi") == 0){
                service_accept->presencemask |= OGS_NAS_5GS_SERVICE_ACCEPT_PDU_SESSION_STATUS_PRESENT;
                pdu_session_status->length = 2;
                pdu_session_status->psi = stringToInt16(parameters[i+1]);
            }else if(strcmp(parameters[i], "pdu_session_reactivation_result_psi") == 0){
                service_accept->presencemask |= OGS_NAS_5GS_SERVICE_ACCEPT_PDU_SESSION_REACTIVATION_RESULT_PRESENT;
                pdu_session_reactivation_result->length = 2;
                pdu_session_reactivation_result->psi = stringToInt16(parameters[i+1]);
            }else if(strcmp(parameters[i], "pdu_session_reactivation_result_error_cause") == 0){
                service_accept->presencemask |= OGS_NAS_5GS_SERVICE_ACCEPT_PDU_SESSION_REACTIVATION_RESULT_ERROR_CAUSE_PRESENT;
                service_accept->pdu_session_reactivation_result_error_cause.buffer = malloc(strlen(parameters[i+1]) + 1);
                memcpy(service_accept->pdu_session_reactivation_result_error_cause.buffer, (void*)parameters[i+1], strlen(parameters[i+1]));
                ((char*) service_accept->pdu_session_reactivation_result_error_cause.buffer)[strlen(parameters[i+1])] = '\0';
                service_accept->pdu_session_reactivation_result_error_cause.length = strlen(parameters[i+1]) + 1;
            }else if(strcmp(parameters[i], "t3448_value") == 0){
                service_accept->presencemask |= OGS_NAS_5GS_SERVICE_ACCEPT_T3448_VALUE_PRESENT;
                service_accept->t3448_value.value = stringToInt8(parameters[i+1]);
                service_accept->t3448_value.length = 1;
            }else if(strcmp(parameters[i], "eap_message") == 0){ 
                service_accept->presencemask |= OGS_NAS_5GS_SERVICE_ACCEPT_EAP_MESSAGE_PRESENT;
                service_accept->eap_message.buffer = malloc(strlen(parameters[i+1]) + 1);
                memcpy(service_accept->eap_message.buffer, (void*)parameters[i+1], strlen(parameters[i+1]));
                ((char*) service_accept->eap_message.buffer)[strlen(parameters[i+1])] = '\0';
                service_accept->eap_message.length = strlen(parameters[i+1]) + 1;
            }else if(strcmp(parameters[i], "security_header_type") == 0){
                if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE") == 0){
                    message.h.security_header_type = OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE;
                }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED") == 0){
                    message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED;
                }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT") == 0){
                    message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT;
                }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_PARTICALLY_CIPHTERD") == 0){
                    message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_PARTICALLY_CIPHTERD;
                }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE") == 0){
                    message.h.security_header_type = OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE;
                }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT") == 0){
                    message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT;
                }
            }
        }
    }

    if(service_accept_security) gmmbuf = user_nas_5gs_security_encode(amf_ue, &message, initial_security_header);
    else gmmbuf = ogs_nas_5gs_plain_encode(&message);
    ogs_expect_or_return_val(gmmbuf, OGS_ERROR);
    
    rv = nas_5gs_send_to_downlink_nas_transport(amf_ue, gmmbuf);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int user_nas_5gs_send_configuration_update_command(amf_ue_t* amf_ue, char** parameters, int size)
{
    int rv, i;
    ogs_pkbuf_t *gmmbuf = NULL;
    ogs_nas_5gs_message_t message;
    ogs_nas_5gs_configuration_update_command_t *configuration_update_command = &message.gmm.configuration_update_command;
    ogs_nas_time_zone_t *local_time_zone = &configuration_update_command->local_time_zone;
    ogs_nas_time_zone_and_time_t *universal_time_and_local_time_zone = &configuration_update_command->universal_time_and_local_time_zone;
    ogs_nas_daylight_saving_time_t *network_daylight_saving_time = &configuration_update_command->network_daylight_saving_time;
    ogs_nas_configuration_update_indication_t *configuration_update_indication = &configuration_update_command->configuration_update_indication;
    ogs_nas_5gs_mobile_identity_t *mobile_identity = &configuration_update_command->guti;
    //ogs_nas_5gs_mobile_identity_guti_t mobile_identity_guti;
    struct timeval tv;
    struct tm gmt, local;
    gmm_configuration_update_command_param_t param;

    ogs_assert(amf_ue);
    ogs_info("Modified Configuration Update Command!!!");

    memset(&message, 0, sizeof(message));
    message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
    uint8_t initial_security_header = message.h.security_header_type;
    message.h.extended_protocol_discriminator = OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM;
    message.gmm.h.extended_protocol_discriminator = OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM;
    message.gmm.h.message_type = OGS_NAS_5GS_CONFIGURATION_UPDATE_COMMAND;

    configuration_update_command->presencemask |= OGS_NAS_5GS_CONFIGURATION_UPDATE_COMMAND_CONFIGURATION_UPDATE_INDICATION_PRESENT;
    param.acknowledgement_requested = 1;
    param.registration_requested = 1;
    configuration_update_indication->acknowledgement_requested = (&param)->acknowledgement_requested;
    configuration_update_indication->registration_requested = (&param)->registration_requested;

    if (amf_self()->full_name.length) {
        configuration_update_command->presencemask |= OGS_NAS_5GS_CONFIGURATION_UPDATE_COMMAND_FULL_NAME_FOR_NETWORK_PRESENT;
        memcpy(&configuration_update_command->full_name_for_network, &amf_self()->full_name, sizeof(ogs_nas_network_name_t));
    }

    if (amf_self()->short_name.length) {
        configuration_update_command->presencemask |= OGS_NAS_5GS_CONFIGURATION_UPDATE_COMMAND_SHORT_NAME_FOR_NETWORK_PRESENT;
        memcpy(&configuration_update_command->short_name_for_network, &amf_self()->short_name, sizeof(ogs_nas_network_name_t));
    }

    ogs_gettimeofday(&tv);
    ogs_gmtime(tv.tv_sec, &gmt);
    ogs_localtime(tv.tv_sec, &local);

    configuration_update_command->presencemask |= OGS_NAS_5GS_CONFIGURATION_UPDATE_COMMAND_LOCAL_TIME_ZONE_PRESENT;
    if (local.tm_gmtoff >= 0) {
        *local_time_zone = OGS_NAS_TIME_TO_BCD(local.tm_gmtoff / 900);
    } else {
        *local_time_zone = OGS_NAS_TIME_TO_BCD((-local.tm_gmtoff) / 900);
        *local_time_zone |= 0x08;
    }

    configuration_update_command->presencemask |= OGS_NAS_5GS_CONFIGURATION_UPDATE_COMMAND_UNIVERSAL_TIME_AND_LOCAL_TIME_ZONE_PRESENT;
    universal_time_and_local_time_zone->year = OGS_NAS_TIME_TO_BCD(gmt.tm_year % 100);
    universal_time_and_local_time_zone->mon = OGS_NAS_TIME_TO_BCD(gmt.tm_mon+1);
    universal_time_and_local_time_zone->mday = OGS_NAS_TIME_TO_BCD(gmt.tm_mday);
    universal_time_and_local_time_zone->hour = OGS_NAS_TIME_TO_BCD(gmt.tm_hour);
    universal_time_and_local_time_zone->min = OGS_NAS_TIME_TO_BCD(gmt.tm_min);
    universal_time_and_local_time_zone->sec = OGS_NAS_TIME_TO_BCD(gmt.tm_sec);
    universal_time_and_local_time_zone->timezone = *local_time_zone;

    configuration_update_command->presencemask |= OGS_NAS_5GS_CONFIGURATION_UPDATE_COMMAND_NETWORK_DAYLIGHT_SAVING_TIME_PRESENT;
    network_daylight_saving_time->length = 1;

    if(parameters != NULL){
      for(i = 0; i < size; i+=2){
       if(strcmp(parameters[i], "configuration_update_indication_acknowledgement_requested") == 0){
        configuration_update_indication->acknowledgement_requested = stringToInt8(parameters[i+1]);
       }else if(strcmp(parameters[i], "configuration_update_indication_registration_requested") == 0){
        configuration_update_indication->registration_requested = stringToInt8(parameters[i+1]);
       }else if(strcmp(parameters[i], "guti") == 0){
        configuration_update_command->presencemask |= OGS_NAS_5GS_CONFIGURATION_UPDATE_COMMAND_5G_GUTI_PRESENT;
        mobile_identity->buffer = malloc(strlen(parameters[i+1]) + 1);
        memcpy(mobile_identity->buffer, (void*)parameters[i+1], strlen(parameters[i+1]));
        ((char*) mobile_identity->buffer)[strlen(parameters[i+1])] = '\0';
        mobile_identity->length = strlen(parameters[i+1]) + 1;
       }else if(strcmp(parameters[i], "tai_list") == 0){
        configuration_update_command->presencemask |= OGS_NAS_5GS_CONFIGURATION_UPDATE_COMMAND_TAI_LIST_PRESENT;
        if(OGS_NAS_5GS_MAX_TAI_LIST_LEN > strlen(parameters[i+1])){
            memcpy(configuration_update_command->tai_list.buffer, parameters[i+1], strlen(parameters[i+1]));
            size_t i;
            for (i = strlen(parameters[i+1]); i < OGS_NAS_5GS_MAX_TAI_LIST_LEN; i++) { // add null characters to fill remaining space in output_buffer
                configuration_update_command->tai_list.buffer[i] = '\0';
            }
            configuration_update_command->tai_list.length = strlen(parameters[i+1]);
        }else{
            memcpy(configuration_update_command->tai_list.buffer, parameters[i+1], OGS_NAS_5GS_MAX_TAI_LIST_LEN);
            configuration_update_command->tai_list.buffer[OGS_NAS_5GS_MAX_TAI_LIST_LEN] = '\0';
            configuration_update_command->tai_list.length = OGS_NAS_5GS_MAX_TAI_LIST_LEN;
        }
       }else if(strcmp(parameters[i], "allowed_nssai") == 0){
        configuration_update_command->presencemask |= OGS_NAS_5GS_CONFIGURATION_UPDATE_COMMAND_ALLOWED_NSSAI_PRESENT;
        if(OGS_NAS_MAX_NSSAI_LEN > strlen(parameters[i+1])){
            memcpy(configuration_update_command->allowed_nssai.buffer, parameters[i+1], strlen(parameters[i+1]));
            size_t i;
            for (i = strlen(parameters[i+1]); i < OGS_NAS_MAX_NSSAI_LEN; i++) { // add null characters to fill remaining space in output_buffer
                configuration_update_command->allowed_nssai.buffer[i] = '\0';
            }
            configuration_update_command->allowed_nssai.length = strlen(parameters[i+1]);
        }else{
            memcpy(configuration_update_command->allowed_nssai.buffer, parameters[i+1], OGS_NAS_MAX_NSSAI_LEN);
            configuration_update_command->allowed_nssai.buffer[OGS_NAS_MAX_NSSAI_LEN] = '\0';
            configuration_update_command->allowed_nssai.length = OGS_NAS_MAX_NSSAI_LEN;
        }
       }else if(strcmp(parameters[i], "service_area_list") == 0){
        configuration_update_command->presencemask |= OGS_NAS_5GS_CONFIGURATION_UPDATE_COMMAND_SERVICE_AREA_LIST_PRESENT;
        if(OGS_NAS_MAX_SERVICE_AREA_LIST_LEN > strlen(parameters[i+1])){
            memcpy(configuration_update_command->service_area_list.buffer, parameters[i+1], strlen(parameters[i+1]));
            size_t i;
            for (i = strlen(parameters[i+1]); i < OGS_NAS_MAX_SERVICE_AREA_LIST_LEN; i++) { // add null characters to fill remaining space in output_buffer
                configuration_update_command->service_area_list.buffer[i] = '\0';
            }
            configuration_update_command->service_area_list.length = strlen(parameters[i+1]);
        }else{
            memcpy(configuration_update_command->service_area_list.buffer, parameters[i+1], OGS_NAS_MAX_SERVICE_AREA_LIST_LEN);
            configuration_update_command->service_area_list.buffer[OGS_NAS_MAX_SERVICE_AREA_LIST_LEN] = '\0';
            configuration_update_command->service_area_list.length = OGS_NAS_MAX_SERVICE_AREA_LIST_LEN;
        }
       }else if(strcmp(parameters[i], "full_name_for_network") == 0){
        configuration_update_command->presencemask |= OGS_NAS_5GS_CONFIGURATION_UPDATE_COMMAND_FULL_NAME_FOR_NETWORK_PRESENT;
        if(OGS_NAS_MAX_NETWORK_NAME_LEN > strlen(parameters[i+1])){
            memcpy(configuration_update_command->full_name_for_network.name, parameters[i+1], strlen(parameters[i+1]));
            size_t i;
            for (i = strlen(parameters[i+1]); i < OGS_NAS_MAX_NETWORK_NAME_LEN; i++) { // add null characters to fill remaining space in output_buffer
                configuration_update_command->full_name_for_network.name[i] = '\0';
            }
            configuration_update_command->full_name_for_network.length = strlen(parameters[i+1]);
        }else{
            memcpy(configuration_update_command->full_name_for_network.name, parameters[i+1], OGS_NAS_MAX_NETWORK_NAME_LEN);
            configuration_update_command->full_name_for_network.name[OGS_NAS_MAX_NETWORK_NAME_LEN] = '\0';
            configuration_update_command->full_name_for_network.length = OGS_NAS_MAX_NETWORK_NAME_LEN;
        }
       }else if(strcmp(parameters[i], "short_name_for_network") == 0){
        configuration_update_command->presencemask |= OGS_NAS_5GS_CONFIGURATION_UPDATE_COMMAND_SHORT_NAME_FOR_NETWORK_PRESENT;
        if(OGS_NAS_MAX_NETWORK_NAME_LEN > strlen(parameters[i+1])){
            memcpy(configuration_update_command->short_name_for_network.name, parameters[i+1], strlen(parameters[i+1]));
            size_t i;
            for (i = strlen(parameters[i+1]); i < OGS_NAS_MAX_NETWORK_NAME_LEN; i++) { // add null characters to fill remaining space in output_buffer
                configuration_update_command->short_name_for_network.name[i] = '\0';
            }
            configuration_update_command->short_name_for_network.length = strlen(parameters[i+1]);
        }else{
            memcpy(configuration_update_command->short_name_for_network.name, parameters[i+1], OGS_NAS_MAX_NETWORK_NAME_LEN);
            configuration_update_command->short_name_for_network.name[OGS_NAS_MAX_NETWORK_NAME_LEN] = '\0';
            configuration_update_command->short_name_for_network.length = OGS_NAS_MAX_NETWORK_NAME_LEN;
        }
       }else if(strcmp(parameters[i], "local_time_zone") == 0){
        configuration_update_command->local_time_zone = stringToInt8(parameters[i+1]);
       }else if(strcmp(parameters[i], "universal_time_and_local_time_zone_year") == 0){
        configuration_update_command->universal_time_and_local_time_zone.year = stringToInt8(parameters[i+1]);
       }else if(strcmp(parameters[i], "universal_time_and_local_time_zone_mon") == 0){
        configuration_update_command->universal_time_and_local_time_zone.mon = stringToInt8(parameters[i+1]);
       }else if(strcmp(parameters[i], "universal_time_and_local_time_zone_mday") == 0){
        configuration_update_command->universal_time_and_local_time_zone.mday = stringToInt8(parameters[i+1]);
       }else if(strcmp(parameters[i], "universal_time_and_local_time_zone_hour") == 0){
        configuration_update_command->universal_time_and_local_time_zone.hour = stringToInt8(parameters[i+1]);
       }else if(strcmp(parameters[i], "universal_time_and_local_time_zone_min") == 0){
        configuration_update_command->universal_time_and_local_time_zone.min = stringToInt8(parameters[i+1]);
       }else if(strcmp(parameters[i], "universal_time_and_local_time_zone_sec") == 0){
        configuration_update_command->universal_time_and_local_time_zone.sec = stringToInt8(parameters[i+1]);
       }else if(strcmp(parameters[i], "universal_time_and_local_time_zone_timezone") == 0){
        configuration_update_command->universal_time_and_local_time_zone.timezone = stringToInt8(parameters[i+1]);
       }else if(strcmp(parameters[i], "network_daylight_saving_time") == 0){
        if(strcmp(parameters[i+1], "OGS_NAS_NO_ADJUSTMENT_FOR_DAYLIGHT_SAVING_TIME") == 0){
            configuration_update_command->network_daylight_saving_time.value = OGS_NAS_NO_ADJUSTMENT_FOR_DAYLIGHT_SAVING_TIME;
        }else if(strcmp(parameters[i+1], "OGS_NAS_PLUS_1_HOUR_ADJUSTMENT_FOR_DAYLIGHT_SAVING_TIME") == 0){
            configuration_update_command->network_daylight_saving_time.value = OGS_NAS_PLUS_1_HOUR_ADJUSTMENT_FOR_DAYLIGHT_SAVING_TIME;
        }else if(strcmp(parameters[i+1], "OGS_NAS_PLUS_2_HOURS_ADJUSTMENT_FOR_DAYLIGHT_SAVING_TIME") == 0){
            configuration_update_command->network_daylight_saving_time.value = OGS_NAS_PLUS_2_HOURS_ADJUSTMENT_FOR_DAYLIGHT_SAVING_TIME;
        }
        configuration_update_command->network_daylight_saving_time.length = sizeof(ogs_nas_daylight_saving_time_t) - 1;  // Set the length field
        configuration_update_command->network_daylight_saving_time.spare = 0;  
       }else if(strcmp(parameters[i], "ladn_information") == 0){
        configuration_update_command->presencemask |= OGS_NAS_5GS_CONFIGURATION_UPDATE_COMMAND_LADN_INFORMATION_PRESENT;
        configuration_update_command->ladn_information.buffer = malloc(strlen(parameters[i+1]) + 1);
        memcpy(configuration_update_command->ladn_information.buffer, (void*)parameters[i+1], strlen(parameters[i+1]));
        ((char*) configuration_update_command->ladn_information.buffer)[strlen(parameters[i+1])] = '\0';
        configuration_update_command->ladn_information.length = strlen(parameters[i+1]) + 1;        
       }else if(strcmp(parameters[i], "mico_indication_raai") == 0){
        configuration_update_command->presencemask |= OGS_NAS_5GS_CONFIGURATION_UPDATE_COMMAND_MICO_INDICATION_PRESENT;
        configuration_update_command->mico_indication.raai = stringToInt8(parameters[i+1]);
       }else if(strcmp(parameters[i], "network_slicing_indication_nssai_indication") == 0){
        configuration_update_command->presencemask |= OGS_NAS_5GS_CONFIGURATION_UPDATE_COMMAND_NETWORK_SLICING_INDICATION_PRESENT;
        configuration_update_command->network_slicing_indication.dcni = stringToInt8(parameters[i+1]);  
       }else if(strcmp(parameters[i], "network_slicing_indication_change_indication") == 0){
        configuration_update_command->presencemask |= OGS_NAS_5GS_CONFIGURATION_UPDATE_COMMAND_NETWORK_SLICING_INDICATION_PRESENT;
        configuration_update_command->network_slicing_indication.nssci = stringToInt8(parameters[i+1]);  
       }else if(strcmp(parameters[i], "configured_nssai") == 0){
        configuration_update_command->presencemask |= OGS_NAS_5GS_CONFIGURATION_UPDATE_COMMAND_CONFIGURED_NSSAI_PRESENT;
        if(OGS_NAS_MAX_NSSAI_LEN > strlen(parameters[i+1])){
            memcpy(configuration_update_command->configured_nssai.buffer, parameters[i+1], strlen(parameters[i+1]));
            size_t i;
            for (i = strlen(parameters[i+1]); i < OGS_NAS_MAX_NSSAI_LEN; i++) { // add null characters to fill remaining space in output_buffer
                configuration_update_command->configured_nssai.buffer[i] = '\0';
            }
            configuration_update_command->configured_nssai.length = strlen(parameters[i+1]);
        }else{
            memcpy(configuration_update_command->configured_nssai.buffer, parameters[i+1], OGS_NAS_MAX_NSSAI_LEN);
            configuration_update_command->configured_nssai.buffer[OGS_NAS_MAX_NSSAI_LEN] = '\0';
            configuration_update_command->configured_nssai.length = OGS_NAS_MAX_NSSAI_LEN;
        }     
       }else if(strcmp(parameters[i], "rejected_nssai") == 0){
        configuration_update_command->presencemask |= OGS_NAS_5GS_CONFIGURATION_UPDATE_COMMAND_REJECTED_NSSAI_PRESENT;
        if(OGS_NAS_MAX_REJECTED_NSSAI_LEN > strlen(parameters[i+1])){
            memcpy(configuration_update_command->rejected_nssai.buffer, parameters[i+1], strlen(parameters[i+1]));
            size_t i;
            for (i = strlen(parameters[i+1]); i < OGS_NAS_MAX_REJECTED_NSSAI_LEN; i++) { // add null characters to fill remaining space in output_buffer
                configuration_update_command->rejected_nssai.buffer[i] = '\0';
            }
            configuration_update_command->rejected_nssai.length = strlen(parameters[i+1]);
        }else{
            memcpy(configuration_update_command->rejected_nssai.buffer, parameters[i+1], OGS_NAS_MAX_REJECTED_NSSAI_LEN);
            configuration_update_command->rejected_nssai.buffer[OGS_NAS_MAX_REJECTED_NSSAI_LEN] = '\0';
            configuration_update_command->rejected_nssai.length = OGS_NAS_MAX_REJECTED_NSSAI_LEN;
        } 
       }else if(strcmp(parameters[i], "operator_defined_access_category_definitions") == 0){
        configuration_update_command->presencemask |= OGS_NAS_5GS_CONFIGURATION_UPDATE_COMMAND_OPERATOR_DEFINED_ACCESS_CATEGORY_DEFINITIONS_PRESENT;
        configuration_update_command->operator_defined_access_category_definitions.buffer = malloc(strlen(parameters[i+1]) + 1);
        memcpy(configuration_update_command->operator_defined_access_category_definitions.buffer, (void*)parameters[i+1], strlen(parameters[i+1]));
        ((char*) configuration_update_command->operator_defined_access_category_definitions.buffer)[strlen(parameters[i+1])] = '\0';
        configuration_update_command->operator_defined_access_category_definitions.length = strlen(parameters[i+1]) + 1;     
       }else if(strcmp(parameters[i], "sms_indication_type") == 0){
        configuration_update_command->presencemask |= OGS_NAS_5GS_CONFIGURATION_UPDATE_COMMAND_SMS_INDICATION_PRESENT;
        if(strcmp(parameters[i+1], "OGS_NAS_SERVICE_TYPE_SIGNALLING") == 0){
            configuration_update_command->sms_indication.type = OGS_NAS_SERVICE_TYPE_SIGNALLING;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SERVICE_TYPE_DATA") == 0){
            configuration_update_command->sms_indication.type = OGS_NAS_SERVICE_TYPE_DATA;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SERVICE_TYPE_MOBILE_TERMINATED_SERVICES") == 0){
            configuration_update_command->sms_indication.type = OGS_NAS_SERVICE_TYPE_MOBILE_TERMINATED_SERVICES;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SERVICE_TYPE_EMERGENCY_SERVICES") == 0){
            configuration_update_command->sms_indication.type = OGS_NAS_SERVICE_TYPE_EMERGENCY_SERVICES;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SERVICE_TYPE_EMERGENCY_SERVICES_FALLBACK") == 0){
            configuration_update_command->sms_indication.type = OGS_NAS_SERVICE_TYPE_EMERGENCY_SERVICES_FALLBACK;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SERVICE_TYPE_HIGH_PRIORITY_ACCESS") == 0){
            configuration_update_command->sms_indication.type = OGS_NAS_SERVICE_TYPE_HIGH_PRIORITY_ACCESS;
        }else if(strcmp(parameters[i+1], "OGS_NAS_SERVICE_TYPE_ELEVATED_SIGNALLING") == 0){
            configuration_update_command->sms_indication.type = OGS_NAS_SERVICE_TYPE_ELEVATED_SIGNALLING;
        }
       }else if(strcmp(parameters[i], "sms_indication_sai") == 0){
        configuration_update_command->presencemask |= OGS_NAS_5GS_CONFIGURATION_UPDATE_COMMAND_SMS_INDICATION_PRESENT;
        configuration_update_command->sms_indication.sai = stringToInt8(parameters[i+1]);
       }else if(strcmp(parameters[i], "t3447_value") == 0){
        configuration_update_command->presencemask |= OGS_NAS_5GS_CONFIGURATION_UPDATE_COMMAND_T3447_VALUE_PRESENT;
        configuration_update_command->t3447_value.unit = OGS_NAS_GRPS_TIMER_3_UNIT_MULTIPLES_OF_1_HH;
        configuration_update_command->t3447_value.value = stringToInt8(parameters[i+1]);
        configuration_update_command->t3447_value.length = 1;
       }else if(strcmp(parameters[i], "cag_information_list") == 0){
        configuration_update_command->presencemask |= OGS_NAS_5GS_CONFIGURATION_UPDATE_COMMAND_CAG_INFORMATION_LIST_PRESENT;
        configuration_update_command->cag_information_list.buffer = malloc(strlen(parameters[i+1]) + 1);
        memcpy(configuration_update_command->cag_information_list.buffer, (void*)parameters[i+1], strlen(parameters[i+1]));
        ((char*) configuration_update_command->cag_information_list.buffer)[strlen(parameters[i+1])] = '\0';
        configuration_update_command->cag_information_list.length = strlen(parameters[i+1]) + 1;
       }else if(strcmp(parameters[i], "ue_radio_capability_id") == 0){
        configuration_update_command->presencemask |= OGS_NAS_5GS_CONFIGURATION_UPDATE_COMMAND_UE_RADIO_CAPABILITY_ID_PRESENT;
        if(OGS_NAS_MAX_UE_RADIO_CAPABILITY_ID_LEN > strlen(parameters[i+1])){
            memcpy(configuration_update_command->ue_radio_capability_id.buffer, parameters[i+1], strlen(parameters[i+1]));
            size_t i;
            for (i = strlen(parameters[i+1]); i < OGS_NAS_MAX_UE_RADIO_CAPABILITY_ID_LEN; i++) { // add null characters to fill remaining space in output_buffer
                configuration_update_command->ue_radio_capability_id.buffer[i] = '\0';
            }
            configuration_update_command->ue_radio_capability_id.length = strlen(parameters[i+1]);
        }else{
            memcpy(configuration_update_command->ue_radio_capability_id.buffer, parameters[i+1], OGS_NAS_MAX_UE_RADIO_CAPABILITY_ID_LEN);
            configuration_update_command->ue_radio_capability_id.buffer[OGS_NAS_MAX_UE_RADIO_CAPABILITY_ID_LEN] = '\0';
            configuration_update_command->ue_radio_capability_id.length = OGS_NAS_MAX_UE_RADIO_CAPABILITY_ID_LEN;
        }    
       }else if(strcmp(parameters[i], "security_header_type") == 0){
            if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_PARTICALLY_CIPHTERD") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_PARTICALLY_CIPHTERD;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE;
            }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT") == 0){
                message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT;
            }
        }
      }
    }

    if(configuration_update_command_security) gmmbuf = user_nas_5gs_security_encode(amf_ue, &message, initial_security_header);
    else gmmbuf = ogs_nas_5gs_plain_encode(&message);
    ogs_expect_or_return_val(gmmbuf, OGS_ERROR);

    rv = nas_5gs_send_to_downlink_nas_transport(amf_ue, gmmbuf);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int user_nas_5gs_send_registration_accept(amf_ue_t* amf_ue, char** parameters, int size)
{
    int rv, i;
    ran_ue_t *ran_ue = NULL;
    ogs_pkbuf_t *gmmbuf = NULL;
    ogs_nas_5gs_message_t message;
    ogs_nas_5gs_registration_accept_t *registration_accept = &message.gmm.registration_accept;
    ogs_nas_5gs_registration_result_t *registration_result = &registration_accept->registration_result;
    ogs_nas_5gs_mobile_identity_t *mobile_identity = &registration_accept->guti;
    ogs_nas_5gs_mobile_identity_guti_t mobile_identity_guti;
    ogs_nas_nssai_t *allowed_nssai = &registration_accept->allowed_nssai;
    ogs_nas_rejected_nssai_t *rejected_nssai = &registration_accept->rejected_nssai;
    ogs_nas_5gs_network_feature_support_t *network_feature_support = &registration_accept->network_feature_support;
    ogs_nas_pdu_session_status_t *pdu_session_status = &registration_accept->pdu_session_status;
    ogs_nas_pdu_session_reactivation_result_t *pdu_session_reactivation_result = &registration_accept->pdu_session_reactivation_result;
    ogs_nas_gprs_timer_3_t *t3512_value = &registration_accept->t3512_value;
    int served_tai_index = 0;

    ogs_assert(amf_ue);
    ran_ue = ran_ue_cycle(amf_ue->ran_ue);
    ogs_expect_or_return_val(ran_ue, OGS_ERROR);
    ogs_info("Modified Registration Accept!!!");

    memset(&message, 0, sizeof(message));
    message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
    uint8_t initial_security_header = message.h.security_header_type;
    message.h.extended_protocol_discriminator = OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM;
    message.gmm.h.extended_protocol_discriminator = OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM;
    message.gmm.h.message_type = OGS_NAS_5GS_REGISTRATION_ACCEPT;

    //Default Values
    /* Registration Result */
    registration_result->length = 1;
    registration_result->value = amf_ue->nas.access_type;

    /* Set GUTI */
    if (amf_ue->next.m_tmsi) {
        registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_5G_GUTI_PRESENT;
        ogs_nas_5gs_nas_guti_to_mobility_identity_guti(&amf_ue->next.guti, &mobile_identity_guti);
        mobile_identity->length = sizeof(mobile_identity_guti);
        mobile_identity->buffer = &mobile_identity_guti;
    }

    /* Set TAI List */
    registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_TAI_LIST_PRESENT;
    served_tai_index = amf_find_served_tai(&amf_ue->nr_tai);
    ogs_debug("[%s] SERVED_TAI_INDEX[%d]", amf_ue->supi, served_tai_index);
    ogs_assert(served_tai_index >= 0 && served_tai_index < OGS_MAX_NUM_OF_SERVED_TAI);
    ogs_assert(OGS_OK == ogs_nas_5gs_tai_list_build(&registration_accept->tai_list, &amf_self()->served_tai[served_tai_index].list0, &amf_self()->served_tai[served_tai_index].list2));

    /* Set Allowed NSSAI */
    ogs_assert(amf_ue->allowed_nssai.num_of_s_nssai);
    ogs_nas_build_nssai(allowed_nssai, amf_ue->allowed_nssai.s_nssai, amf_ue->allowed_nssai.num_of_s_nssai);
    registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_ALLOWED_NSSAI_PRESENT;

    if (amf_ue->rejected_nssai.num_of_s_nssai) {
        ogs_nas_build_rejected_nssai(rejected_nssai, amf_ue->rejected_nssai.s_nssai, amf_ue->rejected_nssai.num_of_s_nssai);
        registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_REJECTED_NSSAI_PRESENT;
    }

    /* 5GS network feature support */
    registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_5GS_NETWORK_FEATURE_SUPPORT_PRESENT;
    network_feature_support->length = 2;
    network_feature_support->ims_vops_3gpp = 1;

    /* Set T3512 */
    registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_T3512_VALUE_PRESENT;
    t3512_value->length = 1;
    t3512_value->unit = OGS_NAS_GRPS_TIMER_3_UNIT_MULTIPLES_OF_1_HH;
    t3512_value->value = 9;

    /* Set T3502 */
    registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_T3502_VALUE_PRESENT;
    registration_accept->t3502_value.length = 1;
    registration_accept->t3502_value.unit = OGS_NAS_GRPS_TIMER_UNIT_MULTIPLES_OF_1_MM;
    registration_accept->t3502_value.value = 12;

    //if (amf_ue->nas.present.pdu_session_status) {
    //    registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_PDU_SESSION_STATUS_PRESENT;
    //    pdu_session_status->length = 2;
    //    pdu_session_status->psi = get_pdu_session_status(amf_ue);
    //}

    //if (amf_ue->nas.present.uplink_data_status) {
    //    registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_PDU_SESSION_REACTIVATION_RESULT_PRESENT;
    //    pdu_session_reactivation_result->length = 2;
    //    pdu_session_reactivation_result->psi = get_pdu_session_reactivation_result(amf_ue);
    //}

    if(parameters != NULL){
        for(i = 0; i < size; i+=2){
            if(strcmp(parameters[i], "registration_result_value") == 0){
                registration_result->value = stringToInt8(parameters[i+1]); //access type
                registration_result->length = 1;
            }else if(strcmp(parameters[i], "guti") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_5G_GUTI_PRESENT;
                mobile_identity->buffer = malloc(strlen(parameters[i+1]) + 1);
                memcpy(mobile_identity->buffer, (void*)parameters[i+1], strlen(parameters[i+1]));
                ((char*) mobile_identity->buffer)[strlen(parameters[i+1])] = '\0';
                mobile_identity->length = strlen(parameters[i+1]) + 1;
            }else if(strcmp(parameters[i], "equivalent_plmns_mcc1") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_EQUIVALENT_PLMNS_PRESENT;
                registration_accept->equivalent_plmns.nas_plmn_id[0].mcc1 = stringToInt8(parameters[i+1]);
                registration_accept->equivalent_plmns.length = 1;
            }else if(strcmp(parameters[i], "equivalent_plmns_mnc1") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_EQUIVALENT_PLMNS_PRESENT;
                registration_accept->equivalent_plmns.nas_plmn_id[0].mnc1 = stringToInt8(parameters[i+1]);
                registration_accept->equivalent_plmns.length = 1;
            }else if(strcmp(parameters[i], "equivalent_plmns_mcc2") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_EQUIVALENT_PLMNS_PRESENT;
                registration_accept->equivalent_plmns.nas_plmn_id[0].mcc2 = stringToInt8(parameters[i+1]);
                registration_accept->equivalent_plmns.length = 1;
            }else if(strcmp(parameters[i], "equivalent_plmns_mnc2") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_EQUIVALENT_PLMNS_PRESENT;
                registration_accept->equivalent_plmns.nas_plmn_id[0].mnc2 = stringToInt8(parameters[i+1]);
                registration_accept->equivalent_plmns.length = 1;
            }else if(strcmp(parameters[i], "equivalent_plmns_mcc3") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_EQUIVALENT_PLMNS_PRESENT;
                registration_accept->equivalent_plmns.nas_plmn_id[0].mcc3 = stringToInt8(parameters[i+1]);
                registration_accept->equivalent_plmns.length = 1;
            }else if(strcmp(parameters[i], "equivalent_plmns_mnc3") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_EQUIVALENT_PLMNS_PRESENT;
                registration_accept->equivalent_plmns.nas_plmn_id[0].mnc3 = stringToInt8(parameters[i+1]);
                registration_accept->equivalent_plmns.length = 1;
            }else if(strcmp(parameters[i], "tai_list") == 0){
                if(OGS_NAS_5GS_MAX_TAI_LIST_LEN > strlen(parameters[i+1])){
                    memcpy(registration_accept->tai_list.buffer, parameters[i+1], strlen(parameters[i+1]));
                    size_t i;
                    for (i = strlen(parameters[i+1]); i < OGS_NAS_5GS_MAX_TAI_LIST_LEN; i++) { // add null characters to fill remaining space in output_buffer
                        registration_accept->tai_list.buffer[i] = '\0';
                    }
                    registration_accept->tai_list.length = strlen(parameters[i+1]);
                }else{
                    memcpy(registration_accept->tai_list.buffer, parameters[i+1], OGS_NAS_5GS_MAX_TAI_LIST_LEN);
                    registration_accept->tai_list.buffer[OGS_NAS_5GS_MAX_TAI_LIST_LEN] = '\0';
                    registration_accept->tai_list.length = OGS_NAS_5GS_MAX_TAI_LIST_LEN;
                }
            }else if(strcmp(parameters[i], "allowed_nssai") == 0){ 
                if(OGS_NAS_MAX_NSSAI_LEN > strlen(parameters[i+1])){
                    memcpy(registration_accept->allowed_nssai.buffer, parameters[i+1], strlen(parameters[i+1]));
                    size_t i;
                    for (i = strlen(parameters[i+1]); i < OGS_NAS_MAX_NSSAI_LEN; i++) { // add null characters to fill remaining space in output_buffer
                        registration_accept->allowed_nssai.buffer[i] = '\0';
                    }
                    registration_accept->allowed_nssai.length = strlen(parameters[i+1]);
                }else{
                    memcpy(registration_accept->allowed_nssai.buffer, parameters[i+1], OGS_NAS_MAX_NSSAI_LEN);
                    registration_accept->allowed_nssai.buffer[OGS_NAS_MAX_NSSAI_LEN] = '\0';
                    registration_accept->allowed_nssai.length = OGS_NAS_MAX_NSSAI_LEN;
                }
            }else if(strcmp(parameters[i], "rejected_nssai") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_REJECTED_NSSAI_PRESENT;
                if(OGS_NAS_MAX_REJECTED_NSSAI_LEN > strlen(parameters[i+1])){
                    memcpy(registration_accept->rejected_nssai.buffer, parameters[i+1], strlen(parameters[i+1]));
                    size_t i;
                    for (i = strlen(parameters[i+1]); i < OGS_NAS_MAX_REJECTED_NSSAI_LEN; i++) { // add null characters to fill remaining space in output_buffer
                        registration_accept->rejected_nssai.buffer[i] = '\0';
                    }
                    registration_accept->rejected_nssai.length = strlen(parameters[i+1]);
                }else{
                    memcpy(registration_accept->rejected_nssai.buffer, parameters[i+1], OGS_NAS_MAX_REJECTED_NSSAI_LEN);
                    registration_accept->rejected_nssai.buffer[OGS_NAS_MAX_REJECTED_NSSAI_LEN] = '\0';
                    registration_accept->rejected_nssai.length = OGS_NAS_MAX_REJECTED_NSSAI_LEN;
                }
            }else if(strcmp(parameters[i], "configured_nssai") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_CONFIGURED_NSSAI_PRESENT;
                if(OGS_NAS_MAX_NSSAI_LEN > strlen(parameters[i+1])){
                    memcpy(registration_accept->configured_nssai.buffer, parameters[i+1], strlen(parameters[i+1]));
                    size_t i;
                    for (i = strlen(parameters[i+1]); i < OGS_NAS_MAX_NSSAI_LEN; i++) { // add null characters to fill remaining space in output_buffer
                        registration_accept->configured_nssai.buffer[i] = '\0';
                    }
                    registration_accept->configured_nssai.length = strlen(parameters[i+1]);
                }else{
                    memcpy(registration_accept->configured_nssai.buffer, parameters[i+1], OGS_NAS_MAX_NSSAI_LEN);
                    registration_accept->configured_nssai.buffer[OGS_NAS_MAX_NSSAI_LEN] = '\0';
                    registration_accept->configured_nssai.length = OGS_NAS_MAX_NSSAI_LEN;
                }     
            }else if(strcmp(parameters[i], "network_feature_support_ims") == 0){
                network_feature_support->ims_vops_3gpp = stringToInt8(parameters[i+1]);
                network_feature_support->length = 2;
            }else if(strcmp(parameters[i], "pdu_session_status_psi") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_PDU_SESSION_STATUS_PRESENT;
                pdu_session_status->length = 2;
                pdu_session_status->psi = stringToInt16(parameters[i+1]);
            }else if(strcmp(parameters[i], "pdu_session_reactivation_result_psi") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_PDU_SESSION_REACTIVATION_RESULT_PRESENT;
                pdu_session_reactivation_result->length = 2;
                pdu_session_reactivation_result->psi = stringToInt16(parameters[i+1]);
            }else if(strcmp(parameters[i], "pdu_session_reactivation_result_error_cause") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_PDU_SESSION_REACTIVATION_RESULT_ERROR_CAUSE_PRESENT;
                registration_accept->pdu_session_reactivation_result_error_cause.buffer = malloc(strlen(parameters[i+1]) + 1);
                memcpy(registration_accept->pdu_session_reactivation_result_error_cause.buffer, (void*)parameters[i+1], strlen(parameters[i+1]));
                ((char*) registration_accept->pdu_session_reactivation_result_error_cause.buffer)[strlen(parameters[i+1])] = '\0';
                registration_accept->pdu_session_reactivation_result_error_cause.length = strlen(parameters[i+1]) + 1;
            }else if(strcmp(parameters[i], "ladn_information") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_LADN_INFORMATION_PRESENT;
                registration_accept->ladn_information.buffer = malloc(strlen(parameters[i+1]) + 1);
                memcpy(registration_accept->ladn_information.buffer, (void*)parameters[i+1], strlen(parameters[i+1]));
                ((char*) registration_accept->ladn_information.buffer)[strlen(parameters[i+1])] = '\0';
                registration_accept->ladn_information.length = strlen(parameters[i+1]) + 1; 
            }else if(strcmp(parameters[i], "mico_indication_raai") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_MICO_INDICATION_PRESENT;
                registration_accept->mico_indication.raai = stringToInt8(parameters[i+1]);
            }else if(strcmp(parameters[i], "network_slicing_indication_nssai_indication") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_CONFIGURATION_UPDATE_COMMAND_NETWORK_SLICING_INDICATION_PRESENT;
                registration_accept->network_slicing_indication.dcni = stringToInt8(parameters[i+1]);  
            }else if(strcmp(parameters[i], "network_slicing_indication_change_indication") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_CONFIGURATION_UPDATE_COMMAND_NETWORK_SLICING_INDICATION_PRESENT;
                registration_accept->network_slicing_indication.nssci = stringToInt8(parameters[i+1]);  
            }else if(strcmp(parameters[i], "service_area_list") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_SERVICE_AREA_LIST_PRESENT;
                if(OGS_NAS_MAX_SERVICE_AREA_LIST_LEN > strlen(parameters[i+1])){
                    memcpy(registration_accept->service_area_list.buffer, parameters[i+1], strlen(parameters[i+1]));
                    size_t i;
                    for (i = strlen(parameters[i+1]); i < OGS_NAS_MAX_SERVICE_AREA_LIST_LEN; i++) { // add null characters to fill remaining space in output_buffer
                        registration_accept->service_area_list.buffer[i] = '\0';
                    }
                    registration_accept->service_area_list.length = strlen(parameters[i+1]);
                }else{
                    memcpy(registration_accept->service_area_list.buffer, parameters[i+1], OGS_NAS_MAX_SERVICE_AREA_LIST_LEN);
                    registration_accept->service_area_list.buffer[OGS_NAS_MAX_SERVICE_AREA_LIST_LEN] = '\0';
                    registration_accept->service_area_list.length = OGS_NAS_MAX_SERVICE_AREA_LIST_LEN;
                }
            }else if(strcmp(parameters[i], "t3512_value") == 0){
                registration_accept->t3512_value.value = stringToInt8(parameters[i+1]);
                registration_accept->t3512_value.length = 1;
            }else if(strcmp(parameters[i], "non_3gpp_de_registration_timer_value") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_NON_3GPP_DE_REGISTRATION_TIMER_VALUE_PRESENT;
                registration_accept->non_3gpp_de_registration_timer_value.unit = OGS_NAS_GRPS_TIMER_UNIT_MULTIPLES_OF_1_MM;
                registration_accept->non_3gpp_de_registration_timer_value.value = stringToInt8(parameters[i+1]);
                registration_accept->non_3gpp_de_registration_timer_value.length = 1;
            }else if(strcmp(parameters[i], "t3502_value") == 0){
                registration_accept->t3502_value.value = stringToInt8(parameters[i+1]);
                registration_accept->t3502_value.length = 1;
            }else if(strcmp(parameters[i], "emergency_number_list") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_EMERGENCY_NUMBER_LIST_PRESENT;
                if(OGS_NAS_MAX_EMERGENCY_NUMBER_LIST_LEN > strlen(parameters[i+1])){
                    memcpy(registration_accept->emergency_number_list.buffer, parameters[i+1], strlen(parameters[i+1]));
                    size_t i;
                    for (i = strlen(parameters[i+1]); i < OGS_NAS_MAX_EMERGENCY_NUMBER_LIST_LEN; i++) { // add null characters to fill remaining space in output_buffer
                        registration_accept->emergency_number_list.buffer[i] = '\0';
                    }
                    registration_accept->emergency_number_list.length = strlen(parameters[i+1]);
                }else{
                    memcpy(registration_accept->emergency_number_list.buffer, parameters[i+1], OGS_NAS_MAX_EMERGENCY_NUMBER_LIST_LEN);
                    registration_accept->emergency_number_list.buffer[OGS_NAS_MAX_EMERGENCY_NUMBER_LIST_LEN] = '\0';
                    registration_accept->emergency_number_list.length = OGS_NAS_MAX_EMERGENCY_NUMBER_LIST_LEN;
                } 
            }else if(strcmp(parameters[i], "extended_emergency_number_list") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_EXTENDED_EMERGENCY_NUMBER_LIST_PRESENT;
                registration_accept->extended_emergency_number_list.buffer = malloc(strlen(parameters[i+1]) + 1);
                memcpy(registration_accept->extended_emergency_number_list.buffer, (void*)parameters[i+1], strlen(parameters[i+1]));
                ((char*) registration_accept->extended_emergency_number_list.buffer)[strlen(parameters[i+1])] = '\0';
                registration_accept->extended_emergency_number_list.length = strlen(parameters[i+1]) + 1;
            }else if(strcmp(parameters[i], "sor_transparent_container") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_SOR_TRANSPARENT_CONTAINER_PRESENT;
                registration_accept->sor_transparent_container.buffer = malloc(strlen(parameters[i+1]) + 1);
                memcpy(registration_accept->sor_transparent_container.buffer, (void*)parameters[i+1], strlen(parameters[i+1]));
                ((char*) registration_accept->sor_transparent_container.buffer)[strlen(parameters[i+1])] = '\0';
                registration_accept->sor_transparent_container.length = strlen(parameters[i+1]) + 1;
            }else if(strcmp(parameters[i], "eap_message") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_EAP_MESSAGE_PRESENT;
                registration_accept->eap_message.buffer = malloc(strlen(parameters[i+1]) + 1);
                memcpy(registration_accept->eap_message.buffer, (void*)parameters[i+1], strlen(parameters[i+1]));
                ((char*) registration_accept->eap_message.buffer)[strlen(parameters[i+1])] = '\0';
                registration_accept->eap_message.length = strlen(parameters[i+1]) + 1;
            }else if(strcmp(parameters[i], "nssai_inclusion_mode_value") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_NSSAI_INCLUSION_MODE_PRESENT;
                registration_accept->nssai_inclusion_mode.value = stringToInt8(parameters[i+1]);
            }else if(strcmp(parameters[i], "nssai_inclusion_mode_type") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_NSSAI_INCLUSION_MODE_PRESENT;
                registration_accept->nssai_inclusion_mode.type = stringToInt8(parameters[i+1]);
            }else if(strcmp(parameters[i], "operator_defined_access_category_definitions") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_OPERATOR_DEFINED_ACCESS_CATEGORY_DEFINITIONS_PRESENT;
                registration_accept->operator_defined_access_category_definitions.buffer = malloc(strlen(parameters[i+1]) + 1);
                memcpy(registration_accept->operator_defined_access_category_definitions.buffer, (void*)parameters[i+1], strlen(parameters[i+1]));
                ((char*) registration_accept->operator_defined_access_category_definitions.buffer)[strlen(parameters[i+1])] = '\0';
                registration_accept->operator_defined_access_category_definitions.length = strlen(parameters[i+1]) + 1;  
            }else if(strcmp(parameters[i], "negotiated_drx_parameters") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_NEGOTIATED_DRX_PARAMETERS_PRESENT;
                registration_accept->negotiated_drx_parameters.value = stringToInt8(parameters[i+1]);
                registration_accept->negotiated_drx_parameters.length = 1;
            }else if(strcmp(parameters[i], "negotiated_extended_drx_parameters_paging") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_NEGOTIATED_EXTENDED_DRX_PARAMETERS_PRESENT;
                registration_accept->negotiated_extended_drx_parameters.paging_time_window = stringToInt8(parameters[i+1]);
                registration_accept->negotiated_extended_drx_parameters.length = 1;
            }else if(strcmp(parameters[i], "negotiated_extended_drx_parameters_drx") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_NEGOTIATED_EXTENDED_DRX_PARAMETERS_PRESENT;
                registration_accept->negotiated_extended_drx_parameters.e_drx_value = stringToInt8(parameters[i+1]);
                registration_accept->negotiated_extended_drx_parameters.length = 1;
            }else if(strcmp(parameters[i], "negotiated_extended_drx_parameters_extended_paging") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_NEGOTIATED_EXTENDED_DRX_PARAMETERS_PRESENT;
                registration_accept->negotiated_extended_drx_parameters.paging_time_window = stringToInt8(parameters[i+1]);
                registration_accept->negotiated_extended_drx_parameters.length = 1;
            }else if(strcmp(parameters[i], "t3447_value") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_T3447_VALUE_PRESENT;
                //registration_accept->t3447_value.unit = OGS_NAS_GPRS_TIMER_3_UNIT_MULTIPLES_OF_1_HH;
                registration_accept->t3447_value.value = stringToInt8(parameters[i+1]);
                registration_accept->t3447_value.length = 1;
            }else if(strcmp(parameters[i], "t3448_value") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_T3448_VALUE_PRESENT;
                registration_accept->t3448_value.value = stringToInt8(parameters[i+1]);
                registration_accept->t3448_value.length = 1;
            }else if(strcmp(parameters[i], "t3324_value") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_T3324_VALUE_PRESENT;
                //registration_accept->t3324_value.unit = OGS_NAS_GPRS_TIMER_3_UNIT_MULTIPLES_OF_1_HH;
                registration_accept->t3324_value.value = stringToInt8(parameters[i+1]);
                registration_accept->t3324_value.length = 1;
            }else if(strcmp(parameters[i], "ue_radio_capability_id") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_UE_RADIO_CAPABILITY_ID_PRESENT;
                if(OGS_NAS_MAX_UE_RADIO_CAPABILITY_ID_LEN > strlen(parameters[i+1])){
                    memcpy(registration_accept->ue_radio_capability_id.buffer, parameters[i+1], strlen(parameters[i+1]));
                    size_t i;
                    for (i = strlen(parameters[i+1]); i < OGS_NAS_MAX_UE_RADIO_CAPABILITY_ID_LEN; i++) { // add null characters to fill remaining space in output_buffer
                        registration_accept->ue_radio_capability_id.buffer[i] = '\0';
                    }
                    registration_accept->ue_radio_capability_id.length = strlen(parameters[i+1]);
                }else{
                    memcpy(registration_accept->ue_radio_capability_id.buffer, parameters[i+1], OGS_NAS_MAX_UE_RADIO_CAPABILITY_ID_LEN);
                    registration_accept->ue_radio_capability_id.buffer[OGS_NAS_MAX_UE_RADIO_CAPABILITY_ID_LEN] = '\0';
                    registration_accept->ue_radio_capability_id.length = OGS_NAS_MAX_UE_RADIO_CAPABILITY_ID_LEN;
                }   
            }else if(strcmp(parameters[i], "pending_nssai") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_PENDING_NSSAI_PRESENT;
                if(OGS_NAS_MAX_NSSAI_LEN > strlen(parameters[i+1])){
                    memcpy(registration_accept->pending_nssai.buffer, parameters[i+1], strlen(parameters[i+1]));
                    size_t i;
                    for (i = strlen(parameters[i+1]); i < OGS_NAS_MAX_NSSAI_LEN; i++) { // add null characters to fill remaining space in output_buffer
                        registration_accept->pending_nssai.buffer[i] = '\0';
                    }
                    registration_accept->pending_nssai.length = strlen(parameters[i+1]);
                }else{
                    memcpy(registration_accept->pending_nssai.buffer, parameters[i+1], OGS_NAS_MAX_NSSAI_LEN);
                    registration_accept->pending_nssai.buffer[OGS_NAS_MAX_NSSAI_LEN] = '\0';
                    registration_accept->pending_nssai.length = OGS_NAS_MAX_NSSAI_LEN;
                }
            }else if(strcmp(parameters[i], "ciphering_key_data") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_CIPHERING_KEY_DATA_PRESENT;
                registration_accept->ciphering_key_data.buffer = malloc(strlen(parameters[i+1]) + 1);
                memcpy(registration_accept->ciphering_key_data.buffer, (void*)parameters[i+1], strlen(parameters[i+1]));
                ((char*) registration_accept->ciphering_key_data.buffer)[strlen(parameters[i+1])] = '\0';
                registration_accept->ciphering_key_data.length = strlen(parameters[i+1]) + 1;
            }else if(strcmp(parameters[i], "cag_information_list") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_CAG_INFORMATION_LIST_PRESENT;
                registration_accept->cag_information_list.buffer = malloc(strlen(parameters[i+1]) + 1);
                memcpy(registration_accept->cag_information_list.buffer, (void*)parameters[i+1], strlen(parameters[i+1]));
                ((char*) registration_accept->cag_information_list.buffer)[strlen(parameters[i+1])] = '\0';
                registration_accept->cag_information_list.length = strlen(parameters[i+1]) + 1;
            }else if(strcmp(parameters[i], "negotiated_wus_assistance_information") == 0){
                registration_accept->presencemask |= OGS_NAS_5GS_REGISTRATION_ACCEPT_NEGOTIATED_WUS_ASSISTANCE_INFORMATION_PRESENT;
                if(OGS_MAX_NAS_WUS_ASSISTANCE_INFORAMTION_LEN > strlen(parameters[i+1])){
                    memcpy(registration_accept->negotiated_wus_assistance_information.buffer, parameters[i+1], strlen(parameters[i+1]));
                    size_t i;
                    for (i = strlen(parameters[i+1]); i < OGS_MAX_NAS_WUS_ASSISTANCE_INFORAMTION_LEN; i++) { // add null characters to fill remaining space in output_buffer
                        registration_accept->negotiated_wus_assistance_information.buffer[i] = '\0';
                    }
                    registration_accept->negotiated_wus_assistance_information.length = strlen(parameters[i+1]);
                }else{
                    memcpy(registration_accept->negotiated_wus_assistance_information.buffer, parameters[i+1], OGS_MAX_NAS_WUS_ASSISTANCE_INFORAMTION_LEN);
                    registration_accept->negotiated_wus_assistance_information.buffer[OGS_MAX_NAS_WUS_ASSISTANCE_INFORAMTION_LEN] = '\0';
                    registration_accept->negotiated_wus_assistance_information.length = OGS_MAX_NAS_WUS_ASSISTANCE_INFORAMTION_LEN;
                }
            }else if(strcmp(parameters[i], "security_header_type") == 0){
                if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE") == 0){
                    message.h.security_header_type = OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE;
                }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED") == 0){
                    message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED;
                }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT") == 0){
                    message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT;
                }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_PARTICALLY_CIPHTERD") == 0){
                    message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_PARTICALLY_CIPHTERD;
                }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE") == 0){
                    message.h.security_header_type = OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE;
                }else if(strcmp(parameters[i+1], "OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT") == 0){
                    message.h.security_header_type = OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT;
                }
            }
        }
    }

    if(registration_accept_security) gmmbuf = user_nas_5gs_security_encode(amf_ue, &message, initial_security_header);
    else gmmbuf = ogs_nas_5gs_plain_encode(&message);
    ogs_expect_or_return_val(gmmbuf, OGS_ERROR);

    rv = nas_5gs_send_to_downlink_nas_transport(amf_ue, gmmbuf);
    ogs_expect(rv == OGS_OK);

    return OGS_OK;
}

ogs_pkbuf_t *user_nas_5gs_security_encode(amf_ue_t *amf_ue, ogs_nas_5gs_message_t *message, uint8_t initial_security_header)
{
    int integrity_protected = 0;
    int new_security_context = 0;
    int ciphered = 0;
    ogs_nas_5gs_security_header_t h;
    ogs_pkbuf_t *new = NULL;

    ogs_assert(amf_ue);

    if(initial_security_header == message->h.security_header_type){ //no modification
        switch (message->h.security_header_type) {
        case OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE:
            return ogs_nas_5gs_plain_encode(message);
        case OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED:
            integrity_protected = 1;
            break;
        case OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED:
            integrity_protected = 1;
            ciphered = 1;
            break;
        case OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT:
            integrity_protected = 1;
            new_security_context = 1;
            break;
        case OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT:
            integrity_protected = 1;
            new_security_context = 1;
            ciphered = 1;
            break;
        default:
            ogs_error("Not implemented(securiry header type:0x%x)", message->h.security_header_type);
            return NULL;
        }
    }else{
        switch (initial_security_header) {
        case OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE:
            return ogs_nas_5gs_plain_encode(message);
        case OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED:
            integrity_protected = 1;
            break;
        case OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED:
            integrity_protected = 1;
            ciphered = 1;
            break;
        case OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT:
            integrity_protected = 1;
            new_security_context = 1;
            break;
        case OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT:
            integrity_protected = 1;
            new_security_context = 1;
            ciphered = 1;
            break;
        default:
            ogs_error("Not implemented(securiry header type:0x%x)", message->h.security_header_type);
            return NULL;
        }
    }

    if (new_security_context) {
        amf_ue->dl_count = 0;
        amf_ue->ul_count.i32 = 0;
    }

    if (amf_ue->selected_enc_algorithm == 0) ciphered = 0;
    if (amf_ue->selected_int_algorithm == 0) integrity_protected = 0;

    memset(&h, 0, sizeof(h));
    h.security_header_type = message->h.security_header_type;
    h.extended_protocol_discriminator = message->h.extended_protocol_discriminator;
    h.sequence_number = (amf_ue->dl_count & 0xff);

    new = ogs_nas_5gs_plain_encode(message);
    if (!new) {
        ogs_error("ogs_nas_5gs_plain_encode() failed");
        return NULL;
    }

    if (ciphered) ogs_nas_encrypt(amf_ue->selected_enc_algorithm, amf_ue->knas_enc, amf_ue->dl_count, amf_ue->nas.access_type, OGS_NAS_SECURITY_DOWNLINK_DIRECTION, new);

    ogs_assert(ogs_pkbuf_push(new, 1));
    *(uint8_t *)(new->data) = h.sequence_number;

    if (integrity_protected) {
        uint8_t mac[4];
        ogs_nas_mac_calculate(amf_ue->selected_int_algorithm, amf_ue->knas_int, amf_ue->dl_count, amf_ue->nas.access_type, OGS_NAS_SECURITY_DOWNLINK_DIRECTION, new, mac);
        memcpy(&h.message_authentication_code, mac, sizeof(mac));
    }

    amf_ue->dl_count = (amf_ue->dl_count + 1) & 0xffffff; /* Use 24bit */

    ogs_assert(ogs_pkbuf_push(new, 6));
    memcpy(new->data, &h, sizeof(ogs_nas_5gs_security_header_t));

    amf_ue->security_context_available = 1;

    return new;
}

uint8_t stringToInt8(char* parameter){

  uint8_t output_uint8;
  int input_int = atoi(parameter);  // convert input string to integer

  if(input_int >= 0 && input_int <= 255) output_uint8 = (uint8_t)input_int;  // cast integer to uint8_t
  else output_uint8 = 0;

  return output_uint8;
}

uint16_t stringToInt16(char* parameter){

  uint16_t output_uint16;
  int input_int = atoi(parameter);  // convert input string to integer
 
  if(input_int >= 0 && input_int <= 65535) output_uint16 = (uint16_t)input_int;  // cast integer to uint16_t
  else output_uint16 = 0;

  return output_uint16;
}

void stringToInt8pointer(uint8_t* data, char* parameter){
  memcpy(data, parameter, strlen(parameter));
  data[strlen(parameter)] = '\0';
}
