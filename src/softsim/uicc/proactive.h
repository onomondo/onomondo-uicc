/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

#include <stdint.h>
#include <onomondo/softsim/list.h>
#include <onomondo/softsim/log.h>
#include "uicc_sms_tx.h"
#include "uicc_sms_rx.h"
#include "uicc_refresh.h"
struct ss_context;
struct ss_apdu;

typedef void (*term_resp_cb)(struct ss_context * ctx, uint8_t *resp_data,
			     uint8_t resp_data_len);

enum ss_proactive_cat_templates {
	/* ETSI TS 101 220 Section 7.2 */
	TS_101_220_IEI_PROPRITARY	= 0xCF,
	TS_101_220_IEI_PROACTIVE_CMD	= 0xD0,
	TS_101_220_IEI_SMS_PP_DWNLD	= 0xD1,
	TS_101_220_IEI_CBC_DWNLD	= 0xD2,
	TS_101_220_IEI_MENU_SELECTION	= 0xD3,
	TS_101_220_IEI_CALL_CTRL	= 0xD4,
	TS_101_220_IEI_MO_SMS_CTRL	= 0xD5,
	TS_101_220_IEI_EVENT_DWNLD	= 0xD6,
	TS_101_220_IEI_TIMER_EXPIR	= 0xD7,
	TS_101_220_IEI_INTRA_UICC	= 0xD8,
	TS_101_220_IEI_USSD_DWNLD	= 0xD9,
	TS_101_220_IEI_MMS_TRX_STAT	= 0xDA,
	TS_101_220_IEI_MMS_NOTIF_DWNLD	= 0xDB,
	TS_101_220_IEI_TERM_APP		= 0xDC,
	TS_101_220_IEI_GEO_LOC		= 0xDD,
	TS_101_220_IEI_ENVELOPE_CONTNR	= 0xDE,
	TS_101_220_IEI_PROSE_REPORT	= 0xDF,
};
const struct ber_tlv_desc *ss_proactive_get_cat_descr(void);

enum ss_proactive_cat_data_obj {
	/* ETSI TS 101 220 Section 7.2 */
	TS_101_220_IEI_CMD_DETAILS			= 0x01,
	TS_101_220_IEI_DEV_ID				= 0x02,
	TS_101_220_IEI_RESULT				= 0x03,
	TS_101_220_IEI_DURATION				= 0x04,
	TS_101_220_IEI_ALPHA_ID				= 0x05,
	TS_101_220_IEI_ADDR				= 0x06,
	TS_101_220_IEI_CAP_CONF				= 0x07,
	TS_101_220_IEI_SUB_ADDR				= 0x08,
	TS_101_220_IEI_SS_STR_OR_PLMN_ID		= 0x09,
	TS_101_220_IEI_USSD_STR				= 0x0A,
	TS_101_220_IEI_SMS_TPDU				= 0x0B,
	TS_101_220_IEI_CBC_PAGE				= 0x0C,
	TS_101_220_IEI_TEXT_STR				= 0x0D,
	TS_101_220_IEI_TONE_OR_ECAD_CLNT_PROF		= 0x0E,
	TS_101_220_IEI_ITEM_OR_ECAD_CLNT_ID		= 0x0F,
	TS_101_220_IEI_ITEM_ID_OR_ENVELOPE		= 0x10,
	TS_101_220_IEI_RESP_LEN_OR_CC_RESULT		= 0x11,
	TS_101_220_IEI_FILE_LST_OR_CAT_SERV_LST		= 0x12,
	TS_101_220_IEI_LOCI				= 0x13,
	TS_101_220_IEI_IMEI				= 0x14,
	TS_101_220_IEI_HLP_REQ				= 0x15,
	TS_101_220_IEI_NET_MEAS_RSLT			= 0x16,
	TS_101_220_IEI_DEFAULT_TEXT			= 0x17,
	TS_101_220_IEI_ITEMS_NEXT_ACT			= 0x18,
	TS_101_220_IEI_EVENT_LST			= 0x19,
	TS_101_220_IEI_CAUSE				= 0x1A,
	TS_101_220_IEI_LOCAT_STATUS			= 0x1B,
	TS_101_220_IEI_TRANS_ID				= 0x1C,
	TS_101_220_IEI_BCCH_CHAN_LST			= 0x1D,
	TS_101_220_IEI_ICON_ID				= 0x1E,
	TS_101_220_IEI_ICON_ID_LST			= 0x1F,
	TS_101_220_IEI_CARDRDR_STAT			= 0x20,
	TS_101_220_IEI_CARD_ATR_OR_ECAT_SEQNUM		= 0x21,
	TS_101_220_IEI_C_APDU_OR_ENC_TLV_LST		= 0x22,
	TS_101_220_IEI_R_APDU_OR_SA_TEMPLATE		= 0x23,
	TS_101_220_IEI_TIMER_ID				= 0x24,
	TS_101_220_IEI_TIMER_VALUE			= 0x25,
	TS_101_220_IEI_DATE_TIME			= 0x26,
	TS_101_220_IEI_CC_REQ_ACT			= 0x27,
	TS_101_220_IEI_AT_CMD				= 0x28,
	TS_101_220_IEI_AT_RESP				= 0x29,
	TS_101_220_IEI_BC_REPEAT			= 0x2A,
	TS_101_220_IEI_IMM_RESP				= 0x2B,
	TS_101_220_IEI_DTMF_STR				= 0x2C,
	TS_101_220_IEI_LANGUAGE				= 0x2D,
	TS_101_220_IEI_TIMING_ADV			= 0x2E,
	TS_101_220_IEI_AID				= 0x2F,
	TS_101_220_IEI_BROWSER_ID			= 0x30,
	TS_101_220_IEI_URL				= 0x31,
	TS_101_220_IEI_BEARER				= 0x32,
	TS_101_220_IEI_PROV_REF_FILE			= 0x33,
	TS_101_220_IEI_BROWSER_CAUSE			= 0x34,
	TS_101_220_IEI_BEARER_DESC			= 0x35,
	TS_101_220_IEI_CHAN_DATA			= 0x36,
	TS_101_220_IEI_CHAN_DATA_LEN			= 0x37,
	TS_101_220_IEI_CHAN_STAT			= 0x38,
	TS_101_220_IEI_CHAN_BUF_SIZE			= 0x39,
	TS_101_220_IEI_DISP_PAR_OR_DNS_ADDR		= 0x40,
	TS_101_220_IEI_SERV_REC				= 0x41,
	TS_101_220_IEI_DEV_FLTR				= 0x42,
	TS_101_220_IEI_SERV_SEARCH			= 0x43,
	TS_101_220_IEI_ATTRIB_INFO			= 0x44,
	TS_101_220_IEI_SERV_AVAIL			= 0x45,
	TS_101_220_IEI_3GPP_1				= 0x46,
	TS_101_220_IEI_NET_ACC_NAME			= 0x47,
	TS_101_220_IEI_3GPP_2				= 0x48,
	TS_101_220_IEI_REM_ENTITY_ADDR			= 0x49,
	TS_101_220_IEI_WLAN_ID				= 0x4A,
	TS_101_220_IEI_WLAN_ACC_STAT			= 0x4B,
	TS_101_220_IEI_TEXT_ATTR			= 0x50,
	TS_101_220_IEI_ITEM_TEXT_ATTR			= 0x51,
	TS_101_220_IEI_PDP_CTX_ACT			= 0x52,
	TS_101_220_IEI_CONTACTLESS_STAT			= 0x53,
	TS_101_220_IEI_CONTACTLESS_FUNCT		= 0x54,
	TS_101_220_IEI_CELL_SEL_STAT			= 0x55,
	TS_101_220_IEI_CSG_ID				= 0x56,
	TS_101_220_IEI_HNB_NAE				= 0x57,
	TS_101_220_IEI_MAC				= 0x60,
	TS_101_220_IEI_3GPP_3				= 0x61,
	TS_101_220_IEI_IMEISV				= 0x62,
	TS_101_220_IEI_BATTERY_STAT			= 0x63,
	TS_101_220_IEI_BROWSER_STAT			= 0x64,
	TS_101_220_IEI_NET_SEARCH_MODE			= 0x65,
	TS_101_220_IEI_FRAME_LAYOUT			= 0x66,
	TS_101_220_IEI_FRAMES_INFO			= 0x67,
	TS_101_220_IEI_FRAME_ID				= 0x68,
	TS_101_220_IEI_MEAS_QUALIF			= 0x69,
	TS_101_220_IEI_MMS_REF				= 0x6A,
	TS_101_220_IEI_MMS_ID				= 0x6B,
	TS_101_220_IEI_MMS_TRANS_STAT			= 0x6C,
	TS_101_220_IEI_3GPP_4				= 0x6D,
	TS_101_220_IEI_MMS_CONTENT_ID			= 0x6E,
	TS_101_220_IEI_MMS_NOTIF			= 0x6F,
	TS_101_220_IEI_LAST_ENVELOPE			= 0x70,
	TS_101_220_IEI_REG_APP				= 0x71,
	TS_101_220_IEI_PLMNwAcT_LST			= 0x72,
	TS_101_220_IEI_RA_INFO				= 0x73,
	TS_101_220_IEI_UPD_ATT_TYPE_OR_PROSE_REP	= 0x74,
	TS_101_220_IEI_REJECTION_CAUSE			= 0x75,
	TS_101_220_IEI_GEO_LOC_OR_IARI			= 0x76,
	TS_101_220_IEI_NEMA_SENTENCE_OR_IMS_STAT	= 0x78,
	TS_101_220_IEI_PLMN_LST_OR_EUTRAN_MEAS		= 0x79,
	TS_101_220_IEI_BCAST_NET_INFO_OR_EXT_REG	= 0x7A,
	TS_101_220_IEI_ACTIVATE_DESC			= 0x7B,
	TS_101_220_IEI_EPS_PDN_CONN			= 0x7C,
	TS_101_220_IEI_TAI				= 0x7D,
	TS_101_220_IEI_CSG_ID_LST			= 0x7E,
};

enum ss_proactive_type_of_cmd {
	TS_102_223_TOC_REFRESH				= 0x01,
	TS_102_223_TOC_MORE_TIME			= 0x02,
	TS_102_223_TOC_POLL_INTERVAL			= 0x03,
	TS_102_223_TOC_POLLING_OFF			= 0x04,
	TS_102_223_TOC_SET_UP_EVENT_LIST		= 0x05,
	TS_102_223_TOC_SET_UP_CALL			= 0x10,
	TS_102_223_TOC_SEND_SS				= 0x11,
	TS_102_223_TOC_SEND_USSD			= 0x12,
	TS_102_223_TOC_SEND_SHORT_MESSAGE		= 0x13,
	TS_102_223_TOC_SEND_DTMF			= 0x14,
	TS_102_223_TOC_LAUNCH_BROWSER			= 0x15,
	TS_102_223_TOC_GEOGRAPHICAL_LOCATION_REQUEST	= 0x16,
	TS_102_223_TOC_PLAY_TONE			= 0x20,
	TS_102_223_TOC_DISPLAY_TEXT			= 0x21,
	TS_102_223_TOC_GET_INKEY			= 0x22,
	TS_102_223_TOC_GET_INPUT			= 0x23,
	TS_102_223_TOC_SELECT_ITEM			= 0x24,
	TS_102_223_TOC_SET_UP_MENU			= 0x25,
	TS_102_223_TOC_PROVIDE_LOCAL_INFORMATION	= 0x26,
	TS_102_223_TOC_TIMER_MANAGEMENT			= 0x27,
	TS_102_223_TOC_SET_UP_IDLE_MODE_TEXT		= 0x28,
	TS_102_223_TOC_PERFORM_CARD_APDU		= 0x30,
	TS_102_223_TOC_POWER_ON_CARD			= 0x31,
	TS_102_223_TOC_POWER_OFF_CARD			= 0x32,
	TS_102_223_TOC_GET_READER_STATUS		= 0x33,
	TS_102_223_TOC_RUN_AT_COMMAND			= 0x34,
	TS_102_223_TOC_LANGUAGE_NOTIFICATION		= 0x35,
	TS_102_223_TOC_OPEN_CHANNEL			= 0x40,
	TS_102_223_TOC_CLOSE_CHANNEL			= 0x41,
	TS_102_223_TOC_RECEIVE_DATA			= 0x42,
	TS_102_223_TOC_SEND_DATA			= 0x43,
	TS_102_223_TOC_GET_CHANNEL_STATUS		= 0x44,
	TS_102_223_TOC_SERVICE_SEARCH			= 0x45,
	TS_102_223_TOC_GET_SERVICE_INFORMATION		= 0x46,
	TS_102_223_TOC_DECLARE_SERVICE			= 0x47,
	TS_102_223_TOC_SET_FRAMES			= 0x50,
	TS_102_223_TOC_GET_FRAMES_STATUS		= 0x51,
	TS_102_223_TOC_RETRIEVE_MULTIMEDIA_MESSAGE	= 0x60,
	TS_102_223_TOC_SUBMIT_MULTIMEDIA_MESSAGE	= 0x61,
	TS_102_223_TOC_DISPLAY_MULTIMEDIA_MESSAGE	= 0x62,
	TS_102_223_TOC_ACTIVATE				= 0x70,
	TS_102_223_TOC_CONTACTLESS_STATE_CHANGED	= 0x71,
	TS_102_223_TOC_COMMAND_CONTAINER		= 0x72,
	TS_102_223_TOC_ENCAPSULATED_SESSION_CONTROL	= 0x73,
	TS_102_223_TOC_END_OF_PROACT_UICC_SESSION	= 0x73,
};

/*! handler for proactive SIM tasks */
struct ss_proactive_task {
	/*! human readable name that describes the proactive task. */
	const char *name;
	/*! CLA and MASK against which to compare CLA from APDU header */
	void (*handler)(struct ss_context * ctx);
};

/*! global context for proactive SIM tasks */
struct ss_proactive_ctx {
	/*! proactive SIM enabled (true after TERMINAL PROFILE command is received) */
	bool enabled;
	/*! TERMINAL PROFILE data */
	uint8_t term_profile[256];
	/*! data to be fetched by FETCH command */
	uint8_t data[256];
	/*! length of data to be fetched by FETCH command */
	uint8_t data_len;
	/*! callback to hanle data from TERMINAL RESPONSE command */
	term_resp_cb term_resp_cb;
	/*! counter to count the poll cycles until a TERMINAL RESPONSE arrives */
	unsigned int term_resp_poll_ctr;
	/*! state to handle the reception of short messages (SMS) */
	struct ss_uicc_sms_rx_state sms_rx_state;
	/*! state to handle the sending of short messages (SMS) */
	struct ss_uicc_sms_tx_state sms_tx_state;
	/*! state to handle the sending of refresh information (file chnages) */
	struct ss_uicc_refresh_state refresh_state;
};

void ss_proactive_poll(struct ss_context *ctx);
bool ss_proactive_rts(const struct ss_context *ctx);
int ss_proactive_put(struct ss_context *ctx, term_resp_cb term_resp_cb,
		     const uint8_t *data, size_t len);
void ss_proactive_reset(struct ss_context *ctx);
int ss_proactive_get_rc(const uint8_t *resp_data, uint8_t resp_data_len,
			enum log_subsys log_subsys);
bool ss_proactive_term_prof_bit(const struct ss_context *ctx, size_t byte_idx,
				uint8_t bit_idx);
