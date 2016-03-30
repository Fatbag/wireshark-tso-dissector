/*
** Authors: Fatbag
** License: Public domain (no warranties)
** Compile: gcc -Wall -ansi -pedantic -Os -g0 -s -shared -fPIC
**	$(pkg-config --cflags wireshark) -o wireshark-tso-dissector.so
**	wireshark-tso-dissector.c $(pkg-config --libs wireshark)
** Install: cp -v wireshark-tso-dissector.so ~/.wireshark/plugins
**
** Usage:
** 1.	After installing the plugin, open Wireshark and go to
**	Edit -> Preferences -> Protocols -> SSL.
** 2.	Edit the RSA Keys list and add the following row:
**	IP address:	<Server IP address, e.g. 127.0.0.1>
**	Port:		49100
**	Protocol:	aries
**	Key file:	<Path to the server's key.pem file>
** 3.	Click OK to everything.
*/
#include <stdio.h>
#include <gmodule.h>
#include <wireshark/config.h>
#include <wireshark/epan/packet.h>
#include <wireshark/epan/dissectors/packet-tcp.h>
#include <wireshark/epan/dissectors/packet-ssl.h>

/* Symbols exported by this library */
G_MODULE_EXPORT const gchar version[] = "0";
G_MODULE_EXPORT void plugin_register(void);
G_MODULE_EXPORT void plugin_reg_handoff(void);

/* Aries protocol handles */
static dissector_handle_t aries_handle = NULL;
static int proto_aries = -1;
static int hf_aries_pdu_type = -1;
static int hf_aries_timestamp = -1;
static int hf_aries_length = -1;
static int hf_aries_sessionresponse_user = -1;
static int hf_aries_sessionresponse_version = -1;
static int hf_aries_sessionresponse_email = -1;
static int hf_aries_sessionresponse_authserv = -1;
static int hf_aries_sessionresponse_product = -1;
static int hf_aries_sessionresponse_unknown1 = -1;
static int hf_aries_sessionresponse_serviceident = -1;
static int hf_aries_sessionresponse_unknown2 = -1;
static int hf_aries_sessionresponse_password = -1;
static gint ett_aries = -1;

/* TSO protocol handles */
static dissector_handle_t tso_handle = NULL;
static int proto_tso = -1;
static int hf_tso_pdu_type = -1;
static int hf_tso_pdu_size = -1;
static int hf_tso_hostonlinepdu_num_reserved_words = -1;
static int hf_tso_hostonlinepdu_host_ver = -1;
static int hf_tso_hostonlinepdu_client_buf_size = -1;
static gint ett_tso = -1;
static gint ett_tso_hostonlinepdu_words = -1;

static const value_string aries_types[] = {
	{0, "Data"},
	{1, "Disconnect"},
	{3, "Reconnect"},
	{21, "SessionResponse"},
	{22, "SessionRequest"},
	{26, "LastError"},
	{27, "Ping"},
	{28, "TimingTest"},
	{29, "TimingTestResults"},
	{31, "RelogonStart"},
	{44, "RelogonComplete"},
	{0, NULL}
};

static hf_register_info hf_aries[] = {
	{
		&hf_aries_pdu_type,
		{
			"PDU Type", "aries.type",
			FT_UINT32, BASE_DEC,
			VALS(aries_types), 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_aries_timestamp,
		{
			"Timestamp", "aries.timestamp",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_aries_length,
		{
			"Length", "aries.length",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_aries_sessionresponse_user,
		{
			"User", "aries.user",
			FT_STRINGZ, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_aries_sessionresponse_version,
		{
			"AriesClient Version", "aries.version",
			FT_STRINGZ, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_aries_sessionresponse_email,
		{
			"Email", "aries.email",
			FT_STRINGZ, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_aries_sessionresponse_authserv,
		{
			"Authserv", "aries.authserv",
			FT_STRINGZ, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_aries_sessionresponse_product,
		{
			"Product", "aries.product",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_aries_sessionresponse_unknown1,
		{
			"Unknown1", "aries.unknown1",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_aries_sessionresponse_serviceident,
		{
			"ServiceIdent", "aries.serviceident",
			FT_STRINGZ, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_aries_sessionresponse_unknown2,
		{
			"Unknown2", "aries.unknown2",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_aries_sessionresponse_password,
		{
			"Password", "aries.password",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL
		}
	}
};

static gint *ett_list_aries[] = {
	&ett_aries,
};

static const value_string tso_types[] = {
	{0x0001, "AlertHandledPDU"},
	{0x0002, "AlertMsgPDU"},
	{0x0003, "AlertMsgResponsePDU"},
	{0x0004, "AnnouncementMsgResponsePDU"},
	{0x0005, "AnnouncementMsgPDU"},
	{0x0006, "ClientByePDU"},
	{0x0007, "ServerByePDU"},
	{0x0008, "ChatMsgFailedPDU"},
	{0x0009, "ChatMsgPDU"},
	{0x000a, "ClientOnlinePDU"},
	{0x000b, "CreateAndJoinRoomFailedPDU"},
	{0x000c, "CreateAndJoinRoomPDU"},
	{0x000d, "CreateRoomPDU"},
	{0x000e, "CreateRoomResponsePDU"},
	{0x000f, "DestroyRoomPDU"},
	{0x0010, "DestroyRoomResponsePDU"},
	{0x0011, "DetachFromRoomFailedPDU"},
	{0x0012, "DetachFromRoomPDU"},
	{0x0013, "EjectOccupantPDU"},
	{0x0014, "EjectOccupantResponsePDU"},
	{0x0015, "ErrorPDU"},
	{0x0016, "ExitRoomFailedPDU"},
	{0x0017, "ExitRoomPDU"},
	{0x0018, "FindPlayerPDU"},
	{0x0019, "FindPlayerResponsePDU"},
	{0x001a, "FlashMsgResponsePDU"},
	{0x001b, "FlashMsgPDU"},
	{0x001c, "HandleAlertPDU"},
	{0x001d, "HostOfflinePDU"},
	{0x001e, "HostOnlinePDU"},
	{0x001f, "InvitationMsgResponsePDU"},
	{0x0020, "InvitationMsgPDU"},
	{0x0021, "JoinPlayerFailedPDU"},
	{0x0022, "JoinPlayerPDU"},
	{0x0023, "JoinRoomFailedPDU"},
	{0x0024, "JoinRoomPDU"},
	{0x0025, "ListOccupantsPDU"},
	{0x0026, "ListOccupantsResponsePDU"},
	{0x0027, "ListRoomsPDU"},
	{0x0028, "ListRoomsResponsePDU"},
	{0x0029, "LogEventPDU"},
	{0x002a, "LogEventResponsePDU"},
	{0x002b, "MessageLostPDU"},
	{0x002c, "OccupantArrivedPDU"},
	{0x002d, "OccupantDepartedPDU"},
	{0x002e, "ReadProfilePDU"},
	{0x002f, "ReadProfileResponsePDU"},
	{0x0030, "ReleaseProfilePDU"},
	{0x0031, "ReleaseProfileResponsePDU"},
	{0x0032, "SetAcceptAlertsPDU"},
	{0x0033, "SetAcceptAlertsResponsePDU"},
	{0x0034, "SetIgnoreListPDU"},
	{0x0035, "SetIgnoreListResponsePDU"},
	{0x0036, "SetInvinciblePDU"},
	{0x0037, "SetInvincibleResponsePDU"},
	{0x0038, "SetInvisiblePDU"},
	{0x0039, "SetInvisibleResponsePDU"},
	{0x003a, "SetRoomNamePDU"},
	{0x003b, "SetRoomNameResponsePDU"},
	{0x003c, "UpdateOccupantsPDU"},
	{0x003d, "UpdatePlayerPDU"},
	{0x003e, "UpdateProfilePDU"},
	{0x003f, "UpdateRoomPDU"},
	{0x0040, "YankPlayerFailedPDU"},
	{0x0041, "YankPlayerPDU"},
	{0x0042, "SetAcceptFlashesPDU"},
	{0x0043, "SetAcceptFlashesResponsePDU"},
	{0x0044, "SplitBufferPDU"},
	{0x0045, "ActionRoomNamePDU"},
	{0x0046, "ActionRoomNameResponsePDU"},
	{0x0047, "NotifyRoomActionedPDU"},
	{0x0048, "ModifyProfilePDU"},
	{0x0049, "ModifyProfileResponsePDU"},
	{0x004a, "ListBBSFoldersPDU"},
	{0x004b, "ListBBSFoldersResponsePDU"},
	{0x004c, "GetBBSMessageListPDU"},
	{0x004d, "GetBBSMessageListResponsePDU"},
	{0x004e, "PostBBSMessagePDU"},
	{0x004f, "PostBBSReplyPDU"},
	{0x0050, "PostBBSMessageResponsePDU"},
	{0x0051, "GetMPSMessagesPDU"},
	{0x0052, "GetMPSMessagesResponsePDU"},
	{0x0053, "DeleteMPSMessagePDU"},
	{0x0054, "DeleteMPSMessageResponsePDU"},
	{0x0055, "BBSMessageDataPDU"},
	{0x0056, "UpdateRoomAdminListPDU"},
	{0x0057, "GetRoomAdminListPDU"},
	{0x0058, "GetRoomAdminListResponsePDU"},
	{0x0059, "GroupInfoRequestPDU"},
	{0x005a, "GroupInfoResponsePDU"},
	{0x005b, "GroupAdminRequestPDU"},
	{0x005c, "GroupAdminResponsePDU"},
	{0x005d, "GroupMembershipRequestPDU"},
	{0x005e, "GroupMembershipResponsePDU"},
	{0x005f, "FlashGroupPDU"},
	{0x0060, "FlashGroupResponsePDU"},
	{0x0061, "UpdateGroupMemberPDU"},
	{0x0062, "UpdateGroupMemberResponsePDU"},
	{0x0063, "UpdateGroupAdminPDU"},
	{0x0064, "UpdateGroupAdminResponsePDU"},
	{0x0065, "ListGroupsPDU"},
	{0x0066, "ListGroupsResponsePDU"},
	{0x0067, "ListJoinedGroupsPDU"},
	{0x0068, "ListJoinedGroupsResponsePDU"},
	{0x0069, "GpsChatPDU"},
	{0x006a, "GpsChatResponsePDU"},
	{0x006b, "PetitionStatusUpdatePDU"},
	{0x006c, "LogGPSPetitionPDU"},
	{0x006d, "LogGPSPetitionResponsePDU"},
	{0x006e, "List20RoomsPDU"},
	{0x006f, "List20RoomsResponsePDU"},
	{0x0070, "UpdateIgnoreListPDU"},
	{0x0071, "ResetWatchdogPDU"},
	{0x0072, "ResetWatchdogResponsePDU"},
	{0x2710, "BroadcastDataBlobPDU"},
	{0x2711, "TransmitDataBlobPDU"},
	{0x2712, "DBRequestWrapperPDU"},
	{0x2713, "TransmitCreateAvatarNotificationPDU"},
	{0x2715, "BC_PlayerLoginEventPDU"},
	{0x2716, "BC_PlayerLogoutEventPDU"},
	{0x2718, "RoomserverUserlistPDU"},
	{0x2719, "LotEntryRequestPDU"},
	{0x271a, "ClientConfigPDU"},
	{0x271c, "KickoutRoommatePDU"},
	{0x271d, "GenericFlashPDU"},
	{0x271e, "GenericFlashRequestPDU"},
	{0x271f, "GenericFlashResponsePDU"},
	{0x2722, "TransmitGenericGDMPDU"},
	{0x2723, "EjectAvatarPDU"},
	{0x2724, "TestPDU"},
	{0x2725, "HouseSimConstraintsPDU"},
	{0x2726, "HouseSimConstraintsResponsePDU"},
	{0x2728, "LoadHouseResponsePDU"},
	{0x2729, "ComponentVersionRequestPDU"},
	{0x272a, "ComponentVersionResponsePDU"},
	{0x272b, "InviteRoommatePDU"},
	{0x272c, "RoommateInvitationAnswerPDU"},
	{0x272d, "RoommateGDMPDU"},
	{0x272e, "HSB_ShutdownSimulatorPDU"},
	{0x272f, "RoommateGDMResponsePDU"},
	{0x2730, "RSGZWrapperPDU"},
	{0x2731, "AvatarHasNewLotIDPDU"},
	{0x2733, "CheatPDU"},
	{0x2734, "DataServiceWrapperPDU"},
	{0x2735, "CsrEjectAvatarPDU"},
	{0x2736, "CsrEjectAvatarResponsePDU"},
	{0x2737, "cTSONetMessagePDU"},
	{0x2738, "LogCsrActionPDU"},
	{0x2739, "LogAvatarActionPDU"},
	{0, NULL}
};

static hf_register_info hf_tso[] = {
	{
		&hf_tso_pdu_type,
		{
			"PDU Type", "tso.type",
			FT_UINT16, BASE_DEC,
			VALS(tso_types), 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_tso_pdu_size,
		{
			"PDU Size", "tso.size",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_tso_hostonlinepdu_num_reserved_words,
		{
			"Num Reserved Words", "tso.num_reserved_words",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_tso_hostonlinepdu_host_ver,
		{
			"Host Version", "tso.host_ver",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_tso_hostonlinepdu_client_buf_size,
		{
			"Client Buffer Size", "tso.client_buf_size",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL
		}
	},
};

static gint *ett_list_tso[] = {
	&ett_tso,
	&ett_tso_hostonlinepdu_words
};

static void tso_dissect_hostonlinepdu(proto_tree *tree, tvbuff_t *tvb)
{
	unsigned i;
	unsigned offset = 6;
	guint16 words_count;

	words_count = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_tso_hostonlinepdu_num_reserved_words, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	if (words_count > 0) {
		proto_item *words_item = proto_tree_add_text(tree, tvb, 8, 0, "Reserved Words");
		proto_tree *words_tree = proto_item_add_subtree(words_item, ett_tso_hostonlinepdu_words);

		for (i = 0; i < words_count; i++) {
			guint32 length;
			char *buffer;

			length = tvb_get_ntohl(tvb, offset) ^ 0x80000000;
			DISSECTOR_ASSERT(length <= tvb_length(tvb) - offset);

			buffer = wmem_alloc(wmem_packet_scope(), length+1);
			tvb_memcpy(tvb, buffer, offset+4, length);
			buffer[length] = '\0';
			proto_tree_add_text(words_tree, tvb, offset, 4+length, buffer);

			offset += 4 + length;
		}

		proto_item_set_len(words_tree, offset - 8);
	}

	proto_tree_add_item(tree, hf_tso_hostonlinepdu_host_ver, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_tso_hostonlinepdu_client_buf_size, tvb, offset, 2, ENC_BIG_ENDIAN);
}

static int dissect_tso_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	void *data)
{
	guint16 pdu_type = tvb_get_ntohs(tvb, 0);
	const char *pdu_name = val_to_str_const(pdu_type, tso_types, "UnknownPDU");

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "TSO");
	col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, pdu_name);

	if (tree) { /* we are being asked for details */
		proto_item *ti = NULL;
		proto_tree *tso_tree = NULL;

		ti = proto_tree_add_protocol_format(tree, proto_tso, tvb, 0, -1,
			"The Sims Online: %s (%u)", pdu_name, pdu_type);
		tso_tree = proto_item_add_subtree(ti, ett_tso);

		proto_tree_add_item(tso_tree, hf_tso_pdu_type, tvb, 0, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tso_tree, hf_tso_pdu_size, tvb, 2, 4, ENC_BIG_ENDIAN);

		if (pdu_type == 30)
			tso_dissect_hostonlinepdu(tso_tree, tvb);
	}

	return tvb_length(tvb);
}

static guint get_tso_message_len(packet_info *pinfo, tvbuff_t *tvb,
	int offset)
{
	return tvb_get_ntohl(tvb, offset+2);
}

static int dissect_tso(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	void *data)
{
	tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 6,
		get_tso_message_len, dissect_tso_message, data);

	return tvb_captured_length(tvb);
}

static void aries_dissect_sessionresponse(proto_tree *tree, tvbuff_t *tvb)
{
	unsigned password_len;

	DISSECTOR_ASSERT(tvb_length(tvb) >= 343);
	password_len = tvb_length(tvb) - 343;

	proto_tree_add_item(tree, hf_aries_sessionresponse_user, tvb, 12, 112, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_aries_sessionresponse_version, tvb, 124, 80, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_aries_sessionresponse_email, tvb, 204, 40, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_aries_sessionresponse_authserv, tvb, 244, 84, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_aries_sessionresponse_product, tvb, 328, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_aries_sessionresponse_unknown1, tvb, 330, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_aries_sessionresponse_serviceident, tvb, 331, 3, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_aries_sessionresponse_unknown2, tvb, 334, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_aries_sessionresponse_password, tvb, 336, password_len, ENC_LITTLE_ENDIAN);
}

static int dissect_aries_message(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, void *data)
{
	guint32 pdu_type = tvb_get_letohl(tvb, 0);
	guint32 pdu_length = tvb_get_letohl(tvb, 8);
	const char *pdu_name = val_to_str_const(pdu_type, aries_types, "Unknown");

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ARIES");
	col_add_fstr(pinfo->cinfo, COL_INFO, "Type=%s Len=%u", pdu_name, pdu_length);

	if (tree) {
		proto_item *ti = NULL;
		proto_tree *aries_tree = NULL;

		ti = proto_tree_add_item(tree, proto_aries, tvb, 0, 12, ENC_NA);
		aries_tree = proto_item_add_subtree(ti, ett_aries);
		proto_tree_add_item(aries_tree, hf_aries_pdu_type, tvb, 0, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(aries_tree, hf_aries_timestamp, tvb, 4, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(aries_tree, hf_aries_length, tvb, 8, 4, ENC_LITTLE_ENDIAN);

		if (pdu_type == 0)
			call_dissector(tso_handle,
				tvb_new_subset_remaining(tvb, 12),
				pinfo, tree);
		else if (pdu_type == 21)
			aries_dissect_sessionresponse(aries_tree, tvb);
	}

	return tvb_length(tvb);
}

static guint get_aries_message_len(packet_info *pinfo, tvbuff_t *tvb,
	int offset)
{
	return 12 + tvb_get_letohl(tvb, offset+8);
}

static int dissect_aries(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	void *data)
{
	tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 12,
		get_aries_message_len, dissect_aries_message, data);

	return tvb_captured_length(tvb);
}

void plugin_register(void)
{
	proto_aries = proto_register_protocol("Kesmai Aries", "ARIES", "aries");
	proto_register_field_array(proto_aries, hf_aries, array_length(hf_aries));
	proto_register_subtree_array(ett_list_aries, array_length(ett_list_aries));

	proto_tso = proto_register_protocol("The Sims Online", "TSO", "tso");
	proto_register_field_array(proto_tso, hf_tso, array_length(hf_tso));
	proto_register_subtree_array(ett_list_tso, array_length(ett_list_tso));
}

void plugin_reg_handoff(void)
{
	aries_handle = new_register_dissector("aries", dissect_aries, proto_aries);
	ssl_dissector_add(49100, "aries", TRUE);

	tso_handle = new_register_dissector("tso", dissect_tso, proto_tso);
}
