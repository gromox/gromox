// SPDX-License-Identifier: AGPL-3.0-or-later, OR GPL-2.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2020 grommunio GmbH
// This file is part of Gromox.
#include <gromox/defs.h>
#include <gromox/exmdb_common_util.hpp>
#include <gromox/exmdb_rpc.hpp>

using namespace gromox;

#define E(s) #s
static constexpr const char *exmdb_rpc_names[] = {
	E(CONNECT),
	E(LISTEN_NOTIFICATION),
	E(PING_STORE),
	E(GET_ALL_NAMED_PROPIDS),
	E(GET_NAMED_PROPIDS),
	E(GET_NAMED_PROPNAMES),
	E(GET_MAPPING_GUID),
	E(GET_MAPPING_REPLID),
	E(GET_STORE_ALL_PROPTAGS),
	E(GET_STORE_PROPERTIES),
	E(SET_STORE_PROPERTIES),
	E(REMOVE_STORE_PROPERTIES),
	E(GET_MBOX_PERM),
	"GET_FOLDER_BY_CLASS_V1",
	E(SET_FOLDER_BY_CLASS),
	E(GET_FOLDER_CLASS_TABLE),
	E(CHECK_FOLDER_ID),
	E(QUERY_FOLDER_MESSAGES),
	E(CHECK_FOLDER_DELETED),
	E(GET_FOLDER_BY_NAME),
	E(CHECK_FOLDER_PERMISSION),
	E(CREATE_FOLDER_BY_PROPERTIES),
	E(GET_FOLDER_ALL_PROPTAGS),
	E(GET_FOLDER_PROPERTIES),
	E(SET_FOLDER_PROPERTIES),
	E(REMOVE_FOLDER_PROPERTIES),
	E(DELETE_FOLDER),
	"EMPTY_FOLDER_V1",
	E(CHECK_FOLDER_CYCLE),
	E(COPY_FOLDER_INTERNAL),
	E(GET_SEARCH_CRITERIA),
	E(SET_SEARCH_CRITERIA),
	E(MOVECOPY_MESSAGE),
	E(MOVECOPY_MESSAGES),
	E(MOVECOPY_FOLDER),
	E(DELETE_MESSAGES),
	E(GET_MESSAGE_BRIEF),
	E(SUM_HIERARCHY),
	E(LOAD_HIERARCHY_TABLE),
	E(SUM_CONTENT),
	E(LOAD_CONTENT_TABLE),
	E(LOAD_PERM_TABLE_V1),
	E(LOAD_RULE_TABLE),
	E(UNLOAD_TABLE),
	E(SUM_TABLE),
	E(QUERY_TABLE),
	E(MATCH_TABLE),
	E(LOCATE_TABLE),
	E(READ_TABLE_ROW),
	E(MARK_TABLE),
	E(GET_TABLE_ALL_PROPTAGS),
	E(EXPAND_TABLE),
	E(COLLAPSE_TABLE),
	E(STORE_TABLE_STATE),
	E(RESTORE_TABLE_STATE),
	E(CHECK_MESSAGE),
	E(CHECK_MESSAGE_DELETED),
	E(LOAD_MESSAGE_INSTANCE),
	E(LOAD_EMBEDDED_INSTANCE),
	E(GET_EMBEDDED_CN),
	E(RELOAD_MESSAGE_INSTANCE),
	E(CLEAR_MESSAGE_INSTANCE),
	E(READ_MESSAGE_INSTANCE),
	"WRITE_MESSAGE_INSTANCE_V1",
	E(LOAD_ATTACHMENT_INSTANCE),
	E(CREATE_ATTACHMENT_INSTANCE),
	E(READ_ATTACHMENT_INSTANCE),
	E(WRITE_ATTACHMENT_INSTANCE),
	E(DELETE_MESSAGE_INSTANCE_ATTACHMENT),
	"FLUSH_INSTANCE_V1",
	E(UNLOAD_INSTANCE),
	E(GET_INSTANCE_ALL_PROPTAGS),
	E(GET_INSTANCE_PROPERTIES),
	E(SET_INSTANCE_PROPERTIES),
	E(REMOVE_INSTANCE_PROPERTIES),
	E(CHECK_INSTANCE_CYCLE),
	E(EMPTY_MESSAGE_INSTANCE_RCPTS),
	E(GET_MESSAGE_INSTANCE_RCPTS_NUM),
	E(GET_MESSAGE_INSTANCE_RCPTS_ALL_PROPTAGS),
	E(GET_MESSAGE_INSTANCE_RCPTS),
	E(UPDATE_MESSAGE_INSTANCE_RCPTS),
	E(EMPTY_MESSAGE_INSTANCE_ATTACHMENTS),
	E(GET_MESSAGE_INSTANCE_ATTACHMENTS_NUM),
	E(GET_MESSAGE_INSTANCE_ATTACHMENT_TABLE_ALL_PROPTAGS),
	E(QUERY_MESSAGE_INSTANCE_ATTACHMENT_TABLE),
	E(SET_MESSAGE_INSTANCE_CONFLICT),
	E(GET_MESSAGE_RCPTS),
	E(GET_MESSAGE_PROPERTIES),
	E(SET_MESSAGE_PROPERTIES),
	E(SET_MESSAGE_READ_STATE),
	E(REMOVE_MESSAGE_PROPERTIES),
	E(ALLOCATE_MESSAGE_ID),
	E(ALLOCATE_CN),
	E(MARK_MODIFIED),
	E(GET_MESSAGE_GROUP_ID),
	E(SET_MESSAGE_GROUP_ID),
	E(SAVE_CHANGE_INDICES),
	E(GET_CHANGE_INDICES),
	E(TRY_MARK_SUBMIT),
	E(CLEAR_SUBMIT),
	E(LINK_MESSAGE),
	E(UNLINK_MESSAGE),
	E(RULE_NEW_MESSAGE),
	E(SET_MESSAGE_TIMER),
	E(GET_MESSAGE_TIMER),
	E(EMPTY_FOLDER_PERMISSION),
	E(UPDATE_FOLDER_PERMISSION),
	E(EMPTY_FOLDER_RULE),
	E(UPDATE_FOLDER_RULE),
	"DELIVER_MESSAGE_V1",
	E(WRITE_MESSAGE),
	E(READ_MESSAGE),
	E(GET_CONTENT_SYNC),
	E(GET_HIERARCHY_SYNC),
	E(ALLOCATE_IDS),
	E(SUBSCRIBE_NOTIFICATION),
	E(UNSUBSCRIBE_NOTIFICATION),
	E(TRANSPORT_NEW_MAIL),
	E(RELOAD_CONTENT_TABLE),
	E(COPY_INSTANCE_RCPTS),
	E(COPY_INSTANCE_ATTACHMENTS),
	E(CHECK_CONTACT_ADDRESS),
	E(GET_PUBLIC_FOLDER_UNREAD_COUNT),
	E(VACUUM),
	E(GET_FOLDER_BY_CLASS),
	E(LOAD_PERMISSION_TABLE),
	E(WRITE_MESSAGE_INSTANCE),
	E(FLUSH_INSTANCE),
	E(UNLOAD_STORE),
	E(DELIVER_MESSAGE),
	E(NOTIFY_NEW_MAIL),
	E(STORE_EID_TO_USER),
	E(EMPTY_FOLDER),
	E(PURGE_SOFTDELETE),
	E(PURGE_DATAFILES),
};
#undef E

const char *exmdb_rpc_idtoname(exmdb_callid i)
{
	auto j = static_cast<uint8_t>(i);
	static_assert(std::size(exmdb_rpc_names) == static_cast<uint8_t>(exmdb_callid::purge_datafiles) + 1);
	const char *s = j < arsizeof(exmdb_rpc_names) ? exmdb_rpc_names[j] : nullptr;
	return znul(s);
}
