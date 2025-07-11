// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 grommunio GmbH
// This file is part of Gromox.
#include <gromox/defs.h>
#include <gromox/exmdb_common_util.hpp>
#include <gromox/exmdb_rpc.hpp>

using namespace gromox;

#define E(s) #s
static constexpr const char *exmdb_rpc_names[] = {
	E(connect),
	E(listen_notification),
	E(ping_store),
	E(get_all_named_propids),
	E(get_named_propids),
	E(get_named_propnames),
	E(get_mapping_guid),
	"get_mapping_replid_v1",
	E(get_store_all_proptags),
	E(get_store_properties),
	E(set_store_properties),
	E(remove_store_properties),
	E(get_mbox_perm),
	"get_folder_by_class_v1",
	E(set_folder_by_class),
	E(get_folder_class_table),
	E(check_folder_id),
	E(query_folder_messages),
	E(check_folder_deleted),
	E(get_folder_by_name),
	E(check_folder_permission),
	E(create_folder_by_properties),
	E(get_folder_all_proptags),
	E(get_folder_properties),
	E(set_folder_properties),
	E(remove_folder_properties),
	E(delete_folder),
	"empty_folder_v1",
	E(check_folder_cycle),
	E(copy_folder_internal),
	E(get_search_criteria),
	E(set_search_criteria),
	E(movecopy_message),
	E(movecopy_messages),
	"movecopy_folder_v1",
	E(delete_messages),
	E(get_message_brief),
	E(sum_hierarchy),
	E(load_hierarchy_table),
	E(sum_content),
	E(load_content_table),
	E(load_perm_table_v1),
	E(load_rule_table),
	E(unload_table),
	E(sum_table),
	E(query_table),
	E(match_table),
	E(locate_table),
	E(read_table_row),
	E(mark_table),
	E(get_table_all_proptags),
	E(expand_table),
	E(collapse_table),
	E(store_table_state),
	E(restore_table_state),
	E(check_message),
	E(check_message_deleted),
	E(load_message_instance),
	E(load_embedded_instance),
	E(get_embedded_cn),
	E(reload_message_instance),
	E(clear_message_instance),
	E(read_message_instance),
	"write_message_instance_v1",
	E(load_attachment_instance),
	E(create_attachment_instance),
	E(read_attachment_instance),
	E(write_attachment_instance),
	E(delete_message_instance_attachment),
	"flush_instance_v1",
	E(unload_instance),
	E(get_instance_all_proptags),
	E(get_instance_properties),
	E(set_instance_properties),
	E(remove_instance_properties),
	E(check_instance_cycle),
	E(empty_message_instance_rcpts),
	E(get_message_instance_rcpts_num),
	E(get_message_instance_rcpts_all_proptags),
	E(get_message_instance_rcpts),
	E(update_message_instance_rcpts),
	E(empty_message_instance_attachments),
	E(get_message_instance_attachments_num),
	E(get_message_instance_attachment_table_all_proptags),
	E(query_message_instance_attachment_table),
	E(set_message_instance_conflict),
	E(get_message_rcpts),
	E(get_message_properties),
	E(set_message_properties),
	E(set_message_read_state),
	E(remove_message_properties),
	E(allocate_message_id),
	E(allocate_cn),
	E(mark_modified),
	E(get_message_group_id),
	E(set_message_group_id),
	E(save_change_indices),
	E(get_change_indices),
	E(try_mark_submit),
	E(clear_submit),
	E(link_message),
	E(unlink_message),
	E(rule_new_message),
	E(set_message_timer),
	E(get_message_timer),
	E(empty_folder_permission),
	E(update_folder_permission),
	E(empty_folder_rule),
	E(update_folder_rule),
	"deliver_message_v1",
	E(write_message),
	E(read_message),
	E(get_content_sync),
	E(get_hierarchy_sync),
	E(allocate_ids),
	E(subscribe_notification),
	E(unsubscribe_notification),
	E(transport_new_mail),
	E(reload_content_table),
	E(copy_instance_rcpts),
	E(copy_instance_attachments),
	E(check_contact_address),
	E(get_public_folder_unread_count),
	E(vacuum),
	E(get_folder_by_class),
	E(load_permission_table),
	E(write_message_instance),
	E(flush_instance),
	E(unload_store),
	E(deliver_message),
	E(notify_new_mail),
	E(store_eid_to_user),
	E(empty_folder),
	E(purge_softdelete),
	E(purge_datafiles),
	E(autoreply_tsquery),
	E(autoreply_tsupdate),
	E(get_mapping_replid),
	E(recalc_store_size),
	E(movecopy_folder),
	E(create_folder),
	E(write_message_v2),
	E(imapfile_read),
	E(imapfile_write),
	E(imapfile_delete),
	E(cgkreset),
};
#undef E

namespace exmdb {

const char *exmdb_rpc_idtoname(exmdb_callid i)
{
	auto j = static_cast<uint8_t>(i);
	static_assert(std::size(exmdb_rpc_names) == static_cast<uint8_t>(exmdb_callid::cgkreset) + 1);
	auto s = j < std::size(exmdb_rpc_names) ? exmdb_rpc_names[j] : nullptr;
	return znul(s);
}

}
