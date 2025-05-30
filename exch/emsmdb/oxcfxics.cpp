// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2025 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <climits>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>
#include <gromox/defs.h>
#include <gromox/eid_array.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/pcl.hpp>
#include <gromox/proc_common.h>
#include <gromox/rop_util.hpp>
#include <gromox/util.hpp>
#include "attachment_object.hpp"
#include "common_util.hpp"
#include "emsmdb_interface.hpp"
#include "exmdb_client.hpp"
#include "fastdownctx_object.hpp"
#include "fastupctx_object.hpp"
#include "folder_object.hpp"
#include "ics_state.hpp"
#include "icsdownctx_object.hpp"
#include "message_object.hpp"
#include "rop_funcs.hpp"
#include "rop_processor.hpp"

using namespace gromox;

static EID_ARRAY *oxcfxics_load_folder_messages(logon_object *plogon,
    uint64_t folder_id, const char *username, BOOL b_fai)
{
	uint32_t table_id;
	uint32_t row_count;
	TARRAY_SET tmp_set;
	PROPTAG_ARRAY proptags;
	RESTRICTION restriction;
	EID_ARRAY *pmessage_ids;
	RESTRICTION_PROPERTY res_prop;
	uint8_t tmp_associated = !!b_fai;
	
	restriction.rt = RES_PROPERTY;
	restriction.pres = &res_prop;
	res_prop.relop = RELOP_EQ;
	res_prop.proptag = PR_ASSOCIATED;
	res_prop.propval.proptag = res_prop.proptag;
	res_prop.propval.pvalue = &tmp_associated;
	if (!exmdb_client->load_content_table(plogon->get_dir(), CP_ACP, folder_id,
	    username, TABLE_FLAG_NONOTIFICATIONS, &restriction, nullptr,
	    &table_id, &row_count))
		return NULL;	
	uint32_t tmp_proptag = PidTagMid;
	proptags.count = 1;
	proptags.pproptag = &tmp_proptag;
	if (!exmdb_client->query_table(plogon->get_dir(), nullptr, CP_ACP,
	    table_id, &proptags, 0, row_count, &tmp_set))
		return NULL;	
	exmdb_client->unload_table(plogon->get_dir(), table_id);
	pmessage_ids = eid_array_init();
	if (pmessage_ids == nullptr)
		return NULL;
	for (size_t i = 0; i < tmp_set.count; ++i) {
		auto pmid = tmp_set.pparray[i]->get<uint64_t>(PidTagMid);
		if (NULL == pmid) {
			eid_array_free(pmessage_ids);
			return NULL;
		}
		if (!eid_array_append(pmessage_ids, *pmid)) {
			eid_array_free(pmessage_ids);
			return NULL;
		}
	}
	return pmessage_ids;
}

static std::unique_ptr<FOLDER_CONTENT>
oxcfxics_load_folder_content(logon_object *plogon, uint64_t folder_id,
    bool b_fai, bool b_normal, bool b_sub)
{
	TARRAY_SET tmp_set;
	EID_ARRAY *pmessage_ids;
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	auto username = plogon->eff_user();
	
	if (username != STORE_OWNER_GRANTED) {
		uint32_t permission = 0;
		if (!exmdb_client->get_folder_perm(plogon->get_dir(),
		    folder_id, username, &permission))
			return NULL;	
		if (!(permission & (frightsReadAny | frightsOwner)))
			return NULL;
	}
	auto pfldctnt = folder_content_init();
	if (pfldctnt == nullptr)
		return NULL;
	if (!exmdb_client->get_folder_all_proptags(plogon->get_dir(),
	    folder_id, &tmp_proptags))
		return NULL;
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (!exmdb_client->get_folder_properties(plogon->get_dir(), pinfo->cpid,
	    folder_id, &tmp_proptags, &tmp_propvals))
		return NULL;
	auto pproplist = pfldctnt->get_proplist();
	for (size_t i = 0; i < tmp_propvals.count; ++i)
		if (pproplist->set(tmp_propvals.ppropval[i]) != ecSuccess)
			return NULL;
	/*
	 * Gromox does not have split public folders, so no need to emit
	 * MetaTagNewFXFolder in this spot.
	 */
	if (b_fai) {
		pmessage_ids = oxcfxics_load_folder_messages(
					plogon, folder_id, username, TRUE);
		if (pmessage_ids == nullptr)
			return NULL;
		pfldctnt->append_failist_internal(pmessage_ids);
	}
	if (b_normal) {
		pmessage_ids = oxcfxics_load_folder_messages(
					plogon, folder_id, username, FALSE);
		if (pmessage_ids == nullptr)
			return NULL;
		pfldctnt->append_normallist_internal(pmessage_ids);
	}
	if (!b_sub)
		return pfldctnt;

	uint32_t table_id = 0, row_count = 0;
	if (!exmdb_client->load_hierarchy_table(plogon->get_dir(),
	    folder_id, username, TABLE_FLAG_NONOTIFICATIONS, nullptr,
	    &table_id, &row_count))
		return NULL;
	uint32_t tmp_proptag = PidTagFolderId;
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &tmp_proptag;
	if (!exmdb_client->query_table(plogon->get_dir(), nullptr, CP_ACP,
	    table_id, &tmp_proptags, 0, row_count, &tmp_set))
		return NULL;
	exmdb_client->unload_table(plogon->get_dir(), table_id);
	for (size_t i = 0; i < tmp_set.count; ++i) {
		auto pfolder_id = tmp_set.pparray[i]->get<uint64_t>(PidTagFolderId);
		if (pfolder_id == nullptr)
			return NULL;
		auto psubfldctnt = oxcfxics_load_folder_content(
		                   plogon, *pfolder_id, TRUE, TRUE, TRUE);
		if (psubfldctnt == nullptr)
			return NULL;
		if (!pfldctnt->append_subfolder_internal(std::move(*psubfldctnt)))
			return NULL;
	}
	return pfldctnt;
}

ec_error_t rop_fasttransferdestconfigure(uint8_t source_operation, uint8_t flags,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	ems_objtype object_type;
	int root_element;
	
	if (flags & ~FAST_DEST_CONFIG_FLAG_MOVE)
		return ecInvalidParam;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto pobject = rop_processor_get_object(plogmap, logon_id, hin, &object_type);
	if (pobject == nullptr)
		return ecNullObject;
	switch (source_operation) {
	case FAST_SOURCE_OPERATION_COPYTO:
	case FAST_SOURCE_OPERATION_COPYPROPERTIES:
		switch (object_type) {
		case ems_objtype::folder:
			root_element = ROOT_ELEMENT_FOLDERCONTENT;
			break;
		case ems_objtype::message:
			root_element = ROOT_ELEMENT_MESSAGECONTENT;
			break;
		case ems_objtype::attach:
			root_element = ROOT_ELEMENT_ATTACHMENTCONTENT;
			break;
		default:
			return ecNotSupported;
		}
		break;
	case FAST_SOURCE_OPERATION_COPYMESSAGES:
		if (object_type != ems_objtype::folder)
			return ecNotSupported;
		root_element = ROOT_ELEMENT_MESSAGELIST;
		break;
	case FAST_SOURCE_OPERATION_COPYFOLDER:
		if (object_type != ems_objtype::folder)
			return ecNotSupported;
		root_element = ROOT_ELEMENT_TOPFOLDER;
		break;
	default:
		return ecInvalidParam;
	}
	if (ROOT_ELEMENT_TOPFOLDER == root_element ||
		ROOT_ELEMENT_MESSAGELIST == root_element ||
		ROOT_ELEMENT_FOLDERCONTENT == root_element) {
		static constexpr proptag_t proptag_buff[] =
			{PR_MESSAGE_SIZE_EXTENDED, PR_STORAGE_QUOTA_LIMIT,
			PR_ASSOC_CONTENT_COUNT, PR_CONTENT_COUNT};
		static constexpr PROPTAG_ARRAY tmp_proptags =
			{std::size(proptag_buff), deconst(proptag_buff)};
		TPROPVAL_ARRAY tmp_propvals;
		if (!plogon->get_properties(&tmp_proptags, &tmp_propvals))
			return ecError;

		auto num = tmp_propvals.get<const uint32_t>(PR_STORAGE_QUOTA_LIMIT);
		uint64_t max_quota = ULLONG_MAX;
		if (num != nullptr) {
			max_quota = *num;
			max_quota = max_quota >= ULLONG_MAX / 1024 ? ULLONG_MAX : max_quota * 1024ULL;
		}
		auto lnum = tmp_propvals.get<const uint64_t>(PR_MESSAGE_SIZE_EXTENDED);
		uint64_t total_size = lnum != nullptr ? *lnum : 0;
		if (total_size > max_quota)
			return ecQuotaExceeded;
		num = tmp_propvals.get<uint32_t>(PR_ASSOC_CONTENT_COUNT);
		uint32_t total_mail = num != nullptr ? *num : 0;
		num = tmp_propvals.get<uint32_t>(PR_CONTENT_COUNT);
		if (num != nullptr)
			total_mail += *num;
		if (total_mail > g_max_message)
			return ecQuotaExceeded;
	}
	auto pctx = fastupctx_object::create(plogon, pobject, root_element);
	if (pctx == nullptr)
		return ecError;
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, {ems_objtype::fastupctx, std::move(pctx)});
	if (hnd < 0)
		return aoh_to_error(hnd);
	*phout = hnd;
	return ecSuccess;
}

ec_error_t rop_fasttransferdestputbuffer(const BINARY *ptransfer_data,
    uint16_t *ptransfer_status, uint16_t *pin_progress_count,
    uint16_t *ptotal_step_count, uint8_t *preserved, uint16_t *pused_size,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	
	*ptransfer_status = 0;
	*pin_progress_count = 0;
	*ptotal_step_count = 1;
	*preserved = 0;
	*pused_size = 0;
	auto pobject = rop_processor_get_object(plogmap, logon_id, hin, &object_type);
	if (pobject == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::fastupctx)
		return ecNotSupported;
	auto err = static_cast<fastupctx_object *>(pobject)->write_buffer(ptransfer_data);
	if (err != ecSuccess)
		return err;
	*pused_size = ptransfer_data->cb;
	return ecSuccess;
}

ec_error_t rop_fasttransfersourcegetbuffer(uint16_t buffer_size,
    uint16_t max_buffer_size, uint16_t *ptransfer_status,
    uint16_t *pin_progress_count, uint16_t *ptotal_step_count,
    uint8_t *preserved, BINARY *ptransfer_data, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	BOOL b_last;
	ems_objtype object_type;
	uint16_t max_rop;
	
	*ptransfer_status = TRANSFER_STATUS_ERROR;
	*pin_progress_count = 0;
	*ptotal_step_count = 1;
	*preserved = 0;
	ptransfer_data->cb = 0;
	auto pobject = rop_processor_get_object(plogmap, logon_id, hin, &object_type);
	if (pobject == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::icsdownctx &&
	    object_type != ems_objtype::fastdownctx)
		return ecNotSupported;
	emsmdb_interface_get_rop_left(&max_rop);
	if (max_rop >= 32)
		max_rop -= 32;
	else
		max_rop = 0;
	if (max_rop > 0x7b00)
		max_rop = 0x7b00;
	uint16_t len = buffer_size == 0xBABE ? max_buffer_size : buffer_size;
	if (len > max_rop)
		len = max_rop;
	ptransfer_data->pv = common_util_alloc(len);
	if (ptransfer_data->pv == nullptr)
		return ecServerOOM;
	if (object_type == ems_objtype::fastdownctx) {
		if (!static_cast<fastdownctx_object *>(pobject)->get_buffer(
		    ptransfer_data->pv, &len, &b_last, pin_progress_count, ptotal_step_count))
			return ecError;
	} else if (object_type == ems_objtype::icsdownctx) {
		auto dobj = static_cast<icsdownctx_object *>(pobject);
		if (!dobj->check_started() && !dobj->make_sync())
			return ecError;
		if (!dobj->get_buffer(ptransfer_data->pv, &len, &b_last,
		    pin_progress_count, ptotal_step_count))
			return ecError;
	}
	if (buffer_size != 0xBABE && len > max_rop)
		return ecBufferTooSmall;
	*ptransfer_status = !b_last ? TRANSFER_STATUS_PARTIAL : TRANSFER_STATUS_DONE;
	ptransfer_data->cb = len;
	return ecSuccess;
}

static bool send_options_ok(uint32_t f)
{
	if (f & ~(SEND_OPTIONS_UNICODE | SEND_OPTIONS_USECPID |
	    SEND_OPTIONS_RECOVERMODE | SEND_OPTIONS_FORCEUNICODE |
	    SEND_OPTIONS_PARTIAL | SEND_OPTIONS_RESERVED1 | SEND_OPTIONS_RESERVED2))
		return false;
	if ((f & SEND_OPTIONS_UNICODE) && (f & SEND_OPTIONS_USECPID) &&
	    (f & SEND_OPTIONS_RECOVERMODE))
		return false;
	return true;
}

ec_error_t rop_fasttransfersourcecopyfolder(uint8_t flags, uint8_t send_options,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	ems_objtype object_type;
	
	if (!send_options_ok(send_options))
		return ecInvalidParam;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto pfolder = rop_proc_get_obj<folder_object>(plogmap, logon_id, hin, &object_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::folder)
		return ecNotSupported;
	BOOL b_sub = (flags & (FAST_COPY_FOLDER_FLAG_MOVE |
	             FAST_COPY_FOLDER_FLAG_COPYSUBFOLDERS)) ? TRUE : false;
	auto pfldctnt = oxcfxics_load_folder_content(plogon, pfolder->folder_id,
	           TRUE, TRUE, b_sub);
	if (pfldctnt == nullptr)
		return ecError;
	auto pctx = fastdownctx_object::create(plogon, send_options & 0x0F);
	if (pctx == nullptr)
		return ecError;
	if (!pctx->make_topfolder(std::move(pfldctnt)))
		return ecError;
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, {ems_objtype::fastdownctx, std::move(pctx)});
	if (hnd < 0)
		return aoh_to_error(hnd);
	*phout = hnd;
	return ecSuccess;
}

ec_error_t rop_fasttransfersourcecopymessages(const LONGLONG_ARRAY *pmessage_ids,
    uint8_t flags, uint8_t send_options, LOGMAP *plogmap, uint8_t logon_id,
    uint32_t hin, uint32_t *phout)
{
	BOOL b_owner;
	ems_objtype object_type;
	
	if (!send_options_ok(send_options))
		return ecInvalidParam;
	/* we ignore the FAST_COPY_MESSAGE_FLAG_MOVE
	   in flags just like exchange 2010 or later */
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto pfolder = rop_proc_get_obj<folder_object>(plogmap, logon_id, hin, &object_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::folder)
		return ecNotSupported;
	auto username = plogon->eff_user();
	if (username != STORE_OWNER_GRANTED) {
		uint32_t permission = 0;
		if (!exmdb_client->get_folder_perm(plogon->get_dir(),
		    pfolder->folder_id, username, &permission))
			return ecError;
		if (!(permission & (frightsReadAny | frightsOwner))) {
			for (size_t i = 0; i < pmessage_ids->count; ++i) {
				if (!exmdb_client->is_message_owner(plogon->get_dir(),
				    pmessage_ids->pll[i], username, &b_owner))
					return ecError;
				if (!b_owner)
					return ecAccessDenied;
			}
		}
	}
	auto pmids = eid_array_init();
	if (pmids == nullptr)
		return ecServerOOM;
	if (!eid_array_batch_append(pmids, pmessage_ids->count,
	    pmessage_ids->pll)) {
		eid_array_free(pmids);
		return ecServerOOM;
	}
	BOOL b_chginfo = (flags & FAST_COPY_MESSAGE_FLAG_SENDENTRYID) ? TRUE : false;
	auto pctx = fastdownctx_object::create(plogon, send_options & 0x0F);
	if (NULL == pctx) {
		eid_array_free(pmids);
		return ecError;
	}
	if (!pctx->make_messagelist(b_chginfo, pmids)) {
		pctx.reset();
		eid_array_free(pmids);
		return ecError;
	}
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, {ems_objtype::fastdownctx, std::move(pctx)});
	if (hnd < 0)
		return aoh_to_error(hnd);
	*phout = hnd;
	return ecSuccess;
}

/*
 * When messages are copied to another store, the one message that has been
 * activated/opened in OL will be copied using IMAPIFolder::CopyTo
 * [ropFastTransferSourceCopyTo]. Others will be copied using
 * IMAPIFolder::CopyMessages [ropFastTransferSourceCopyMessages].
 *
 */

/**
 * @proptags: proptag exclusion list for this object only
 *
 * Cf. rop_fasttransfersourcecopyproperties too.
 *
 * Note that if @hin refers to a message, that's really a message instance(!).
 * So, CopyTo can be used for instances (unsaved ones even), whereas
 * CopyMessages cannot do that.
 */
ec_error_t rop_fasttransfersourcecopyto(uint8_t level, uint32_t flags,
    uint8_t send_options, const PROPTAG_ARRAY *pproptags, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	ems_objtype object_type;
	MESSAGE_CONTENT msgctnt;
	ATTACHMENT_CONTENT attctnt;
	
	if (!send_options_ok(send_options))
		return ecInvalidParam;
	/* just like exchange 2010 or later */
	if (flags & FAST_COPY_TO_FLAG_MOVE)
		return ecInvalidParam;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto pobject = rop_processor_get_object(plogmap, logon_id, hin, &object_type);
	if (pobject == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::folder &&
	    object_type != ems_objtype::message &&
	    object_type != ems_objtype::attach)
		return ecNotSupported;
	auto pctx = fastdownctx_object::create(plogon, send_options & 0x0F);
	if (pctx == nullptr)
		return ecError;
	switch (object_type) {
	case ems_objtype::folder: {
		auto bg = pproptags->begin(), end = pproptags->end();
		auto b_sub    = level == 0 && std::find(bg, end, PR_CONTAINER_HIERARCHY) == end;
		auto b_fai    = level == 0 && std::find(bg, end, PR_CONTAINER_CONTENTS) == end;
		auto b_normal = level == 0 && std::find(bg, end, PR_FOLDER_ASSOCIATED_CONTENTS) == end;
		auto pfldctnt = oxcfxics_load_folder_content(plogon,
		                static_cast<folder_object *>(pobject)->folder_id,
		                b_fai, b_normal, b_sub);
		if (pfldctnt == nullptr)
			return ecError;
		auto pproplist = pfldctnt->get_proplist();
		for (const auto tag : *pproptags)
			pproplist->erase(tag);
		if (!pctx->make_foldercontent(b_sub, std::move(pfldctnt)))
			return ecError;
		break;
	}
	case ems_objtype::message:
		if (!static_cast<message_object *>(pobject)->flush_streams())
			return ecError;
		if (!exmdb_client->read_message_instance(plogon->get_dir(),
		    static_cast<message_object *>(pobject)->get_instance_id(), &msgctnt))
			return ecError;
		for (const auto tag : *pproptags) {
			switch (tag) {
			case PR_MESSAGE_RECIPIENTS:	
				msgctnt.children.prcpts = NULL;
				break;
			case PR_MESSAGE_ATTACHMENTS:
				msgctnt.children.pattachments = NULL;
				break;
			default:
				common_util_remove_propvals(&msgctnt.proplist, tag);
				break;
			}
		}
		if (0 != level) {
			msgctnt.children.prcpts = NULL;
			msgctnt.children.pattachments = NULL;
		}
		if (!pctx->make_messagecontent(&msgctnt))
			return ecError;
		break;
	case ems_objtype::attach:
		if (!static_cast<attachment_object *>(pobject)->flush_streams())
			return ecError;
		if (!exmdb_client->read_attachment_instance(plogon->get_dir(),
		    static_cast<attachment_object *>(pobject)->get_instance_id(), &attctnt))
			return ecError;
		for (const auto tag : *pproptags) {
			switch (tag) {
			case PR_ATTACH_DATA_OBJ:
				attctnt.pembedded = NULL;
				break;
			default:
				common_util_remove_propvals(&attctnt.proplist, tag);
				break;
			}
		}
		if (!pctx->make_attachmentcontent(&attctnt))
			return ecError;
		break;
	default:
		break;
	}
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, {ems_objtype::fastdownctx, std::move(pctx)});
	if (hnd < 0)
		return aoh_to_error(hnd);
	*phout = hnd;
	return ecSuccess;
}

ec_error_t rop_fasttransfersourcecopyproperties(uint8_t level, uint8_t flags,
    uint8_t send_options, const PROPTAG_ARRAY *pproptags, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	ems_objtype object_type;
	MESSAGE_CONTENT msgctnt;
	ATTACHMENT_CONTENT attctnt;
	
	if (!send_options_ok(send_options))
		return ecInvalidParam;
	/* just like exchange 2010 or later */
	if (flags & FAST_COPY_PROPERTIES_FLAG_MOVE)
		return ecInvalidParam;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto pobject = rop_processor_get_object(plogmap, logon_id, hin, &object_type);
	if (pobject == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::folder &&
	    object_type != ems_objtype::message &&
	    object_type != ems_objtype::attach)
		return ecNotSupported;
	auto pctx = fastdownctx_object::create(plogon, send_options & 0x0F);
	if (pctx == nullptr)
		return ecError;
	switch (object_type) {
	case ems_objtype::folder: {
		/*
		 * OXCFXICS v24 §2.2.3.1.1.2: @proptags specifies """a list of
		 * properties and subobjects to include, as opposed to
		 * exclude""" [like rop_fasttransfersourcecopyproperties]
		 */
		auto bg = pproptags->begin(), end = pproptags->end();
		auto b_sub    = level == 0 && std::find(bg, end, PR_CONTAINER_HIERARCHY) != end;
		auto b_normal = level == 0 && std::find(bg, end, PR_CONTAINER_CONTENTS) != end;
		auto b_fai    = level == 0 && std::find(bg, end, PR_FOLDER_ASSOCIATED_CONTENTS) != end;
		auto pfldctnt = oxcfxics_load_folder_content(plogon,
		                static_cast<folder_object *>(pobject)->folder_id,
		                b_fai, b_normal, b_sub);
		if (pfldctnt == nullptr)
			return ecError;
		auto pproplist = pfldctnt->get_proplist();
		for (unsigned int i = 0; i < pproplist->count; ) {
			if (pproplist->ppropval[i].proptag != MetaTagNewFXFolder) {
				if (!pproptags->has(pproplist->ppropval[i].proptag)) {
					pproplist->erase(pproplist->ppropval[i].proptag);
					continue;
				}
			}
			i ++;
		}
		if (!pctx->make_foldercontent(b_sub, std::move(pfldctnt)))
			return ecError;
		break;
	}
	case ems_objtype::message:
		if (!static_cast<message_object *>(pobject)->flush_streams())
			return ecError;
		if (!exmdb_client->read_message_instance(plogon->get_dir(),
		    static_cast<message_object *>(pobject)->get_instance_id(), &msgctnt))
			return ecError;
		for (unsigned int i = 0; i < msgctnt.proplist.count; ) {
			if (!pproptags->has(msgctnt.proplist.ppropval[i].proptag)) {
				common_util_remove_propvals(&msgctnt.proplist,
						msgctnt.proplist.ppropval[i].proptag);
				continue;
			}
			i ++;
		}
		if (!pproptags->has(PR_MESSAGE_RECIPIENTS))
			msgctnt.children.prcpts = NULL;
		if (!pproptags->has(PR_MESSAGE_ATTACHMENTS))
			msgctnt.children.pattachments = NULL;
		if (0 != level) {
			msgctnt.children.prcpts = NULL;
			msgctnt.children.pattachments = NULL;
		}
		if (!pctx->make_messagecontent(&msgctnt))
			return ecError;
		break;
	case ems_objtype::attach:
		if (!static_cast<attachment_object *>(pobject)->flush_streams())
			return ecError;
		if (!exmdb_client->read_attachment_instance(plogon->get_dir(),
		    static_cast<attachment_object *>(pobject)->get_instance_id(), &attctnt))
			return ecError;
		for (unsigned int i = 0; i < attctnt.proplist.count; ) {
			if (!pproptags->has(attctnt.proplist.ppropval[i].proptag)) {
				common_util_remove_propvals(&attctnt.proplist,
						attctnt.proplist.ppropval[i].proptag);
				continue;
			}
			i ++;
		}
		if (!pproptags->has(PR_ATTACH_DATA_OBJ))
			attctnt.pembedded = NULL;
		if (!pctx->make_attachmentcontent(&attctnt))
			return ecError;
		break;
	default:
		break;
	}
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, {ems_objtype::fastdownctx, std::move(pctx)});
	if (hnd < 0)
		return aoh_to_error(hnd);
	*phout = hnd;
	return ecSuccess;
}

ec_error_t rop_tellversion(const uint16_t *pversion, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	return ecSuccess;
}

ec_error_t rop_syncconfigure(uint8_t sync_type, uint8_t send_options,
    uint16_t sync_flags, const RESTRICTION *pres, uint32_t extra_flags,
    const PROPTAG_ARRAY *pproptags, LOGMAP *plogmap, uint8_t logon_id,
    uint32_t hin, uint32_t *phout)
{
	ems_objtype object_type;
	uint32_t permission;
	
	if (SYNC_TYPE_CONTENTS != sync_type &&
	    sync_type != SYNC_TYPE_HIERARCHY)
		return ecInvalidParam;
	if (!send_options_ok(send_options))
		return ecInvalidParam;
	if (sync_type == SYNC_TYPE_HIERARCHY && pres != nullptr)
		return ecInvalidParam;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto pfolder = rop_proc_get_obj<folder_object>(plogmap, logon_id, hin, &object_type);
	if (pfolder == nullptr)
		return ecNullObject;
	auto username = plogon->eff_user();
	if (sync_type == SYNC_TYPE_CONTENTS && username != STORE_OWNER_GRANTED) {
		if (!exmdb_client->get_folder_perm(plogon->get_dir(),
		    pfolder->folder_id, username, &permission))
			return ecError;
		if (!(permission & (frightsOwner | frightsReadAny)))
			return ecAccessDenied;
	}
	if (pres != nullptr && !common_util_convert_restriction(TRUE,
	    const_cast<RESTRICTION *>(pres)))
			return ecError;

	std::vector<uint32_t> new_tags;
	PROPTAG_ARRAY new_pta;
	auto bodyof = pproptags->indexof(PR_BODY);
	if (!(sync_flags & SYNC_ONLY_SPECIFIED_PROPS) &&
	    bodyof != pproptags->npos && !pproptags->has(PR_HTML)) try {
		/*
		 * Ignore Outlook's request to exclude PR_BODY.
		 * PR_BODY may be the only format some message has.
		 * Send at least one body format. (Ignoring RTF presence
		 * altogether here; that is another consideration.)
		 */
		auto p = pproptags->pproptag;
		new_tags.insert(new_tags.end(), p, p + bodyof);
		new_tags.insert(new_tags.end(), p + bodyof + 1, p + pproptags->count - 1);
		new_pta.count = new_tags.size();
		new_pta.pproptag = new_tags.data();
		pproptags = &new_pta;
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1610: ENOMEM");
		return ecServerOOM;
	}
	auto pctx = icsdownctx_object::create(plogon, pfolder, sync_type,
	            send_options, sync_flags, pres, extra_flags, pproptags);
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, {ems_objtype::icsdownctx, std::move(pctx)});
	if (hnd < 0)
		return aoh_to_error(hnd);
	*phout = hnd;
	return ecSuccess;
}

/**
 * PR_SOURCE_KEY consists of a (varying) mdguid and a GC value; that GCV is
 * scoped to the particular mdguid. PR_CHANGE_KEY consists of a (varying)
 * cnguid [in .ost files: PR_OST_OLFI] and a CN value.
 *
 * The message_id columns in exchange.sqlite3 currently only store the GCV. To
 * work around this shortcoming, simc_otherstore obtains a GCV in the "home"
 * mdguid namespace producing a new SK.
 *
 * A new SK means "new message", which also means the message gets downloaded
 * back by the client, which should eventually be fixed.
 */
static ec_error_t simc_otherstore(LOGMAP *logmap, uint8_t logon_id,
    unsigned int import_flags, icsupctx_object *ctx,
    const TPROPVAL_ARRAY *props, uint64_t *msg_idp,
    uint32_t hnd_in, uint32_t *hnd_out)
{
	auto logon = rop_processor_get_logon_object(logmap, logon_id);
	if (logon == nullptr)
		return ecError;
	auto folder = ctx->get_parent_object();
	auto folder_id = folder->folder_id;
	uint32_t tag_access = 0;
	auto dir = logon->get_dir();
	auto username = logon->eff_user();

	if (username != STORE_OWNER_GRANTED) {
		uint32_t permission = 0;
		if (!exmdb_client->get_folder_perm(dir,
		    folder_id, username, &permission))
			return ecError;
		if (!(permission & frightsCreate))
			return ecAccessDenied;
		tag_access = MAPI_ACCESS_READ;
		if (permission & (frightsEditAny | frightsEditOwned))
			tag_access |= MAPI_ACCESS_MODIFY;
		if (permission & (frightsDeleteAny | frightsDeleteOwned))
			tag_access |= MAPI_ACCESS_DELETE;
	} else {
		tag_access = MAPI_ACCESS_MODIFY | MAPI_ACCESS_READ | MAPI_ACCESS_DELETE;
	}

	uint64_t message_id = 0;
	if (!exmdb_client->allocate_message_id(dir, folder_id, &message_id))
		return ecError;
	auto info = emsmdb_interface_get_emsmdb_info();
	auto msg = message_object::create(logon, TRUE, info->cpid, message_id,
	           &folder_id, tag_access, MAPI_MODIFY, ctx->pstate);
	if (msg == nullptr)
		return ecError;

	/* Retain PCL and assign a new CN */
	uint64_t change_num;
	if (!exmdb_client->allocate_cn(dir, &change_num))
		return ecError;
	auto new_ck = cu_xid_to_bin({logon->guid(), change_num});
	if (new_ck == nullptr)
		return ecServerOOM;
	auto new_pcl = common_util_pcl_append(static_cast<BINARY *>(props->ppropval[3].pvalue), new_ck);
	if (new_pcl == nullptr)
		return ecServerOOM;

	BOOL b_fai = (import_flags & IMPORT_FLAG_ASSOCIATED) ? TRUE : false;
	if (msg->init_message(b_fai, info->cpid) != 0)
		return ecError;

	TAGGED_PROPVAL nupropd[2];
	nupropd[0].proptag = PR_CHANGE_KEY;
	nupropd[0].pvalue = new_ck;
	nupropd[1].proptag = PR_PREDECESSOR_CHANGE_LIST;
	nupropd[1].pvalue = new_pcl;
	const TPROPVAL_ARRAY nuprops = {std::size(nupropd), deconst(nupropd)};
	PROBLEM_ARRAY problems{};
	if (!exmdb_client->set_instance_properties(dir,
	    msg->get_instance_id(), &nuprops, &problems))
		return ecError;
	auto hnd = rop_processor_add_object_handle(logmap, logon_id, hnd_in,
	           {ems_objtype::message, std::move(msg)});
	if (hnd < 0)
		return aoh_to_error(hnd);
	*hnd_out = hnd;
	/*
	 * When Cached Mode clients see upload success, the assumption is that
	 * the message exists with the same PR_SOURCE_KEY. That assumption is
	 * broken by simc_otherstore, so signal a deletion of the old SK.
	 * [Events are ignored by Outlook; so the signalling happens via
	 * delete_impossible_mids instead.]
	 */
	return ecSuccess;
}

ec_error_t rop_syncimportmessagechange(uint8_t import_flags,
    const TPROPVAL_ARRAY *ppropvals, uint64_t *pmessage_id, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	XID tmp_xid;
	BOOL b_exist;
	BOOL b_owner;
	void *pvalue;
	uint32_t result;
	ems_objtype object_type;
	uint32_t permission = rightsNone, tag_access = 0, tmp_proptag;
	PROPTAG_ARRAY proptags;
	PROBLEM_ARRAY tmp_problems;
	TPROPVAL_ARRAY tmp_propvals;
	
	if (import_flags & (~(IMPORT_FLAG_ASSOCIATED | IMPORT_FLAG_FAILONCONFLICT)))
		return ecInvalidParam;
	if (4 != ppropvals->count ||
	    ppropvals->ppropval[0].proptag != PR_SOURCE_KEY ||
	    ppropvals->ppropval[1].proptag != PR_LAST_MODIFICATION_TIME ||
	    ppropvals->ppropval[2].proptag != PR_CHANGE_KEY ||
	    ppropvals->ppropval[3].proptag != PR_PREDECESSOR_CHANGE_LIST)
		return ecInvalidParam;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto pctx = rop_proc_get_obj<icsupctx_object>(plogmap, logon_id, hin, &object_type);
	if (pctx == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::icsupctx)
		return ecNotSupported;
	if (pctx->get_sync_type() != SYNC_TYPE_CONTENTS)
		return ecNotSupported;
	pctx->mark_started();
	auto pfolder = pctx->get_parent_object();
	auto folder_id = pfolder->folder_id;
	auto pbin = static_cast<BINARY *>(ppropvals->ppropval[0].pvalue);
	if (pbin == nullptr || pbin->cb != 22)
		return ecInvalidParam;
	if (!common_util_binary_to_xid(pbin, &tmp_xid))
		return ecError;
	auto tmp_guid = plogon->guid();
	if (tmp_guid != tmp_xid.guid)
		return simc_otherstore(plogmap, logon_id, import_flags, pctx, ppropvals,
		       pmessage_id, hin, phout);
	auto message_id = rop_util_make_eid(1, tmp_xid.local_to_gc());
	auto dir = plogon->get_dir();
	if (!exmdb_client->is_msg_present(dir, folder_id, message_id, &b_exist))
		return ecError;
	BOOL b_new = !b_exist ? TRUE : false;
	*pmessage_id = 0;
	auto username = plogon->eff_user();
	if (username != STORE_OWNER_GRANTED) {
		if (!exmdb_client->get_folder_perm(dir,
		    folder_id, username, &permission))
			return ecError;
		if (b_new) {
			if (!(permission & frightsCreate))
				return ecAccessDenied;
			tag_access = MAPI_ACCESS_READ;
			if (permission & (frightsEditAny | frightsEditOwned))
				tag_access |= MAPI_ACCESS_MODIFY;
			if (permission & (frightsDeleteAny | frightsDeleteOwned))
				tag_access |= MAPI_ACCESS_DELETE;
		} else if (permission & frightsOwner) {
			tag_access = MAPI_ACCESS_MODIFY | MAPI_ACCESS_READ|MAPI_ACCESS_DELETE;
		} else {
			if (!exmdb_client->is_message_owner(dir,
			    message_id, username, &b_owner))
				return ecError;
			if (b_owner || (permission & frightsReadAny))
				tag_access |= MAPI_ACCESS_READ;
			if ((permission & frightsEditAny) ||
			    (b_owner && (permission & frightsEditOwned)))
				tag_access |= MAPI_ACCESS_MODIFY;
			if ((permission & frightsDeleteAny) ||
			    (b_owner && (permission & frightsDeleteOwned)))
				tag_access |= MAPI_ACCESS_DELETE;
		}
	} else {
		tag_access = MAPI_ACCESS_MODIFY | MAPI_ACCESS_READ | MAPI_ACCESS_DELETE;
	}
	if (!b_new) {
		if (!exmdb_client->get_message_property(dir, nullptr, CP_ACP,
		    message_id, PR_ASSOCIATED, &pvalue))
			return ecError;
		bool orig_is_fai = pvb_enabled(pvalue);
		if (!!(import_flags & IMPORT_FLAG_ASSOCIATED) != orig_is_fai)
			return ecInvalidParam;
		b_new = FALSE;
	} else {
		b_new = TRUE;
	}
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	auto pmessage = message_object::create(plogon, b_new, pinfo->cpid,
	                message_id, &folder_id, tag_access,
	                MAPI_MODIFY, pctx->pstate);
	if (pmessage == nullptr)
		return ecError;
	if (!b_new) {
		proptags.count = 1;
		proptags.pproptag = &tmp_proptag;
		tmp_proptag = PR_PREDECESSOR_CHANGE_LIST;
		if (!pmessage->get_properties(0, &proptags, &tmp_propvals))
			return ecError;
		auto bin = tmp_propvals.get<const BINARY>(PR_PREDECESSOR_CHANGE_LIST);
		if (bin == nullptr)
			return ecError;
		if (!common_util_pcl_compare(bin,
		    static_cast<BINARY *>(ppropvals->ppropval[3].pvalue), &result))
			return ecError;
		if (result & PCL_INCLUDE) {
			return SYNC_E_IGNORE;
		} else if (PCL_CONFLICT == result) {
			if (import_flags & IMPORT_FLAG_FAILONCONFLICT)
				return SYNC_E_CONFLICT;
		}
	}
	if (!b_new) {
		if (!exmdb_client->clear_message_instance(dir,
		    pmessage->get_instance_id()))
			return ecError;
	} else {
		BOOL b_fai = (import_flags & IMPORT_FLAG_ASSOCIATED) ? TRUE : false;
		if (pmessage->init_message(b_fai, pinfo->cpid) != 0)
			return ecError;
	}
	tmp_propvals.count = 3;
	tmp_propvals.ppropval = ppropvals->ppropval + 1;
	if (!exmdb_client->set_instance_properties(dir,
	    pmessage->get_instance_id(), &tmp_propvals, &tmp_problems))
		return ecError;
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, {ems_objtype::message, std::move(pmessage)});
	if (hnd < 0)
		return aoh_to_error(hnd);
	*phout = hnd;
	return ecSuccess;
}

ec_error_t rop_syncimportreadstatechanges(uint16_t count,
    const MESSAGE_READ_STAT *pread_stat, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	XID tmp_xid;
	BOOL b_owner;
	ems_objtype object_type;
	uint64_t read_cn;
	uint64_t folder_id;
	uint32_t permission;
	TPROPVAL_ARRAY tmp_propvals;
	
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto pctx = rop_proc_get_obj<icsupctx_object>(plogmap, logon_id, hin, &object_type);
	if (pctx == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::icsupctx)
		return ecNotSupported;
	if (pctx->get_sync_type() != SYNC_TYPE_CONTENTS)
		return ecNotSupported;
	pctx->mark_started();
	auto dir = plogon->get_dir();
	auto eff_user = plogon->eff_user();
	if (eff_user != STORE_OWNER_GRANTED) {
		auto pfolder = pctx->get_parent_object();
		folder_id = pfolder->folder_id;
		if (!exmdb_client->get_folder_perm(dir,
		    folder_id, eff_user, &permission))
			return ecError;
		if (permission & frightsReadAny)
			eff_user = nullptr;
	}
	auto rds_user = plogon->readstate_user();
	for (unsigned int i = 0; i < count; ++i) {
		if (!common_util_binary_to_xid(&pread_stat[i].message_xid, &tmp_xid))
			return ecError;
		auto tmp_guid = plogon->guid();
		if (tmp_guid != tmp_xid.guid)
			continue;
		auto message_id = rop_util_make_eid(1, tmp_xid.local_to_gc());
		if (eff_user != STORE_OWNER_GRANTED) {
			if (!exmdb_client->is_message_owner(dir,
			    message_id, eff_user, &b_owner))
				return ecError;
			if (!b_owner)
				continue;
		}
		static constexpr proptag_t proptag_buff[] = {PR_ASSOCIATED, PR_READ};
		static constexpr PROPTAG_ARRAY tmp_proptags =
			{std::size(proptag_buff), deconst(proptag_buff)};
		if (!exmdb_client->get_message_properties(dir, nullptr, CP_ACP,
		    message_id, &tmp_proptags, &tmp_propvals))
			return ecError;
		auto flag = tmp_propvals.get<const uint8_t>(PR_ASSOCIATED);
		if (flag != nullptr && *flag != 0)
			continue;
		flag = tmp_propvals.get<uint8_t>(PR_READ);
		if ((flag == nullptr || *flag == 0) == (pread_stat[i].mark_as_read == 0))
			continue;
		if (!exmdb_client->set_message_read_state(dir, rds_user,
		    message_id, pread_stat[i].mark_as_read, &read_cn))
			return ecError;
		pctx->pstate->pread->append(read_cn);
	}
	return ecSuccess;
}

ec_error_t rop_syncimporthierarchychange(const TPROPVAL_ARRAY *phichyvals,
    const TPROPVAL_ARRAY *ppropvals, uint64_t *pfolder_id, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	XID tmp_xid;
	BOOL b_exist;
	BINARY *pbin;
	BOOL b_guest;
	void *pvalue;
	uint32_t result;
	ems_objtype object_type;
	uint16_t replid;
	uint64_t tmp_fid;
	uint32_t tmp_type;
	uint64_t folder_id;
	uint64_t parent_id1;
	uint64_t change_num;
	uint32_t permission;
	uint32_t parent_type;
	PROBLEM_ARRAY tmp_problems;
	TPROPVAL_ARRAY tmp_propvals;
	
	if (6 != phichyvals->count ||
	    phichyvals->ppropval[0].proptag != PR_PARENT_SOURCE_KEY ||
	    phichyvals->ppropval[1].proptag != PR_SOURCE_KEY ||
	    phichyvals->ppropval[2].proptag != PR_LAST_MODIFICATION_TIME ||
	    phichyvals->ppropval[3].proptag != PR_CHANGE_KEY ||
	    phichyvals->ppropval[4].proptag != PR_PREDECESSOR_CHANGE_LIST ||
	    phichyvals->ppropval[5].proptag != PR_DISPLAY_NAME)
		return ecInvalidParam;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto pctx = rop_proc_get_obj<icsupctx_object>(plogmap, logon_id, hin, &object_type);
	if (pctx == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::icsupctx)
		return ecNotSupported;
	if (pctx->get_sync_type() != SYNC_TYPE_HIERARCHY)
		return ecNotSupported;
	pctx->mark_started();
	auto pfolder = pctx->get_parent_object();
	auto rpc_info = get_rpc_info();
	auto dir = plogon->get_dir();
	if (static_cast<BINARY *>(phichyvals->ppropval[0].pvalue)->cb == 0) {
		parent_type = pfolder->type;
		parent_id1 = pfolder->folder_id;
		if (!exmdb_client->is_folder_present(dir,
		    parent_id1, &b_exist))
			return ecError;
		if (!b_exist)
			return SYNC_E_NO_PARENT;
	} else {
		pbin = static_cast<BINARY *>(phichyvals->ppropval[0].pvalue);
		if (pbin == nullptr || pbin->cb != 22)
			return ecInvalidParam;
		if (!common_util_binary_to_xid(pbin, &tmp_xid))
			return ecError;
		auto tmp_guid = plogon->is_private() ?
		                rop_util_make_user_guid(plogon->account_id) :
		                rop_util_make_domain_guid(plogon->account_id);
		if (tmp_guid != tmp_xid.guid)
			return ecInvalidParam;
		parent_id1 = rop_util_make_eid(1, tmp_xid.local_to_gc());
		if (!exmdb_client->get_folder_property(dir, CP_ACP,
		    parent_id1, PR_FOLDER_TYPE, &pvalue))
			return ecError;
		if (pvalue == nullptr)
			return SYNC_E_NO_PARENT;
		parent_type = *static_cast<uint32_t *>(pvalue);
	}
	if (parent_type == FOLDER_SEARCH)
		return ecNotSupported;
	pbin = static_cast<BINARY *>(phichyvals->ppropval[1].pvalue);
	if (pbin == nullptr || pbin->cb != 22)
		return ecInvalidParam;
	if (!common_util_binary_to_xid(pbin, &tmp_xid))
		return ecError;
	if (plogon->is_private()) {
		auto tmp_guid = rop_util_make_user_guid(plogon->account_id);
		if (tmp_guid != tmp_xid.guid)
			return ecInvalidParam;
		folder_id = rop_util_make_eid(1, tmp_xid.local_to_gc());
	} else {
		auto tmp_guid = rop_util_make_domain_guid(plogon->account_id);
		if (tmp_guid != tmp_xid.guid) {
			auto domain_id = rop_util_get_domain_id(tmp_xid.guid);
			if (domain_id == -1)
				return ecInvalidParam;
			if (!mysql_adaptor_check_same_org(domain_id, plogon->account_id))
				return ecInvalidParam;
			ec_error_t ret = ecSuccess;
			if (!exmdb_client->get_mapping_replid(dir,
			    tmp_xid.guid, &replid, &ret))
				return ecError;
			if (ret != ecSuccess)
				return ret;
			folder_id = rop_util_make_eid(replid, tmp_xid.local_to_gc());
		} else {
			folder_id = rop_util_make_eid(1, tmp_xid.local_to_gc());
		}
	}
	if (!exmdb_client->is_folder_present(dir, folder_id, &b_exist))
		return ecError;
	*pfolder_id = 0;
	auto username = plogon->eff_user();
	if (!b_exist) {
		if (username != STORE_OWNER_GRANTED) {
			if (!exmdb_client->get_folder_perm(dir,
			    parent_id1, username, &permission))
				return ecError;
			if (!(permission & frightsCreateSubfolder))
				return ecAccessDenied;
		}
		if (!exmdb_client->get_folder_by_name(dir, parent_id1,
		    static_cast<char *>(phichyvals->ppropval[5].pvalue), &tmp_fid))
			return ecError;
		if (tmp_fid != 0)
			return ecDuplicateName;
		if (!exmdb_client->allocate_cn(dir, &change_num))
			return ecError;
		tmp_propvals.count = 0;
		tmp_propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(8 + ppropvals->count);
		if (tmp_propvals.ppropval == nullptr)
			return ecServerOOM;
		tmp_propvals.emplace_back(PidTagFolderId, &folder_id);
		tmp_propvals.emplace_back(PidTagParentFolderId, &parent_id1);
		tmp_propvals.emplace_back(PR_LAST_MODIFICATION_TIME, phichyvals->ppropval[2].pvalue);
		tmp_propvals.emplace_back(PR_CHANGE_KEY, phichyvals->ppropval[3].pvalue);
		tmp_propvals.emplace_back(PR_PREDECESSOR_CHANGE_LIST, phichyvals->ppropval[4].pvalue);
		tmp_propvals.emplace_back(PR_DISPLAY_NAME, phichyvals->ppropval[5].pvalue);
		tmp_propvals.emplace_back(PidTagChangeNumber, &change_num);
		for (unsigned int i = 0; i < ppropvals->count; ++i)
			tmp_propvals.ppropval[tmp_propvals.count++] = ppropvals->ppropval[i];
		if (!tmp_propvals.has(PR_FOLDER_TYPE)) {
			tmp_type = FOLDER_GENERIC;
			tmp_propvals.emplace_back(PR_FOLDER_TYPE, &tmp_type);
		}
		auto pinfo = emsmdb_interface_get_emsmdb_info();
		ec_error_t ret = ecSuccess;
		if (!exmdb_client->create_folder(dir, pinfo->cpid,
		    &tmp_propvals, &tmp_fid, &ret))
			return ecError;
		if (ret != ecSuccess)
			return ret;
		if (folder_id != tmp_fid)
			return ecError;
		pctx->pstate->pseen->append(change_num);
		return ecSuccess;
	}
	if (!exmdb_client->get_folder_property(dir, CP_ACP,
	    folder_id, PR_PREDECESSOR_CHANGE_LIST, &pvalue) ||
	    pvalue == nullptr)
		return ecError;
	if (!common_util_pcl_compare(static_cast<BINARY *>(pvalue),
	    static_cast<BINARY *>(phichyvals->ppropval[4].pvalue), &result))
		return ecError;
	if (result & PCL_INCLUDE)
		return SYNC_E_IGNORE;
	if (username != STORE_OWNER_GRANTED) {
		if (!exmdb_client->get_folder_perm(dir,
		    folder_id, username, &permission))
			return ecError;
		if (!(permission & frightsOwner))
			return ecAccessDenied;
	}
	if (!exmdb_client->get_folder_property(dir, CP_ACP, folder_id,
	    PidTagParentFolderId, &pvalue) || pvalue == nullptr)
		return ecError;
	auto parent_id = *static_cast<uint64_t *>(pvalue);
	if (parent_id != parent_id1) {
		/* MS-OXCFXICS 3.3.5.8.8 move folders
		within public mailbox is not supported */
		if (!plogon->is_private())
			return ecNotSupported;
		if (rop_util_get_gc_value(folder_id) < CUSTOM_EID_BEGIN)
			return ecAccessDenied;
		if (plogon->logon_mode != logon_mode::owner) {
			if (!exmdb_client->get_folder_perm(dir,
			    parent_id1, rpc_info.username, &permission))
				return ecError;
			if (!(permission & frightsCreateSubfolder))
				return ecAccessDenied;
			b_guest = TRUE;
		} else {
			b_guest = FALSE;
		}
		auto pinfo = emsmdb_interface_get_emsmdb_info();
		ec_error_t err = ecSuccess;
		if (!exmdb_client->movecopy_folder(dir, pinfo->cpid, b_guest,
		    rpc_info.username, parent_id, folder_id, parent_id1,
		    static_cast<char *>(phichyvals->ppropval[5].pvalue), false,
		    &err))
			return ecError;
		if (err != ecSuccess)
			return err;
	}
	if (!exmdb_client->allocate_cn(dir, &change_num))
		return ecError;
	tmp_propvals.count = 0;
	tmp_propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(5 + ppropvals->count);
	if (tmp_propvals.ppropval == nullptr)
		return ecServerOOM;
	tmp_propvals.ppropval[0].proptag = PR_LAST_MODIFICATION_TIME;
	tmp_propvals.ppropval[0].pvalue = phichyvals->ppropval[2].pvalue;
	tmp_propvals.ppropval[1].proptag = PR_CHANGE_KEY;
	tmp_propvals.ppropval[1].pvalue = phichyvals->ppropval[3].pvalue;
	tmp_propvals.ppropval[2].proptag = PR_PREDECESSOR_CHANGE_LIST;
	tmp_propvals.ppropval[2].pvalue = phichyvals->ppropval[4].pvalue;
	tmp_propvals.ppropval[3].proptag = PR_DISPLAY_NAME;
	tmp_propvals.ppropval[3].pvalue = phichyvals->ppropval[5].pvalue;
	tmp_propvals.ppropval[4].proptag = PidTagChangeNumber;
	tmp_propvals.ppropval[4].pvalue = &change_num;
	tmp_propvals.count = 5;
	for (unsigned int i = 0; i < ppropvals->count; ++i)
		tmp_propvals.ppropval[tmp_propvals.count++] = ppropvals->ppropval[i];
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (!exmdb_client->set_folder_properties(dir,
	    pinfo->cpid, folder_id, &tmp_propvals, &tmp_problems))
		return ecError;
	pctx->pstate->pseen->append(change_num);
	return ecSuccess;
}

ec_error_t rop_syncimportdeletes(uint8_t flags, const TPROPVAL_ARRAY *ppropvals,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	XID tmp_xid;
	void *pvalue;
	BOOL b_exist;
	uint64_t eid;
	BOOL b_owner;
	BOOL b_result;
	BOOL b_partial;
	ems_objtype object_type;
	uint16_t replid;
	uint32_t permission;
	EID_ARRAY message_ids;
	
	if (ppropvals->count != 1 ||
	    ppropvals->ppropval[0].proptag != PROP_TAG(PT_MV_BINARY, 0)) {
		mlog(LV_WARN, "W-2150: importdeletes expected proptag 00001102h, but got tag %xh",
		        ppropvals->ppropval[0].proptag);
		return ecInvalidParam;
	}
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto pctx = rop_proc_get_obj<icsupctx_object>(plogmap, logon_id, hin, &object_type);
	if (pctx == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::icsupctx)
		return ecNotSupported;
	auto sync_type = pctx->get_sync_type();
	BOOL b_hard = (flags & SYNC_DELETES_FLAG_HARDDELETE) ? TRUE : false;
	if ((flags & SYNC_DELETES_FLAG_HIERARCHY) && sync_type == SYNC_TYPE_CONTENTS)
		return ecNotSupported;
	pctx->mark_started();
	auto pfolder = pctx->get_parent_object();
	auto folder_id = pfolder->folder_id;
	auto dir = plogon->get_dir();
	auto username = plogon->eff_user();
	if (username != STORE_OWNER_GRANTED &&
	    sync_type == SYNC_TYPE_CONTENTS &&
	    !exmdb_client->get_folder_perm(dir,
	    folder_id, username, &permission)) {
		if (permission & (frightsOwner | frightsDeleteAny))
			username = NULL;
		else if (!(permission & frightsDeleteOwned))
			return ecAccessDenied;
	}
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	auto pbins = static_cast<BINARY_ARRAY *>(ppropvals->ppropval[0].pvalue);
	if (SYNC_TYPE_CONTENTS == sync_type) {
		message_ids.count = 0;
		message_ids.pids = cu_alloc<uint64_t>(pbins->count);
		if (message_ids.pids == nullptr)
			return ecServerOOM;
	}
	for (size_t i = 0; i < pbins->count; ++i) {
		if (22 != pbins->pbin[i].cb) {
			mlog(LV_WARN, "W-2151: importdeletes expected 22-byte XID, "
 			        "but got a %u-long object instead", pbins->pbin[i].cb);
			return ecInvalidParam;
		}
		if (!common_util_binary_to_xid(&pbins->pbin[i], &tmp_xid))
			return ecError;
		if (plogon->is_private()) {
			auto tmp_guid = rop_util_make_user_guid(plogon->account_id);
			if (tmp_guid != tmp_xid.guid) {
				mlog(LV_WARN, "W-2152: importdeletes expected store %s but got store+XID %s",
				        bin2hex(&tmp_guid, sizeof(tmp_guid)).c_str(),
				        bin2hex(&tmp_xid, tmp_xid.size).c_str());
				return ecInvalidParam;
			}
			eid = rop_util_make_eid(1, tmp_xid.local_to_gc());
		} else if (sync_type == SYNC_TYPE_CONTENTS) {
			auto tmp_guid = rop_util_make_domain_guid(plogon->account_id);
			if (tmp_guid != tmp_xid.guid) {
				mlog(LV_WARN, "W-2153: importdeletes expected store %s but got store+XID %s",
				        bin2hex(&tmp_guid, sizeof(tmp_guid)).c_str(),
				        bin2hex(&tmp_xid, tmp_xid.size).c_str());
				return ecInvalidParam;
			}
			eid = rop_util_make_eid(1, tmp_xid.local_to_gc());
		} else {
			auto tmp_guid = rop_util_make_domain_guid(plogon->account_id);
			if (tmp_guid != tmp_xid.guid) {
				auto domain_id = rop_util_get_domain_id(tmp_xid.guid);
				if (domain_id == -1)
					return ecInvalidParam;
				if (!mysql_adaptor_check_same_org(domain_id,
				    plogon->account_id))
					return ecInvalidParam;
				ec_error_t ret = ecSuccess;
				if (!exmdb_client->get_mapping_replid(dir,
				    tmp_xid.guid, &replid, &ret))
					return ecError;
				if (ret != ecSuccess)
					return ret;
				eid = rop_util_make_eid(replid, tmp_xid.local_to_gc());
			} else {
				eid = rop_util_make_eid(1, tmp_xid.local_to_gc());
			}
		}
		if (SYNC_TYPE_CONTENTS == sync_type) {
			if (!exmdb_client->is_msg_present(dir,
			    folder_id, eid, &b_exist))
				return ecError;
		} else if (!exmdb_client->is_folder_present(dir,
		    eid, &b_exist)) {
			return ecError;
		}
		if (!b_exist)
			continue;
		if (username != STORE_OWNER_GRANTED) {
			if (SYNC_TYPE_CONTENTS == sync_type) {
				if (!exmdb_client->is_message_owner(dir,
				    eid, username, &b_owner))
					return ecError;
				if (!b_owner)
					return ecAccessDenied;
			} else if (!exmdb_client->get_folder_perm(dir,
			    eid, username, &permission) && !(permission & frightsOwner)) {
				return ecAccessDenied;
			}
		}
		if (SYNC_TYPE_CONTENTS == sync_type) {
			message_ids.pids[message_ids.count++] = eid;
		} else {
			unsigned int empty_flags = DEL_MESSAGES | DEL_ASSOCIATED | DEL_FOLDERS;
			empty_flags |= b_hard ? DELETE_HARD_DELETE : 0;
			if (plogon->is_private()) {
				if (!exmdb_client->get_folder_property(dir,
				    CP_ACP, eid, PR_FOLDER_TYPE, &pvalue))
					return ecError;
				if (pvalue == nullptr)
					return ecSuccess;
				if (*static_cast<uint32_t *>(pvalue) == FOLDER_SEARCH)
					goto DELETE_FOLDER;
			}
			if (!exmdb_client->empty_folder(dir,
			    pinfo->cpid, username, eid, empty_flags,
			    &b_partial) || b_partial)
				return ecError;
 DELETE_FOLDER:
			if (!exmdb_client->delete_folder(dir,
			    pinfo->cpid, eid, b_hard, &b_result) || !b_result)
				return ecError;
		}
	}
	if (sync_type == SYNC_TYPE_CONTENTS && message_ids.count > 0 &&
	    (!exmdb_client->delete_messages(dir, pinfo->cpid, nullptr,
	    folder_id, &message_ids, b_hard, &b_partial) || b_partial))
		return ecError;
	return ecSuccess;
}

ec_error_t rop_syncimportmessagemove(const BINARY *psrc_folder_id,
    const BINARY *psrc_message_id, const BINARY *pchange_list,
    const BINARY *pdst_message_id, const BINARY *pchange_number,
    uint64_t *pmessage_id, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	XID xid_src;
	XID xid_dst;
	XID xid_fsrc;
	void *pvalue;
	BOOL b_exist;
	BOOL b_owner;
	BOOL b_result;
	uint32_t result;
	ems_objtype object_type;
	uint32_t permission;
	TAGGED_PROPVAL tmp_propval;
	
	if (22 != psrc_folder_id->cb ||
		22 != psrc_message_id->cb ||
	    pdst_message_id->cb != 22)
		return ecInvalidParam;
	if (pchange_number->cb < 17 || pchange_number->cb > 24)
		return ecInvalidParam;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto pctx = rop_proc_get_obj<icsupctx_object>(plogmap, logon_id, hin, &object_type);
	if (pctx == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::icsupctx)
		return ecNotSupported;
	if (pctx->get_sync_type() != SYNC_TYPE_CONTENTS)
		return ecNotSupported;
	pctx->mark_started();
	auto pfolder = pctx->get_parent_object();
	auto folder_id = pfolder->folder_id;
	if (!common_util_binary_to_xid(psrc_folder_id, &xid_fsrc) ||
	    !common_util_binary_to_xid(psrc_message_id, &xid_src) ||
	    !common_util_binary_to_xid(pdst_message_id, &xid_dst))
		return ecError;
	auto tmp_guid = plogon->guid();
	if (tmp_guid != xid_fsrc.guid || tmp_guid != xid_src.guid ||
	    tmp_guid != xid_dst.guid)
		return ecInvalidParam;
	auto src_fid = rop_util_make_eid(1, xid_fsrc.local_to_gc());
	auto src_mid = rop_util_make_eid(1, xid_src.local_to_gc());
	auto dst_mid = rop_util_make_eid(1, xid_dst.local_to_gc());
	auto dir = plogon->get_dir();
	if (!exmdb_client->is_msg_present(dir, src_fid, src_mid, &b_exist))
		return ecError;
	/*
	 * No client would normally try to move an entity they have not seen
	 * before (ecNotFound). As such, every practical move operation will
	 * either succeed, or {fail because the object is no longer there}
	 * (SYNC_E_OBJECT_DELETED). Cf. tombstoning mechanism in LDAP for
	 * something similar.
	 */
	if (!b_exist)
		return SYNC_E_OBJECT_DELETED;
	auto rpc_info = get_rpc_info();
	if (plogon->logon_mode != logon_mode::owner) {
		if (!exmdb_client->get_folder_perm(dir,
		    src_fid, rpc_info.username, &permission))
			return ecError;
		if (permission & frightsDeleteAny) {
			/* do nothing */
		} else if (permission & frightsDeleteOwned) {
			if (!exmdb_client->is_message_owner(dir,
			    src_mid, rpc_info.username, &b_owner))
				return ecError;
			if (!b_owner)
				return ecAccessDenied;
		} else {
			return ecAccessDenied;
		}
		if (!exmdb_client->get_folder_perm(dir,
		    folder_id, rpc_info.username, &permission))
			return ecError;
		if (!(permission & frightsCreate))
			return ecAccessDenied;
	}
	if (!exmdb_client->get_message_property(dir, nullptr, CP_ACP,
	    src_mid, PR_ASSOCIATED, &pvalue))
		return ecError;
	if (pvalue == nullptr)
		return ecNotFound;
	BOOL b_fai = *static_cast<uint8_t *>(pvalue) != 0 ? TRUE : false;
	if (!exmdb_client->get_message_property(dir, nullptr, CP_ACP,
	    src_mid, PR_PREDECESSOR_CHANGE_LIST, &pvalue))
		return ecError;
	if (pvalue == nullptr)
		return ecError;
	if (!common_util_pcl_compare(static_cast<BINARY *>(pvalue), pchange_list, &result))
		return ecError;
	BOOL b_newer = result == PCL_INCLUDED ? TRUE : false;
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (!exmdb_client->movecopy_message(dir, pinfo->cpid, src_mid,
	    folder_id, dst_mid, TRUE, &b_result) || !b_result)
		return ecError;
	if (b_newer) {
		uint32_t result_unused;
		tmp_propval.proptag = PR_PREDECESSOR_CHANGE_LIST;
		tmp_propval.pvalue = pvalue;
		exmdb_client->set_message_property(dir, nullptr,
			CP_ACP, dst_mid, &tmp_propval, &result_unused);
	}
	if (!exmdb_client->get_message_property(dir, nullptr, CP_ACP,
	    dst_mid, PidTagChangeNumber, &pvalue) || pvalue == nullptr)
		return ecError;
	auto &s = b_fai ? pctx->pstate->pseen_fai : pctx->pstate->pseen;
	s->append(*static_cast<uint64_t *>(pvalue));
	pctx->pstate->pgiven->append(dst_mid);
	*pmessage_id = 0;
	if (b_newer)
		return SYNC_W_CLIENT_CHANGE_NEWER;
	return ecSuccess;
}

ec_error_t rop_syncopencollector(uint8_t is_content_collector, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	ems_objtype object_type;
	
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto pfolder = rop_proc_get_obj<folder_object>(plogmap, logon_id, hin, &object_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::folder)
		return ecNotSupported;
	uint8_t sync_type = is_content_collector == 0 ? SYNC_TYPE_HIERARCHY : SYNC_TYPE_CONTENTS;
	auto pctx = icsupctx_object::create(plogon, pfolder, sync_type);
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, {ems_objtype::icsupctx, std::move(pctx)});
	if (hnd < 0)
		return aoh_to_error(hnd);
	*phout = hnd;
	return ecSuccess;
}

ec_error_t rop_syncgettransferstate(LOGMAP *plogmap, uint8_t logon_id,
    uint32_t hin, uint32_t *phout)
{
	ems_objtype object_type;
	ics_state *pstate;

	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto pobject = rop_processor_get_object(plogmap, logon_id, hin, &object_type);
	if (pobject == nullptr)
		return ecNullObject;
	if (object_type == ems_objtype::icsdownctx)
		pstate = static_cast<icsdownctx_object *>(pobject)->get_state();
	else if (object_type == ems_objtype::icsupctx)
		pstate = static_cast<icsupctx_object *>(pobject)->get_state();
	else
		return ecNotSupported;
	if (pstate == nullptr)
		return ecError;
	auto pctx = fastdownctx_object::create(plogon, 0);
	if (pctx == nullptr)
		return ecError;
	if (!pctx->make_state(pstate))
		return ecError;
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, {ems_objtype::fastdownctx, std::move(pctx)});
	if (hnd < 0)
		return aoh_to_error(hnd);
	*phout = hnd;
	return ecSuccess;
}

ec_error_t rop_syncuploadstatestreambegin(uint32_t proptag_state,
    uint32_t buffer_size, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	auto pctx = rop_processor_get_object(plogmap, logon_id, hin, &object_type);
	if (pctx == nullptr)
		return ecNullObject;
	if (object_type == ems_objtype::icsdownctx) {
		if (!static_cast<icsdownctx_object *>(pctx)->begin_state_stream(proptag_state))
			return ecError;
	} else if (object_type == ems_objtype::icsupctx) {
		if (!static_cast<icsupctx_object *>(pctx)->begin_state_stream(proptag_state))
			return ecError;
	} else {
		return ecNotSupported;
	}
	return ecSuccess;
}

ec_error_t rop_syncuploadstatestreamcontinue(const BINARY *pstream_data,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	auto pctx = rop_processor_get_object(plogmap, logon_id, hin, &object_type);
	if (pctx == nullptr)
		return ecNullObject;
	if (object_type == ems_objtype::icsdownctx) {
		if (!static_cast<icsdownctx_object *>(pctx)->continue_state_stream(pstream_data))
			return ecError;
	} else if (object_type == ems_objtype::icsupctx) {
		if (!static_cast<icsupctx_object *>(pctx)->continue_state_stream(pstream_data))
			return ecError;
	} else {
		return ecNotSupported;
	}
	return ecSuccess;
}

ec_error_t rop_syncuploadstatestreamend(LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	auto pctx = rop_processor_get_object(plogmap, logon_id, hin, &object_type);
	if (pctx == nullptr)
		return ecNullObject;
	if (object_type == ems_objtype::icsdownctx) {
		if (!static_cast<icsdownctx_object *>(pctx)->end_state_stream())
			return ecError;
	} else if (object_type == ems_objtype::icsupctx) {
		if (!static_cast<icsupctx_object *>(pctx)->end_state_stream())
			return ecError;
	} else {
		return ecNotSupported;
	}
	return ecSuccess;
}

ec_error_t rop_setlocalreplicamidsetdeleted(uint32_t count,
    const LONG_TERM_ID_RANGE *prange, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	return ecSuccess;
}

ec_error_t rop_getlocalreplicaids(uint32_t count, GUID *pguid,
    GLOBCNT *pglobal_count, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	uint64_t begin_eid;
	auto plogon = rop_proc_get_obj<logon_object>(plogmap, logon_id, hin, &object_type);
	if (plogon == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::logon)
		return ecError;
	if (!exmdb_client->allocate_ids(plogon->get_dir(), count, &begin_eid))
		return ecError;
	/* allocate too many eids within an interval */
	if (begin_eid == 0)
		return ecError;
	*pguid = plogon->guid();
	*pglobal_count = rop_util_get_gc_array(begin_eid);
	return ecSuccess;
}
