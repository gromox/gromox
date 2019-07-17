#include "rops.h"
#include "rop_util.h"
#include "common_util.h"
#include "proc_common.h"
#include "exmdb_client.h"
#include "logon_object.h"
#include "table_object.h"
#include "folder_object.h"
#include "rop_processor.h"
#include "processor_types.h"


uint32_t rop_openfolder(uint64_t folder_id,
	uint8_t open_flags, uint8_t *phas_rules,
	GHOST_SERVER **ppghost, void *plogmap,
	uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	BOOL b_del;
	uint8_t type;
	BOOL b_exist;
	void *pvalue;
	uint16_t replid;
	int object_type;
	uint64_t fid_val;
	uint32_t tag_access;
	uint32_t permission;
	DCERPC_INFO rpc_info;
	LOGON_OBJECT *plogon;
	FOLDER_OBJECT *pfolder;
	
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	if (NULL == rop_processor_get_object(plogmap,
		logon_id, hin, &object_type)) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_LOGON != object_type &&
		OBJECT_TYPE_FOLDER != object_type) {
		return EC_NOT_SUPPORTED;	
	}
	replid = rop_util_get_replid(folder_id);
	if (TRUE == logon_object_check_private(plogon)) {
		if (1 != replid) {
			return EC_INVALID_PARAMETER;
		}
	} else {
		if (1 != replid) {
			*phas_rules = 0;
			*ppghost = common_util_alloc(sizeof(GHOST_SERVER));
			if (NULL == ppghost) {
				return EC_OUT_OF_MEMORY;
			}
			return rop_getowningservers(folder_id,
					*ppghost, plogmap, logon_id, hin);
		}
	}
	if (FALSE == exmdb_client_check_folder_id(
		logon_object_get_dir(plogon), folder_id, &b_exist)) {
		return EC_ERROR;	
	}
	if (FALSE == b_exist) {
		return EC_NOT_FOUND;
	}
	if (FALSE == logon_object_check_private(plogon)) {
		if (FALSE == exmdb_client_check_folder_deleted(
			logon_object_get_dir(plogon), folder_id, &b_del)) {
			return EC_ERROR;	
		}
		if (TRUE == b_del && 0 == (open_flags &
			OPEN_FOLDER_FLAG_OPENSOFTDELETED)) {
			return EC_NOT_FOUND;
		}
	}
	if (FALSE == exmdb_client_get_folder_property(
		logon_object_get_dir(plogon), 0, folder_id,
		PROP_TAG_FOLDERTYPE, &pvalue) || NULL == pvalue) {
		return EC_ERROR;	
	}
	type = *(uint32_t*)pvalue;
	rpc_info = get_rpc_info();
	if (LOGON_MODE_OWNER == logon_object_get_mode(plogon)) {
		tag_access = TAG_ACCESS_MODIFY | TAG_ACCESS_READ |
				TAG_ACCESS_DELETE | TAG_ACCESS_HIERARCHY |
				TAG_ACCESS_CONTENTS | TAG_ACCESS_FAI_CONTENTS;
	} else {
		if (FALSE == exmdb_client_check_folder_permission(
			logon_object_get_dir(plogon), folder_id,
			rpc_info.username, &permission)) {
			return EC_ERROR;	
		}
		if (0 == permission) {
			fid_val = rop_util_get_gc_value(folder_id);
			if (TRUE == logon_object_check_private(plogon)) {
				if (PRIVATE_FID_ROOT == fid_val ||
					PRIVATE_FID_IPMSUBTREE == fid_val) {
					permission = PERMISSION_FOLDERVISIBLE;
				}
			} else {
				if (PUBLIC_FID_ROOT == fid_val) {
					permission = PERMISSION_FOLDERVISIBLE;
				}
			}
		}
		if (0 == (permission & PERMISSION_READANY) &&
			0 == (permission & PERMISSION_FOLDERVISIBLE) &&
			0 == (permission & PERMISSION_FOLDEROWNER)) {
			/* same as exchange 2013, not EC_ACCESS_DENIED */
			return EC_NOT_FOUND;
		}
		if (permission & PERMISSION_FOLDEROWNER) {
			tag_access = TAG_ACCESS_MODIFY | TAG_ACCESS_READ |
				TAG_ACCESS_DELETE | TAG_ACCESS_HIERARCHY |
				TAG_ACCESS_CONTENTS | TAG_ACCESS_FAI_CONTENTS;
		} else {
			tag_access = TAG_ACCESS_READ;
			if (permission & PERMISSION_CREATE) {
				tag_access |= TAG_ACCESS_CONTENTS |
							TAG_ACCESS_FAI_CONTENTS;
			}
			if (permission & PERMISSION_CREATESUBFOLDER) {
				tag_access |= TAG_ACCESS_HIERARCHY;
			}
		}
	}
	if (FALSE == exmdb_client_get_folder_property(
		logon_object_get_dir(plogon), 0, folder_id,
		PROP_TAG_HASRULES, &pvalue)) {
		return EC_ERROR;
	}
	if (NULL == pvalue) {
		*phas_rules = 0;
	} else {
		*phas_rules = *(uint8_t*)pvalue;
	}
	pfolder = folder_object_create(plogon,
			folder_id, type, tag_access);
	if (NULL == pfolder) {
		return EC_OUT_OF_MEMORY;
	}
	*phout = rop_processor_add_object_handle(plogmap,
		logon_id, hin, OBJECT_TYPE_FOLDER, pfolder);
	if (*phout < 0) {
		folder_object_free(pfolder);
		return EC_ERROR;
	}
	*ppghost = NULL;
	return EC_SUCCESS;
}

uint32_t rop_createfolder(uint8_t folder_type,
	uint8_t use_unicode, uint8_t open_existing,
	uint8_t reserved, const char *pfolder_name,
	const char *pfolder_comment, uint64_t *pfolder_id,
	uint8_t *pis_existing, uint8_t *phas_rules,
	GHOST_SERVER **ppghost, void *plogmap,
	uint8_t logon_id,  uint32_t hin, uint32_t *phout)
{
	XID tmp_xid;
	void *pvalue;
	uint64_t tmp_id;
	int object_type;
	uint32_t result;
	BINARY *pentryid;
	uint32_t tmp_type;
	EMSMDB_INFO *pinfo;
	uint64_t last_time;
	uint64_t parent_id;
	uint64_t folder_id;
	uint64_t change_num;
	uint32_t tag_access;
	uint32_t permission;
	DCERPC_INFO rpc_info;
	LOGON_OBJECT *plogon;
	char folder_name[256];
	FOLDER_OBJECT *pfolder;
	FOLDER_OBJECT *pparent;
	char folder_comment[1024];
	TPROPVAL_ARRAY tmp_propvals;
	PERMISSION_DATA permission_row;
	TAGGED_PROPVAL propval_buff[10];
	
	
	switch (folder_type) {
	case FOLDER_TYPE_GENERIC:
	case FOLDER_TYPE_SEARCH:
		break;
	default:
		return EC_INVALID_PARAMETER;	
	}
	pparent = rop_processor_get_object(plogmap, logon_id, hin, &object_type);
	if (NULL == pparent) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_FOLDER != object_type) {
		return EC_NOT_SUPPORTED;
	}
	if (1 != rop_util_get_replid(folder_object_get_id(pparent))) {
		return EC_ACCESS_DENIED;
	}
	if (FOLDER_TYPE_SEARCH == folder_object_get_type(pparent)) {
		return EC_NOT_SUPPORTED;
	}
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	if (FALSE == logon_object_check_private(plogon) &&
		FOLDER_TYPE_SEARCH == folder_type) {
		return EC_NOT_SUPPORTED;
	}
	if (0 == use_unicode) {
		if (common_util_convert_string(TRUE, pfolder_name,
			folder_name, sizeof(folder_name)) < 0) {
			return EC_INVALID_PARAMETER;	
		}
		if (common_util_convert_string(TRUE, pfolder_comment,
			folder_comment, sizeof(folder_comment)) < 0) {
			return EC_INVALID_PARAMETER;	
		}
	} else {
		if (strlen(pfolder_name) >= sizeof(folder_name)) {
			return EC_INVALID_PARAMETER;
		}
		strcpy(folder_name, pfolder_name);
		strncpy(folder_comment, pfolder_comment, sizeof(folder_comment));
	}
	rpc_info = get_rpc_info();
	if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
		if (FALSE == exmdb_client_check_folder_permission(
			logon_object_get_dir(plogon),
			folder_object_get_id(pparent),
			rpc_info.username, &permission)) {
			return EC_ERROR;	
		}
		if (0 == (permission & PERMISSION_FOLDEROWNER) &&
			0 == (permission & PERMISSION_CREATESUBFOLDER)) {
			return EC_ACCESS_DENIED;
		}
	}
	if (FALSE == exmdb_client_get_folder_by_name(
		logon_object_get_dir(plogon),
		folder_object_get_id(pparent),
		folder_name, &folder_id)) {
		return EC_ERROR;
	}
	if (0 != folder_id) {
		if (FALSE == exmdb_client_get_folder_property(
			logon_object_get_dir(plogon), 0, folder_id,
			PROP_TAG_FOLDERTYPE, &pvalue) || NULL == pvalue) {
			return EC_ERROR;	
		}
		if (0 == open_existing || folder_type != *(uint32_t*)pvalue) {
			return EC_DUPLICATE_NAME;
		}
	} else {
		parent_id = folder_object_get_id(pparent);
		if (FALSE == exmdb_client_allocate_cn(
			logon_object_get_dir(plogon), &change_num)) {
			return EC_ERROR;
		}
		tmp_type = folder_type;
		last_time = rop_util_current_nttime();
		tmp_propvals.count = 9;
		tmp_propvals.ppropval = propval_buff;
		propval_buff[0].proptag = PROP_TAG_PARENTFOLDERID;
		propval_buff[0].pvalue = &parent_id;
		propval_buff[1].proptag = PROP_TAG_FOLDERTYPE;
		propval_buff[1].pvalue = &tmp_type;
		propval_buff[2].proptag = PROP_TAG_DISPLAYNAME;
		propval_buff[2].pvalue = folder_name;
		propval_buff[3].proptag = PROP_TAG_COMMENT;
		propval_buff[3].pvalue = folder_comment;
		propval_buff[4].proptag = PROP_TAG_CREATIONTIME;
		propval_buff[4].pvalue = &last_time;
		propval_buff[5].proptag = PROP_TAG_LASTMODIFICATIONTIME;
		propval_buff[5].pvalue = &last_time;
		propval_buff[6].proptag = PROP_TAG_CHANGENUMBER;
		propval_buff[6].pvalue = &change_num;
		if (TRUE == logon_object_check_private(plogon)) {
			tmp_xid.guid = rop_util_make_user_guid(
				logon_object_get_account_id(plogon));
		} else {
			tmp_xid.guid = rop_util_make_domain_guid(
				logon_object_get_account_id(plogon));
		}
		rop_util_get_gc_array(change_num, tmp_xid.local_id);
		propval_buff[7].proptag = PROP_TAG_CHANGEKEY;
		propval_buff[7].pvalue = common_util_xid_to_binary(22, &tmp_xid);
		if (NULL == propval_buff[7].pvalue) {
			return EC_OUT_OF_MEMORY;
		}
		propval_buff[8].proptag = PROP_TAG_PREDECESSORCHANGELIST;
		propval_buff[8].pvalue = common_util_pcl_append(
							NULL, propval_buff[7].pvalue);
		if (NULL == propval_buff[8].pvalue) {
			return EC_OUT_OF_MEMORY;
		}
		pinfo = emsmdb_interface_get_emsmdb_info();
		if (FALSE == exmdb_client_create_folder_by_properties(
			logon_object_get_dir(plogon), pinfo->cpid,
			&tmp_propvals, &folder_id)) {
			return EC_ERROR;
		}
		if (0 == folder_id) {
			return EC_ERROR;
		}
		if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
			pentryid = common_util_username_to_addressbook_entryid(
												rpc_info.username);
			if (NULL == pentryid) {
				return EC_OUT_OF_MEMORY;
			}
			tmp_id = 1;
			permission = PERMISSION_FOLDEROWNER|PERMISSION_READANY|
						PERMISSION_FOLDERVISIBLE|PERMISSION_CREATE|
						PERMISSION_EDITANY|PERMISSION_DELETEANY|
						PERMISSION_CREATESUBFOLDER;
			permission_row.flags = PERMISSION_DATA_FLAG_ADD_ROW;
			permission_row.propvals.count = 3;
			permission_row.propvals.ppropval = propval_buff;
			propval_buff[0].proptag = PROP_TAG_ENTRYID;
			propval_buff[0].pvalue = pentryid;
			propval_buff[1].proptag = PROP_TAG_MEMBERID;
			propval_buff[1].pvalue = &tmp_id;
			propval_buff[2].proptag = PROP_TAG_MEMBERRIGHTS;
			propval_buff[2].pvalue = &permission;
			if (FALSE == exmdb_client_update_folder_permission(
				logon_object_get_dir(plogon), folder_id,
				FALSE, 1, &permission_row)) {
				return EC_ERROR;
			}
		}
	}
	tag_access = TAG_ACCESS_MODIFY | TAG_ACCESS_READ |
				TAG_ACCESS_DELETE | TAG_ACCESS_HIERARCHY |
				TAG_ACCESS_CONTENTS | TAG_ACCESS_FAI_CONTENTS;
	pfolder = folder_object_create(plogon,
		folder_id, folder_type, tag_access);
	if (NULL == pfolder) {
		return EC_OUT_OF_MEMORY;
	}
	*phout = rop_processor_add_object_handle(plogmap,
		logon_id, hin, OBJECT_TYPE_FOLDER, pfolder);
	if (*phout < 0) {
		folder_object_free(pfolder);
		return EC_ERROR;
	}
	*pfolder_id = folder_id;
	*pis_existing = 0; /* just like exchange 2010 or later */
	/* no need to set value for "phas_rules" */
	*ppghost = NULL;
	return EC_SUCCESS;
}

uint32_t rop_deletefolder(uint8_t flags,
	uint64_t folder_id, uint8_t *ppartial_completion,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	BOOL b_fai;
	BOOL b_sub;
	BOOL b_hard;
	BOOL b_done;
	void *pvalue;
	BOOL b_exist;
	BOOL b_normal;
	BOOL b_partial;
	int object_type;
	EMSMDB_INFO *pinfo;
	uint32_t permission;
	DCERPC_INFO rpc_info;
	LOGON_OBJECT *plogon;
	const char *username;
	FOLDER_OBJECT *pfolder;
	
	*ppartial_completion = 1;
	pfolder = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == pfolder) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_FOLDER != object_type) {
		return EC_NOT_SUPPORTED;
	}
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	 if (TRUE == logon_object_check_private(plogon)) {
		if (rop_util_get_gc_value(folder_id) < PRIVATE_FID_CUSTOM) {
			return EC_ACCESS_DENIED;
		}
	} else {
		if (1 == rop_util_get_replid(folder_id) &&
			rop_util_get_gc_value(folder_id) < PUBLIC_FID_CUSTOM) {
			return EC_ACCESS_DENIED;
		}
	}
	pinfo = emsmdb_interface_get_emsmdb_info();
	rpc_info = get_rpc_info();
	username = NULL;
	if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
		if (FALSE == exmdb_client_check_folder_permission(
			logon_object_get_dir(plogon), folder_id,
			rpc_info.username, &permission)) {
			return EC_ERROR;	
		}
		if (0 == (permission & PERMISSION_FOLDEROWNER)) {
			return EC_ACCESS_DENIED;
		}
		username = rpc_info.username;
	}
	if (FALSE == exmdb_client_check_folder_id(
		logon_object_get_dir(plogon), folder_id,
		&b_exist)) {
		return EC_ERROR;
	}
	if (FALSE == b_exist) {
		*ppartial_completion = 0;
		return EC_SUCCESS;
	}
	if (flags & DELETE_FOLDER_FLAG_MESSAGES) {
		b_normal = TRUE;
		b_fai = TRUE;
	} else {
		b_normal = FALSE;
		b_fai = FALSE;
	}
	if (flags & DELETE_FOLDER_FLAG_FOLDERS) {
		b_sub = TRUE;
	} else {
		b_sub = FALSE;
	}
	if (flags & DELETE_FOLDER_FLAG_HARD_DELETE) {
		b_hard = TRUE;
	} else {
		b_hard = FALSE;
	}
	if (TRUE == logon_object_check_private(plogon)) {
		if (FALSE == exmdb_client_get_folder_property(
			logon_object_get_dir(plogon), 0, folder_id,
			PROP_TAG_FOLDERTYPE, &pvalue)) {
			return EC_ERROR;	
		}
		if (NULL == pvalue) {
			*ppartial_completion = 0;
			return EC_SUCCESS;
		}
		if (FOLDER_TYPE_SEARCH == *(uint32_t*)pvalue) {
			goto DELETE_FOLDER;
		}
	}
	if (TRUE == b_sub || TRUE == b_normal || TRUE == b_fai) {
		if (FALSE == exmdb_client_empty_folder(
			logon_object_get_dir(plogon), pinfo->cpid, username,
			folder_id, b_hard, b_normal, b_fai, b_sub, &b_partial)) {
			return EC_ERROR;
		}
		if (TRUE == b_partial) {
			/* failure occurs, stop deleting folder */
			*ppartial_completion = 1;
			return EC_SUCCESS;
		}
	}
DELETE_FOLDER:
	if (FALSE == exmdb_client_delete_folder(
		logon_object_get_dir(plogon), pinfo->cpid,
		folder_id, b_hard, &b_done)) {
		return EC_ERROR;
	}
	if (TRUE == b_done) {
		*ppartial_completion = 0;
	} else {
		*ppartial_completion = 1;
	}
	return EC_SUCCESS;
}

uint32_t rop_setsearchcriteria(const RESTRICTION *pres,
	const LONGLONG_ARRAY *pfolder_ids, uint32_t search_flags,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	int i;
	BOOL b_result;
	int object_type;
	EMSMDB_INFO *pinfo;
	uint32_t permission;
	DCERPC_INFO rpc_info;
	LOGON_OBJECT *plogon;
	uint32_t search_status;
	FOLDER_OBJECT *pfolder;
	
	if (0 == (search_flags & SEARCH_FLAG_RESTART) &&
		0 == (search_flags & SEARCH_FLAG_STOP)) {
		/* make the default search_flags */
		search_flags |= SEARCH_FLAG_STOP;	
	}
	if (0 == (search_flags & SEARCH_FLAG_RECURSIVE) &&
		0 == (search_flags & SEARCH_FLAG_SHALLOW)) {
		/* make the default search_flags */
		search_flags |= SEARCH_FLAG_SHALLOW;
	}
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	if (FALSE == logon_object_check_private(plogon)) {
		return EC_NOT_SUPPORTED;
	}
	pfolder = rop_processor_get_object(plogmap, logon_id, hin, &object_type);
	if (NULL == pfolder) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_FOLDER != object_type) {
		return EC_NOT_SUPPORTED;
	}
	if (FOLDER_TYPE_SEARCH != folder_object_get_type(pfolder)) {
		return EC_NOT_SEARCH_FOLDER;
	}
	rpc_info = get_rpc_info();
	if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
		if (FALSE == exmdb_client_check_folder_permission(
			logon_object_get_dir(plogon),
			folder_object_get_id(pfolder),
			rpc_info.username, &permission)) {
			return EC_ERROR;	
		}
		if (0 == (permission & PERMISSION_FOLDEROWNER)) {
			return EC_ACCESS_DENIED;
		}
	}
	if (NULL == pres || 0 == pfolder_ids->count) {
		if (FALSE == exmdb_client_get_search_criteria(
			logon_object_get_dir(plogon),
			folder_object_get_id(pfolder),
			&search_status, NULL, NULL)) {
			return EC_ERROR;
		}
		if (SEARCH_STATUS_NOT_INITIALIZED == search_status) {
			return EC_NOT_INITIALIZED;
		}
		if (0 == (search_flags & SEARCH_FLAG_RESTART) &&
			NULL == pres && 0 == pfolder_ids->count) {
			/* stop static search folder has no meaning,
				status of dynamic running search folder
				cannot be changed */
			return EC_SUCCESS;
		}
	}
	for (i=0; i<pfolder_ids->count; i++) {
		if (1 != rop_util_get_replid(pfolder_ids->pll[i])) {
			return EC_SEARCH_SCOPE_VIOLATED;
		}
		if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
			if (FALSE == exmdb_client_check_folder_permission(
				logon_object_get_dir(plogon), pfolder_ids->pll[i],
				rpc_info.username, &permission)) {
				return EC_ERROR;	
			}
			if (0 == (permission & PERMISSION_FOLDEROWNER) &&
				0 == (permission & PERMISSION_READANY)) {
				return EC_ACCESS_DENIED;
			}
		}
	}
	if (NULL != pres) {
		if (FALSE == common_util_convert_restriction(
			TRUE, (RESTRICTION*)pres)) {
			return EC_ERROR;
		}
	}
	pinfo = emsmdb_interface_get_emsmdb_info();
	if (FALSE == exmdb_client_set_search_criteria(
		logon_object_get_dir(plogon), pinfo->cpid,
		folder_object_get_id(pfolder), search_flags,
		pres, pfolder_ids, &b_result)) {
		return EC_ERROR;	
	}
	if (FALSE == b_result) {
		return EC_SEARCH_SCOPE_VIOLATED;
	}
	return EC_SUCCESS;
}

uint32_t rop_getsearchcriteria(uint8_t use_unicode,
	uint8_t include_restriction, uint8_t include_folders,
	RESTRICTION **ppres, LONGLONG_ARRAY *pfolder_ids,
	uint32_t *psearch_flags, void *plogmap, uint8_t logon_id,
	uint32_t hin)
{
	int i;
	int object_type;
	LOGON_OBJECT *plogon;
	FOLDER_OBJECT *pfolder;
	
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	if (FALSE == logon_object_check_private(plogon)) {
		return EC_NOT_SUPPORTED;
	}
	pfolder = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == pfolder || OBJECT_TYPE_FOLDER != object_type) {
		return EC_NULL_OBJECT;
	}
	if (FOLDER_TYPE_SEARCH != folder_object_get_type(pfolder)) {
		return EC_NOT_SEARCH_FOLDER;
	}
	if (0 == include_restriction) {
		*ppres = NULL;
		ppres = NULL;
	}
	if (0 == include_folders) {
		pfolder_ids->count = 0;
		pfolder_ids = NULL;
	}
	if (FALSE == exmdb_client_get_search_criteria(
		logon_object_get_dir(plogon),
		folder_object_get_id(pfolder),
		psearch_flags, ppres, pfolder_ids)) {
		return EC_ERROR;
	}
	if (0 == use_unicode && NULL != ppres && NULL != *ppres) {
		if (FALSE == common_util_convert_restriction(FALSE, *ppres)) {
			return EC_ERROR;
		}
	}
	return EC_SUCCESS;
}

uint32_t rop_movecopymessages(const LONGLONG_ARRAY *pmessage_ids,
	uint8_t want_asynchronous, uint8_t want_copy,
	uint8_t *ppartial_completion, void *plogmap,
	uint8_t logon_id, uint32_t hsrc, uint32_t hdst)
{
	BOOL b_copy;
	BOOL b_guest;
	EID_ARRAY ids;
	BOOL b_partial;
	int object_type;
	EMSMDB_INFO *pinfo;
	uint32_t permission;
	DCERPC_INFO rpc_info;
	LOGON_OBJECT *plogon;
	FOLDER_OBJECT *psrc_folder;
	FOLDER_OBJECT *pdst_folder;
	
	if (0 == pmessage_ids->count) {
		*ppartial_completion = 0;
		return EC_SUCCESS;
	}
	*ppartial_completion = 1;
	psrc_folder = rop_processor_get_object(plogmap,
					logon_id, hsrc, &object_type);
	if (NULL == psrc_folder) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_FOLDER != object_type) {
		return EC_NOT_SUPPORTED;
	}
	pdst_folder = rop_processor_get_object(plogmap,
					logon_id, hdst, &object_type);
	if (NULL == pdst_folder) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_FOLDER != object_type) {
		return EC_NOT_SUPPORTED;
	}
	if (FOLDER_TYPE_SEARCH == folder_object_get_type(pdst_folder)) {
		return EC_NOT_SUPPORTED;
	}
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	ids.count = pmessage_ids->count;
	ids.pids = pmessage_ids->pll;
	if (0 == want_copy) {
		b_copy = FALSE;
	} else {
		b_copy = TRUE;
	}
	rpc_info = get_rpc_info();
	if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
		if (FALSE == exmdb_client_check_folder_permission(
			logon_object_get_dir(plogon),
			folder_object_get_id(pdst_folder),
			rpc_info.username, &permission)) {
			return EC_ERROR;	
		}
		if (0 == (permission & PERMISSION_CREATE)) {
			return EC_ACCESS_DENIED;
		}
		b_guest = TRUE;
	} else {
		b_guest = FALSE;
	}
	pinfo = emsmdb_interface_get_emsmdb_info();
	if (FALSE == exmdb_client_movecopy_messages(
		logon_object_get_dir(plogon),
		logon_object_get_account_id(plogon),
		pinfo->cpid, b_guest, rpc_info.username,
		folder_object_get_id(psrc_folder),
		folder_object_get_id(pdst_folder),
		b_copy, &ids, &b_partial)) {
		return EC_ERROR;
	}
	if (TRUE == b_partial) {
		*ppartial_completion = 1;
	} else {
		*ppartial_completion = 0;
	}
	return EC_SUCCESS;
}

uint32_t rop_movefolder(uint8_t want_asynchronous,
	uint8_t use_unicode, uint64_t folder_id, const char *pnew_name,
	uint8_t *ppartial_completion, void *plogmap,
	uint8_t logon_id, uint32_t hsrc, uint32_t hdst)
{
	XID tmp_xid;
	BOOL b_exist;
	BOOL b_cycle;
	BOOL b_guest;
	BOOL b_partial;
	int object_type;
	BINARY *pbin_pcl;
	uint64_t nt_time;
	char new_name[128];
	EMSMDB_INFO *pinfo;
	uint32_t permission;
	uint64_t change_num;
	DCERPC_INFO rpc_info;
	LOGON_OBJECT *plogon;
	BINARY *pbin_changekey;
	PROBLEM_ARRAY problems;
	TPROPVAL_ARRAY propvals;
	FOLDER_OBJECT *psrc_parent;
	FOLDER_OBJECT *pdst_folder;
	TAGGED_PROPVAL propval_buff[4];
	
	*ppartial_completion = 1;
	psrc_parent = rop_processor_get_object(plogmap,
					logon_id, hsrc, &object_type);
	if (NULL == psrc_parent) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_FOLDER != object_type) {
		return EC_NOT_SUPPORTED;
	}
	pdst_folder = rop_processor_get_object(plogmap,
					logon_id, hdst, &object_type);
	if (NULL == pdst_folder) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_FOLDER != object_type) {
		return EC_NOT_SUPPORTED;
	}
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	if (0 == use_unicode) {
		if (common_util_convert_string(TRUE, pnew_name,
			new_name, sizeof(new_name)) < 0) {
			return EC_INVALID_PARAMETER;	
		}
	} else {
		if (strlen(pnew_name) >= sizeof(new_name)) {
			return EC_INVALID_PARAMETER;
		}
		strcpy(new_name, pnew_name);
	}
	rpc_info = get_rpc_info();
	if (TRUE == logon_object_check_private(plogon)) {
		if (rop_util_get_gc_value(folder_id) < PRIVATE_FID_CUSTOM) {
			return EC_ACCESS_DENIED;
		}
	} else {
		if (rop_util_get_gc_value(folder_id) < PUBLIC_FID_CUSTOM) {
			return EC_ACCESS_DENIED;
		}
	}
	if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
		if (FALSE == exmdb_client_check_folder_permission(
			logon_object_get_dir(plogon), folder_id,
			rpc_info.username, &permission)) {
			return EC_ERROR;	
		}
		if (0 == (permission & PERMISSION_FOLDEROWNER)) {
			return EC_ACCESS_DENIED;
		}
		if (FALSE == exmdb_client_check_folder_permission(
			logon_object_get_dir(plogon),
			folder_object_get_id(pdst_folder),
			rpc_info.username, &permission)) {
			return EC_ERROR;	
		}
		if (0 == (permission & PERMISSION_FOLDEROWNER) &&
			0 == (permission & PERMISSION_CREATESUBFOLDER)) {
			return EC_ACCESS_DENIED;
		}
		b_guest = TRUE;
	} else {
		b_guest = FALSE;
	}
	if (FALSE == exmdb_client_check_folder_cycle(
		logon_object_get_dir(plogon), folder_id,
		folder_object_get_id(pdst_folder), &b_cycle)) {
		return EC_ERROR;
	}
	if (TRUE == b_cycle) {
		return EC_FOLDER_CYCLE;
	}
	if (FALSE == exmdb_client_allocate_cn(
		logon_object_get_dir(plogon), &change_num)) {
		return EC_ERROR;
	}
	if (FALSE == exmdb_client_get_folder_property(
		logon_object_get_dir(plogon), 0,
		folder_id, PROP_TAG_PREDECESSORCHANGELIST,
		(void**)&pbin_pcl) || NULL == pbin_pcl) {
		return EC_ERROR;
	}
	if (TRUE == logon_object_check_private(plogon)) {
		tmp_xid.guid = rop_util_make_user_guid(
			logon_object_get_account_id(plogon));
	} else {
		tmp_xid.guid = rop_util_make_domain_guid(
			logon_object_get_account_id(plogon));
	}
	rop_util_get_gc_array(change_num, tmp_xid.local_id);
	pbin_changekey = common_util_xid_to_binary(22, &tmp_xid);
	if (NULL == pbin_changekey) {
		return EC_ERROR;
	}
	pbin_pcl = common_util_pcl_append(pbin_pcl, pbin_changekey);
	if (NULL == pbin_pcl) {
		return EC_ERROR;
	}
	pinfo = emsmdb_interface_get_emsmdb_info();
	if (FALSE == exmdb_client_movecopy_folder(
		logon_object_get_dir(plogon),
		logon_object_get_account_id(plogon),
		pinfo->cpid, b_guest, rpc_info.username,
		folder_object_get_id(psrc_parent),
		folder_id, folder_object_get_id(pdst_folder),
		new_name, FALSE, &b_exist, &b_partial)) {
		return EC_ERROR;
	}
	if (TRUE == b_exist) {
		return EC_DUPLICATE_NAME;
	}
	if (TRUE == b_partial) {
		*ppartial_completion = 1;
	} else {
		*ppartial_completion = 0;
	}
	nt_time = rop_util_current_nttime();
	propvals.count = 4;
	propvals.ppropval = propval_buff;
	propval_buff[0].proptag = PROP_TAG_CHANGENUMBER;
	propval_buff[0].pvalue = &change_num;
	propval_buff[1].proptag = PROP_TAG_CHANGEKEY;
	propval_buff[1].pvalue = pbin_changekey;
	propval_buff[2].proptag = PROP_TAG_PREDECESSORCHANGELIST;
	propval_buff[2].pvalue = pbin_pcl;
	propval_buff[3].proptag = PROP_TAG_LASTMODIFICATIONTIME;
	propval_buff[3].pvalue = &nt_time;
	if (FALSE == exmdb_client_set_folder_properties(
		logon_object_get_dir(plogon), 0, folder_id,
		&propvals, &problems)) {
		return EC_ERROR;	
	}
	return EC_SUCCESS;
}

uint32_t rop_copyfolder(uint8_t want_asynchronous,
	uint8_t want_recursive, uint8_t use_unicode, uint64_t folder_id,
	const char *pnew_name, uint8_t *ppartial_completion, void *plogmap,
	uint8_t logon_id, uint32_t hsrc, uint32_t hdst)
{
	BOOL b_exist;
	BOOL b_cycle;
	BOOL b_guest;
	BOOL b_partial;
	int object_type;
	EMSMDB_INFO *pinfo;
	char new_name[128];
	uint32_t permission;
	DCERPC_INFO rpc_info;
	LOGON_OBJECT *plogon;
	FOLDER_OBJECT *psrc_parent;
	FOLDER_OBJECT *pdst_folder;
	
	*ppartial_completion = 1;
	psrc_parent = rop_processor_get_object(plogmap,
					logon_id, hsrc, &object_type);
	if (NULL == psrc_parent) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_FOLDER != object_type) {
		return EC_NOT_SUPPORTED;
	}
	pdst_folder = rop_processor_get_object(plogmap,
					logon_id, hdst, &object_type);
	if (NULL == pdst_folder) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_FOLDER != object_type) {
		return EC_NOT_SUPPORTED;
	}
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	if (0 == use_unicode) {
		if (common_util_convert_string(TRUE, pnew_name,
			new_name, sizeof(new_name)) < 0) {
			return EC_INVALID_PARAMETER;	
		}
	} else {
		if (strlen(pnew_name) >= sizeof(new_name)) {
			return EC_INVALID_PARAMETER;
		}
		strcpy(new_name, pnew_name);
	}
	rpc_info = get_rpc_info();
	if (TRUE == logon_object_check_private(plogon)) {
		if (PRIVATE_FID_ROOT == rop_util_get_gc_value(folder_id)) {
			return EC_ACCESS_DENIED;
		}
	} else {
		if (PUBLIC_FID_ROOT == rop_util_get_gc_value(folder_id)) {
			return EC_ACCESS_DENIED;
		}
	}
	if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
		if (FALSE == exmdb_client_check_folder_permission(
			logon_object_get_dir(plogon), folder_id,
			rpc_info.username, &permission)) {
			return EC_ERROR;	
		}
		if (0 == (permission & PERMISSION_READANY)) {
			return EC_ACCESS_DENIED;
		}
		if (FALSE == exmdb_client_check_folder_permission(
			logon_object_get_dir(plogon),
			folder_object_get_id(pdst_folder),
			rpc_info.username, &permission)) {
			return EC_ERROR;	
		}
		if (0 == (permission & PERMISSION_FOLDEROWNER) &&
			0 == (permission & PERMISSION_CREATESUBFOLDER)) {
			return EC_ACCESS_DENIED;
		}
		b_guest = TRUE;
	} else {
		b_guest = FALSE;
	}
	if (FALSE == exmdb_client_check_folder_cycle(
		logon_object_get_dir(plogon), folder_id,
		folder_object_get_id(pdst_folder), &b_cycle)) {
		return EC_ERROR;	
	}
	if (TRUE == b_cycle) {
		return EC_FOLDER_CYCLE;
	}
	pinfo = emsmdb_interface_get_emsmdb_info();
	if (FALSE == exmdb_client_movecopy_folder(
		logon_object_get_dir(plogon),
		logon_object_get_account_id(plogon),
		pinfo->cpid, b_guest, rpc_info.username,
		folder_object_get_id(psrc_parent), folder_id,
		folder_object_get_id(pdst_folder), new_name,
		TRUE, &b_exist, &b_partial)) {
		return EC_ERROR;
	}
	if (TRUE == b_exist) {
		return EC_DUPLICATE_NAME;
	}
	if (TRUE == b_partial) {
		*ppartial_completion = 1;
	} else {
		*ppartial_completion = 0;
	}
	return EC_SUCCESS;
}

static uint32_t oxcfold_emptyfolder(BOOL b_hard,
	uint8_t want_delete_associated, uint8_t *ppartial_completion,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	BOOL b_fai;
	BOOL b_partial;
	int object_type;
	uint64_t fid_val;
	EMSMDB_INFO *pinfo;
	uint32_t permission;
	DCERPC_INFO rpc_info;
	LOGON_OBJECT *plogon;
	const char *username;
	FOLDER_OBJECT *pfolder;
	
	*ppartial_completion = 1;
	pfolder = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == pfolder) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_FOLDER != object_type) {
		return EC_NOT_SUPPORTED;
	}
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	if (0 == want_delete_associated) {
		b_fai = FALSE;
	} else {
		b_fai = TRUE;
	}
	rpc_info = get_rpc_info();
	if (FALSE == logon_object_check_private(plogon)) {
		/* just like exchange 2013 or later */
		return EC_NOT_SUPPORTED;
	}
	fid_val = rop_util_get_gc_value(folder_object_get_id(pfolder));
	if (PRIVATE_FID_ROOT == fid_val ||
		PRIVATE_FID_IPMSUBTREE == fid_val) {
		return EC_ACCESS_DENIED;
	}
	username = NULL;
	if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
		if (FALSE == exmdb_client_check_folder_permission(
			logon_object_get_dir(plogon),
			folder_object_get_id(pfolder),
			rpc_info.username, &permission)) {
			return EC_ERROR;	
		}
		if (0 == (permission & PERMISSION_DELETEANY) &&
			0 == (permission & PERMISSION_DELETEOWNED)) {
			return EC_ACCESS_DENIED;
		}
		username = rpc_info.username;
	}
	pinfo = emsmdb_interface_get_emsmdb_info();
	if (FALSE == exmdb_client_empty_folder(
		logon_object_get_dir(plogon), pinfo->cpid,
		username, folder_object_get_id(pfolder),
		b_hard, TRUE, b_fai, TRUE, &b_partial)) {
		return EC_ERROR;
	}
	if (TRUE == b_partial) {
		*ppartial_completion = 1;
	} else {
		*ppartial_completion = 0;
	}
	return EC_SUCCESS;
}

uint32_t rop_emptyfolder(uint8_t want_asynchronous,
	uint8_t want_delete_associated, uint8_t *ppartial_completion,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	return oxcfold_emptyfolder(FALSE, want_delete_associated,
			ppartial_completion, plogmap, logon_id, hin);	
}

uint32_t rop_harddeletemessagesandsubfolders(
	uint8_t want_asynchronous, uint8_t want_delete_associated,
	uint8_t *ppartial_completion, void *plogmap,
	uint8_t logon_id, uint32_t hin)
{
	return oxcfold_emptyfolder(TRUE, want_delete_associated,
			ppartial_completion, plogmap, logon_id, hin);
}

static uint32_t oxcfold_deletemessages(BOOL b_hard,
	uint8_t want_asynchronous, uint8_t notify_non_read,
	const LONGLONG_ARRAY *pmessage_ids,
	uint8_t *ppartial_completion, void *plogmap,
	uint8_t logon_id, uint32_t hin)
{
	int i;
	BOOL b_owner;
	void *pvalue;
	EID_ARRAY ids;
	BOOL b_partial;
	BOOL b_partial1;
	int object_type;
	EMSMDB_INFO *pinfo;
	uint32_t permission;
	DCERPC_INFO rpc_info;
	LOGON_OBJECT *plogon;
	const char *username;
	FOLDER_OBJECT *pfolder;
	MESSAGE_CONTENT *pbrief;
	uint32_t proptag_buff[2];
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	*ppartial_completion = 1;
	pinfo = emsmdb_interface_get_emsmdb_info();
	pfolder = rop_processor_get_object(plogmap, logon_id, hin, &object_type);
	if (NULL == pfolder) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_FOLDER != object_type) {
		return EC_NOT_SUPPORTED;
	}
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	rpc_info = get_rpc_info();
	if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
		if (FALSE == exmdb_client_check_folder_permission(
			logon_object_get_dir(plogon),
			folder_object_get_id(pfolder),
			rpc_info.username, &permission)) {
			return EC_ERROR;	
		}
		if ((permission & PERMISSION_DELETEANY) ||
			(permission & PERMISSION_FOLDEROWNER)) {
			username = NULL;
		} else if (permission & PERMISSION_DELETEOWNED) {
			username = rpc_info.username;
		} else {
			return EC_ACCESS_DENIED;
		}
	} else {
		username = NULL;
	}
	if (0 == notify_non_read) {
		ids.count = pmessage_ids->count;
		ids.pids = pmessage_ids->pll;
		if (FALSE == exmdb_client_delete_messages(
			logon_object_get_dir(plogon),
			logon_object_get_account_id(plogon), pinfo->cpid,
			username, folder_object_get_id(pfolder), &ids,
			b_hard, &b_partial)) {
			return EC_ERROR;
		}
		if (TRUE == b_partial) {
			*ppartial_completion = 1;
		} else {
			*ppartial_completion = 0;
		}
		return EC_SUCCESS;
	}
	b_partial = FALSE;
	ids.count = 0;
	ids.pids = common_util_alloc(sizeof(uint64_t)*pmessage_ids->count);
	if (NULL == ids.pids) {
		return EC_ERROR;
	}
	for (i=0; i<pmessage_ids->count; i++) {
		if (NULL != username) {
			if (FALSE == exmdb_client_check_message_owner(
				logon_object_get_dir(plogon), pmessage_ids->pll[i],
				username, &b_owner)) {
				return EC_ERROR;
			}
			if (FALSE == b_owner) {
				b_partial = TRUE;
				continue;
			}
		}
		tmp_proptags.count = 2;
		tmp_proptags.pproptag = proptag_buff;
		proptag_buff[0] = PROP_TAG_NONRECEIPTNOTIFICATIONREQUESTED;
		proptag_buff[1] = PROP_TAG_READ;
		if (FALSE == exmdb_client_get_message_properties(
			logon_object_get_dir(plogon), NULL, 0,
			pmessage_ids->pll[i], &tmp_proptags, &tmp_propvals)) {
			return EC_ERROR;
		}
		pbrief = NULL;
		pvalue = common_util_get_propvals(&tmp_propvals,
				PROP_TAG_NONRECEIPTNOTIFICATIONREQUESTED);
		if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
			pvalue = common_util_get_propvals(
				&tmp_propvals, PROP_TAG_READ);
			if (NULL == pvalue || 0 == *(uint8_t*)pvalue) {
				if (FALSE == exmdb_client_get_message_brief(
					logon_object_get_dir(plogon), pinfo->cpid,
					pmessage_ids->pll[i], &pbrief)) {
					return EC_ERROR;
				}
			}
		}
		ids.pids[ids.count] = pmessage_ids->pll[i];
		ids.count ++;
		if (NULL != pbrief) {
			common_util_notify_receipt(
				logon_object_get_account(plogon),
				NOTIFY_RECEIPT_NON_READ, pbrief);
		}
	}
	if (FALSE == exmdb_client_delete_messages(
		logon_object_get_dir(plogon),
		logon_object_get_account_id(plogon),
		pinfo->cpid, username, folder_object_get_id(pfolder),
		&ids, b_hard, &b_partial1)) {
		return EC_ERROR;
	}
	if (TRUE == b_partial || TRUE == b_partial1) {
		*ppartial_completion = 1;
	} else {
		*ppartial_completion = 0;
	}
	return EC_SUCCESS;
}

uint32_t rop_deletemessages(uint8_t want_asynchronous,
	uint8_t notify_non_read, const LONGLONG_ARRAY *pmessage_ids,
	uint8_t *ppartial_completion, void *plogmap, uint8_t logon_id,
	uint32_t hin)
{
	return oxcfold_deletemessages(FALSE, want_asynchronous,
			notify_non_read, pmessage_ids, ppartial_completion,
			plogmap, logon_id, hin);
}

uint32_t rop_harddeletemessages(uint8_t want_asynchronous,
	uint8_t notify_non_read, const LONGLONG_ARRAY *pmessage_ids,
	uint8_t *ppartial_completion, void *plogmap, uint8_t logon_id,
	uint32_t hin)
{
	return oxcfold_deletemessages(TRUE, want_asynchronous,
			notify_non_read, pmessage_ids, ppartial_completion,
			plogmap, logon_id, hin);
}

uint32_t rop_gethierarchytable(uint8_t table_flags,
	uint32_t *prow_count, void *plogmap,
	uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	BOOL b_depth;
	int object_type;
	TABLE_OBJECT *ptable;
	LOGON_OBJECT *plogon;
	const char *username;
	DCERPC_INFO rpc_info;
	FOLDER_OBJECT *pfolder;
	
	if (table_flags & (~(TABLE_FLAG_DEPTH | TABLE_FLAG_DEFERREDERRORS |
		TABLE_FLAG_NONOTIFICATIONS | TABLE_FLAG_SOFTDELETES |
		TABLE_FLAG_USEUNICODE | TABLE_FLAG_SUPPRESSNOTIFICATIONS))) {
		return EC_INVALID_PARAMETER;	
	}
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	pfolder = rop_processor_get_object(plogmap, logon_id, hin, &object_type);
	if (NULL == pfolder) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_FOLDER != object_type) {
		return EC_NOT_SUPPORTED;
	}
	if (table_flags & TABLE_FLAG_DEPTH) {
		b_depth = TRUE;
	} else {
		b_depth = FALSE;
	}
	rpc_info = get_rpc_info();
	if (LOGON_MODE_OWNER == logon_object_get_mode(plogon)) {
		username = NULL;
	} else {
		username = rpc_info.username;
	}
	if (FALSE == exmdb_client_sum_hierarchy(
		logon_object_get_dir(plogon),
		folder_object_get_id(pfolder),
		username, b_depth, prow_count)) {
		return EC_ERROR;	
	}
	ptable = table_object_create(plogon, pfolder,
				table_flags, ROP_ID_GETHIERARCHYTABLE, logon_id);
	if (NULL == ptable) {
		return EC_OUT_OF_MEMORY;
	}
	*phout = rop_processor_add_object_handle(plogmap,
			logon_id, hin, OBJECT_TYPE_TABLE, ptable);
	if (*phout < 0) {
		table_object_free(ptable);
		return EC_ERROR;
	}
	table_object_set_handle(ptable, *phout);
	return EC_SUCCESS;
}

uint32_t rop_getcontentstable(uint8_t table_flags,
	uint32_t *prow_count, void *plogmap,
	uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	BOOL b_fai;
	BOOL b_deleted;
	int object_type;
	uint32_t permission;
	BOOL b_conversation;
	TABLE_OBJECT *ptable;
	LOGON_OBJECT *plogon;
	const char *username;
	DCERPC_INFO rpc_info;
	FOLDER_OBJECT *pfolder;
	
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	pfolder = rop_processor_get_object(plogmap, logon_id, hin, &object_type);
	if (NULL == pfolder) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_FOLDER != object_type) {
		return EC_NOT_SUPPORTED;
	}
	b_conversation = FALSE;
	if (TRUE == logon_object_check_private(plogon)) {
		if (folder_object_get_id(pfolder) ==
			rop_util_make_eid_ex(1, PRIVATE_FID_ROOT) &&
			(table_flags & TABLE_FLAG_CONVERSATIONMEMBERS)) {
			b_conversation = TRUE;
		}
	} else {
		if (table_flags & TABLE_FLAG_CONVERSATIONMEMBERS) {
			b_conversation = TRUE;
		}
	}
	if (FALSE == b_conversation && (table_flags
		& TABLE_FLAG_CONVERSATIONMEMBERS)) {
		return EC_INVALID_PARAMETER;
	}
	if (table_flags & TABLE_FLAG_ASSOCIATED) {
		if (table_flags & TABLE_FLAG_CONVERSATIONMEMBERS) {
			return EC_INVALID_PARAMETER;
		}
		b_fai = TRUE;
	} else {
		b_fai = FALSE;
	}
	if (table_flags & TABLE_FLAG_SOFTDELETES) {
		b_deleted = TRUE;
	} else {
		b_deleted = FALSE;
	}
	if (FALSE == b_conversation) {
		rpc_info = get_rpc_info();
		username = NULL;
		if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
			if (FALSE == exmdb_client_check_folder_permission(
				logon_object_get_dir(plogon),
				folder_object_get_id(pfolder),
				rpc_info.username, &permission)) {
				return EC_ERROR;
			}
			if (0 == (permission & PERMISSION_READANY) &&
				0 == (permission & PERMISSION_FOLDEROWNER)) {
				return EC_ACCESS_DENIED;
			}
		}
		if (FALSE == exmdb_client_sum_content(
			logon_object_get_dir(plogon),
			folder_object_get_id(pfolder),
			b_fai, b_deleted, prow_count)) {
			return EC_ERROR;
		}
	} else {
		*prow_count = 1; /* arbitrary value */
	}
	ptable = table_object_create(plogon, pfolder,
		table_flags, ROP_ID_GETCONTENTSTABLE, logon_id);
	if (NULL == ptable) {
		return EC_OUT_OF_MEMORY;
	}
	*phout = rop_processor_add_object_handle(plogmap,
			logon_id, hin, OBJECT_TYPE_TABLE, ptable);
	if (*phout < 0) {
		table_object_free(ptable);
		return EC_ERROR;
	}
	table_object_set_handle(ptable, *phout);
	return EC_SUCCESS;
}
