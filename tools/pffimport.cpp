// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021 grammm GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <list>
#include <memory>
#include <string>
#include <unordered_map>
#include <libpff.h>
#include <libHX/option.h>
#include <libHX/string.h>
#include <gromox/config_file.hpp>
#include <gromox/database_mysql.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/list_file.hpp>
#include <gromox/paths.h>
#include <gromox/pcl.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include <gromox/socket.h>
#include <gromox/tarray_set.hpp>
#include <gromox/tie.hpp>
#include <gromox/tpropval_array.hpp>
#include <gromox/util.hpp>
#include "genimport.hpp"

#define E(a, b) static_assert(static_cast<unsigned int>(LIBPFF_VALUE_TYPE_ ## a) == static_cast<unsigned int>(PT_ ## b));
E(UNSPECIFIED, UNSPECIFIED)
E(INTEGER_16BIT_SIGNED, SHORT)
E(INTEGER_32BIT_SIGNED, LONG)
E(FLOAT_32BIT, FLOAT)
E(DOUBLE_64BIT, DOUBLE)
E(CURRENCY, CURRENCY)
E(FLOATINGTIME, APPTIME)
E(ERROR, ERROR)
E(BOOLEAN, BOOLEAN)
E(OBJECT, OBJECT)
E(INTEGER_64BIT_SIGNED, I8)
E(STRING_ASCII, STRING8)
E(STRING_UNICODE, UNICODE)
E(FILETIME, SYSTIME)
E(GUID, CLSID)
E(SERVER_IDENTIFIER, SVREID)
E(RESTRICTION, SRESTRICT)
E(RULE_ACTION, ACTIONS)
E(BINARY_DATA, BINARY)
#undef E

namespace {

struct libpff_error_del { void operator()(libpff_error_t *x) { libpff_error_free(&x); } };
struct libpff_file_del { void operator()(libpff_file_t *x) { libpff_file_free(&x, nullptr); } };
struct libpff_item_del { void operator()(libpff_item_t *x) { libpff_item_free(&x, nullptr); } };
struct libpff_record_set_del { void operator()(libpff_record_set_t *x) { libpff_record_set_free(&x, nullptr); } };
struct libpff_record_entry_del { void operator()(libpff_record_entry_t *x) { libpff_record_entry_free(&x, nullptr); } };
struct libpff_multi_value_del { void operator()(libpff_multi_value_t *x) { libpff_multi_value_free(&x, nullptr); } };
struct libpff_noop_del { void operator()(void *x) { } };

using libpff_error_ptr        = std::unique_ptr<libpff_error_t, libpff_error_del>;
using libpff_file_ptr         = std::unique_ptr<libpff_file_t, libpff_file_del>;
using libpff_item_ptr         = std::unique_ptr<libpff_item_t, libpff_item_del>;
using libpff_record_set_ptr   = std::unique_ptr<libpff_record_set_t, libpff_record_set_del>;
using libpff_record_entry_ptr = std::unique_ptr<libpff_record_entry_t, libpff_record_entry_del>;
using libpff_multi_value_ptr  = std::unique_ptr<libpff_multi_value_t, libpff_multi_value_del>;
using libpff_nti_entry_ptr    = std::unique_ptr<libpff_name_to_id_map_entry_t, libpff_noop_del>;

enum {
	NID_TYPE_HID = 0x0,
	NID_TYPE_INTERNAL = 0x1,
	NID_TYPE_NORMAL_FOLDER = 0x2,
	NID_TYPE_SEARCH_FOLDER = 0x3,
	NID_TYPE_NORMAL_MESSAGE = 0x4,
	NID_TYPE_ATTACHMENT = 0x5,
	NID_TYPE_SEARCH_UPDATE_QUEUE = 0x6,
	NID_TYPE_SEARCH_CRITERIA_OBJECT = 0x7,
	NID_TYPE_ASSOC_MESSAGE = 0x8,
	NID_TYPE_CONTENTS_TABLE_INDEX = 0xA,
	NID_TYPE_RECEIVE_FOLDER_TABLE = 0xB,
	NID_TYPE_OUTGOING_QUEUE_TABLE = 0xC,
	NID_TYPE_HIERARCHY_TABLE = 0xD,
	NID_TYPE_CONTENTS_TABLE = 0xE,
	NID_TYPE_ASSOC_CONTENTS_TABLE = 0xF,
	NID_TYPE_SEARCH_CONTENTS_TABLE = 0x10,
	NID_TYPE_ATTACHMENT_TABLE = 0x11,
	NID_TYPE_RECIPIENT_TABLE = 0x12,
	NID_TYPE_SEARCH_TABLE_INDEX = 0x13,
	NID_TYPE_LTP = 0x1F,
	NID_TYPE_MASK = 0x1F,
};

enum {
	NID_MESSAGE_STORE = 0x20 | NID_TYPE_INTERNAL,
	NID_NAME_TO_ID_MAP = 0x60 | NID_TYPE_INTERNAL,
	NID_NORMAL_FOLDER_TEMPLATE = 0xA0 | NID_TYPE_INTERNAL,
	NID_SEARCH_FOLDER_TEMPLATE = 0xC0 | NID_TYPE_INTERNAL,
	NID_ROOT_FOLDER = 0x120 | NID_TYPE_NORMAL_FOLDER,
	NID_SEARCH_MANAGEMENT_QUEUE = 0x1E0 | NID_TYPE_INTERNAL,
	NID_SEARCH_ACTIVITY_LIST = 0x200 | NID_TYPE_INTERNAL,
	NID_SEARCH_DOMAIN_OBJECT = 0x260 | NID_TYPE_INTERNAL,
	NID_SEARCH_GATHERER_QUEUE = 0x280 | NID_TYPE_INTERNAL,
	NID_SEARCH_GATHERER_DESCRIPTOR = 0x2A0 | NID_TYPE_INTERNAL,
	NID_SEARCH_GATHERER_FOLDER_QUEUE = 0x320 | NID_TYPE_INTERNAL,
};

}

using namespace std::string_literals;
using namespace gromox;
namespace exmdb_client = exmdb_client_remote;

static char *g_username;
static unsigned int g_splice;
static const struct HXoption g_options_table[] = {
	{nullptr, 'n', HXTYPE_VAL, &g_wet_run, nullptr, nullptr, 0, "Dry run"},
	{nullptr, 'p', HXTYPE_NONE, &g_show_props, nullptr, nullptr, 0, "Show properties in detail (if -t)"},
	{nullptr, 's', HXTYPE_NONE, &g_splice, nullptr, nullptr, 0, "Splice PFF objects into existing store hierarchy"},
	{nullptr, 't', HXTYPE_NONE, &g_show_tree, nullptr, nullptr, 0, "Show tree-based analysis of the archive"},
	{nullptr, 'u', HXTYPE_STRING, &g_username, nullptr, nullptr, 0, "Username of store to import to", "EMAILADDR"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static int do_item(unsigned int, const parent_desc &, libpff_item_t *);

static YError az_error(const char *prefix, const libpff_error_ptr &err)
{
	char buf[160];
	buf[0] = '\0';
	libpff_error_sprint(err.get(), buf, arsizeof(buf));
	return YError(std::string(prefix) + ": " + buf);
}

static const char *az_item_type_to_str(uint8_t t)
{
	thread_local char buf[32];
	switch (t) {
	case LIBPFF_ITEM_TYPE_ACTIVITY: return "activity";
	case LIBPFF_ITEM_TYPE_APPOINTMENT: return "appointment";
	case LIBPFF_ITEM_TYPE_ATTACHMENT: return "atx";
	case LIBPFF_ITEM_TYPE_CONTACT: return "contact";
	case LIBPFF_ITEM_TYPE_DISTRIBUTION_LIST: return "dlist";
	case LIBPFF_ITEM_TYPE_DOCUMENT: return "document";
	case LIBPFF_ITEM_TYPE_CONFLICT_MESSAGE: return "conflict message";
	case LIBPFF_ITEM_TYPE_EMAIL: return "email";
	case LIBPFF_ITEM_TYPE_EMAIL_SMIME: return "email(smime)";
	case LIBPFF_ITEM_TYPE_FOLDER: return "folder";
	case LIBPFF_ITEM_TYPE_MEETING: return "meeting";
	case LIBPFF_ITEM_TYPE_NOTE: return "note";
	case LIBPFF_ITEM_TYPE_RSS_FEED: return "rss";
	case LIBPFF_ITEM_TYPE_TASK: return "task";
	case LIBPFF_ITEM_TYPE_RECIPIENTS: return "rcpts";
	case LIBPFF_ITEM_TYPE_UNDEFINED: return "undef";
	default: snprintf(buf, sizeof(buf), "unknown-%u", t); return buf;
	}
}

static const char *az_special_ident(uint32_t nid)
{
#define E(s) case s: return #s;
	switch (nid) {
	E(NID_MESSAGE_STORE)
	E(NID_NAME_TO_ID_MAP)
	E(NID_NORMAL_FOLDER_TEMPLATE)
	E(NID_SEARCH_FOLDER_TEMPLATE)
	E(NID_ROOT_FOLDER)
	E(NID_SEARCH_MANAGEMENT_QUEUE)
	E(NID_SEARCH_ACTIVITY_LIST)
	E(NID_SEARCH_DOMAIN_OBJECT)
	E(NID_SEARCH_GATHERER_QUEUE)
	E(NID_SEARCH_GATHERER_DESCRIPTOR)
	E(NID_SEARCH_GATHERER_FOLDER_QUEUE)
	}
	return "";
}

/* Lookup the pff record entry for the given propid */
static bool az_item_get_propv(libpff_item_t *item, uint32_t proptag,
    libpff_record_entry_t **rent)
{
	libpff_record_set_ptr rset;
	auto ret = libpff_item_get_record_set_by_index(item, 0, &unique_tie(rset), nullptr);
	if (ret <= 0)
		return false;
	uint8_t flags = PROP_TYPE(proptag) == PT_UNSPECIFIED ?
	                LIBPFF_ENTRY_VALUE_FLAG_MATCH_ANY_VALUE_TYPE : 0;
	libpff_error_ptr err;
	ret = libpff_record_set_get_entry_by_type(rset.get(), PROP_ID(proptag),
	      PROP_TYPE(proptag), rent, flags, &unique_tie(err));
	if (ret < 0)
		throw az_error("PF-1001", err);
	else if (ret == 0)
		return false;
	return true;
}

static bool is_mapi_message(uint32_t nid)
{
	/*
	 * libpff_internal_item_determine_type just yolos it on the
	 * presence of PR_MESSAGE_CLASS. Until someone starts having
	 * a folder with PR_MESSAGE_CLASS, then that falls apart.
	 */
	nid &= NID_TYPE_MASK;
	return nid == NID_TYPE_NORMAL_MESSAGE || nid == NID_TYPE_ASSOC_MESSAGE;
}

/* Obtain a string value from a libpff item's property */
static std::string az_item_get_str(libpff_item_t *item, uint32_t proptag)
{
	libpff_record_entry_ptr rent;

	auto ret = az_item_get_propv(item, CHANGE_PROP_TYPE(proptag, PT_UNSPECIFIED),
	           &unique_tie(rent));
	if (ret == 0)
		return {};
	size_t dsize = 0;
	libpff_error_ptr err;
	if (libpff_record_entry_get_data_as_utf8_string_size(rent.get(), &dsize, &unique_tie(err)) < 1)
		throw az_error("PF-1026", err);
	++dsize;
	auto buf = std::make_unique<uint8_t[]>(dsize);
	if (libpff_record_entry_get_data_as_utf8_string(rent.get(), buf.get(), dsize, &~unique_tie(err)) < 1)
		throw az_error("PF-1002", err);
	return reinterpret_cast<char *>(buf.get());
}

static int do_attach(unsigned int depth, ATTACHMENT_CONTENT *atc, libpff_item_t *atx)
{
	int atype = 0;
	uint64_t asize = 0;
	libpff_error_ptr err;

	if (libpff_attachment_get_type(atx, &atype, &unique_tie(err)) < 1) {
		fprintf(stderr, "%s\n", az_error("PF-1012: Attachment is corrupted", err).what());
		return 0;
	}
	tree(depth);
	if (atype == LIBPFF_ATTACHMENT_TYPE_DATA) {
		if (libpff_attachment_get_data_size(atx, &asize, &~unique_tie(err)) < 1) {
			fprintf(stderr, "%s\n", az_error("PF-1013: Attachment is corrupted", err).what());
			return 0;
		}
		/*
		 * Data is in PR_ATTACH_DATA_BIN, and so was
		 * already spooled into atc->proplist by the caller.
		 */
		tlog("[attachment type=%c size=%zu]\n", atype, asize);
	} else if (atype == LIBPFF_ATTACHMENT_TYPE_ITEM) {
		libpff_item_ptr emb_item;
		if (libpff_attachment_get_item(atx, &unique_tie(emb_item),
		    &~unique_tie(err)) < 1) {
			fprintf(stderr, "%s\n", az_error("PF-1014: Attachment is corrupted", err).what());
			return 0;
		}
		tlog("[attachment type=%c embedded_msg]\n", atype);
		auto ret = do_item(depth + 1, parent_desc::as_attach(atc), emb_item.get());
		if (ret < 0)
			return ret;
	} else if (atype == LIBPFF_ATTACHMENT_TYPE_REFERENCE) {
		tlog("[attachment type=%c]\n", atype);
		throw YError("PF-1005: EOPNOTSUPP");
	} else {
		tlog("[attachment type=unknown]\n");
		throw YError("PF-1006: EOPNOTSUPP");
	}
	return 0;
}

static uint32_t az_resolve_namedprop(libpff_record_entry_t *rent, uint32_t proptag)
{
	if (!g_wet_run)
		return proptag;
	auto it = g_propname_cache.find(proptag);
	if (it != g_propname_cache.end())
		return PROP_TAG(PROP_TYPE(proptag), it->second);

	libpff_nti_entry_ptr nti_entry;
	uint8_t nti_type = 0;
	if (libpff_record_entry_get_name_to_id_map_entry(rent, &unique_tie(nti_entry), nullptr) < 1)
		return proptag;
	if (libpff_name_to_id_map_entry_get_type(nti_entry.get(), &nti_type, nullptr) < 1)
		return proptag;

	std::unique_ptr<char[]> pnstr;
	PROPERTY_NAME pn_req{};
	if (libpff_name_to_id_map_entry_get_guid(nti_entry.get(),
	    reinterpret_cast<uint8_t *>(&pn_req.guid), sizeof(pn_req.guid), nullptr) < 1)
		return proptag;

	if (nti_type == LIBPFF_NAME_TO_ID_MAP_ENTRY_TYPE_NUMERIC) {
		if (libpff_name_to_id_map_entry_get_number(nti_entry.get(), &pn_req.lid, nullptr) < 1)
			throw YError("PF-1007");
		pn_req.kind = MNID_ID;
	} else if (nti_type == LIBPFF_NAME_TO_ID_MAP_ENTRY_TYPE_STRING) {
		size_t dsize = 0;
		if (libpff_name_to_id_map_entry_get_utf8_string_size(nti_entry.get(), &dsize, nullptr) < 1)
			return proptag;
		pnstr = std::make_unique<char[]>(dsize + 1);
		if (libpff_name_to_id_map_entry_get_utf8_string(nti_entry.get(), reinterpret_cast<uint8_t *>(pnstr.get()), dsize + 1, nullptr) < 1)
			throw YError("PF-1009");
		pn_req.kind = MNID_STRING;
		pn_req.pname = pnstr.get();
	} else {
		fprintf(stderr, "PF-1046: unable to handle libpff propname type %xh\n", nti_type);
		throw YError("PF-1010: EOPNOTSUPP");
	}

	auto new_propid = gi_resolve_namedprop(&pn_req);
	g_propname_cache.emplace(PROP_ID(proptag), new_propid);
	return PROP_TAG(PROP_TYPE(proptag), new_propid);
}

static void recordent_to_tpropval(libpff_record_entry_t *rent, TPROPVAL_ARRAY *ar)
{
	libpff_multi_value_ptr mv;
	libpff_error_ptr err;
	unsigned int etype = 0, vtype = 0;
	size_t dsize = 0;
	int mvnum = 0;

	if (libpff_record_entry_get_entry_type(rent, &etype, &unique_tie(err)) < 1)
		throw az_error("PF-1030", err);
	if (libpff_record_entry_get_value_type(rent, &vtype, &~unique_tie(err)) < 1)
		throw az_error("PF-1031", err);
	if (libpff_record_entry_get_data_size(rent, &dsize, &~unique_tie(err)) < 1)
		throw az_error("PF-1032", err);

	TAGGED_PROPVAL pv;
	pv.proptag = PROP_TAG(vtype, etype);
	if (g_wet_run)
		pv.proptag = az_resolve_namedprop(rent, pv.proptag);
	auto buf = std::make_unique<uint8_t[]>(dsize + 1);
	if (dsize == 0)
		buf[0] = '\0';
	else if (libpff_record_entry_get_data(rent, buf.get(), dsize + 1, &~unique_tie(err)) < 1)
		throw az_error("PF-1033", err);
	if (vtype & LIBPFF_VALUE_TYPE_MULTI_VALUE_FLAG) {
		auto ret = libpff_record_entry_get_multi_value(rent, &unique_tie(mv), &~unique_tie(err));
		if (ret == 0)
			return;
		if (ret < 0)
			throw az_error("PF-1034", err);
		if (libpff_multi_value_get_number_of_values(mv.get(), &mvnum, &~unique_tie(err)) < 1)
			throw az_error("PF-1035", err);
		if (dsize > 4 && mvnum == 0) {
			/* See also MS-PST 2.3.3.4.2 */
			fprintf(stderr, "Broken PFF file: Multivalue property %xh with 0 items, but still with size %zu.\n",
			        pv.proptag, dsize);
			return;
		}
	}

	union {
		GUID guid;
		BINARY bin;
		SHORT_ARRAY sa;
		LONG_ARRAY la;
		LONGLONG_ARRAY lla;
	} u;
	pv.pvalue = buf.get();
	switch (vtype) {
	case PT_SHORT:
		if (dsize == sizeof(uint16_t))
			break;
		throw YError("PF-1015: Datasize mismatch on %xh\n", pv.proptag);
	case PT_LONG:
		if (dsize == sizeof(uint32_t))
			break;
		throw YError("PF-1016: Datasize mismatch on %xh\n", pv.proptag);
	case PT_I8:
	case PT_SYSTIME:
		if (dsize == sizeof(uint64_t))
			break;
		throw YError("PF-1019: Datasize mismatch on %xh\n", pv.proptag);
	case PT_FLOAT:
		if (dsize == sizeof(float))
			break;
		throw YError("PF-1020: Datasize mismatch on %xh\n", pv.proptag);
	case PT_DOUBLE:
	case PT_APPTIME:
		if (dsize == sizeof(double))
			break;
		throw YError("PF-1021: Datasize mismatch on %xh\n", pv.proptag);
	case PT_BOOLEAN:
		if (dsize == sizeof(uint8_t))
			break;
		throw YError("PF-1024: Datasize mismatch on %xh\n", pv.proptag);
	case PT_STRING8:
	case PT_UNICODE: {
		libpff_error_ptr err;
		size_t dsize2 = 0;
		if (libpff_record_entry_get_data_as_utf8_string_size(rent, &dsize2, &unique_tie(err)) >= 1) {
			++dsize2;
			buf = std::make_unique<uint8_t[]>(dsize2);
			if (libpff_record_entry_get_data_as_utf8_string(rent,
			    buf.get(), dsize2, &~unique_tie(err)) < 1)
				throw az_error("PF-1036", err);
		} else {
			fprintf(stderr, "PF-1041: Garbage in Unicode string\n");
			auto s = iconvtext(reinterpret_cast<char *>(buf.get()), dsize, "UTF-16", "UTF-8//IGNORE");
			dsize = s.size() + 1;
			buf = std::make_unique<uint8_t[]>(dsize);
			memcpy(buf.get(), s.data(), dsize);
		}
		pv.pvalue = buf.get();
		break;
	}
	case PT_BINARY:
		u.bin.cb = dsize;
		u.bin.pv = buf.get();
		pv.pvalue = &u.bin;
		break;
	case PT_CLSID:
		if (dsize != sizeof(u.guid))
			throw YError("PF-1040: GUID size incorrect: " + std::to_string(dsize));
		memcpy(&u.guid, buf.get(), sizeof(u.guid));
		pv.pvalue = &u.guid;
		break;
	case PT_MV_SHORT:
		if (dsize != mvnum * sizeof(uint16_t))
			throw YError("PF-1027: Datasize mismatch on %xh\n", pv.proptag);
		u.sa.count = mvnum;
		u.sa.ps = reinterpret_cast<uint16_t *>(buf.get());
		pv.pvalue = &u.sa;
		break;
	case PT_MV_LONG:
		if (dsize != mvnum * sizeof(uint32_t))
			throw YError("PF-1037: Datasize mismatch on %xh\n", pv.proptag);
		u.la.count = mvnum;
		u.la.pl = reinterpret_cast<uint32_t *>(buf.get());
		pv.pvalue = &u.la;
		break;
	case PT_MV_I8:
	case PT_MV_SYSTIME:
		if (dsize != mvnum * sizeof(uint64_t))
			throw YError("PF-1038: Datasize mismatch on %xh\n", pv.proptag);
		u.lla.count = mvnum;
		u.lla.pll = reinterpret_cast<uint64_t *>(buf.get());
		pv.pvalue = &u.lla;
		break;
	case PT_OBJECT:
		if (pv.proptag == PR_ATTACH_DATA_OBJ)
			return; /* Embedded message, which separately handled. */
		throw YError("PF-1039: Unsupported proptag %xh (datasize %zu). Implement me!\n",
		        pv.proptag, dsize);
	default:
		throw YError("PF-1042: Unsupported proptype %xh (datasize %zu). Implement me!\n",
		        pv.proptag, dsize);
	}
	if (!tpropval_array_set_propval(ar, &pv))
		throw std::bad_alloc();
}

static void recordset_to_tpropval_a(libpff_record_set_t *rset, TPROPVAL_ARRAY *props)
{
	int nent = 0;
	libpff_error_ptr err;
	if (libpff_record_set_get_number_of_entries(rset, &nent, &unique_tie(err)) < 1)
		throw az_error("PF-1028", err);
	for (int i = 0; i < nent; ++i) {
		libpff_record_entry_ptr rent;
		if (libpff_record_set_get_entry_by_index(rset, i,
		    &unique_tie(rent), &~unique_tie(err)) < 1)
			throw az_error("PF-1029", err);
		recordent_to_tpropval(rent.get(), props);
	}
}

static tpropval_array_ptr item_to_tpropval_a(libpff_item_t *item)
{
	tpropval_array_ptr props(tpropval_array_init());
	if (props == nullptr)
		throw std::bad_alloc();
	int nsets = 0;
	libpff_error_ptr err;
	if (libpff_item_get_number_of_record_sets(item, &nsets, &unique_tie(err)) < 1)
		throw az_error("PF-1060", err);
	for (int n = 0; n < nsets; ++n) {
		libpff_record_set_ptr rset;
		if (libpff_item_get_record_set_by_index(item, 0,
		    &unique_tie(rset), &~unique_tie(err)) < 1)
			throw az_error("PF-1022", err);
		recordset_to_tpropval_a(rset.get(), props.get());
	}
	return props;
}

static int do_item2(unsigned int depth, const parent_desc &parent,
    libpff_item_t *item, unsigned int item_type, uint32_t ident, int nsets,
    uint64_t *new_fld_id)
{
	std::unique_ptr<MESSAGE_CONTENT, gi_delete> ctnt;

	if (item_type == LIBPFF_ITEM_TYPE_FOLDER) {
		auto props = item_to_tpropval_a(item);
		if (g_show_tree)
			gi_dump_tpropval_a(depth, *props);
		if (g_wet_run) {
		auto iter = g_folder_map.find(ident);
		if (iter == g_folder_map.end() && parent.type == MAPI_FOLDER) {
			/* O_EXCL style behavior <=> not splicing. */
			bool o_excl = !g_splice;
			/* PST folder with name -> new folder in store */
			auto ret = exm_create_folder(parent.folder_id, props.get(), o_excl, new_fld_id);
			if (ret < 0)
				return ret;
		} else if (iter == g_folder_map.end()) {
			/* No @parent for writing the item anywhere, and no hints in map => do not create. */
		} else if (!iter->second.create) {
			/* Splice request (e.g. PST wastebox -> Store wastebox) */
			*new_fld_id = iter->second.fid_to;
		} else {
			/* Create request (e.g. PST root without name -> new folder in store with name) */
			if (!tpropval_array_set_propval(props.get(), PR_DISPLAY_NAME,
			    iter->second.create_name.c_str()))
				throw std::bad_alloc();
			auto ret = exm_create_folder(iter->second.fid_to,
			           props.get(), false, new_fld_id);
			if (ret < 0)
				return ret;
		}
		}
	} else if (is_mapi_message(ident)) {
		auto props = item_to_tpropval_a(item);
		if (g_show_tree)
			gi_dump_tpropval_a(depth, *props);
		ctnt.reset(message_content_init());
		if (ctnt == nullptr)
			throw std::bad_alloc();
		ctnt->children.pattachments = attachment_list_init();
		if (ctnt->children.pattachments == nullptr)
			throw std::bad_alloc();
		ctnt->children.prcpts = tarray_set_init();
		if (ctnt->children.prcpts == nullptr)
			throw std::bad_alloc();
		std::swap(ctnt->proplist.count, props->count);
		std::swap(ctnt->proplist.ppropval, props->ppropval);
		libpff_item_ptr recip_set;
		if (libpff_message_get_recipients(item, &unique_tie(recip_set), nullptr) >= 1) {
			auto ret = do_item(depth + 1, parent_desc::as_msg(ctnt.get()), recip_set.get());
			if (ret < 0)
				return ret;
		}
		int atnum = 0;
		if (libpff_message_get_number_of_attachments(item, &atnum, nullptr) >= 1) {
			for (int atidx = 0; atidx < atnum; ++atidx) {
				libpff_item_ptr atx;
				libpff_error_ptr err;
				if (libpff_message_get_attachment(item, atidx,
				    &unique_tie(atx), &~unique_tie(err)) < 1)
					throw az_error("PF-1017", err);
				auto ret = do_item(depth, parent_desc::as_msg(ctnt.get()), atx.get());
				if (ret < 0)
					return ret;
			}
		}
	} else if (item_type == LIBPFF_ITEM_TYPE_RECIPIENTS) {
		libpff_error_ptr err;
		if (libpff_item_get_number_of_record_sets(item, &nsets, &unique_tie(err)) < 1)
			throw az_error("PF-1050", err);
		tpropval_array_ptr props(tpropval_array_init());
		if (props == nullptr)
			throw std::bad_alloc();
		for (int s = 0; s < nsets; ++s) {
			libpff_record_set_ptr rset;
			if (libpff_item_get_record_set_by_index(item, s, &unique_tie(rset), nullptr) < 1)
				throw YError("PF-1049");
			recordset_to_tpropval_a(rset.get(), props.get());
			if (g_show_tree)
				gi_dump_tpropval_a(depth, *props);
			assert(parent.type == MAPI_MESSAGE);
			if (!tarray_set_append_internal(parent.message->children.prcpts, props.get()))
				throw std::bad_alloc();
			props.release();
			props.reset(tpropval_array_init());
			if (props == nullptr)
				throw std::bad_alloc();
		}
	} else if (item_type == LIBPFF_ITEM_TYPE_ATTACHMENT) {
		attachment_content_ptr atc(attachment_content_init());
		if (atc == nullptr)
			throw std::bad_alloc();
		auto props = item_to_tpropval_a(item);
		if (g_show_tree)
			gi_dump_tpropval_a(depth, *props);
		std::swap(atc->proplist.count, props->count);
		std::swap(atc->proplist.ppropval, props->ppropval);
		auto ret = do_attach(depth, atc.get(), item);
		if (ret < 0)
			return ret;
		if (parent.type == MAPI_MESSAGE) {
			if (!attachment_list_append_internal(parent.message->children.pattachments, atc.get()))
				throw std::bad_alloc();
			atc.release();
		}
	}

	auto name = az_item_get_str(item, PR_DISPLAY_NAME);
	if (g_show_tree) {
		if (!name.empty()) {
			tree(depth);
			tlog("display_name=\"%s\"\n", name.c_str());
		}
		name = az_item_get_str(item, PR_SUBJECT);
		if (!name.empty()) {
			tree(depth);
			tlog("subject=\"%s\"\n", name.c_str());
		}
		name = az_item_get_str(item, PR_ATTACH_LONG_FILENAME);
		if (!name.empty()) {
			tree(depth);
			tlog("filename=\"%s\"\n", name.c_str());
		}
	} else if (item_type == LIBPFF_ITEM_TYPE_FOLDER &&
	    (parent.type == MAPI_FOLDER || *new_fld_id != 0)) {
		printf("Processing folder \"%s\"...\n", name.c_str());
	}

	if (!is_mapi_message(ident))
		return 0;
	if (g_wet_run && parent.type == MAPI_FOLDER)
		return exm_create_msg(parent.folder_id, ctnt.get());
	if (parent.type == MAPI_ATTACH)
		attachment_content_set_embedded_internal(parent.attach, ctnt.release());
	return 0;
}

/* General look at an (arbitrary) PFF item */
static int do_item(unsigned int depth, const parent_desc &parent, libpff_item_t *item)
{
	uint32_t ident = 0, nent = 0;
	uint8_t item_type = LIBPFF_ITEM_TYPE_UNDEFINED;
	int nsets = 0;
	libpff_error_ptr err;

	if (libpff_item_get_identifier(item, &ident, &unique_tie(err)) < 1)
		throw az_error("PF-1018", err);
	libpff_item_get_type(item, &item_type, nullptr);
	libpff_item_get_number_of_record_sets(item, &nsets, nullptr);
	if (g_show_tree) {
		libpff_item_get_number_of_entries(item, &nent, nullptr);
		tree(depth);
		auto sp_nid = az_special_ident(ident);
		tlog("[id=%lxh%s%s type=%s nent=%lu nset=%d]\n",
		        static_cast<unsigned long>(ident),
		        *sp_nid != '\0' ? " " : "", sp_nid,
		        az_item_type_to_str(item_type),
		        static_cast<unsigned long>(nent), nsets);
	}

	++depth;
	/*
	 * If folder: collect props and create.
	 * If message: collect props and recurse into recipient sets & attachments...
	 */
	uint64_t new_fld_id = 0;
	auto ret = do_item2(depth, parent, item, item_type, ident, nsets, &new_fld_id);
	if (ret < 0)
		return ret;
	auto new_parent = parent;
	if (new_fld_id != 0) {
		new_parent.type = MAPI_FOLDER;
		new_parent.folder_id = new_fld_id;
	}

	/*
	 * Subitems usually consist exclusively of messages (<=> attachments
	 * are not subitems, even if they are nested (sub) within a message).
	 */
	int nsub = 0;
	if (libpff_item_get_number_of_sub_items(item, &nsub, &~unique_tie(err)) < 1)
		throw az_error("PF-1003", err);
	for (int i = 0; i < nsub; ++i) {
		libpff_item_ptr subitem;
		if (libpff_item_get_sub_item(item, i, &unique_tie(subitem), &~unique_tie(err)) < 1)
			throw az_error("PF-1004", err);
		ret = do_item(depth, new_parent, subitem.get());
		if (ret < 0)
			return ret;
	}
	return 0;
}

static uint32_t az_nid_from_mst(libpff_item_t *item, uint32_t proptag)
{
	libpff_record_entry_ptr rent;
	if (az_item_get_propv(item, proptag, &~unique_tie(rent)) < 1)
		return 0;
	char eid[24];
	uint32_t nid;
	if (libpff_record_entry_get_data(rent.get(),
	    reinterpret_cast<uint8_t *>(eid), arsizeof(eid), nullptr) < 1)
		return 0;
	memcpy(&nid, &eid[20], sizeof(nid));
	return le32_to_cpu(nid);
}

static void az_lookup_specials(libpff_file_t *file)
{
	libpff_item_ptr mst;

	if (libpff_file_get_message_store(file, &~unique_tie(mst), nullptr) < 1)
		return;
	auto nid = az_nid_from_mst(mst.get(), PR_IPM_SUBTREE_ENTRYID);
	if (nid != 0)
		g_folder_map.emplace(nid, tgt_folder{false, rop_util_make_eid_ex(1, PRIVATE_FID_IPMSUBTREE), "FID_IPMSUBTREE"});
	nid = az_nid_from_mst(mst.get(), PR_IPM_OUTBOX_ENTRYID);
	if (nid != 0)
		g_folder_map.emplace(nid, tgt_folder{false, rop_util_make_eid_ex(1, PRIVATE_FID_OUTBOX), "FID_OUTBOX"});
	nid = az_nid_from_mst(mst.get(), PR_IPM_WASTEBASKET_ENTRYID);
	if (nid != 0)
		g_folder_map.emplace(nid, tgt_folder{false, rop_util_make_eid_ex(1, PRIVATE_FID_DELETED_ITEMS), "FID_DELETED_ITEMS"});
	nid = az_nid_from_mst(mst.get(), PR_IPM_SENTMAIL_ENTRYID);
	if (nid != 0)
		g_folder_map.emplace(nid, tgt_folder{false, rop_util_make_eid_ex(1, PRIVATE_FID_SENT_ITEMS), "FID_SENT_ITEMS"});
	nid = az_nid_from_mst(mst.get(), PR_COMMON_VIEWS_ENTRYID);
	if (nid != 0)
		g_folder_map.emplace(nid, tgt_folder{false, rop_util_make_eid_ex(1, PRIVATE_FID_COMMON_VIEWS), "FID_COMMON_VIEWS"});
	nid = az_nid_from_mst(mst.get(), PR_FINDER_ENTRYID);
	if (nid != 0)
		g_folder_map.emplace(nid, tgt_folder{false, rop_util_make_eid_ex(1, PRIVATE_FID_FINDER), "FID_FINDER"});
}

static void az_fmap_standard(libpff_file_t *file, const char *filename)
{
	char timebuf[64];
	time_t now = time(nullptr);
	auto tm = localtime(&now);
	strftime(timebuf, arsizeof(timebuf), " @%FT%T", tm);
	g_folder_map.emplace(NID_ROOT_FOLDER, tgt_folder{true, rop_util_make_eid_ex(1, PRIVATE_FID_IPMSUBTREE),
		"Import of "s + HX_basename(filename) + timebuf});
}

static void az_fmap_splice(libpff_file_t *file)
{
	g_folder_map.emplace(NID_ROOT_FOLDER, tgt_folder{false, rop_util_make_eid_ex(1, PRIVATE_FID_ROOT), "FID_ROOT"});
	az_lookup_specials(file);
}

static int do_file(const char *filename) try
{
	libpff_error_ptr err;
	libpff_file_ptr file;
	if (libpff_file_initialize(&unique_tie(file), &unique_tie(err)) < 1) {
		fprintf(stderr, "%s\n", az_error("PF-1023", err).what());
		return -EIO;
	}
	fprintf(stderr, "Reading %s...\n", filename);
	if (libpff_file_open(file.get(), filename, LIBPFF_OPEN_READ, nullptr) < 1) {
		int s = errno;
		fprintf(stderr, "Could not open \"%s\": %s\n", filename, strerror(s));
		return -(errno = s);
	}

	g_folder_map.clear();
	g_propname_cache.clear();
	if (g_wet_run)
		fprintf(stderr, "Transferring objects...\n");
	if (g_splice)
		az_fmap_splice(file.get());
	else
		az_fmap_standard(file.get(), filename);
	if (g_show_props) {
		printf("Folder map:\n");
		for (const auto &pair : g_folder_map)
			printf("\t%xh -> %s%s\n", pair.first, pair.second.create_name.c_str(),
			       pair.second.create ? " (create)" : "");
	}

	libpff_item_ptr root;
	if (libpff_file_get_root_item(file.get(), &~unique_tie(root), &~unique_tie(err)) < 1)
		throw az_error("PF-1025", err);
	return do_item(0, {}, root.get());
} catch (const char *e) {
	fprintf(stderr, "Exception: %s\n", e);
	return -ECANCELED;
} catch (const std::string &e) {
	fprintf(stderr, "Exception: %s\n", e.c_str());
	return -ECANCELED;
} catch (const std::exception &e) {
	fprintf(stderr, "Exception: %s\n", e.what());
	return -ECANCELED;
}

int main(int argc, const char **argv)
{
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (g_wet_run && g_username == nullptr) {
		fprintf(stderr, "When -n is absent, the -u option is mandatory.\n");
		return EXIT_FAILURE;
	}
	if (argc < 2) {
		fprintf(stderr, "Usage: pffimport [-pst] {-n|-u username} input.pst...\n");
		return EXIT_FAILURE;
	}
	if (g_username != nullptr && gi_setup(g_username) != EXIT_SUCCESS)
		return EXIT_FAILURE;
	int ret = EXIT_SUCCESS;
	while (--argc > 0) {
		auto r2 = do_file(*++argv);
		if (r2 < 0) {
			ret = EXIT_FAILURE;
			break;
		}
	}
	if (ret == EXIT_FAILURE)
		fprintf(stderr, "Import unsuccessful.\n");
	return ret ? EXIT_SUCCESS : EXIT_FAILURE;
}
