// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021-2024 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <map>
#include <memory>
#include <string>
#include <unistd.h>
#include <utility>
#include <libHX/option.h>
#include <libHX/scope.hpp>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/authmgr.hpp>
#include <gromox/bounce_gen.hpp>
#include <gromox/defs.h>
#include <gromox/dsn.hpp>
#include <gromox/fileio.h>
#include <gromox/mail_func.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include "exmdb_local.hpp"

using namespace std::string_literals;
using namespace gromox;
DECLARE_HOOK_API(exmdb_local, extern);
using namespace exmdb_local;

/*
 *	make a bounce mail
 *	@param
 *		bounce_type			type of bounce mail
 *		pmail [out]			bounce mail object
 */
bool exml_bouncer_make(const char *from, const char *rcpt_to,
    MAIL *pmail_original, time_t original_time, const char *bounce_type,
    MAIL *pmail) try
{
	MIME *pmime;
	char date_buff[128];
	sql_meta_result mres;
	const char *charset = nullptr;

	auto pdomain = strchr(from, '@');
	if (NULL != pdomain) {
		pdomain ++;
		if (mysql_adaptor_domain_list_query(pdomain) >= 1 &&
		    mysql_adaptor_meta(from, WANTPRIV_METAONLY, mres) == 0)
			charset = lang_to_charset(mres.lang.c_str());
	}
	rfc1123_dstring(date_buff, std::size(date_buff), original_time);
	auto mcharset = bounce_gen_charset(*pmail_original);
	if (charset == nullptr)
		charset = mcharset.c_str();
	charset = znul(charset);
	auto tpptr = bounce_gen_lookup(charset, bounce_type);
	if (tpptr == nullptr)
		return false;
	auto &tp = *tpptr;
	auto fa = HXformat_init();
	if (fa == nullptr)
		return false;
	auto cl_0 = HX::make_scope_exit([&]() { HXformat_free(fa); });
	unsigned int immed = HXFORMAT_IMMED;
	if (HXformat_add(fa, "time", date_buff, HXTYPE_STRING | immed) < 0 ||
	    HXformat_add(fa, "from", from, HXTYPE_STRING) < 0 ||
	    HXformat_add(fa, "rcpt", rcpt_to, HXTYPE_STRING) < 0 ||
	    HXformat_add(fa, "rcpts", rcpt_to, HXTYPE_STRING) < 0 ||
	    HXformat_add(fa, "postmaster", bounce_gen_postmaster(), HXTYPE_STRING) < 0)
		return false;
	auto str = bounce_gen_subject(*pmail_original, mcharset.c_str());
	if (HXformat_add(fa, "subject", str.c_str(), HXTYPE_STRING | immed) < 0)
		return false;
	auto mail_len = pmail_original->get_length();
	if (mail_len < 0) {
		mlog(LV_ERR, "exmdb_local: failed to get mail length");
		mail_len = 0;
	}
	HX_unit_size(date_buff, std::size(date_buff), mail_len, 1000, 0);
	if (HXformat_add(fa, "length", date_buff, HXTYPE_STRING) < 0)
		return false;

	hxmc_t *replaced = nullptr;
	auto aprint_len = HXformat_aprintf(fa, &replaced, &tp.content[tp.body_start]);
	if (aprint_len < 0)
		return false;
	auto cl_1 = HX::make_scope_exit([&]() { HXmc_free(replaced); });

	auto phead = pmail->add_head();
	if (NULL == phead) {
		mlog(LV_ERR, "exmdb_local: MIME pool exhausted");
		return false;
	}
	pmime = phead;
	pmime->set_content_type("multipart/report");
	pmime->set_content_param("report-type", "delivery-status");
	str = bounce_gen_thrindex(*pmail_original);
	if (!str.empty())
		pmime->set_field("Thread-Index", str.c_str());
	pmime->set_field("From", tp.from.size() > 0 ? tp.from.c_str() : bounce_gen_postmaster());
	pmime->set_field("To", ("<"s + from + ">").c_str());
	pmime->set_field("MIME-Version", "1.0");
	pmime->set_field("X-Auto-Response-Suppress", "All");
	rfc1123_dstring(date_buff, std::size(date_buff), 0);
	pmime->set_field("Date", date_buff);
	pmime->set_field("Subject", tp.subject.c_str());
	
	pmime = pmail->add_child(phead, MIME_ADD_FIRST);
	if (NULL == pmime) {
		mlog(LV_ERR, "exmdb_local: MIME pool exhausted");
		return false;
	}
	pmime->set_content_type("text/plain");
	pmime->set_content_param("charset", "utf-8");
	if (!pmime->write_content(replaced, aprint_len,
	    mime_encoding::automatic)) {
	mlog(LV_ERR, "exmdb_local: failed to write content");
		return false;
	}
	
	DSN dsn;
	auto pdsn_fields = dsn.get_message_fields();
	auto mta = "dns;"s + get_host_ID();
	auto t_addr = "rfc822;"s + rcpt_to;
	dsn.append_field(pdsn_fields, "Reporting-MTA", mta.c_str());
	rfc1123_dstring(date_buff, std::size(date_buff), original_time);
	dsn.append_field(pdsn_fields, "Arrival-Date", date_buff);
	pdsn_fields = dsn.new_rcpt_fields();
	if (pdsn_fields == nullptr)
		return false;
	dsn.append_field(pdsn_fields, "Final-Recipient", t_addr.c_str());
	if (strcmp(bounce_type, "BOUNCE_MAIL_DELIVERED") != 0) {
		dsn.append_field(pdsn_fields, "Action", "failed");
		dsn.append_field(pdsn_fields, "Status", "5.0.0");
	} else {
		dsn.append_field(pdsn_fields, "Action", "delivered");
		dsn.append_field(pdsn_fields, "Status", "2.0.0");
	}
	dsn.append_field(pdsn_fields, "Remote-MTA", mta.c_str());
	char original_ptr[256*1024];
	if (dsn.serialize(original_ptr, std::size(original_ptr))) {
		pmime = pmail->add_child(phead, MIME_ADD_LAST);
		if (NULL != pmime) {
			pmime->set_content_type("message/delivery-status");
			pmime->write_content(original_ptr,
				strlen(original_ptr), mime_encoding::none);
		}
	}
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1216: ENOMEM");
	return false;
}
