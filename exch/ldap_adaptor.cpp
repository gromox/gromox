// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2020–2025 grommunio GmbH
// This file is part of Gromox.

/*
 * openldap uses some global state, and an ELF Global Destructor function to
 * get rid of it; but there is no particular guaranteed order among global
 * destructors, and libasan's reporting can run ahead of libldap deallocating
 * its state.
 *
 * [ASAN] Direct leak of 15 byte(s) in 3 object(s) allocated from:
 *   #0 malloc (/usr/lib64/libasan.so.8+0xf72b7) (BuildId: 4ee117fa2a132af1da9f17a0a5fe1f888398d50f)
 *   #1 ber_memalloc_x /usr/src/debug/openldap2-2.4.46-0.x86_64/libraries/liblber/memory.c:228
 *   #2 ber_strdup_x /usr/src/debug/openldap2-2.4.46-0.x86_64/libraries/liblber/memory.c:638
 *   #3 ldap_int_initialize /usr/src/debug/openldap2-2.4.46-0.x86_64/libraries/libldap_r/init.c:682
 *   #4 ldap_create /usr/src/debug/openldap2-2.4.46-0.x86_64/libraries/libldap_r/open.c:108
 *   #5 ldap_initialize /usr/src/debug/openldap2-2.4.46-0.x86_64/libraries/libldap_r/open.c:240
 */

#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ldap.h>
#include <memory>
#include <string>
#include <typeinfo>
#include <utility>
#include <libHX/string.h>
#include <gromox/config_file.hpp>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/resource_pool.hpp>
#include <gromox/svc_common.h>
#include <gromox/tie.hpp>
#include <gromox/util.hpp>
#include "ldap_adaptor.hpp"

using namespace gromox;
using namespace std::string_literals;
DECLARE_SVC_API(,);

namespace {
struct ldapfree {
	void operator()(char *s) const { ldap_memfree(s); }
	void operator()(LDAP *ld) const { ldap_unbind_ext_s(ld, nullptr, nullptr); }
	void operator()(LDAPMessage *m) const { ldap_msgfree(m); }
};
}

using ldap_msg = std::unique_ptr<LDAPMessage, ldapfree>;
using ldap_ptr = std::unique_ptr<LDAP, ldapfree>;

namespace {

struct twoconn {
	ldap_ptr meta, bind;
};

struct ldap_plugin final {
	public:
	bool load();
	int gx_ldap_bind(ldap_ptr &, const char *, struct berval *);
	int gx_ldap_search(ldap_ptr &, const char *, const char *, char **, ldap_msg &);
	bool ldaplogin_host(ldap_ptr &, ldap_ptr &, const char *, const char *, const char *, const std::string &);
	bool ldaplogin_dpool(const char *, const char *);
	bool login3(const char *, const char *, const sql_meta_result &);

	protected:
	std::string g_ldap_host, g_search_base, g_mail_attr;
	std::string g_bind_user, g_bind_pass;
	bool g_use_tls;
	unsigned int g_edir_workaround; /* server sends garbage sometimes */
	resource_pool<twoconn> g_conn_pool;
};

}

static std::optional<ldap_plugin> le_ldap_plugin;
static constexpr const char *no_attrs[] = {nullptr};
static constexpr cfg_directive ldap_adaptor_cfg_defaults[] = {
	{"data_connections", "4", CFG_SIZE, "1"},
	{"ldap_bind_pass", ""},
	{"ldap_bind_user", ""},
	{"ldap_edirectory_workaround", "false", CFG_BOOL},
	{"ldap_host", "ldapi:///"},
	{"ldap_mail_attr", "mail"},
	{"ldap_search_base", ""},
	{"ldap_start_tls", "false", CFG_BOOL},
	CFG_TABLE_END,
};

/**
 * Make sure the response has exactly one entry and at most
 * one optional informational search trailer.
 */
static int validate_response(LDAP *ld, LDAPMessage *result)
{
	if (result == nullptr) {
		mlog(LV_ERR, "ldap_adaptor: ldap_search yielded success, but result is null?!");
		return -1;
	}
	auto count = ldap_count_messages(ld, result);
	unsigned int i = 0, match = 0;
	for (auto msg = ldap_first_message(ld, result); msg != nullptr;
	     msg = ldap_next_message(ld, msg)) {
		++i;
		auto mtype = ldap_msgtype(msg);
		if (mtype == LDAP_RES_SEARCH_REFERENCE ||
		    mtype == LDAP_RES_SEARCH_RESULT)
			/*
			 * Ignore referrals and the "# search result" block
			 * (visible in ldapsearch(1) output).
			 */
			continue;
		if (mtype != LDAP_RES_SEARCH_ENTRY) {
			mlog(LV_ERR, "ldap_adaptor: ldap_search yielded a result with "
			        "msg %d/%d of unexpected type %d", i, count, mtype);
			return -1;
		}
		if (match < INT_MAX)
			++match;
	}
	return match;
}

static ldap_ptr make_conn(const std::string &uri, const char *bind_user,
    const char *bind_pass, bool start_tls, bool perform_bind)
{
	ldap_ptr ld;
	auto ret = ldap_initialize(&unique_tie(ld), uri.empty() ? nullptr : uri.c_str());
	if (ret != LDAP_SUCCESS)
		return {};
	static constexpr int version = LDAP_VERSION3;
	ret = ldap_set_option(ld.get(), LDAP_OPT_PROTOCOL_VERSION, &version);
	if (ret != LDAP_SUCCESS)
		return {};
	ret = ldap_set_option(ld.get(), LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
	if (ret != LDAP_SUCCESS)
		return {};
	if (start_tls) {
		ret = ldap_start_tls_s(ld.get(), nullptr, nullptr);
		if (ret != LDAP_SUCCESS) {
			mlog(LV_ERR, "ldap_start_tls_s: %s", ldap_err2string(ret));
			return {};
		}
	}
	if (!perform_bind)
		return ld;

	struct berval cred{};
	if (*bind_user != '\0') {
		cred.bv_val = deconst(bind_pass);
		cred.bv_len = strlen(znul(bind_pass));
	} else {
		bind_user = nullptr;
	}
	ret = ldap_sasl_bind_s(ld.get(), bind_user, LDAP_SASL_SIMPLE, &cred,
	      nullptr, nullptr, nullptr);
	if (ret != LDAP_SUCCESS) {
		mlog(LV_ERR, "ldap_adaptor: bind as \"%s\" on \"%s\": %s",
		        znul(bind_user), uri.c_str(), ldap_err2string(ret));
		return {};
	}
	return ld;
}

static constexpr bool AVOID_BIND = false, DO_BIND = true;

int ldap_plugin::gx_ldap_bind(ldap_ptr &ld, const char *dn, struct berval *bv)
{
	if (ld == nullptr)
		ld = make_conn(g_ldap_host, nullptr, nullptr, g_use_tls, AVOID_BIND);
	if (ld == nullptr)
		return LDAP_SERVER_DOWN;
	auto ret = ldap_sasl_bind_s(ld.get(), dn, LDAP_SASL_SIMPLE, bv,
		   nullptr, nullptr, nullptr);
	if (ret == LDAP_LOCAL_ERROR && g_edir_workaround)
		/* try full reconnect */;
	else if (ret != LDAP_SERVER_DOWN)
		return ret;
	ld = make_conn(g_ldap_host, nullptr, nullptr, g_use_tls, AVOID_BIND);
	if (ld == nullptr)
		return ret;
	return ldap_sasl_bind_s(ld.get(), dn, LDAP_SASL_SIMPLE, bv,
	       nullptr, nullptr, nullptr);
}

int ldap_plugin::gx_ldap_search(ldap_ptr &ld, const char *base, const char *filter,
    char **attrs, ldap_msg &msg)
{
	if (ld == nullptr)
		ld = make_conn(g_ldap_host, g_bind_user.c_str(),
		     g_bind_pass.c_str(), g_use_tls, DO_BIND);
	if (ld == nullptr)
		return LDAP_SERVER_DOWN;
	auto ret = ldap_search_ext_s(ld.get(), base, LDAP_SCOPE_SUBTREE,
	           filter, attrs, true, nullptr, nullptr, nullptr, 1, &unique_tie(msg));
	if (ret == LDAP_LOCAL_ERROR && g_edir_workaround)
		/* try full reconnect */;
	else if (ret != LDAP_SERVER_DOWN)
		return ret;
	ld = make_conn(g_ldap_host, g_bind_user.c_str(),
	     g_bind_pass.c_str(), g_use_tls, DO_BIND);
	if (ld == nullptr)
		return ret;
	return ldap_search_ext_s(ld.get(), base, LDAP_SCOPE_SUBTREE,
	       filter, attrs, true, nullptr, nullptr, nullptr, 1, &~unique_tie(msg));
}

bool ldap_plugin::ldaplogin_host(ldap_ptr &tok_meta, ldap_ptr &tok_bind,
    const char *attr, const char *username, const char *password,
    const std::string &base_dn)
{
	ldap_msg msg;
	std::unique_ptr<char[], stdlib_delete> freeme;
	auto quoted = HX_strquote(username, HXQUOTE_LDAPRDN, &unique_tie(freeme));
	auto filter = attr + "="s + quoted;
	auto ret = gx_ldap_search(tok_meta,
	           base_dn.size() > 0 ? base_dn.c_str() : nullptr,
	           filter.c_str(), const_cast<char **>(no_attrs), msg);
	auto act_base = base_dn.size() > 0 ? base_dn.c_str() : "(ldap.conf->BASE)";
	if (ret != LDAP_SUCCESS && ret != LDAP_SIZELIMIT_EXCEEDED) {
		mlog(LV_ERR, "ldap_adaptor: error during search in base \"%s\" for \"%s\": %s",
		        act_base, filter.c_str(), ldap_err2string(ret));
		return FALSE;
	}
	auto matches = validate_response(tok_meta.get(), msg.get());
	if (matches < 0) {
		return FALSE;
	} else if (matches == 0) {
		mlog(LV_DEBUG, "ldap_adaptor: search in base \"%s\" for \"%s\": 0 matches",
			act_base, filter.c_str());
		return false;
	} else if (ret == LDAP_SIZELIMIT_EXCEEDED) {
		mlog(LV_ERR, "ldap_adaptor: search in base \"%s\" for \"%s\": >1 match (ambiguous result)",
			act_base, filter.c_str());
		return false;
	}
	auto firstmsg = ldap_first_message(tok_meta.get(), msg.get());
	if (firstmsg == nullptr)
		return FALSE;
	std::unique_ptr<char[], ldapfree> dn(ldap_get_dn(tok_meta.get(), firstmsg));
	if (dn == nullptr)
		return FALSE;

	struct berval bv;
	bv.bv_val = deconst(znul(password));
	bv.bv_len = password != nullptr ? strlen(password) : 0;
	ret = gx_ldap_bind(tok_bind, dn.get(), &bv);
	if (ret == LDAP_SUCCESS)
		return TRUE;
	mlog(LV_ERR, "ldap_adaptor: ldap_simple_bind \"%s\": %s", dn.get(), ldap_err2string(ret));
	return FALSE;
}

bool ldap_plugin::ldaplogin_dpool(const char *username, const char *password)
{
	auto tok = g_conn_pool.get_wait();
	return ldaplogin_host(tok->meta, tok->bind, g_mail_attr.c_str(),
	       username, password, g_search_base);
}

bool ldap_plugin::login3(const char *user, const char *pass, const sql_meta_result &m)
{
	if (*znul(pass) == '\0')
		return false;
	bool pooling_enabled = g_conn_pool.capacity() > 0;
	if (m.ldap_uri.empty() && pooling_enabled)
		return ldaplogin_dpool(user, pass);
	/*
	 * Keeping a pool per LDAP server can quickly exhaust file descriptors,
	 * so don't even go there when multiple LDAP servers are in use.
	 */
	if (pooling_enabled) {
		mlog(LV_NOTICE, "ldap_adaptor: Pooling is now disabled (would use too many resources in multi-LDAP)");
		g_conn_pool.resize(0);
		g_conn_pool.clear();
	}
	if (m.ldap_uri.empty()) {
		auto conn = make_conn(g_ldap_host.c_str(), g_bind_user.c_str(),
		            g_bind_pass.c_str(), g_use_tls, true);
		return ldaplogin_host(conn, conn, g_mail_attr.c_str(), user,
		       pass, g_search_base.c_str());
	}
	auto conn = make_conn(m.ldap_uri.c_str(), m.ldap_binddn.c_str(),
	            m.ldap_bindpw.c_str(), m.ldap_start_tls, true);
	auto attr = m.ldap_mail_attr.empty() ? g_mail_attr.c_str() : m.ldap_mail_attr.c_str();
	return ldaplogin_host(conn, conn, attr, user, pass, m.ldap_basedn);
}

BOOL ldap_adaptor_login3(const char *user, const char *pass,
    const sql_meta_result &m)
{
	return le_ldap_plugin->login3(user, pass, m) ? TRUE : false;
}

bool ldap_plugin::load() try
{
	auto pfile = config_file_initd("ldap_adaptor.cfg", get_config_path(),
	             ldap_adaptor_cfg_defaults);
	if (pfile == nullptr) {
		mlog(LV_ERR, "ldap_adaptor: config_file_initd ldap_adaptor.cfg: %s",
		       strerror(errno));
		return false;
	}
	unsigned int dataconn_num = pfile->get_ll("data_connections");
	g_ldap_host = pfile->get_value("ldap_host");
	g_bind_user = pfile->get_value("ldap_bind_user");
	g_bind_pass = pfile->get_value("ldap_bind_pass");
	auto p2 = pfile->get_value("ldap_bind_pass_mode_id107");
	if (p2 != nullptr)
		g_bind_pass = zstd_decompress(base64_decode(p2));
	p2 = pfile->get_value("ldap_bind_pass_mode_id555");
	if (p2 != nullptr)
		g_bind_pass = sss_obf_reverse(base64_decode(p2));
	g_use_tls = pfile->get_ll("ldap_start_tls");
	g_mail_attr = pfile->get_value("ldap_mail_attr");
	g_search_base = pfile->get_value("ldap_search_base");
	g_edir_workaround = pfile->get_ll("ldap_edirectory_workaround");
	mlog(LV_NOTICE, "ldap_adaptor: default host <%s>%s%s, base <%s>, #conn=%d, mailattr=%s",
	       g_ldap_host.c_str(), g_use_tls ? " +TLS" : "",
	       g_edir_workaround ? " +EDIRECTORY_WORKAROUNDS" : "",
	       g_search_base.c_str(), 2 * dataconn_num, g_mail_attr.c_str());
	g_conn_pool.resize(dataconn_num);
	g_conn_pool.bump();
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1455: ENOMEM");
	return false;
}

BOOL SVC_ldap_adaptor(enum plugin_op reason, const struct dlfuncs &ppdata) try
{
	if (reason == PLUGIN_FREE) {
		le_ldap_plugin.reset();
		return TRUE;
	} else if (reason == PLUGIN_RELOAD) {
		if (le_ldap_plugin.has_value())
			le_ldap_plugin->load();
		return TRUE;
	}
	if (reason != PLUGIN_INIT)
		return TRUE;

	le_ldap_plugin.emplace();
	LINK_SVC_API(ppdata);
	if (!le_ldap_plugin->load())
		return false;
	return TRUE;
} catch (...) {
	return false;
}
