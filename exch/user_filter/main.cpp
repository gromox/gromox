// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <unistd.h>
#include <libHX/string.h>
#include <sys/types.h>
#include <gromox/config_file.hpp>
#include <gromox/defs.h>
#include <gromox/svc_common.h>
#include <gromox/util.hpp>
#include "user_filter.hpp"

using namespace std::string_literals;
using namespace gromox;
DECLARE_SVC_API(user_filter, );
using namespace user_filter;

BOOL SVC_user_filter(enum plugin_op reason, const struct dlfuncs &ppdata)
{
	char temp_buff[128];
	int audit_max, audit_interval, audit_times, temp_list_size;
	BOOL case_sensitive;
	
	switch(reason) {
	case PLUGIN_INIT: {
		LINK_SVC_API(ppdata);
		auto pfile = config_file_initd("user_filter.cfg", get_config_path(), nullptr);
		if (NULL == pfile) {
			mlog(LV_ERR, "user_filter: config_file_initd user_filter.cfg: %s",
				strerror(errno));
			return FALSE;
		}
		auto str_value = pfile->get_value("IS_CASE_SENSITIVE");
		case_sensitive = str_value != nullptr && parse_bool(str_value);
		str_value = pfile->get_value("AUDIT_MAX_NUM");
		audit_max = str_value != nullptr ? strtol(str_value, nullptr, 0) : 0;
		if (audit_max < 0)
			audit_max = 0;
		str_value = pfile->get_value("AUDIT_INTERVAL");
		if (NULL == str_value) {
			audit_interval = 60;
		} else {
			audit_interval = HX_strtoull_sec(str_value, nullptr);
			if (audit_interval <= 0)
				audit_interval = 60;
		}
		HX_unit_seconds(temp_buff, std::size(temp_buff), audit_interval, 0);
		str_value = pfile->get_value("AUDIT_TIMES");
		audit_times = str_value != nullptr ? strtol(str_value, nullptr, 0) : 10;
		if (audit_times <= 0)
			audit_times = 10;
		str_value = pfile->get_value("TEMP_LIST_SIZE");
		temp_list_size = str_value != nullptr ? strtol(str_value, nullptr, 0) : 0;
		if (temp_list_size < 0)
			temp_list_size = 0;
		mlog(LV_INFO, "user_filter: case-%ssensitive, audit_capacity=%d, "
		        "audit_interval=%s, audit_times=%d, tmplist_capacity=%d",
		        case_sensitive ? "" : "in",
		        audit_max, temp_buff, audit_times, temp_list_size);
		str_value = pfile->get_value("JUDGE_SERVICE_NAME");
		std::string judge_name = str_value != nullptr ? str_value : "user_filter_judge";
		str_value = pfile->get_value("ADD_SERVICE_NAME");
		std::string add_name = str_value != nullptr ? str_value : "user_filter_add"s;
		str_value = pfile->get_value("QUERY_SERVICE_NAME");
		std::string query_name = str_value != nullptr ? str_value : "user_filter_query"s;
		str_filter_init("user_filter", case_sensitive, audit_max,
			audit_interval, audit_times, temp_list_size);
		if (0 != str_filter_run()) {
			mlog(LV_ERR, "user_filter: failed to run the module");
			return FALSE;
		}
		if (judge_name.size() > 0 && !register_service(judge_name.c_str(), str_filter_judge)) {
			mlog(LV_ERR, "user_filter: failed to register \"%s\" service",
				judge_name.c_str());
			return FALSE;
		}
		if (query_name.size() > 0 && !register_service(query_name.c_str(), str_filter_query)) {
			mlog(LV_ERR, "user_filter: failed to register \"%s\" service",
				query_name.c_str());
			return FALSE;
		}
		if (add_name.size() > 0 && !register_service(add_name.c_str(), str_filter_add_string_into_temp_list)) {
			mlog(LV_ERR, "user_filter: failed to register \"%s\" service",
				add_name.c_str());
			return FALSE;
		}
		return TRUE;
	}
	case PLUGIN_FREE:
		str_filter_stop();
		str_filter_free();
		return TRUE;
	default:
		return TRUE;
	}
}
