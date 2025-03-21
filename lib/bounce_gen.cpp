// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2024 grommunio GmbH
// This file is part of Gromox.
#include <dirent.h>
#include <map>
#include <netdb.h>
#include <string>
#include <libHX/io.h>
#include <libHX/option.h>
#include <gromox/bounce_gen.hpp>
#include <gromox/config_file.hpp>
#include <gromox/element_data.hpp>
#include <gromox/fileio.h>
#include <gromox/mail_func.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mapitags.hpp>
#include <gromox/util.hpp>

namespace gromox {

using template_map = std::map<std::string, bounce_template>;
static std::string g_bounce_postmaster;
static std::map<std::string, template_map> g_resource_list;

static errno_t bounce_gen_load(const std::string &cset_path, template_map &tplist)
{
	auto di = opendir_sd(cset_path.c_str(), nullptr);
	if (di.m_dir == nullptr)
		return errno;

	struct dirent *de;
	while ((de = readdir(di.m_dir.get())) != nullptr) {
		if (*de->d_name == '.')
			continue;
		auto tpl_file = cset_path + "/" + de->d_name;
		bounce_template bt;
		bt.content.reset(HX_slurp_file(tpl_file.c_str(), &bt.ctlen));
		if (bt.content == nullptr) {
			errno_t se = errno;
			mlog(LV_ERR, "Bounce template %s: %s",
				tpl_file.c_str(), strerror(se));
			return se;
		}

		size_t j = 0;
		while (j < bt.ctlen) {
			MIME_FIELD mf;
			auto parsed = parse_mime_field(&bt.content[j], bt.ctlen - j, &mf);
			j += parsed;
			if (parsed == 0) {
				mlog(LV_ERR, "Bounce template %s: Format error",
					tpl_file.c_str());
				return EIO;
			}
			if (strcasecmp(mf.name.c_str(), "From") == 0)
				bt.from = std::move(mf.value);
			else if (strcasecmp(mf.name.c_str(), "Subject") == 0)
				bt.subject = std::move(mf.value);
			if (bt.content[j] == '\n') {
				++j;
				break;
			} else if (bt.content[j] == '\r' && bt.content[j+1] == '\n') {
				j += 2;
				break;
			}
		}
		bt.body_start = j;
		tplist.emplace(de->d_name, std::move(bt));
	}
	return 0;
}

static constexpr cfg_directive bounce_gen_dflt[] = {
	{"bounce_postmaster", "postmaster@"},
	CFG_TABLE_END,
};

errno_t bounce_gen_init(const char *cfgdir, const char *datadir,
    const char *bounce_grp) try
{
	auto cfg = config_file_initd("gromox.cfg", cfgdir, bounce_gen_dflt);
	if (cfg == nullptr) {
		mlog(LV_ERR, "exmdb_provider: config_file_initd gromox.cfg: %s",
		       strerror(errno));
		return EIO;
	}
	auto str = cfg->get_value("bounce_postmaster");
	if (strchr(str, '@') == nullptr) {
		mlog(LV_ERR, "gromox.cfg: \"bounce_postmaster\" directive has bogus value: no @ character");
		return EINVAL;
	}
	g_bounce_postmaster = str;
	if (str[strlen(str)-1] == '@') {
		std::string hn;
		auto ret = canonical_hostname(hn);
		if (ret != 0) {
			mlog(LV_ERR, "canonical_hostname: %s", strerror(ret));
			return EINVAL;
		}
		g_bounce_postmaster += std::move(hn);
		mlog(LV_INFO, "bounce_gen: postmaster set to <%s>", g_bounce_postmaster.c_str());
	}

	auto di = opendir_sd(bounce_grp, datadir);
	if (di.m_dir == nullptr) {
		mlog(LV_ERR, "bounce_producer: opendir_sd(%s) %s: %s",
			bounce_grp, di.m_path.c_str(), strerror(errno));
		return EIO;
	}

	struct dirent *de;
	while ((de = readdir(di.m_dir.get())) != nullptr) {
		if (*de->d_name == '.')
			continue;
		auto ret = bounce_gen_load(di.m_path + "/" + de->d_name,
		           g_resource_list[de->d_name]);
		if (ret != 0)
			return ret;
	}
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1501: ENOMEM");
	return ENOMEM;
}

const bounce_template *bounce_gen_lookup(const char *cset, const char *tname)
{
	auto i = g_resource_list.find(cset);
	if (i == g_resource_list.end())
		i = g_resource_list.find("ascii");
	if (i == g_resource_list.end())
		return nullptr;
	auto j = i->second.find(tname);
	if (j == i->second.end())
		return nullptr;
	return &j->second;
}

const char *bounce_gen_postmaster() { return g_bounce_postmaster.c_str(); }

std::string bounce_gen_rcpts(const tarray_set &rcpts)
{
	std::string r;
	for (size_t i = 0; i < rcpts.count; ++i) {
		auto str = rcpts.pparray[i]->get<const char>(PR_SMTP_ADDRESS);
		if (str == nullptr)
			continue;
		if (!r.empty())
			r += ", ";
		r += str;
	}
	return r;
}

}
