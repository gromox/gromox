// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdlib>
#include <cstring>
#include <memory>
#include <gromox/mapi_types.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/util.hpp>
#include "common_util.h"
#include "ics_state.h"

using LLU = unsigned long long;

static ics_state *ics_state_init(ics_state *pstate, logon_object *plogon, int type)
{
	BINARY tmp_bin;
	tmp_bin.cb = sizeof(void*);
	tmp_bin.pv = &plogon;
	pstate->pseen = idset::create(true, REPL_TYPE_GUID);
	if (NULL == pstate->pseen) {
		return NULL;
	}
	if (!pstate->pseen->register_mapping(&tmp_bin, common_util_mapping_replica))
		return NULL;
	switch (type) {
	case ICS_STATE_CONTENTS_DOWN:
		pstate->pgiven = idset::create(true, REPL_TYPE_GUID);
		if (NULL == pstate->pgiven) {
			return NULL;
		}
		if (!pstate->pgiven->register_mapping(&tmp_bin,
		    common_util_mapping_replica))
			return NULL;
		pstate->pseen_fai = idset::create(true, REPL_TYPE_GUID);
		if (NULL == pstate->pseen_fai) {
			return NULL;
		}
		if (!pstate->pseen_fai->register_mapping(&tmp_bin,
		    common_util_mapping_replica))
			return NULL;
		pstate->pread = idset::create(true, REPL_TYPE_GUID);
		if (NULL == pstate->pread) {
			return NULL;
		}
		if (!pstate->pread->register_mapping(&tmp_bin,
		    common_util_mapping_replica))
			return NULL;
		break;
	case ICS_STATE_HIERARCHY_DOWN:
		pstate->pgiven = idset::create(true, REPL_TYPE_GUID);
		if (NULL == pstate->pgiven) {
			return NULL;
		}
		if (!pstate->pgiven->register_mapping(&tmp_bin,
		    common_util_mapping_replica))
			return NULL;
		break;
	case ICS_STATE_CONTENTS_UP:
		pstate->pgiven = idset::create(true, REPL_TYPE_GUID);
		if (NULL == pstate->pgiven) {
			return NULL;
		}
		if (!pstate->pgiven->register_mapping(&tmp_bin,
		    common_util_mapping_replica))
			return NULL;
		pstate->pseen_fai = idset::create(true, REPL_TYPE_GUID);
		if (NULL == pstate->pseen_fai) {
			return NULL;
		}
		if (!pstate->pseen_fai->register_mapping(&tmp_bin,
		    common_util_mapping_replica))
			return NULL;
		pstate->pread = idset::create(true, REPL_TYPE_GUID);
		if (NULL == pstate->pread) {
			return NULL;
		}
		if (!pstate->pread->register_mapping(&tmp_bin,
		    common_util_mapping_replica))
			return NULL;
		break;
	case ICS_STATE_HIERARCHY_UP:
		break;
	}
	pstate->type = type;
	return pstate;
}

std::unique_ptr<ics_state> ics_state::create(logon_object *plogon, int type) try
{
	auto pstate = std::make_unique<ics_state>();
	if (ics_state_init(pstate.get(), plogon, type) == nullptr)
		return nullptr;
	return pstate;
} catch (const std::bad_alloc &) {
	return nullptr;
}

std::shared_ptr<ics_state> ics_state::create_shared(logon_object *plogon, int type) try
{
	auto pstate = std::make_shared<ics_state>();
	if (ics_state_init(pstate.get(), plogon, type) == nullptr)
		return nullptr;
	return pstate;
} catch (const std::bad_alloc &) {
	return nullptr;
}

static void dump(ics_state *is, uint32_t proptag, idset *pset)
{
	fprintf(stderr, "dump of ics_state %p (%xh, %s)={\n", is, proptag,
		proptag == MetaTagIdsetGiven ? "idgiven" :
		proptag == MetaTagIdsetGiven1 ? "idgiven1" :
		proptag == MetaTagCnsetSeen ? "cnseen" : "other");
	for (const auto &repl_node : pset->repl_list) {
	for (const auto &range_node : repl_node.range_list) {
		if (pset->repl_type == REPL_TYPE_GUID)
			fprintf(stderr, "\t%s ", gromox::bin2hex(repl_node.replguid).c_str());
		else
			fprintf(stderr, "\t#%u ", repl_node.replid);
		fprintf(stderr, "%llxh--%llxh\n", LLU(range_node.low_value),
			LLU(range_node.high_value));
	}
	}
	fprintf(stderr, "}\n");
}

BOOL ics_state::append_idset(uint32_t state_property, std::unique_ptr<idset> &&pset)
{
	auto pstate = this;
	switch (state_property) {
	case MetaTagIdsetGiven:
	case MetaTagIdsetGiven1:
		pstate->pgiven = std::move(pset);
		dump(this, state_property, pstate->pgiven.get());
		return TRUE;
	case MetaTagCnsetSeen:
		if (NULL != pstate->pseen) {
			if ((ICS_STATE_CONTENTS_UP == pstate->type ||
				ICS_STATE_HIERARCHY_UP == pstate->type) &&
			    !pstate->pseen->check_empty() &&
			    !pset->concatenate(pstate->pseen.get()))
				return FALSE;
		}
		pstate->pseen = std::move(pset);
		dump(this, state_property, pstate->pseen.get());
		return TRUE;
	case MetaTagCnsetSeenFAI:
		if (NULL != pstate->pseen_fai) {
			if (ICS_STATE_CONTENTS_UP == pstate->type &&
			    !pstate->pseen_fai->check_empty() &&
			    !pset->concatenate(pstate->pseen_fai.get()))
				return FALSE;
		}
		pstate->pseen_fai = std::move(pset);
		return TRUE;
	case MetaTagCnsetRead:
		if (NULL != pstate->pread) {
			if (ICS_STATE_CONTENTS_UP == pstate->type &&
			    !pstate->pread->check_empty() &&
			    !pset->concatenate(pstate->pread.get()))
				return FALSE;
		}
		pstate->pread = std::move(pset);
		return TRUE;
	}
	return FALSE;
}

TPROPVAL_ARRAY *ics_state::serialize()
{
	struct mdel {
		inline void operator()(BINARY *x) const { rop_util_free_binary(x); }
		inline void operator()(TPROPVAL_ARRAY *x) const { tpropval_array_free(x); }
	};
	auto pstate = this;
	std::unique_ptr<TPROPVAL_ARRAY, mdel> pproplist(tpropval_array_init());
	if (NULL == pproplist) {
		return NULL;
	}
	
	if (ICS_STATE_CONTENTS_DOWN == pstate->type ||
		ICS_STATE_HIERARCHY_DOWN == pstate->type ||
		(ICS_STATE_CONTENTS_UP == pstate->type &&
	    !pstate->pgiven->check_empty())) {
		auto pbin = pstate->pgiven->serialize();
		if (NULL == pbin) {
			return NULL;
		}
		if (pproplist->set(MetaTagIdsetGiven1, pbin) != 0) {
			rop_util_free_binary(pbin);
			return NULL;
		}
		rop_util_free_binary(pbin);
	}
	
	std::unique_ptr<BINARY, mdel> ser(pstate->pseen->serialize());
	if (ser == nullptr || pproplist->set(MetaTagCnsetSeen, ser.get()) != 0)
		return NULL;
	
	if (ICS_STATE_CONTENTS_DOWN == pstate->type ||
		ICS_STATE_CONTENTS_UP == pstate->type) {
		decltype(ser) s(pstate->pseen_fai->serialize());
		if (s == nullptr ||
		    pproplist->set(MetaTagCnsetSeenFAI, s.get()) != 0)
			return NULL;
	}
	
	if (ICS_STATE_CONTENTS_DOWN == pstate->type ||
		(ICS_STATE_CONTENTS_UP == pstate->type &&
	    !pstate->pread->check_empty())) {
		decltype(ser) s(pstate->pread->serialize());
		if (s == nullptr ||
		    pproplist->set(MetaTagCnsetRead, s.get()) != 0)
			return NULL;
	}
	return pproplist.release();
}
