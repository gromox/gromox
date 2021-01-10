#pragma once
#include <gromox/mapi_types.hpp>
#include "store_object.h"


struct ICS_STATE {
	int type;
	IDSET *pgiven;
	IDSET *pseen;
	IDSET *pseen_fai;
	IDSET *pread;
};

#ifdef __cplusplus
extern "C" {
#endif

ICS_STATE* ics_state_create(uint8_t type);

BINARY* ics_state_serialize(ICS_STATE *pstate);

BOOL ics_state_deserialize(ICS_STATE *pstate, const BINARY *pbin);

void ics_state_free(ICS_STATE *pstate);

#ifdef __cplusplus
} /* extern "C" */
#endif
