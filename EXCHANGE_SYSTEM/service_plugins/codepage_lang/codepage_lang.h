#ifndef _H_CODEPAGE_LANG_
#define _H_CODEPAGE_LANG_

#ifdef __cplusplus
#	include <cstdint>
#else
#	include <stdint.h>
#endif
#include "common_types.h"

void codepage_lang_init(const char *path);

int codepage_lang_run();

int codepage_lang_stop();

void codepage_lang_free();

BOOL codepage_lang_get_lang(uint32_t codepage, const char *tag,
	char *value, int len);
	
BOOL codepage_lang_reload();

#endif /* _H_CODEPAGE_LANG_ */