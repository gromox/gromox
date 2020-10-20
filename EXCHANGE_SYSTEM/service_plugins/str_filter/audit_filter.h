#pragma once
#include "common_types.h"
#include <time.h>

/* the index of audit param is from 0 to 99 */
enum {
    AUDIT_INTERVAL = 0,
    AUDIT_TIMES,
	AUDIT_CAPABILITY
};

#ifdef __cplusplus
extern "C" {
#endif

void audit_filter_init(BOOL case_sensitive, int audit_num, int audit_interval, 
    int audit_times);
extern int audit_filter_run(void);
extern int audit_filter_stop(void);
int audit_filter_set_param(int tpye, int value);

int audit_filter_get_param(int type);
extern void audit_filter_free(void);
BOOL audit_filter_query(const char *str);

BOOL audit_filter_judge(const char *str);

BOOL audit_filter_echo(const char *str, time_t *pfirst_access,
	time_t *plast_access, int *ptimes);

BOOL audit_filter_dump(const char *path);

BOOL audit_filter_remove_string(const char *str);

#ifdef __cplusplus
} /* extern "C" */
#endif
