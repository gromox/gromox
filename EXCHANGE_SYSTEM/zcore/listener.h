#pragma once

#ifdef __cplusplus
extern "C" {
#endif

extern void listener_init(void);
extern int listener_run(const char *sockpath);
extern int listener_stop(void);
extern void listener_free(void);

#ifdef __cplusplus
} /* extern "C" */
#endif
