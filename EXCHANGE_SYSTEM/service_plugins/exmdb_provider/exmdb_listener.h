#pragma once

#ifdef __cplusplus
extern "C" {
#endif

void exmdb_listener_init(const char *ip,
	int port, const char *list_path);
extern int exmdb_listener_run(void);
extern int exmdb_listener_trigger_accept(void);
extern int exmdb_listener_stop(void);

#ifdef __cplusplus
} /* extern "C" */
#endif
