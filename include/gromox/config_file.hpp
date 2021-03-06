#pragma once
#include <memory>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>

struct CONFIG_ENTRY {
    char keyname[256];
    char value[256];
	BOOL is_touched;
};

struct GX_EXPORT CONFIG_FILE {
	~CONFIG_FILE();
    CONFIG_ENTRY *config_table;
    size_t num_entries;
	size_t total_entries;
	char file_name[256];
};

extern GX_EXPORT std::shared_ptr<CONFIG_FILE> config_file_init(const char *filename);
extern GX_EXPORT std::shared_ptr<CONFIG_FILE> config_file_initd(const char *basename, const char *searchdirs = nullptr);
extern GX_EXPORT std::shared_ptr<CONFIG_FILE> config_file_prg(const char *priority_location, const char *fallback_location_basename);
extern GX_EXPORT const char *config_file_get_value(std::shared_ptr<CONFIG_FILE>, const char *key);
extern GX_EXPORT BOOL config_file_set_value(std::shared_ptr<CONFIG_FILE>, const char *key, const char *value);
extern GX_EXPORT BOOL config_file_save(std::shared_ptr<CONFIG_FILE>);
extern GX_EXPORT BOOL config_file_get_int(std::shared_ptr<CONFIG_FILE>, const char *key, int *);
extern GX_EXPORT BOOL config_file_set_int(std::shared_ptr<CONFIG_FILE>, const char *key, int);
