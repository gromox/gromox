#pragma once
#include <cstdint>
#include <gromox/tpropval_array.hpp>
#include <gromox/simple_tree.hpp>
#include <gromox/int_hash.hpp>
#define ROOT_HANDLE						0
#define INVALID_HANDLE					0xFFFFFFFF

struct OBJECT_TREE {
	uint32_t last_handle;
	INT_HASH_TABLE *phash;
	SIMPLE_TREE tree;
};

OBJECT_TREE* object_tree_create(const char *maildir);

void object_tree_free(OBJECT_TREE *ptree);
	
uint32_t object_tree_add_object_handle(OBJECT_TREE *ptree,
	int parent_handle, int type, void *pobject);

void* object_tree_get_object(OBJECT_TREE *ptree,
	uint32_t obj_handle, uint8_t *ptype);
	
void object_tree_release_object_handle(
	OBJECT_TREE *ptree, uint32_t obj_handle);

void* object_tree_get_zarafa_store_propval(
	OBJECT_TREE *pobjtree, uint32_t proptag);
	
BOOL object_tree_set_zarafa_store_propval(
	OBJECT_TREE *pobjtree, const TAGGED_PROPVAL *ppropval);

void object_tree_remove_zarafa_store_propval(
	OBJECT_TREE *pobjtree, uint32_t proptag);

TPROPVAL_ARRAY* object_tree_get_profile_sec(
	OBJECT_TREE *pobjtree, GUID sec_guid);

void object_tree_touch_profile_sec(OBJECT_TREE *pobjtree);

uint32_t object_tree_get_store_handle(OBJECT_TREE *pobjtree,
	BOOL b_private, int account_id);
