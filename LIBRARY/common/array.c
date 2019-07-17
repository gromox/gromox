/*
 *	array is a certain data struct same as type of array, but the number of
 *	items is not fix. items can be appended into array any time. but when an 
 *	item is added into array, it can not be deleted because the index is 
 *	permanently assigned to this item. access the data according index will be 
 *	slow if the index is very large (e.g. 100000). 128 is recommanded as the 
 *	capacity of array
 */

#include "array.h"
#include "util.h"
#include <string.h>

/* the extra memory ocupation for array node */
#define EXTRA_ARRAYNODE_SIZE		sizeof(SINGLE_LIST_NODE)


/*
 *	init a array with the specified size of data and max capacity.
 *
 *	@param
 *		parray		[in]	the array that will be init
 *		pbuf_pool	[in]	the outside allocator that manage the 
 *							memory core
 *		data_size			the data elements size
 */
void array_init(ARRAY* parray, LIB_BUFFER* pbuf_pool, size_t data_size)
{
#ifdef _DEBUG_UMTA
	if (NULL == parray || NULL == pbuf_pool) {
		debug_info("[array]: NULL pointer found in array_init");
		return;
	}
#endif
	memset(parray, 0, sizeof(ARRAY));
	single_list_init(&(parray->mlist));
	
	parray->mbuf_pool	= pbuf_pool;
	parray->cur_size	= 0;
	parray->data_size	= data_size;
   
	if (data_size > lib_buffer_get_param(pbuf_pool, 
		MEM_ITEM_SIZE) - EXTRA_ARRAYNODE_SIZE) {
		debug_info("[array]: array_init warning!!!! array data"
			" size larger than allocator item size");
	}
}

/*
 *	free the specified array
 *
 *	@param
 *		parray [in]		the array object to free
 */

void array_free(ARRAY* parray)
{
#ifdef _DEBUG_UMTA
	if (NULL == parray) {
		debug_info("[array]: NULL pointer found in array_free");
		return;
	}
#endif
	array_clear(parray);
	single_list_free(&parray->mlist);
}


/*
 *	init a memory allocator with the specified requirement for the array
 *
 *	@param	
 *		data_size		the array data size
 *		max_size		the capacity of the array
 *		thread_safe		is the allocator thread safe?
 *
 *	@return
 *		the allocator pointer, NULL if fail
 */
LIB_BUFFER* array_allocator_init(size_t data_size, size_t max_size, BOOL thread_safe)
{
	return lib_buffer_init(data_size + EXTRA_ARRAYNODE_SIZE, 
					max_size, thread_safe);
}


/*
 *	free the specified array allocator
 *
 *	@param	
 *		buf [in]	the specified allocator
 */
void array_allocator_free(LIB_BUFFER* buf)
{
	if (NULL == buf) {
		return;
	}

	lib_buffer_free(buf);
}
/*
 *	append the data into the specified array
 *
 *	@param
 *		parray [in]		the array that will 
 *						push the data onto
 *		pdata  [in]		pointer to the data
 *						that will be push on
 *	@return
 *		<0				fail to append
 *		>=0				index of the item
 */
long array_append(ARRAY* parray, void* pdata)
{
	SINGLE_LIST_NODE   *node = NULL;
	long ret_index;

#ifdef _DEBUG_UMTA
	if (NULL == parray || NULL == pdata) {	  
		debug_info("[array]: NULL pointer found in array_init");
		return -1;
	}
#endif

	node = lib_buffer_get(parray->mbuf_pool);
	if (NULL == node) {
		return -1;
	}
	node->pdata = (char*)node + sizeof(SINGLE_LIST_NODE);
	memcpy(node->pdata, pdata, parray->data_size);

	single_list_append_as_tail(&parray->mlist, node);
	ret_index = parray->cur_size;
	parray->cur_size ++;
	/* cache the ptr in cache table */
	if (ret_index < ARRAY_CACHEITEM_NUMBER) {
		parray->cache_ptrs[ret_index] = node->pdata;
	}
	return ret_index;
}

/*
 *	get item from the specified array
 *	
 *	@param	
 *		parray [in]		the specified array object
 *
 *	@return
 *		pointer to the item data
 */
void* array_get_item(ARRAY* parray, size_t index)
{
	SINGLE_LIST_NODE   *node = NULL;
	size_t i;
	
#ifdef _DEBUG_UMTA
	if (NULL == parray) {
		debug_info("[array]: NULL pointer found in array_get_item");
	}
#endif
	if (NULL == parray) {
		return NULL;
	}
	if (index + 1> parray->cur_size || index < 0) {
		return NULL;
	}

	if (index < ARRAY_CACHEITEM_NUMBER) {
		return parray->cache_ptrs[index];
	}
	node = (SINGLE_LIST_NODE*)((char*)parray->cache_ptrs[ARRAY_CACHEITEM_NUMBER-1]
		   - sizeof(SINGLE_LIST_NODE));
	for(i=ARRAY_CACHEITEM_NUMBER; i<=index; i++) {
		node = single_list_get_after(&parray->mlist, node);
	}
	return node->pdata;
}

/*
 *	get items of array
 *
 *	@param	
 *		parray [in]		the array object
 *
 *	@return
 *		number of items
 */
size_t array_get_capacity(ARRAY* parray)
{
#ifdef _DEBUG_UMTA
	if (NULL == parray) {
		debug_info("[array]: NULL pointer found in array_get_capacity");
		return 0;
	}
#endif
	return parray->cur_size;
}

/*
 *	clear the items in the array and free 
 *	the memory it allocates
 *
 *	@param
 *		parray [in]		the cleared array
 */

void array_clear(ARRAY* parray)
{
	SINGLE_LIST_NODE *node;
#ifdef _DEBUG_UMTA
	if (NULL == parray) {
		debug_info("[array]: NULL pointer found in array_clear");
	}
#endif
	while (NULL != (node=single_list_get_from_head(&parray->mlist))) {
		lib_buffer_put(parray->mbuf_pool, node);
	}
	parray->cur_size = 0;
	memset(parray->cache_ptrs, 0, sizeof(parray->cache_ptrs));
}

