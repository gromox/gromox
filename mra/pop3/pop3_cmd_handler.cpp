// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/* 
 * collection of functions for handling the pop3 command
 */ 
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <unistd.h>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include "pop3_cmd_handler.h"
#include "system_services.h"
#include "resource.h"
#include "blocks_allocator.h"
#include "units_allocator.h"
#include <gromox/util.hpp>
#include <gromox/array.hpp>
#include <gromox/mail_func.hpp>
#include <cstring>
#include <cstdio>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>


#define MIDB_RESULT_OK          0

#define MIDB_NO_SERVER          1

#define MIDB_RDWR_ERROR         2

#define MIDB_RESULT_ERROR       3

#define DEF_MODE                S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH


int pop3_cmd_handler_capa(const char* cmd_line, int line_length,
	POP3_CONTEXT *pcontext)
{
	char buff[256];

	snprintf(buff, sizeof(buff),
			"+OK capability list follows\r\n"
			"STLS\r\n"
			"TOP\r\n"
			"USER\r\n"
			"PIPELINING\r\n"
			"UIDL\r\n"
			"TOP\r\n");
	if (parse_bool(resource_get_string("enable_capa_implementation")))
		snprintf(buff + strlen(buff), sizeof(buff) - strlen(buff),
			"IMPLEMENTATION gromox-pop3-%s\r\n",
			PACKAGE_VERSION);
	snprintf(buff + strlen(buff), sizeof(buff) - strlen(buff), ".\r\n");

	if (NULL != pcontext->connection.ssl) {
		SSL_write(pcontext->connection.ssl, buff, strlen(buff));
	} else {
		write(pcontext->connection.sockd, buff, strlen(buff));
	}
	return DISPATCH_CONTINUE;
}

int pop3_cmd_handler_stls(const char *cmd_line, int line_length,
	POP3_CONTEXT *pcontext)
{
	if (NULL != pcontext->connection.ssl) {
		return 1703;
	}

	if (FALSE == pop3_parser_get_param(POP3_SUPPORT_STLS)) {
		return 1703;
	}

	if (TRUE == pcontext->is_login) {
		return 1725;
	}
	pcontext->is_stls = TRUE;
	return 1724;
}


int pop3_cmd_handler_user(const char* cmd_line, int line_length,
    POP3_CONTEXT *pcontext)
{
	size_t string_length = 0;
	char buff[1024];
    
	if (TRUE == pop3_parser_get_param(POP3_SUPPORT_STLS) &&
		TRUE == pop3_parser_get_param(POP3_FORCE_STLS) &&
		NULL == pcontext->connection.ssl) {
		return 1726;
	}

	if (line_length <= 5 || line_length > 255 + 1 + 4) {
		return 1704;
	}
	
    /* command error, cannot be recognized by system */
    if (cmd_line[4] != ' ') {
		return 1703;
	} else {
		if (TRUE == pcontext->is_login) {
			return 1720;
		}
        memcpy(pcontext->username, cmd_line + 5, line_length - 5);
        pcontext->username[line_length - 5] = '\0';
		HX_strltrim(pcontext->username);
		if (system_services_judge_user != nullptr &&
		    !system_services_judge_user(pcontext->username)) {
			string_length = sprintf(buff, "%s%s%s",
			                resource_get_pop3_code(1717, 1, &string_length),
			                pcontext->username,
			                resource_get_pop3_code(1717, 2, &string_length));
			if (NULL != pcontext->connection.ssl) {
				SSL_write(pcontext->connection.ssl, buff, string_length);
			} else {
				write(pcontext->connection.sockd, buff, string_length);
			}
			pop3_parser_log_info(pcontext, 8, "user %s is denied by user filter",
					pcontext->username);
			return DISPATCH_SHOULD_CLOSE;
		}
    }
	return 1700;
}    

int pop3_cmd_handler_pass(const char* cmd_line, int line_length,
    POP3_CONTEXT *pcontext)
{
	int count;
	size_t string_length = 0;
	char reason[256];
	char temp_buff[1024];
	char temp_password[256];
    
	if (line_length <= 5 || line_length > 255 + 1 + 4) {
		return 1704;
	}
	
    /* command error, cannot be recognized by system */
    if (cmd_line[4] != ' ') {
		return 1703;
	}
	
	if (TRUE == pcontext->is_login) {
		return 1720;
	}
	
	if ('\0' == pcontext->username[0]) {
		return 1705;
	}
	
    memcpy(temp_password, cmd_line + 5, line_length - 5);
    temp_password[line_length - 5] = '\0';
	HX_strltrim(temp_password);
	if (TRUE == system_services_auth_login(pcontext->username, temp_password,
		pcontext->maildir, NULL, reason, 256)) {
		array_clear(&pcontext->array);
		pcontext->total_size = 0;
		
		if ('\0' == pcontext->maildir[0]) {
			return 1715;
		}
		
		switch (system_services_list_mail(pcontext->maildir, "inbox",
			&pcontext->array, &pcontext->total_mail, &pcontext->total_size)) {
		case MIDB_RESULT_OK:
			break;
		case MIDB_NO_SERVER:
			/* write back nothing and close the connection */
			pop3_parser_log_info(pcontext, 8, "lack of midb connection");
			return DISPATCH_SHOULD_CLOSE;
		case MIDB_RDWR_ERROR:
			/* write back nothing and close the connection */
			pop3_parser_log_info(pcontext, 8, "read write error with midb server");
			return DISPATCH_SHOULD_CLOSE;
		case MIDB_RESULT_ERROR:
			/* write back nothing and close the connection */
			pop3_parser_log_info(pcontext, 8, "midb return error result");
			return DISPATCH_SHOULD_CLOSE;
		}

		count = array_get_capacity(&pcontext->array);
		if (count != pcontext->total_mail) {
			return 1722;
		}

		pcontext->is_login = TRUE;
		pop3_parser_log_info(pcontext, 8, "login success");
		return 1700;
	} else {
		pop3_parser_log_info(pcontext, 8, "login fail");
		pcontext->auth_times ++;
		if (pcontext->auth_times >= pop3_parser_get_param(MAX_AUTH_TIMES)) {
			if (system_services_add_user_into_temp_list != nullptr)
				system_services_add_user_into_temp_list(pcontext->username,
					pop3_parser_get_param(BLOCK_AUTH_FAIL));
			return 1706 | DISPATCH_SHOULD_CLOSE;
		}
		string_length = sprintf(temp_buff, "%s%s%s",
		                resource_get_pop3_code(1714, 1, &string_length),
		                reason,
		                resource_get_pop3_code(1714, 2, &string_length));
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, temp_buff, string_length);
		} else {
			write(pcontext->connection.sockd, temp_buff, string_length);
		}
		return DISPATCH_CONTINUE;
	}

}

int pop3_cmd_handler_stat(const char* cmd_line, int line_length,
    POP3_CONTEXT *pcontext)
{
	size_t string_length = 0;
	char temp_buff[1024];
    
	if (4 != line_length) {
		return 1704;
	}

	if (FALSE == pcontext->is_login) {
		return 1708;
	}
	
	snprintf(temp_buff, sizeof(temp_buff), "+OK %d %llu\r\n",
	         pcontext->total_mail, static_cast<unsigned long long>(pcontext->total_size));
	string_length = strlen(temp_buff);
	if (NULL != pcontext->connection.ssl) {
		SSL_write(pcontext->connection.ssl, temp_buff, string_length);
	} else {
		write(pcontext->connection.sockd, temp_buff, string_length);
	}
    return DISPATCH_CONTINUE;    
}

int pop3_cmd_handler_uidl(const char* cmd_line, int line_length,
    POP3_CONTEXT *pcontext)
{
	int n, i;
	int count;
	unsigned int tmp_len;
	size_t string_length = 0;
	char temp_buff[1024];
	char temp_command[1024];
	MSG_UNIT *punit;
	
	memcpy(temp_command, cmd_line, line_length);
	temp_command[line_length] = '\0';
	HX_strrtrim(temp_command);
	
	if (4 == strlen(temp_command)) {
		
		if (FALSE == pcontext->is_login) {
			return 1708;
		}
		
		stream_clear(&pcontext->stream);
		stream_write(&pcontext->stream, "+OK\r\n", 5);

		count = array_get_capacity(&pcontext->array);
		for (i=0; i<count; i++) {
			punit = (MSG_UNIT*)array_get_item(&pcontext->array, i);
			string_length = sprintf(temp_buff, "%d %s\r\n", i + 1,
								punit->file_name);
			stream_write(&pcontext->stream, temp_buff, string_length);
		}
		stream_write(&pcontext->stream, ".\r\n", 3);
		pcontext->write_offset = 0;
		tmp_len = MAX_LINE_LENGTH;
		pcontext->write_buff = static_cast<char *>(stream_getbuffer_for_reading(&pcontext->stream, &tmp_len));
		pcontext->write_length = tmp_len;
		if (NULL == pcontext->write_buff) {
			pop3_parser_log_info(pcontext, 8, "fatal error on stream object!");
			return 1718;
		}
		return DISPATCH_LIST;
	}
	
	if (temp_command[4] != ' ') {
		return 1703;
	}
	
	if (FALSE == pcontext->is_login) {
		return 1708;
	}
	
	n = atoi(temp_command + 5);
	if (n > 0 && static_cast<size_t>(n) <= array_get_capacity(&pcontext->array)) {
		punit = (MSG_UNIT*)array_get_item(&pcontext->array, n - 1);
		string_length = sprintf(temp_buff, "+OK %d %s\r\n", n,
							punit->file_name);
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, temp_buff, string_length);
		} else {
			write(pcontext->connection.sockd, temp_buff, string_length);
		}
		return DISPATCH_CONTINUE;
	}
	return 1707;
}

int pop3_cmd_handler_list(const char* cmd_line, int line_length,
	POP3_CONTEXT *pcontext)
{
	int i, n;
	int count;
	unsigned int tmp_len;
	size_t string_length = 0;
	char temp_buff[1024];
	char temp_command[1024];
	MSG_UNIT *punit;
	
	memcpy(temp_command, cmd_line, line_length);
	temp_command[line_length] = '\0';
	HX_strrtrim(temp_command);
	
	if (4 == strlen(temp_command)) {
		
		if (FALSE == pcontext->is_login) {
			return 1708;
		}
		
		
		stream_clear(&pcontext->stream);
		stream_write(&pcontext->stream, "+OK\r\n", 5);
		
		count = array_get_capacity(&pcontext->array);

		for (i=0; i<count; i++) {
			punit = (MSG_UNIT*)array_get_item(&pcontext->array, i);
			string_length = sprintf(temp_buff, "%d %ld\r\n", i + 1, punit->size);
			stream_write(&pcontext->stream, temp_buff, string_length);
		}
		stream_write(&pcontext->stream, ".\r\n", 3);
		pcontext->write_offset = 0;
		tmp_len = MAX_LINE_LENGTH;
		pcontext->write_buff = static_cast<char *>(stream_getbuffer_for_reading(
		                       &pcontext->stream, &tmp_len));
		pcontext->write_length = tmp_len;
		if (NULL == pcontext->write_buff) {
			pop3_parser_log_info(pcontext, 8, "fatal error on stream object!");
			return 1718;
		}
		return DISPATCH_LIST;
	}
	
	if (temp_command[4] != ' ') {
		return 1703;
	}
	
	if (FALSE == pcontext->is_login) {
		return 1708;
	}
	
	n = atoi(temp_command + 5);
	if (n > 0 && static_cast<size_t>(n) <= array_get_capacity(&pcontext->array)) {
		punit = (MSG_UNIT*)array_get_item(&pcontext->array, n - 1);
			
		string_length = sprintf(temp_buff, "+OK %d %ld\r\n", n, punit->size);	
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, temp_buff, string_length);
		} else {
			write(pcontext->connection.sockd, temp_buff, string_length);
		}
		return DISPATCH_CONTINUE;
	}
	return 1707;
}

int pop3_cmd_handler_retr(const char* cmd_line, int line_length,
	POP3_CONTEXT *pcontext)
{
	int n;
	char temp_path[256];
	char temp_command[256];
	MSG_UNIT *punit;
	
	memcpy(temp_command, cmd_line, line_length);
	temp_command[line_length] = '\0';
	HX_strrtrim(temp_command);
	
	if (strlen(temp_command) <= 5) {
		return 1704;
	}
	
	if (temp_command[4] != ' ') {
		return 1703;
	}
	
	if (FALSE == pcontext->is_login) {
		return 1708;
	}
	
	n = atoi(temp_command + 5);
	pcontext->cur_line = -1;
	pcontext->until_line = 0x7FFFFFFF;
	if (n > 0 && static_cast<size_t>(n) <= array_get_capacity(&pcontext->array)) {
		punit = (MSG_UNIT*)array_get_item(&pcontext->array, n - 1);
		snprintf(temp_path, 255, "%s/eml/%s", pcontext->maildir,
			punit->file_name);
		pcontext->message_fd = open(temp_path, O_RDONLY);
		if (-1 == pcontext->message_fd) {
			pop3_parser_log_info(pcontext, 8, "fail"
					" to open message %s", temp_path);
			return 1709;
		}
		stream_clear(&pcontext->stream);
		stream_write(&pcontext->stream, "+OK\r\n", 5);
		if (POP3_RETRIEVE_ERROR == pop3_parser_retrieve(pcontext)) {
			stream_clear(&pcontext->stream);
			return 1719;
		}
		pop3_parser_log_info(pcontext, 8, "message %s"
				" is going to be retrieved", temp_path);
		return DISPATCH_DATA;
	}
	return 1707;
}

int pop3_cmd_handler_dele(const char* cmd_line, int line_length,
	POP3_CONTEXT *pcontext)
{
	int n;
	char temp_command[256];
	MSG_UNIT *punit;
	
	memcpy(temp_command, cmd_line, line_length);
	temp_command[line_length] = '\0';
	HX_strrtrim(temp_command);
	
	if (strlen(temp_command) <= 5) {
		return 1704;
	}
	
	if (temp_command[4] != ' ') {
		return 1703;
	}
	
	if (FALSE == pcontext->is_login) {
		return 1708;
	}
	
	n = atoi(temp_command + 5);
	if (n > 0 && static_cast<size_t>(n) <= array_get_capacity(&pcontext->array)) {
		punit = (MSG_UNIT*)array_get_item(&pcontext->array, n - 1);
		if (FALSE == punit->b_deleted) {
			punit->b_deleted = TRUE;
			punit->node.pdata = punit;
			single_list_append_as_tail(&pcontext->list, &punit->node);
		}
		return 1700;
	}
	return 1707;
}

int pop3_cmd_handler_top(const char* cmd_line, int line_length,
	POP3_CONTEXT *pcontext)
{
	int n;
	char *ptoken;
	char temp_path[256];
	char temp_buff[1024];
	char temp_command[256];
	MSG_UNIT *punit;
	
	memcpy(temp_command, cmd_line, line_length);
	temp_command[line_length] = '\0';
	HX_strrtrim(temp_command);
	
	if (strlen(temp_command) <= 4) {
		return 1704;
	}
	
	if (temp_command[3] != ' ') {
		return 1703;
	}
	
	if (FALSE == pcontext->is_login) {
		return 1708;
	}
	
	gx_strlcpy(temp_buff, temp_command + 4, GX_ARRAY_SIZE(temp_buff));
	HX_strltrim(temp_buff);
	ptoken = strchr(temp_buff, ' ');
	if (NULL == ptoken) {
		n = atoi(temp_buff);
		pcontext->until_line = 0x7FFFFFFF;
	} else {
		*ptoken = '\0';
		n = atoi(temp_buff);
		pcontext->until_line = atoi(ptoken + 1);
	}
	pcontext->cur_line = -1;
	if (n > 0 && static_cast<size_t>(n) <= array_get_capacity(&pcontext->array)) {
		punit = (MSG_UNIT*)array_get_item(&pcontext->array, n - 1);
		snprintf(temp_path, 255, "%s/eml/%s", pcontext->maildir,
			punit->file_name);
		pcontext->message_fd = open(temp_path, O_RDONLY);
		if (-1 == pcontext->message_fd) {
			return 1709;
		}
		stream_clear(&pcontext->stream);
		stream_write(&pcontext->stream, "+OK\r\n", 5);
		if (POP3_RETRIEVE_ERROR == pop3_parser_retrieve(pcontext)) {
			stream_clear(&pcontext->stream);
			return 1719;
		}
		return DISPATCH_DATA;
	}
	return 1707;
}

int pop3_cmd_handler_quit(const char* cmd_line, int line_length,
    POP3_CONTEXT *pcontext)
{
	size_t string_length = 0;
	char temp_path[256];
	char temp_buff[1024];
	MSG_UNIT *punit;
	SINGLE_LIST_NODE *pnode;
    
	if (4 != line_length) {
		return 1704;
	}
	
	if (TRUE == pcontext->is_login) {
		if (single_list_get_nodes_num(&pcontext->list) > 0) {
			switch (system_services_delete_mail(pcontext->maildir, "inbox",
				&pcontext->list)) {
			case MIDB_RESULT_OK:
				break;
			case MIDB_NO_SERVER: {
				return 1716 | DISPATCH_SHOULD_CLOSE;
			}
			case MIDB_RDWR_ERROR: {
				pop3_parser_log_info(pcontext, 8, "fail to read/write with "
					"midb server!");
				return 1721 | DISPATCH_SHOULD_CLOSE;
			}
			case MIDB_RESULT_ERROR: {
				pop3_parser_log_info(pcontext, 8, "fail to execute delete "
					"command with midb server!");
				return 1722 | DISPATCH_SHOULD_CLOSE;
			}
			}
			string_length = gx_snprintf(temp_buff, GX_ARRAY_SIZE(temp_buff),
				"FOLDER-TOUCH %s inbox", pcontext->username);
			system_services_broadcast_event(temp_buff);

			while ((pnode = single_list_pop_front(&pcontext->list)) != nullptr) {
				punit = (MSG_UNIT*)pnode->pdata;
				snprintf(temp_path, 255, "%s/eml/%s", pcontext->maildir,
					punit->file_name);
				if (0 == remove(temp_path)) {
					pop3_parser_log_info(pcontext, 8, "message %s is deleted",
						temp_path);
				}
			}
		}
	}

	array_clear(&pcontext->array);
	sprintf(temp_buff, "%s%s%s", resource_get_pop3_code(1710, 1,
		&string_length), resource_get_string("HOST_ID"),
			resource_get_pop3_code(1710, 2, &string_length));
	if (NULL != pcontext->connection.ssl) {
		SSL_write(pcontext->connection.ssl, temp_buff, strlen(temp_buff));
	} else {
		write(pcontext->connection.sockd, temp_buff, strlen(temp_buff));
	}
	return DISPATCH_SHOULD_CLOSE;
	
}

int pop3_cmd_handler_rset(const char* cmd_line, int line_length,
    POP3_CONTEXT *pcontext)
{
	MSG_UNIT *punit;
	SINGLE_LIST_NODE *pnode;
            
	if (4 != line_length) {
		return 1704;
	}

	if (TRUE == pcontext->is_login) {
		while ((pnode = single_list_pop_front(&pcontext->list)) != nullptr) {
			punit = (MSG_UNIT*)pnode->pdata;
			punit->b_deleted = FALSE;
		}
	}
	return 1700;
}    

int pop3_cmd_handler_noop(const char* cmd_line, int line_length,
    POP3_CONTEXT *pcontext)
{
	if (4 != line_length) {
		return 1704;
	}
	return 1700;
}


int pop3_cmd_handler_else(const char* cmd_line, int line_length,
    POP3_CONTEXT *pcontext)
{
    /* command not implement*/
	return 1703;
}
