// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2025 grommunio GmbH
// This file is part of Gromox.
#include <climits>
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <poll.h>
#include <pthread.h>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>
#include <libHX/io.h>
#include <libHX/string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include <gromox/midb.hpp>
#include <gromox/process.hpp>
#include <gromox/util.hpp>
#include "cmd_parser.hpp"
#include "common_util.hpp"
#define MAX_ARGS			(32*1024)

#define CONN_BUFFLEN        (257*1024)

using namespace gromox;

static unsigned int g_threads_num;
static gromox::atomic_bool g_notify_stop;
static int g_timeout_interval;
static std::vector<pthread_t> g_thread_ids;
static std::mutex g_connection_lock; /* protects g_connlist_active, g_connlist_idle */
static std::mutex g_cond_mutex;
static std::condition_variable g_waken_cond;
static std::list<midb_conn> g_connlist_active, g_connlist_idle;
static std::unordered_map<std::string, midb_cmd> g_cmd_entry;
unsigned int g_cmd_debug;

static void *midcp_thrwork(void *);
static int cmd_parser_generate_args(char* cmd_line, int cmd_len, char** argv);

static int cmd_parser_ping(int argc, char **argv, int sockd);

void cmd_parser_init(unsigned int threads_num, int timeout, unsigned int debug)
{
	g_threads_num = threads_num;
	g_thread_ids.reserve(g_threads_num);
	g_timeout_interval = timeout;
	g_cmd_debug = debug;
}

std::list<midb_conn> cmd_parser_make_conn() try
{
	std::unique_lock chold(g_connection_lock);
	if (g_connlist_active.size() + 1 + g_connlist_idle.size() >= g_threads_num)
		return {};
	chold.unlock();
	std::list<midb_conn> holder;
	holder.emplace_back();
	return holder;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1985: ENOMEM");
	return {};
}

void cmd_parser_insert_conn(std::list<midb_conn> &&holder)
{	
	std::unique_lock chold(g_connection_lock);
	g_connlist_idle.splice(g_connlist_idle.end(), std::move(holder));
	chold.unlock();
	g_waken_cond.notify_one();
}

int cmd_parser_run()
{
	cmd_parser_register_command("PING", {cmd_parser_ping, 2});
	g_notify_stop = false;

	for (unsigned int i = 0; i < g_threads_num; ++i) {
		pthread_t tid;
		auto ret = pthread_create4(&tid, nullptr, midcp_thrwork, nullptr);
		if (ret != 0) {
			mlog(LV_ERR, "cmd_parser: failed to create pool thread: %s", strerror(ret));
			return -1;
		}
		char buf[32];
		snprintf(buf, sizeof(buf), "cmd_parser/%u", i);
		pthread_setname_np(tid, buf);
		g_thread_ids.push_back(tid);
	}
	return 0;
}

void cmd_parser_stop()
{
	g_notify_stop = true;
	g_waken_cond.notify_all();
	std::unique_lock chold(g_connection_lock);
	for (auto &c : g_connlist_active) {
		auto pconnection = &c;
		if (pconnection->is_selecting) {
			pthread_kill(pconnection->thr_id, SIGALRM);
		} else {
			close(pconnection->sockd);
			pconnection->sockd = -1;
		}	
	}
	chold.unlock();
	for (auto tid : g_thread_ids) {
		pthread_kill(tid, SIGALRM);
		pthread_join(tid, nullptr);
	}
	g_thread_ids.clear();
	chold.lock();
	g_connlist_active.clear();
	g_connlist_idle.clear();
}

void cmd_parser_register_command(const char *command, const midb_cmd &info)
{
	auto r = g_cmd_entry.emplace(command, info);
	if (!r.second)
		mlog(LV_ERR, "Could not add \"%s\" to command table: already present", command);
	auto &i = r.first->second;
	if (i.max_args == 0)
		i.max_args = i.min_args;
	if (i.min_args < 2)
		/* midcp_exec1 always needs a store-dir */
		mlog(LV_ERR, "midb_cmd::min_args must be at least 2, even for %s", command);
}

static thread_local int dbg_current_argc;
static thread_local char **dbg_current_argv;

static void cmd_dump_argv(int argc, char **argv)
{
	fprintf(stderr, "<");
	for (int i = 0; i < argc; ++i)
		fprintf(stderr, " %s", argv[i]);
	fprintf(stderr, "\n");
}

static ssize_t __attribute__((warn_unused_result))
cmd_write_x(unsigned int level, int fd, const char *buf, size_t z)
{
	auto ret = HXio_fullwrite(fd, buf, z);
	if (g_cmd_debug < level)
		return ret;
	if (dbg_current_argv != nullptr) {
		cmd_dump_argv(dbg_current_argc, dbg_current_argv);
		dbg_current_argv = nullptr;
	}
	if (z >= 1 && buf[z-1] == '\n')
		--z;
	if (z >= 1 && buf[z-1] == '\r')
		--z;
	if (z > INT_MAX)
		z = INT_MAX;
	fprintf(stderr, "> %.*s\n", static_cast<int>(z), buf);
	return ret;
} 

int cmd_write(int fd, const char *sbuf, size_t z)
{
	if (z == static_cast<size_t>(-1))
		z = strlen(sbuf);
	/* Note: cmd_write is also only called for successful responses */
	return cmd_write_x(2, fd, sbuf, z) < 0 ? MIDB_E_NETIO : 0;
}

static std::pair<bool, int> midcp_exec1(int argc, char **argv, MIDB_CONNECTION *conn)
{
	if (g_notify_stop)
		return {false, 0};
	auto cmd_iter = g_cmd_entry.find(argv[0]);
	if (cmd_iter == g_cmd_entry.end())
		return {false, 0};
	const auto &info = cmd_iter->second;
	/*
	 * [1] is always the store-dir for length checking.
	 * [2], if present, is a folder-name for length checking (X-RSYF has a GCV, but strlen doesn't hurt)
	 */
	if (argc < info.min_args || argc > info.max_args ||
	    strlen(argv[1]) >= 256)
		return {false, MIDB_E_PARAMETER_ERROR};
	if (argc >= 3 && strlen(argv[1]) >= 1024)
		return {false, MIDB_E_PARAMETER_ERROR};
	if (!cu_build_environment(argv[1]))
		return {false, 0};
	auto err = info.func(argc, argv, conn->sockd);
	cu_free_environment();
	if (err == 0)
		return {true, 0};
	return {false, err};
}

static int midcp_exec(int argc, char **argv, MIDB_CONNECTION *conn)
{
	dbg_current_argc = argc;
	dbg_current_argv = argv;
	auto [replied, result] = midcp_exec1(argc, argv, conn);
	if (replied)
		return 0;
	if (result == MIDB_E_NETIO)
		return MIDB_E_NETIO;
	char rsp[20];
	auto len = snprintf(rsp, std::size(rsp), "FALSE %d\r\n", result);
	return cmd_write_x(1, conn->sockd, rsp, len) < 0 ? MIDB_E_NETIO : 0;
}

static size_t connlist_idle_size()
{
	std::unique_lock lk(g_connection_lock);
	return g_connlist_idle.size();
}

static void *midcp_thrwork(void *param)
{
	int i, argc, offset, tv_msec, read_len;
	char *argv[MAX_ARGS];
	struct pollfd pfd_read;
	char buffer[CONN_BUFFLEN];

	while (!g_notify_stop) {
		{
			std::unique_lock cm_hold(g_cond_mutex);
			g_waken_cond.wait(cm_hold, []() { return g_notify_stop.load() || connlist_idle_size() > 0; });
			if (g_notify_stop)
				return nullptr;
		}

		std::list<midb_conn>::iterator pconnection;
		{
			std::unique_lock co_hold(g_connection_lock);
			if (g_connlist_idle.size() > 0) {
				g_connlist_active.splice(g_connlist_active.end(), g_connlist_idle, g_connlist_idle.begin());
				pconnection = std::prev(g_connlist_active.end());
			} else {
				continue;
			}
		}
		offset = 0;

		while (!g_notify_stop) {
			tv_msec = g_timeout_interval * 1000;
			pfd_read.fd = pconnection->sockd;
			pfd_read.events = POLLIN | POLLPRI;
			pconnection->is_selecting = TRUE;
			pconnection->thr_id = pthread_self();

			/*
			 * gc is our little "garbage collector" which, when it
			 * goes out of scope, destroys the connections -
			 * outside locked sections.
			 */
			std::list<midb_conn> gc;
			if (1 != poll(&pfd_read, 1, tv_msec)) {
				pconnection->is_selecting = FALSE;
				std::unique_lock co_hold(g_connection_lock);
				gc.splice(gc.end(), g_connlist_active, pconnection);
				break;
			}
			pconnection->is_selecting = FALSE;
			read_len = read(pconnection->sockd, buffer + offset,
			           CONN_BUFFLEN - offset);
			if (read_len <= 0) {
				std::unique_lock co_hold(g_connection_lock);
				gc.splice(gc.end(), g_connlist_active, pconnection);
				break;
			}
			offset += read_len;
			for (i = 0; i < offset - 1; ++i) {
				if (buffer[i] != '\r' || buffer[i + 1] != '\n')
					continue;
				if (i == 4 && strncasecmp(buffer, "QUIT", 4) == 0) {
					if (HXio_fullwrite(pconnection->sockd, "BYE\r\n", 5) < 0)
						/* ignore */;
					std::unique_lock co_hold(g_connection_lock);
					gc.splice(gc.end(), g_connlist_active, pconnection);
					goto NEXT_CONN;
				}

				argc = cmd_parser_generate_args(buffer, i, argv);
				if (argc < 2) {
					if (HXio_fullwrite(pconnection->sockd, "FALSE 1\r\n", 9) < 0) {
						std::unique_lock co_hold(g_connection_lock);
						gc.splice(gc.end(), g_connlist_active, pconnection);
						goto NEXT_CONN;
					}
					offset -= i + 2;
					if (offset >= 0)
						memmove(buffer, buffer + i + 2, offset);
					i = 0;
					continue;
				}

				HX_strupper(argv[0]);
				if (midcp_exec(argc, argv, &*pconnection) == MIDB_E_NETIO) {
					std::unique_lock co_hold(g_connection_lock);
					gc.splice(gc.end(), g_connlist_active, pconnection);
					goto NEXT_CONN;
				}
				offset -= i + 2;
				memmove(buffer, buffer + i + 2, offset);
				i = 0;
			}

			if (offset == CONN_BUFFLEN) {
				std::unique_lock co_hold(g_connection_lock);
				gc.splice(gc.end(), g_connlist_active, pconnection);
				break;
			}
		}
 NEXT_CONN:
		;
	}
	return nullptr;
}

static int cmd_parser_ping(int argc, char **argv, int sockd)
{
	return HXio_fullwrite(sockd, "TRUE\r\n", 6) < 0 ? MIDB_E_NETIO : 0;
}

static int cmd_parser_generate_args(char* cmd_line, int cmd_len, char** argv)
{
	int argc;                    /* number of args */
	char *ptr;                   /* ptr that traverses command line  */
	char *last_space;
	
	cmd_line[cmd_len] = ' ';
	cmd_line[cmd_len + 1] = '\0';
	ptr = cmd_line;
	/* Build the argv list */
	argc = 0;
	last_space = cmd_line;
	while (*ptr != '\0') {
		if ('{' == *ptr) {
			if (cmd_line[cmd_len-1] != '}')
				return 0;
			argv[argc] = ptr;
			cmd_line[cmd_len] = '\0';
			argc ++;
			break;
		}

		if (' ' == *ptr) {
			/* ignore leading spaces */
			if (ptr == last_space) {
				last_space ++;
			} else {
				argv[argc] = last_space;
				*ptr = '\0';
				last_space = ptr + 1;
				argc ++;
			}
		}
		ptr ++;
	}
	
	argv[argc] = NULL;
	return argc;
}	

