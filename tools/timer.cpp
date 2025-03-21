// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2025 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <list>
#include <mutex>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>
#include <libHX/io.h>
#include <libHX/option.h>
#include <libHX/scope.hpp>
#include <libHX/socket.h>
#include <libHX/string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <gromox/atomic.hpp>
#include <gromox/config_file.hpp>
#include <gromox/generic_connection.hpp>
#include <gromox/list_file.hpp>
#include <gromox/paths.h>
#include <gromox/process.hpp>
#include <gromox/util.hpp>

#define COMMAND_LENGTH		512

#define MAXARGS				128

using namespace gromox;

namespace {

struct CONNECTION_NODE : public generic_connection {
	CONNECTION_NODE() = default;
	CONNECTION_NODE(CONNECTION_NODE &&) noexcept;
	CONNECTION_NODE(generic_connection &&o) : generic_connection(std::move(o)) {}
	void operator=(CONNECTION_NODE &&) noexcept = delete;
	ssize_t sk_write(const char *, size_t = -1);

	int offset = 0;
	char buffer[1024]{};
	char line[1024]{};
};

struct TIMER {
	int t_id;
	time_t exec_time;
	std::string command;
};

struct srcitem {
	int tid;
	long exectime;
	char command[512];
} __attribute__((packed));

}

static constexpr auto POLLIN_SET =
	POLLRDNORM | POLLRDBAND | POLLIN | POLLHUP | POLLERR | POLLNVAL;
static gromox::atomic_bool g_notify_stop;
static unsigned int g_threads_num;
static std::atomic<int> g_last_tid;
static int g_list_fd = -1;
static std::string g_list_path;
static std::vector<std::string> g_acl_list;
static std::list<CONNECTION_NODE> g_connection_list, g_connection_list1;
static std::list<TIMER> g_exec_list;
static std::mutex g_list_lock /*(g_exec_list)*/, g_connection_lock /*(g_connection_list0/1)*/;
static std::condition_variable g_waken_cond;
static char *opt_config_file;
static unsigned int opt_show_version;

static struct HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	{"version", 0, HXTYPE_NONE, &opt_show_version, nullptr, nullptr, 0, "Output version information and exit"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static constexpr cfg_directive timer_cfg_defaults[] = {
	{"config_file_path", PKGSYSCONFDIR "/timer:" PKGSYSCONFDIR},
	{"timer_hosts_allow", ""}, /* ::1 default set later during startup */
	{"timer_listen_ip", "::1"},
	{"timer_listen_port", "6666"},
	{"timer_log_file", "-"},
	{"timer_log_level", "4" /* LV_NOTICE */},
	{"timer_state_path", PKGSTATEDIR "/timer.txt"},
	{"timer_threads_num", "50", CFG_SIZE, "5", "50"},
	CFG_TABLE_END,
};

static void *tmr_acceptwork(void *);
static void *tmr_thrwork(void *);
static void execute_timer(TIMER *ptimer);

static int parse_line(char *pbuff, const char* cmdline, char** argv);

static void encode_line(const char *in, char *out);

static BOOL read_mark(CONNECTION_NODE *pconnection);

static void term_handler(int signo);

CONNECTION_NODE::CONNECTION_NODE(CONNECTION_NODE &&o) noexcept :
	generic_connection(std::move(o)), offset(o.offset)
	//ask qir about D::D() : B(move(o.B)) {}
{
	memcpy(buffer, o.buffer, sizeof(buffer));
	memcpy(line, o.line, sizeof(line));
}

ssize_t CONNECTION_NODE::sk_write(const char *s, size_t z)
{
	if (z == static_cast<size_t>(-1))
		z = strlen(s);
	auto ret = HXio_fullwrite(sockd, s, z);
	if (ret < 0) {
		close(sockd);
		sockd = -1;
	}
	return ret;
}

static void save_timers(time_t &last_cltime, const time_t &cur_time)
{
	close(g_list_fd);
	auto pfile = list_file_initd(g_list_path.c_str(), "/", "%d%l%s:512");
	if (pfile == nullptr) {
		g_list_fd = open(g_list_path.c_str(), O_APPEND | O_WRONLY);
		if (g_list_fd < 0)
			fprintf(stderr, "open %s: %s\n", g_list_path.c_str(), strerror(errno));
		return;
	}
	auto item_num = pfile->get_size();
	auto pitem = static_cast<srcitem *>(pfile->get_list());
	for (size_t i = 0; i < item_num; ++i) {
		if (pitem[i].exectime != 0)
			continue;
		for (size_t j = 0; j < item_num; ++j) {
			if (i == j)
				continue;
			if (pitem[i].tid == pitem[j].tid) {
				pitem[j].exectime = 0;
				break;
			}
		}
	}
	auto temp_path = g_list_path + ".tmp";
	auto temp_fd = open(temp_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, FMODE_PRIVATE);
	if (temp_fd >= 0) {
		for (size_t i = 0; i < item_num; ++i) {
			if (pitem[i].exectime == 0)
				continue;
			char temp_line[2048];
			auto temp_len = gx_snprintf(temp_line, std::size(temp_line), "%d\t%ld\t",
				   pitem[i].tid, pitem[i].exectime);
			encode_line(pitem[i].command, temp_line + temp_len);
			temp_len = strlen(temp_line);
			temp_line[temp_len] = '\n';
			++temp_len;
			if (HXio_fullwrite(temp_fd, temp_line, temp_len) < 0)
				fprintf(stderr, "write %s: %s\n", temp_path.c_str(), strerror(errno));
		}
		close(temp_fd);
		if (remove(g_list_path.c_str()) < 0 && errno != ENOENT)
			fprintf(stderr, "W-1403: remove %s: %s\n",
			        g_list_path.c_str(), strerror(errno));
		if (rename(temp_path.c_str(), g_list_path.c_str()) < 0)
			fprintf(stderr, "E-1404: rename %s %s: %s\n",
			        temp_path.c_str(), g_list_path.c_str(), strerror(errno));
	}
	last_cltime = cur_time;
	g_list_fd = open(g_list_path.c_str(), O_APPEND | O_WRONLY);
	if (g_list_fd < 0)
		fprintf(stderr, "open %s: %s\n", g_list_path.c_str(), strerror(errno));
}

static TIMER *put_timer(TIMER &&ptimer)
{
	for (auto pos = g_exec_list.begin(); pos != g_exec_list.end(); ++pos) {
		if (pos->exec_time <= ptimer.exec_time)
			continue;
		std::list<TIMER> stash;
		stash.push_back(std::move(ptimer));
		g_exec_list.splice(pos, stash, stash.begin());
		return &*pos;
	}
	g_exec_list.push_back(std::move(ptimer));
	return &g_exec_list.back();
}

int main(int argc, char **argv)
{
	pthread_t thr_accept_id{};
	std::vector<pthread_t> thr_ids;

	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt5(g_options_table, argv, nullptr, nullptr,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;

	startup_banner("gromox-timer");
	if (opt_show_version)
		return EXIT_SUCCESS;
	struct sigaction sact{};
	sigemptyset(&sact.sa_mask);
	sact.sa_handler = SIG_IGN;
	sact.sa_flags   = SA_RESTART;
	sigaction(SIGPIPE, &sact, nullptr);
	auto pconfig = config_file_prg(opt_config_file, "timer.cfg",
	               timer_cfg_defaults);
	if (opt_config_file != nullptr && pconfig == nullptr)
		printf("[system]: config_file_init %s: %s\n", opt_config_file, strerror(errno));
	if (pconfig == nullptr)
		return EXIT_FAILURE;

	mlog_init("gromox-timer", pconfig->get_value("timer_log_file"),
		pconfig->get_ll("timer_log_level"),
		pconfig->get_value("running_identity"));
	g_list_path = pconfig->get_value("timer_state_path");
	uint16_t listen_port = pconfig->get_ll("timer_listen_port");
	auto listen_ip = pconfig->get_value("timer_listen_ip");
	printf("[system]: listen address is [%s]:%hu\n",
	       *listen_ip == '\0' ? "*" : listen_ip, listen_port);

	g_threads_num = pconfig->get_ll("timer_threads_num");
	printf("[system]: processing threads number is %u\n", g_threads_num);
	g_threads_num ++;

	auto sockd = HX_inet_listen(listen_ip, listen_port);
	if (sockd < 0) {
		printf("[system]: failed to create listen socket: %s\n", strerror(-sockd));
		return EXIT_FAILURE;
	}
	gx_reexec_record(sockd);
	auto cl_0 = HX::make_scope_exit([&]() { close(sockd); });
	if (switch_user_exec(*pconfig, argv) != 0)
		return EXIT_FAILURE;

	auto pfile = list_file_initd(g_list_path.c_str(), "/", "%d%l%s:512");
	if (NULL == pfile) {
		printf("[system]: Failed to read timers from %s: %s\n",
		       g_list_path.c_str(), strerror(errno));
		return EXIT_FAILURE;
	}

	auto item_num = pfile->get_size();
	auto pitem = static_cast<srcitem *>(pfile->get_list());
	for (size_t i = 0; i < item_num; ++i) {
		if (pitem[i].exectime != 0)
			continue;
		for (size_t j = 0; j < item_num; ++j) {
			if (i == j)
				continue;
			if (pitem[i].tid == pitem[j].tid) {
				pitem[j].exectime = 0;
				break;
			}
		}
	}

	auto cur_time = time(nullptr);
	for (size_t i = 0; i < item_num; ++i) {
		if (pitem[i].tid > g_last_tid)
			g_last_tid = pitem[i].tid;
		if (pitem[i].exectime == 0)
			continue;
		try {
			TIMER tmr;
			tmr.t_id = pitem[i].tid;
			tmr.exec_time = pitem[i].exectime;
			tmr.command = pitem[i].command;
			put_timer(std::move(tmr));
		} catch (std::bad_alloc &) {
		}
	}
	pfile.reset();

	g_list_fd = open(g_list_path.c_str(), O_CREAT | O_APPEND | O_WRONLY, FMODE_PRIVATE);
	if (g_list_fd < 0) {
		printf("[system]: Failed to open %s: %s\n", g_list_path.c_str(), strerror(errno));
		return EXIT_FAILURE;
	}
	auto cl_1 = HX::make_scope_exit([&]() { close(g_list_fd); });

	thr_ids.reserve(g_threads_num);
	auto cl_2 = HX::make_scope_exit([&]() {
		/* thread might be waiting at the condvar */
		g_waken_cond.notify_all();
		for (auto tid : thr_ids) {
			/* thread might be waiting in read_mark/select */
			pthread_kill(tid, SIGALRM);
			pthread_join(tid, nullptr);
		}
	});
	for (unsigned int i = 0; i < g_threads_num; ++i) {
		pthread_t tid;
		auto ret = pthread_create4(&tid, nullptr, tmr_thrwork, nullptr);
		if (ret != 0) {
			printf("[system]: failed to create pool thread: %s\n", strerror(ret));
			g_notify_stop = true;
			return EXIT_FAILURE;
		}
		char buf[32];
		snprintf(buf, sizeof(buf), "worker/%u", i);
		pthread_setname_np(tid, buf);
		thr_ids.push_back(tid);
	}

	auto hosts_allow = pconfig->get_value("timer_hosts_allow");
	if (hosts_allow != nullptr)
		g_acl_list = gx_split(hosts_allow, ' ');
	auto err = list_file_read_fixedstrings("timer_acl.txt",
	           pconfig->get_value("config_file_path"), g_acl_list);
	if (err == ENOENT) {
	} else if (err != 0) {
		printf("[system]: list_file_initd timer_acl.txt: %s\n", strerror(err));
		g_notify_stop = true;
		return EXIT_FAILURE;
	}
	std::sort(g_acl_list.begin(), g_acl_list.end());
	g_acl_list.erase(std::remove(g_acl_list.begin(), g_acl_list.end(), ""), g_acl_list.end());
	g_acl_list.erase(std::unique(g_acl_list.begin(), g_acl_list.end()), g_acl_list.end());
	if (g_acl_list.size() == 0) {
		mlog(LV_NOTICE, "system: defaulting to implicit access ACL containing ::1.");
		g_acl_list = {"::1"};
	}
	
	auto ret = pthread_create4(&thr_accept_id, nullptr, tmr_acceptwork,
	      reinterpret_cast<void *>(static_cast<intptr_t>(sockd)));
	if (ret != 0) {
		printf("[system]: failed to create accept thread: %s\n", strerror(ret));
		g_notify_stop = true;
		return EXIT_FAILURE;
	}
	auto cl_3 = HX::make_scope_exit([&]() {
		pthread_kill(thr_accept_id, SIGALRM); /* kick accept() */
		pthread_join(thr_accept_id, nullptr);
	});
	
	pthread_setname_np(thr_accept_id, "accept");
	auto last_cltime = time(nullptr);
	setup_signal_defaults();
	sact.sa_handler = term_handler;
	sact.sa_flags   = SA_RESTART;
	sigaction(SIGINT, &sact, nullptr);
	sigaction(SIGTERM, &sact, nullptr);
	printf("[system]: TIMER is now running\n");

	while (!g_notify_stop) {
		std::unique_lock li_hold(g_list_lock);
		cur_time = time(nullptr);
		for (auto ptimer = g_exec_list.begin(); ptimer != g_exec_list.end(); ) {
			if (ptimer->exec_time > cur_time)
				break;
			std::list<TIMER> stash;
			stash.splice(stash.end(), g_exec_list, ptimer++);
			execute_timer(&stash.front());
		}

		if (cur_time - last_cltime > 7 * 86400)
			save_timers(last_cltime, cur_time);
		li_hold.unlock();
		sleep(1);

	}
	return EXIT_SUCCESS;
}

static void *tmr_acceptwork(void *param)
{
	int sockd = reinterpret_cast<intptr_t>(param);
	while (!g_notify_stop) {
		CONNECTION_NODE conn(generic_connection::accept(sockd, false, &g_notify_stop));
		if (conn.sockd == -2)
			break;
		else if (conn.sockd < 0)
			continue;
		if (std::find(g_acl_list.cbegin(), g_acl_list.cend(),
		    conn.client_addr) == g_acl_list.cend()) {
			if (HXio_fullwrite(conn.sockd, "FALSE Access denied\r\n", 19) < 0)
				/* ignore */;
			continue;
		}

		std::unique_lock co_hold(g_connection_lock);
		if (g_connection_list.size() + 1 + g_connection_list1.size() >= g_threads_num) {
			co_hold.unlock();
			if (HXio_fullwrite(conn.sockd, "FALSE Maximum number of connections reached!\r\n", 35) < 0)
				/* ignore */;
			continue;
		}

		CONNECTION_NODE *cn;
		auto rawfd = conn.sockd;
		try {
			g_connection_list1.push_back(std::move(conn));
			cn = &g_connection_list1.back();
		} catch (const std::bad_alloc &) {
			// conn may be trash already (push_back isn't try_emplace)
			if (HXio_fullwrite(rawfd, "FALSE Not enough memory\r\n", 25) < 0)
				/* ignore */;
			continue;
		}
		co_hold.unlock();
		if (HXio_fullwrite(cn->sockd, "OK\r\n", 4) < 0) {
			close(cn->sockd);
			cn->sockd = -1;
		}
		g_waken_cond.notify_one();
	}
	return nullptr;
}

static void execute_timer(TIMER *ptimer)
{
	int len;
	int status;
	pid_t pid;
	char result[1024];
	char temp_buff[2048];
	char* argv[MAXARGS];

	int argc = parse_line(temp_buff, ptimer->command.c_str(), argv);
	if (argc > 0) {
		pid = fork();
		if (0 == pid) {
			execve(argv[0], argv, NULL);
			_exit(-1);
		} else if (pid > 0) {
			if (waitpid(pid, &status, 0) > 0) {
				strcpy(result, WIFEXITED(status) && !WEXITSTATUS(status) ? "DONE" : "EXEC-FAILURE");
			} else {
				strcpy(result, "FAIL-TO-WAIT");
			}
		} else {
			strcpy(result, "FAIL-TO-FORK");
		}
	} else {
		strcpy(result, "FORMAT-ERROR");
	}

	len = sprintf(temp_buff, "%d\t0\t%s\n", ptimer->t_id, result);
	if (HXio_fullwrite(g_list_fd, temp_buff, len) < 0)
		fprintf(stderr, "write to timerlist: %s\n", strerror(errno));
}

enum { X_STOP, X_LOOP };

static int tmr_thrwork_1()
{
	int temp_len;
	char *pspace, temp_line[1024];
	
	std::unique_lock co_hold(g_connection_lock);
	g_waken_cond.wait(co_hold, []() { return g_notify_stop || g_connection_list1.size() > 0; });
	if (g_notify_stop)
		return X_STOP;
	if (g_connection_list1.size() == 0)
		return X_LOOP;
	g_connection_list.splice(g_connection_list.end(), g_connection_list1, g_connection_list1.begin());
	auto pconnection = std::prev(g_connection_list.end());
	co_hold.unlock();

	while (true) {
		if (!read_mark(&*pconnection)) {
			co_hold.lock();
			g_connection_list.erase(pconnection);
			return X_LOOP;
		}

		if (0 == strncasecmp(pconnection->line, "CANCEL ", 7)) {
			int t_id = strtol(pconnection->line + 7, nullptr, 0);
			if (t_id <= 0) {
				pconnection->sk_write("FALSE 1\r\n");
				continue;
			}
			bool removed_timer = false;
			std::unique_lock li_hold(g_list_lock);
			for (auto pos = g_exec_list.begin(); pos != g_exec_list.end(); ++pos) {
				auto ptimer = &*pos;
				if (t_id == ptimer->t_id) {
					temp_len = sprintf(temp_line, "%d\t0\tCANCEL\n",
								ptimer->t_id);
					g_exec_list.erase(pos);
					removed_timer = true;
					if (HXio_fullwrite(g_list_fd, temp_line, temp_len) < 0)
						fprintf(stderr, "write to timerlist: %s\n", strerror(errno));
					break;
				}
			}
			li_hold.unlock();
			pconnection->sk_write(removed_timer ? "TRUE\r\n" : "FALSE\r\n");
		} else if (0 == strncasecmp(pconnection->line, "ADD ", 4)) {
			pspace = strchr(pconnection->line + 4, ' ');
			if (NULL == pspace) {
				pconnection->sk_write("FALSE 1\r\n");
				continue;
			}
			*pspace++ = '\0';

			int exec_interval = strtol(pconnection->line + 4, nullptr, 0);
			if (exec_interval <= 0 || strlen(pspace) >= COMMAND_LENGTH) {
				pconnection->sk_write("FALSE 2\r\n");
				continue;
			}

			TIMER tmr;
			tmr.t_id = ++g_last_tid;
			tmr.exec_time = exec_interval + time(nullptr);
			try {
				tmr.command = pspace;
			} catch (const std::bad_alloc &) {
				pconnection->sk_write("FALSE 3\r\n");
				continue;
			}

			std::unique_lock li_hold(g_list_lock);
			auto ptimer = put_timer(std::move(tmr));

			temp_len = sprintf(temp_line, "%d\t%lld\t", ptimer->t_id,
			           static_cast<long long>(ptimer->exec_time));
			encode_line(ptimer->command.c_str(), temp_line + temp_len);
			temp_len = strlen(temp_line);
			temp_line[temp_len++] = '\n';
			if (HXio_fullwrite(g_list_fd, temp_line, temp_len) < 0)
				fprintf(stderr, "write to timerlist: %s\n", strerror(errno));
			li_hold.unlock();
			temp_len = sprintf(temp_line, "TRUE %d\r\n", ptimer->t_id);
			pconnection->sk_write(temp_line, temp_len);
		} else if (0 == strcasecmp(pconnection->line, "QUIT")) {
			pconnection->sk_write("BYE\r\n");
			close(pconnection->sockd);
			co_hold.lock();
			g_connection_list.erase(pconnection);
			return X_LOOP;
		} else if (0 == strcasecmp(pconnection->line, "PING")) {
			pconnection->sk_write("TRUE\r\n");
		} else {
			pconnection->sk_write("FALSE\r\n");
		}
	}
}

static void *tmr_thrwork(void *param)
{
	while (tmr_thrwork_1() != X_STOP)
		;
	return nullptr;
}

static BOOL read_mark(CONNECTION_NODE *pconnection)
{
	int i, read_len;

	while (true) {
		struct pollfd pfd = {pconnection->sockd};
		pfd.events = POLLIN_SET;
		if (poll(&pfd, 1, SOCKET_TIMEOUT * 1000) <= 0)
			return FALSE;
		read_len = read(pconnection->sockd, pconnection->buffer +
		pconnection->offset, 1024 - pconnection->offset);
		if (read_len <= 0)
			return FALSE;
		pconnection->offset += read_len;
		for (i=0; i<pconnection->offset-1; i++) {
			if ('\r' == pconnection->buffer[i] &&
				'\n' == pconnection->buffer[i + 1]) {
				memcpy(pconnection->line, pconnection->buffer, i);
				pconnection->line[i] = '\0';
				pconnection->offset -= i + 2;
				memmove(pconnection->buffer, pconnection->buffer + i + 2,
					pconnection->offset);
				return TRUE;
			}
		}
		if (pconnection->offset == 1024)
			return FALSE;
	}
}

static void term_handler(int signo)
{
	g_notify_stop = true;
}

static int parse_line(char *pbuff, const char* cmdline, char** argv)
{
	int string_len;
    char *ptr;                   /* ptr that traverses command line  */
    int argc;                    /* number of args */
	char *last_space;
	char *last_quote = nullptr;

	string_len = strlen(cmdline);
	memcpy(pbuff, cmdline, string_len);
	pbuff[string_len++] = ' ';
	pbuff[string_len] = '\0';
	ptr = pbuff;
    /* Build the argv list */
    argc = 0;
	last_space = pbuff;
    while (*ptr != '\0') {
		/* back slash should be treated as transferred meaning */
		if ((*ptr == '\\' && ptr[1] == '\"') ||
		    (*ptr == '\\' && ptr[1] == '\\')) {
			memmove(ptr, ptr + 1, strlen(ptr + 1) + 1);
			ptr ++;
		}
		if ('\"' == *ptr) {
			if (last_quote == nullptr) {
				last_quote = ptr + 1;
			} else {
				/* ignore "" */
				if (ptr == last_quote) {
					last_quote = nullptr;
					last_space = ptr + 1;
				} else {
					argv[argc] = last_quote;
					*ptr = '\0';
					last_quote = nullptr;
					last_space = ptr + 1;
					argc ++;
					if (argc >= MAXARGS)
						return 0;
				}
			}
		}
		if (*ptr == ' ' && last_quote == nullptr) {
			/* ignore leading spaces */
			if (ptr == last_space) {
				last_space ++;
			} else {
				argv[argc] = last_space;
				*ptr = '\0';
				last_space = ptr + 1;
				argc ++;
				if (argc >= MAXARGS)
					return 0;
			}
		}
		ptr ++;
    }
	/* only one quote is found, error */
	if (last_quote != nullptr)
		argc = 0;
    argv[argc] = NULL;
    return argc;
}

static void encode_line(const char *in, char *out)
{
	int len, i, j;

	len = strlen(in);
	for (i=0, j=0; i<len; i++, j++) {
		if (' ' == in[i] || '\\' == in[i] || '\t' == in[i] || '#' == in[i]) {
			out[j++] = '\\';
		}
		out[j] = in[i];
	}
	out[j] = '\0';
}
