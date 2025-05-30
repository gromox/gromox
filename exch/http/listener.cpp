// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/*
 *    listener is a module, which listen a certain port and if a connection is
 *    coming, pass the connection in connection filter module and if the
 *    connection is legal, construct a context to represent the connection and 
 *    throw it into contexts pool, or close the connection
 */
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <string>
#include <unistd.h>
#include <libHX/io.h>
#include <libHX/socket.h>
#include <libHX/string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/contexts_pool.hpp>
#include <gromox/fileio.h>
#include <gromox/process.hpp>
#include <gromox/util.hpp>
#include "http_parser.hpp"
#include "listener.hpp"
#include "resource.hpp"
#include "system_services.hpp"

using namespace gromox;

static void *htls_thrwork(void *);

static unsigned int g_mss_size;
static gromox::atomic_bool g_stop_accept;
static pthread_t g_thr_id;
static int g_listener_sock = -1, g_listener_ssl_sock = -1;
static std::string g_listener_addr;
static uint16_t g_listener_port, g_listener_ssl_port;
static pthread_t g_ssl_thr_id;

void listener_init(const char *addr, uint16_t port, uint16_t ssl_port,
    unsigned int mss_size)
{
	g_listener_addr = addr;
	g_listener_port = port;
	g_listener_ssl_port = ssl_port;
	g_mss_size = mss_size;
	g_stop_accept = false;
}

/*
 *    @return     
 *         0    success 
 *        -1    fail to create socket for listening
 *        -2    fail to set address for reuse
 *        -3    fail to bind listening socket
 *        -4    fail to listen    
 */
int listener_run()
{
	g_listener_sock = HX_inet_listen(g_listener_addr.c_str(), g_listener_port);
	if (g_listener_sock < 0) {
		mlog(LV_ERR, "listener: failed to create socket [*]:%hu: %s",
		       g_listener_port, strerror(-g_listener_sock));
		return -1;
	}
	gx_reexec_record(g_listener_sock);
	if (g_mss_size > 0 &&
	    setsockopt(g_listener_sock, IPPROTO_TCP, TCP_MAXSEG,
	    &g_mss_size, sizeof(g_mss_size)) < 0)
		return -2;
	
	if (g_listener_ssl_port > 0) {
		g_listener_ssl_sock = HX_inet_listen(g_listener_addr.c_str(), g_listener_ssl_port);
		if (g_listener_ssl_sock < 0) {
			mlog(LV_ERR, "listener: failed to create socket [*]:%hu: %s",
			       g_listener_ssl_port, strerror(-g_listener_ssl_sock));
			return -1;
		}
		gx_reexec_record(g_listener_ssl_sock);
		if (g_mss_size > 0 &&
		    setsockopt(g_listener_ssl_sock, IPPROTO_TCP, TCP_MAXSEG,
		    &g_mss_size, sizeof(g_mss_size)) < 0)
			return -2;
	}

	return 0;
}

int listener_trigger_accept()
{
	auto ret = pthread_create4(&g_thr_id, nullptr, htls_thrwork,
	           reinterpret_cast<void *>(uintptr_t(false)));
	if (ret != 0) {
		mlog(LV_ERR, "listener: failed to create listener thread: %s", strerror(ret));
		return -1;
	}
	pthread_setname_np(g_thr_id, "accept");
	if (g_listener_ssl_port > 0) {
		ret = pthread_create4(&g_ssl_thr_id, nullptr, htls_thrwork,
		      reinterpret_cast<void *>(uintptr_t(true)));
		if (ret != 0) {
			mlog(LV_ERR, "listener: failed to create listener thread: %s", strerror(ret));
			return -2;
		}
		pthread_setname_np(g_ssl_thr_id, "tls_accept");
	}
	return 0;
}

void listener_stop_accept()
{
	g_stop_accept = true;
	if (g_listener_sock >= 0)
		shutdown(g_listener_sock, SHUT_RDWR); /* closed in listener_stop */
	if (!pthread_equal(g_thr_id, {})) {
		pthread_kill(g_thr_id, SIGALRM);
		pthread_join(g_thr_id, NULL);
	}
	if (g_listener_ssl_sock >= 0)
		shutdown(g_listener_ssl_sock, SHUT_RDWR);
	if (!pthread_equal(g_ssl_thr_id, {})) {
		pthread_kill(g_ssl_thr_id, SIGALRM);
		pthread_join(g_ssl_thr_id, NULL);
	}
}

static void *htls_thrwork(void *arg)
{
	bool use_tls = reinterpret_cast<uintptr_t>(arg);
	char buff[1024];
	auto sv_sock = use_tls ? g_listener_ssl_sock : g_listener_sock;
	
	for (;;) {
		auto conn = generic_connection::accept(sv_sock, false, &g_stop_accept);
		if (conn.sockd == -2)
			break;
		else if (conn.sockd < 0)
			continue;
		if (fcntl(conn.sockd, F_SETFL, O_NONBLOCK) < 0)
			mlog(LV_WARN, "W-1408: fcntl: %s", strerror(errno));
		static const int flag = 1;
		if (setsockopt(conn.sockd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0)
			mlog(LV_WARN, "W-1409: setsockopt: %s", strerror(errno));
		auto pcontext = static_cast<HTTP_CONTEXT *>(contexts_pool_get_context(sctx_status::free));
		/* there's no context available in contexts pool, close the connection*/
		if (NULL == pcontext) {
			mlog(LV_NOTICE, "Rejecting connection from [%s]:%hu: "
				"reached %d connections (http.cfg:context_num)",
				conn.client_addr, conn.client_port,
				contexts_pool_get_param(MAX_CONTEXTS_NUM));
			auto len = gx_snprintf(buff, std::size(buff), "HTTP/1.1 503 L-202 Service Unavailable\r\n"
								"Content-Length: 0\r\n"
								"Connection: close\r\n"
								"\r\n");
			if (HXio_fullwrite(conn.sockd, buff, len) < 0)
				mlog(LV_WARN, "W-1984: write: %s", strerror(errno));
			continue;
		}
		pcontext->type = sctx_status::constructing;
		/* pass the client ipaddr into the ipaddr filter */
		std::string reason;
		if (!system_services_judge_addr(conn.client_addr, reason)) {
			auto len = gx_snprintf(buff, std::size(buff), "HTTP/1.1 503 L-216 Service Unavailable\r\n"
								"Content-Length: 0\r\n"
								"Connection: close\r\n"
								"\r\n");
			if (HXio_fullwrite(conn.sockd, buff, len) < 0)
				mlog(LV_WARN, "W-1983: write: %s", strerror(errno));
			mlog(LV_DEBUG, "Connection %s is denied by ipaddr filter: %s",
				conn.client_addr, reason.c_str());
			/* release the context */
			contexts_pool_insert(pcontext, sctx_status::free);
			continue;
		}

		/* construct the context object */
		pcontext->connection = std::move(conn);
		pcontext->sched_stat = use_tls ? hsched_stat::initssl : hsched_stat::rdhead;
		/* 
		valid the context and wake up one thread if there are some threads
		block on the condition variable 
		*/
		pcontext->polling_mask = POLLING_READ;
		contexts_pool_insert(pcontext, sctx_status::polling);
	}
	return nullptr;
}

void listener_stop()
{
	if (g_listener_sock >= 0) {
		close(g_listener_sock);
		g_listener_sock = -1;
	}
	if (g_listener_ssl_sock >= 0) {
		close(g_listener_ssl_sock);
		g_listener_ssl_sock = -1;
	}
}
