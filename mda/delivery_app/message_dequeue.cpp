// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2025 grommunio GmbH
// This file is part of Gromox.
/*
 *  mail queue have three parts, tape, mess, message queue.when a mail
 *  is put into mail queue, first, check whether it is less
 *  than 64K, if it is, get a block (128K) from tape, and write the mail
 *  into this block; or, create a file in mess directory and write the
 *  mail into file. after mail is saved, system will send a message to
 *  message queue to indicate there's a new mail arrived!
 */
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <memory>
#include <mutex>
#include <pthread.h>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <vector>
#include <libHX/endian.h>
#include <libHX/io.h>
#include <libHX/string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/fileio.h>
#include <gromox/process.hpp>
#include <gromox/util.hpp>
#include "delivery.hpp"
#define TOKEN_MESSAGE_QUEUE		1
#define BLOCK_SIZE				64*1024*2
#define SLEEP_INTERVAL			50000

using namespace std::string_literals;
using namespace gromox;

namespace {

struct MSG_BUFF {
	long msg_type;
	int msg_content;
};

}

static std::string g_path, g_path_mess, g_path_save;
static int				g_msg_id;	    /* message queue id */
static size_t			g_message_units;/* allocated message units number */
static size_t			g_max_memory;   /* maximum allocated memory for mess*/
static size_t			g_current_mem;  /*current allocated memory */
static std::unique_ptr<MESSAGE[]> g_message_ptr;
static std::unordered_map<int, MESSAGE *> g_mess_hash;
static std::vector<MESSAGE *> g_free_list, g_used_list;
static std::mutex g_hash_mutex, g_used_mutex, g_free_mutex, g_mess_mutex;
static pthread_t		g_thread_id;
static gromox::atomic_bool g_notify_stop;
static int				g_dequeued_num;

static BOOL message_dequeue_check();
static MESSAGE *message_dequeue_get_from_free(int message_option, size_t size);

static void message_dequeue_put_to_free(MESSAGE *pmessage);

static void message_dequeue_put_to_used(MESSAGE *pmessage);
static void message_dequeue_load_from_mess(int mess);
static void message_dequeue_collect_resource();
static void *mdq_thrwork(void *);

/* 
 *	@param
 *		path [in]	path of directory
 *		max_memory	maximum memory system allowed concurrently
 */
void message_dequeue_init(const char *path, size_t max_memory)
{	
	g_path = path;
	g_path_mess = path + "/mess"s;
	g_path_save = path + "/save"s;
	g_max_memory = ((max_memory-1)/(BLOCK_SIZE/2) + 1) * (BLOCK_SIZE/2);
	g_current_mem = 0;
	g_msg_id = -1;
	g_message_ptr.reset();
	g_notify_stop = false;
	g_dequeued_num = 0;
}


/*
 *	check the message queue's parameters is same as the entity in file system
 *	@return
 *		TRUE				OK
 *		FALSE				fail
 */
static BOOL message_dequeue_check()
{
	struct	stat node_stat;

	/* check if the directory exists and is a real directory */
	if (stat(g_path.c_str(), &node_stat) != 0) {
		mlog(LV_ERR, "mdq: cannot find directory %s", g_path.c_str());
		return FALSE;
	}
	if (0 == S_ISDIR(node_stat.st_mode)) {
		mlog(LV_ERR, "mdq: %s is not a directory", g_path.c_str());
		return FALSE;
	}
	/* mess directory is used to save the message larger than BLOCK_SIZE */
	if (stat(g_path_mess.c_str(), &node_stat) != 0) {
		mlog(LV_ERR, "mdq: cannot find directory %s", g_path_mess.c_str());
        return FALSE;
    }
    if (0 == S_ISDIR(node_stat.st_mode)) {
		mlog(LV_ERR, "mdq: %s is not a directory", g_path_mess.c_str());
        return FALSE;
    }
	/* save directory is used to save the message for debugging */
	if (stat(g_path_save.c_str(), &node_stat) != 0) {
		mlog(LV_ERR, "mdq: cannot find directory %s", g_path_save.c_str());
        return FALSE;
    }
    if (0 == S_ISDIR(node_stat.st_mode)) {
		mlog(LV_ERR, "mdq: %s is not a directory", g_path_save.c_str());
        return FALSE;
    }
	return TRUE;
}

static void message_dequeue_collect_resource()
{
	g_message_ptr.reset();
	std::lock_guard lk(g_hash_mutex);
	g_mess_hash.clear();
}

int message_dequeue_run()
{
	if (!message_dequeue_check())
		return -1;
	std::string name;
	try {
		name = g_path + "/token.ipc"s;
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "MDQ-167: ENOMEM");
		return false;
	}
	int fd = open(name.c_str(), O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd >= 0)
		close(fd);
	auto k_msg = ftok(name.c_str(), TOKEN_MESSAGE_QUEUE);
    if (-1 == k_msg) {
		mlog(LV_ERR, "mdq: ftok %s: %s", name.c_str(), strerror(errno));
        return -2;
    }
	/* create the message queue */
	g_msg_id = msgget(k_msg, IPC_CREAT | FMODE_PUBLIC);
	if (-1 == g_msg_id) {
		mlog(LV_ERR, "mdq: msgget: %s", strerror(errno));
		return -6;
	}
	g_message_units = g_max_memory/(BLOCK_SIZE/2);
	g_message_ptr = std::make_unique<MESSAGE[]>(g_message_units);
	g_free_list.reserve(g_message_units);
	g_used_list.reserve(g_message_units);
	/* append rest of message node into free list */
	for (size_t i = 0; i < g_message_units; ++i) {
		g_free_list.push_back(&g_message_ptr[i]);
	}
	auto ret = pthread_create4(&g_thread_id, nullptr, mdq_thrwork, nullptr);
	if (ret != 0) {
		mlog(LV_ERR, "mdq: failed to create message dequeue thread: %s", strerror(ret));
		message_dequeue_collect_resource();
		return -9;
	}
	pthread_setname_np(g_thread_id, "msg_dequeue");
	return 0;
}

/*
 *	get a mail message from mail queue
 *	@return
 *		pointer to mail message, NULL means none message
 */
MESSAGE* message_dequeue_get()
{
	std::unique_lock h(g_used_mutex);
	if (g_used_list.size() == 0)
		return NULL;
	auto msg = g_used_list.front();
	g_used_list.erase(g_used_list.begin());
	return msg;
}

/*
 *	put message back to mail queue
 *	@param
 *		pmessage [in]		pointer to message struct
 */
void message_dequeue_put(MESSAGE *pmessage) try
{
	delete[] pmessage->begin_address;
	pmessage->begin_address = NULL;
	auto name = g_path_mess + "/" + std::to_string(pmessage->message_data);
	if (remove(name.c_str()) < 0 && errno != ENOENT)
		mlog(LV_WARN, "W-1352: remove %s: %s", name.c_str(), strerror(errno));
	std::unique_lock h(g_hash_mutex);
	g_mess_hash.erase(pmessage->message_data);
	h.unlock();
	message_dequeue_put_to_free(pmessage);
	g_dequeued_num ++;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "mdq: MDQ-254");
}

void message_dequeue_stop()
{
	g_notify_stop = true;
	if (!pthread_equal(g_thread_id, {})) {
		pthread_kill(g_thread_id, SIGALRM);
		pthread_join(g_thread_id, NULL);
	}
	message_dequeue_collect_resource();
    g_max_memory = 0;
	g_current_mem  = 0;
    g_msg_id = -1;
	g_notify_stop = true;
}

/*
 *	@param
 *		pmessage [out]			message struct pointer
 *		in_buff [in]			buffer of mail message
 */
static void message_dequeue_retrieve_to_message(MESSAGE *pmessage,
    std::unique_ptr<char[]> &&msgtext)
{
	auto in_buff = msgtext.get();
	pmessage->begin_address = msgtext.release();
	pmessage->mail_begin = deconst(in_buff) + sizeof(size_t);
	memcpy(&pmessage->mail_length, in_buff, sizeof(size_t));
	memcpy(&pmessage->flush_ID, in_buff + sizeof(size_t) + pmessage->mail_length, sizeof(uint32_t));
	memcpy(&pmessage->bound_type, in_buff + sizeof(size_t) + sizeof(uint32_t) + pmessage->mail_length, sizeof(uint32_t));
	pmessage->envelope_from = deconst(in_buff) + sizeof(size_t) + 3*sizeof(uint32_t) + pmessage->mail_length;
	pmessage->envelope_rcpt = pmessage->envelope_from + strlen(pmessage->envelope_from) + 1;
}

/*
 *	get a message node back from free list
 *	@param
 *		message_option			MESSAGE_MESS
 *	@return
 *		message pointer, NULL means fail to get
 */
static MESSAGE *message_dequeue_get_from_free(int message_option, size_t size)
{
	/* at a certain time, number of mess message node is limited */
	if (MESSAGE_MESS == message_option) {
		std::unique_lock h(g_mess_mutex);
		if (g_current_mem + size > g_max_memory) {
			return NULL;
		} else {
			g_current_mem += size;
		}
	}
	std::unique_lock fr_hold(g_free_mutex);
	if (g_free_list.empty()) {
		mlog(LV_DEBUG, "error in %s", __PRETTY_FUNCTION__);
		return NULL;
	}
	auto pmessage = g_free_list.front();
	g_free_list.erase(g_free_list.begin());
	fr_hold.unlock();
	pmessage->message_option = message_option;
	if (MESSAGE_MESS == message_option) {
		pmessage->size = size;
	} else {
		pmessage->size = 0;
	}
	pmessage->begin_address = NULL;
	pmessage->mail_begin = NULL;
	pmessage->mail_length = 0;
	pmessage->envelope_from = pmessage->envelope_rcpt = nullptr;
	return pmessage;
}

/*
 *	put message node back to free list
 *	@param
 *		pmessage [in]		pointer to message struct
 */
static void message_dequeue_put_to_free(MESSAGE *pmessage)
{
	if (MESSAGE_MESS == pmessage->message_option) {
		std::unique_lock h(g_mess_mutex);
		g_current_mem -= pmessage->size;
	}
	std::unique_lock h(g_free_mutex);
	g_free_list.push_back(pmessage);
}

/*
 *	add a message struct into used list
 *	@param
 *		pmessage [in]		pointer to message struct
 */
static void message_dequeue_put_to_used(MESSAGE *pmessage)
{
	std::unique_lock h(g_used_mutex);
	g_used_list.push_back(pmessage);
	h.unlock();
	/* send a signal to threads pool in transporter */
	transporter_wakeup_one_thread();
}

/*
 *	load a mess file into used list, and so threads of other modules can
 *	get message from used list
 *	@param
 *		mess			mess ID
 */
static void message_dequeue_load_from_mess(int mess) try
{
	struct stat node_stat;

	std::unique_lock h(g_hash_mutex);
	auto msg_iter = g_mess_hash.find(mess);
	h.unlock();
	if (msg_iter != g_mess_hash.end())
		return;
	auto name = g_path_mess + "/"s + std::to_string(mess);
	wrapfd fd = open(name.c_str(), O_RDONLY);
	if (fd.get() < 0 || fstat(fd.get(), &node_stat) != 0 ||
	    !S_ISREG(node_stat.st_mode))
		return;
	uint64_t size = ((node_stat.st_size - 1) / (64 * 1024) + 1) * 64 * 1024;
	auto pmessage = message_dequeue_get_from_free(MESSAGE_MESS, size);
	if (NULL == pmessage) {
		return;
	}
	pmessage->message_data = mess;
	std::unique_ptr<char[]> ptr;
	try {
		ptr = std::make_unique<char[]>(size + 1);
	} catch (const std::bad_alloc &) {
		message_dequeue_put_to_free(pmessage);
	        return;
	}
	auto rdret = read(fd.get(), ptr.get(), node_stat.st_size);
	if (rdret < 0 || rdret != node_stat.st_size) {
		message_dequeue_put_to_free(pmessage);
        return;
	}
	ptr[rdret] = '\0';
	/* check if it is an incomplete message */
	if (le64p_to_cpu(ptr.get()) == 0) {
		message_dequeue_put_to_free(pmessage);
		return;	
	}
	message_dequeue_retrieve_to_message(pmessage, std::move(ptr));
	message_dequeue_put_to_used(pmessage);
	h.lock();
	if (g_mess_hash.size() >= 2 * g_message_units + 1)
		mlog(LV_ERR, "E-2043: Too many messages loaded (%zu;"
		        " derived from delivery.cfg:dequeue_maximum_mem)\n",
		        2 * g_message_units);
	else
		g_mess_hash.emplace(mess, pmessage);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1940: ENOMEM");
	return;
}

static void *mdq_thrwork(void *arg)
{
	MSG_BUFF msg;
    DIR *dirp;
    struct dirent *direntp;

	while ((dirp = opendir(g_path_mess.c_str())) == nullptr) {
		mlog(LV_ERR, "mdq: failed to open directory %s: %s",
		       g_path_mess.c_str(), strerror(errno));
        sleep(1);
    }

	while (!g_notify_stop) {
		if (msgrcv(g_msg_id, &msg, sizeof(uint32_t), 0, IPC_NOWAIT) != -1) {
			switch(msg.msg_type) {
			case MESSAGE_MESS:
				message_dequeue_load_from_mess(msg.msg_content);
				break;
			default:
				mlog(LV_ERR, "mdq: unknown message queue type %ld, "
					"should be MESSAGE_MESS", msg.msg_type);
			}
			continue;
		}
		usleep(SLEEP_INTERVAL);
		if (g_free_list.size() != g_message_units)
			continue;
		/* clean up mess */
		seekdir(dirp, 0);
		while ((direntp = readdir(dirp)) != NULL) {
        	if (0 == strcmp(direntp->d_name, ".") ||
				0 == strcmp(direntp->d_name, "..")) {
				continue;
			}
			if (g_current_mem == g_max_memory) {
				break;
			}
			std::string file_name;
			try {
				file_name = g_path_mess + "/" + direntp->d_name;
			} catch (const std::bad_alloc &) {
				continue;
			}
			auto mess_fd = open(file_name.c_str(), O_RDONLY);
			if (-1 == mess_fd) {
				continue;
			}
			uint64_t size;
			ssize_t len = read(mess_fd, &size, sizeof(size));
			close(mess_fd);
			if (len < 0 || len != sizeof(size) || size == 0)
				continue;
			message_dequeue_load_from_mess(strtol(direntp->d_name, nullptr, 0));
		}
	}
	closedir(dirp);
	return NULL;
}

int message_dequeue_get_param(int param)
{
	if (param != MESSAGE_DEQUEUE_HOLDING)
		return 0;
	std::lock_guard lk(g_used_mutex);
	return g_used_list.size();
}

/*
 *	for debugging when fail to retrieve message into mail object
 *	@param
 *		pmessage [in]			message object
 */
errno_t message_dequeue_save(MESSAGE *pmessage)
{
	std::string new_file, old_file;
	char *ptr;
	
	try {
		new_file = g_path_save + "/" + std::to_string(time(nullptr)) + "." + std::to_string(pmessage->flush_ID);
		old_file = g_path_mess + "/" + std::to_string(pmessage->message_data);
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "MDQ-536: ENOMEM");
		return ENOMEM;
	}
	if (MESSAGE_MESS == pmessage->message_option) {
		if (link(old_file.c_str(), new_file.c_str()) != 0)
			return errno;
		return 0;
	}
	int fd = open(new_file.c_str(), O_WRONLY | O_CREAT | O_TRUNC, FMODE_PRIVATE);
	if (fd < 0) {
		int se = errno;
		mlog(LV_ERR, "mdq: opening %s for write: %s",
		       new_file.c_str(), strerror(se));
		return errno = se;
	}
	auto z = pmessage->mail_length + 4 * sizeof(uint32_t);
	if (HXio_fullwrite(fd, pmessage->begin_address, z) < 0)
		return -9999;
	auto len = strlen(pmessage->envelope_from);
	if (HXio_fullwrite(fd, pmessage->envelope_from, len + 1) < 0)
		return -9999;
	ptr = pmessage->envelope_rcpt;
	while ((len = strlen(ptr)) != 0) {
		len++;
		if (HXio_fullwrite(fd, ptr, len) < 0)
			return -9999;
		ptr += len;
	}
	close(fd);
	return 0;
}
