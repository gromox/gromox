// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021-2023 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <mutex>
#include <unordered_map>
#include <sqlite3.h>
#include <string>
#include <unistd.h>
#include <gromox/database.h>
#include <gromox/util.hpp>

namespace gromox {

unsigned int gx_sqlite_debug, gx_force_write_txn;

static bool write_statement(const char *q)
{
	return strncasecmp(q, "CREATE", 6) == 0 || strncasecmp(q, "ALTER", 5) == 0 ||
	       strncasecmp(q, "DROP", 4) == 0 || strncasecmp(q, "INSERT", 6) == 0 ||
	       strncasecmp(q, "UPDATE", 6) == 0 || strncasecmp(q, "REPLACE", 7) == 0 ||
	       strncasecmp(q, "DELETE", 6) == 0;
}

xstmt gx_sql_prep(sqlite3 *db, const char *query)
{
	xstmt out;
	if (gx_sqlite_debug >= 1)
		mlog(LV_DEBUG, "> sqlite3_prep(%s, %s)", znul(sqlite3_db_filename(db, nullptr)), query);
	auto state = sqlite3_txn_state(db, "main");
	if (state == SQLITE_TXN_READ && write_statement(query))
		mlog(LV_ERR, "> sqlite3_prep(%s) inside a readonly TXN", query);
	int ret = sqlite3_prepare_v2(db, query, -1, &out.m_ptr, nullptr);
	if (ret != SQLITE_OK)
		mlog(LV_ERR, "sqlite3_prepare_v2(%s) \"%s\": %s (%d)",
			znul(sqlite3_db_filename(db, nullptr)),
		        query, sqlite3_errstr(ret), ret);
	return out;
}

xtransaction &xtransaction::operator=(xtransaction &&o) noexcept
{
	teardown();
	m_db = o.m_db;
	o.m_db = nullptr;
	return *this;
}

static std::unordered_map<std::string, std::string> active_xa;
static std::mutex active_xa_lock;

xtransaction::~xtransaction()
{
	teardown();
}

void xtransaction::teardown()
{
	if (m_db != nullptr) {
		gx_sql_exec(m_db, "ROLLBACK");
		auto fn = sqlite3_db_filename(m_db, nullptr);
		if (fn != nullptr && *fn != '\0') {
			std::unique_lock lk(active_xa_lock);
			active_xa.erase(fn);
		}
	}
}

int xtransaction::commit()
{
	if (m_db == nullptr)
		return SQLITE_OK;
	auto ret = gx_sql_exec(m_db, "COMMIT TRANSACTION");
	if (ret == SQLITE_BUSY)
		mlog(LV_NOTICE, "Something external has a query running "
			"(stop doing that!) on this sqlite db that blocks us "
			"from writing the changes amassed in a transaction.");
	size_t count = 10;
	while (ret == SQLITE_BUSY && count-- > 0) {
		sleep(1);
		ret = gx_sql_exec(m_db, "COMMIT TRANSACTION");
	}
	if (ret == SQLITE_BUSY)
		/*
		 * As most callers have nothing else to do, they themselves
		 * return from their frame, triggering ~xtransaction and a
		 * rollback.
		 */
		return ret;

	auto fn = sqlite3_db_filename(m_db, nullptr);
	if (fn != nullptr && *fn != '\0') {
		std::unique_lock lk(active_xa_lock);
		active_xa.erase(fn);
	}
	m_db = nullptr;
	return ret;
}

xtransaction gx_sql_begin3(const std::string &pos, sqlite3 *db, txn_mode mode)
{
	if (gx_force_write_txn)
		mode = txn_mode::write;
	auto ret = gx_sql_exec(db, mode == txn_mode::write ? "BEGIN IMMEDIATE" : "BEGIN");
	if (ret == SQLITE_OK) {
		auto fn = sqlite3_db_filename(db, nullptr);
		if (fn != nullptr && *fn != '\0') {
			std::unique_lock lk(active_xa_lock);
			active_xa[fn] = pos;
		}
		return xtransaction(db);
	}
	if (ret == SQLITE_BUSY && mode == txn_mode::write) {
		auto fn = sqlite3_db_filename(db, nullptr);
		if (fn == nullptr || *fn == '\0')
			fn = ":memory:";
		auto it = active_xa.find(fn);
		mlog(LV_ERR, "sqlite_busy on %s: write txn held by %s", znul(fn),
			it != active_xa.end() ? it->second.c_str() : "unknown");
	}
	return xtransaction(nullptr);
}

/**
 * @brief      Start savepoint with given name
 *
 * @param      d     Database handle
 * @param      name  Savepoint name
 */
xsavepoint::xsavepoint(sqlite3 *d, const char *name) : m_db(d), m_name(name)
{
	if (gx_sql_exec(m_db, ("SAVEPOINT " + m_name).c_str()) != SQLITE_OK)
		m_db = nullptr;
}

/**
 * @brief      End savepoint
 *
 * Rolls back to the savepoint if still active
 */
xsavepoint::~xsavepoint()
{
	rollback();
}

/**
 * @brief      Release savepoint
 *
 * @return     SQLite return code
 */
int xsavepoint::commit()
{
	if(!m_db)
		return SQLITE_OK;
	int res = gx_sql_exec(m_db, ("RELEASE " + m_name).c_str());
	m_db = nullptr;
	return res;
}

/**
 * @brief      Rollback to savepoint
 *
 * @return     SQLite return code
 */
int xsavepoint::rollback()
{
	if(!m_db)
		return SQLITE_OK;
	int res = gx_sql_exec(m_db, ("ROLLBACK TO " + m_name).c_str());
	m_db = nullptr;
	return res;
}

int gx_sql_exec(sqlite3 *db, const char *query, unsigned int flags)
{
	char *estr = nullptr;
	if (gx_sqlite_debug >= 1)
		mlog(LV_DEBUG, "> sqlite3_exec(%s, %s)", znul(sqlite3_db_filename(db, nullptr)), query);
	auto state = sqlite3_txn_state(db, "main");
	if (state == SQLITE_TXN_READ && write_statement(query))
		mlog(LV_ERR, "> sqlite3_exec(%s) inside a readonly TXN", query);
	auto ret = sqlite3_exec(db, query, nullptr, nullptr, &estr);
	if (ret == SQLITE_OK)
		return ret;
	else if (ret == SQLITE_CONSTRAINT && (flags & SQLEXEC_SILENT_CONSTRAINT))
		;
	else
		mlog(LV_ERR, "sqlite3_exec(%s) \"%s\": %s (%d)",
			znul(sqlite3_db_filename(db, nullptr)), query,
		        estr != nullptr ? estr : sqlite3_errstr(ret), ret);
	sqlite3_free(estr);
	return ret;
}

int gx_sql_step(sqlite3_stmt *stm, unsigned int flags)
{
	auto ret = sqlite3_step(stm);
	char *exp = nullptr;
	if (gx_sqlite_debug >= 1) {
		exp = sqlite3_expanded_sql(stm);
		mlog(LV_DEBUG, "> sqlite3_step(%s)", exp);
	}
	if (ret == SQLITE_OK || ret == SQLITE_ROW || ret == SQLITE_DONE)
		return ret;
	else if (ret == SQLITE_CONSTRAINT && (flags & SQLEXEC_SILENT_CONSTRAINT))
		return ret;
	if (exp == nullptr)
		exp = sqlite3_expanded_sql(stm);
	auto db  = sqlite3_db_handle(stm);
	auto fn  = db != nullptr ? sqlite3_db_filename(db, nullptr) : nullptr;
	auto msg = sqlite3_errmsg(db);
	if (msg == nullptr || *msg == '\0')
		msg = sqlite3_errstr(ret);
	mlog(LV_ERR, "sqlite3_step(%s) \"%s\": %s (%d)", znul(fn), exp != nullptr ?
		exp : sqlite3_sql(stm), znul(msg), ret);
	sqlite3_free(exp);
	return ret;
}

}
