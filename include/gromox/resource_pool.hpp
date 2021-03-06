// SPDX-License-Identifier: AGPL-3.0-or-later, OR GPL-2.0-or-later WITH licensing exception
// SPDX-FileCopyrightText: 2020 grammm GmbH
// This file is part of Gromox.
#pragma once
#include <atomic>
#include <condition_variable>
#include <list>
#include <mutex>
#include <utility>

namespace gromox {

/*
 * Your Tp should be modeled such that a default-constructed Tp counts as
 * "unset". This makes resource_pool<unique_ptr<X>> work, but
 * resource_pool<int> (file descriptors) not so much.
 */
template<typename Tp> class resource_pool {
	public:
	class token {
		/* automatically return connection back to pool when going out of scope */
		public:
		token(resource_pool &pool, Tp &&r) :
			m_pool(pool), res(std::move(r)) {}
		token(token &&o) :
			m_pool(o.m_pool), res(std::move(o.res)), m_done(o.m_done)
		{
			o.m_done = true;
		}
		~token() { if (!m_done) finish(); }
		void finish() {
			try {
				m_pool.put(std::move(res));
			} catch (...) {
				m_pool.put_slot();
			}
			m_done = true;
			res = Tp();
		}
		protected:
		resource_pool &m_pool;
		public:
		Tp res;
		bool m_done = false;
	};

	token get_wait() {
		std::unique_lock<std::mutex> lk(m_mtx);
		m_cv.wait(lk, [this]() { return m_numslots > 0; });
		--m_numslots;
		Tp c{};
		if (m_list.size() > 0) {
			c = std::move(*m_list.begin());
			m_list.pop_front();
		}
		return {*this, std::move(c)};
	}
	void put_slot() {
		++m_numslots;
		m_cv.notify_one();
	}
	void put(Tp &&x) {
		std::unique_lock<std::mutex> lk(m_mtx);
		m_list.push_back(std::move(x));
		++m_numslots;
		lk.unlock();
		m_cv.notify_one();
	}
	void resize(size_t n) {
		if (m_numslots < n)
			m_numslots = n;
	}
	void clear() { m_list.clear(); }
	size_t size() const { return m_list.size(); }

	private:
	std::atomic<size_t> m_numslots{0};
	std::mutex m_mtx;
	std::condition_variable m_cv;
	std::list<Tp> m_list;
};

}
