//
// Created by lexis on 22.09.22.
//

#include "generic_service.hpp"

namespace l15::service {


void details::ThreadBody::main_cycle() const noexcept
{
    while (!m_service->m_exit) {
        m_service->m_task_sem.acquire();

        if (m_service->m_exit) {
            break;
        }

        std::unique_ptr<task_base> task;

        {
            std::lock_guard<std::mutex> task_que_lock(m_service->m_task_que_mutex);

            if (m_service->m_task_que.empty()) {
                if (m_service->m_exit) {
                    break;
                }

                continue;
            }

            task = move(m_service->m_task_que.front());
            m_service->m_task_que.pop_front();
        }

        (*task)();
    }
}


void GenericService::ServeInternal(std::unique_ptr<details::task_base>&& task)
{
    if (m_exit) {
        throw ServiceAlreadyStoppedError();
    }

    {
        std::lock_guard<std::mutex> lock(m_task_que_mutex);
        m_task_que.emplace_back(move(task));
    }
    m_task_sem.release();
}


GenericService::GenericService(size_t thread_count)
: m_exit(false), m_threads(thread_count), m_task_sem(0)
{
    for(details::ThreadBody& body: m_threads) {
        body.m_service = this;
        body.m_thread = std::thread([&body](){ body.main_cycle();} );
    }
}

GenericService::~GenericService()
{
    m_exit = true;
    m_task_sem.release(static_cast<ptrdiff_t>(m_threads.size()));
    std::for_each(m_threads.begin(), m_threads.end(), [](auto& tb) { tb.m_thread.join(); });
}


}// l15

