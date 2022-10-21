#pragma once

#include <functional>
#include <future>
#include <list>
#include <thread>
#include <mutex>
#include <atomic>
#include <semaphore>
#include <algorithm>
#include <execution>
#include <memory>


#include "common.hpp"
#include "common_error.hpp"

namespace l15::service {

class IllegalServiceParameterError : public Error
{
    std::string m_details;
public:
    explicit IllegalServiceParameterError(std::string&& details) noexcept : m_details(move(details)) {}
    IllegalServiceParameterError(IllegalServiceParameterError&& another) noexcept : m_details(move(another.m_details)) {}

    const char* what() const override
    { return "IllegalServiceParameterError"; }

    const char* details() const override
    { return m_details.c_str(); }
};

class ServiceAlreadyStoppedError : public Error
{
public:
    const char* what() const override
    { return "ServiceAlreadyStoppedError"; }

};

class GenericService;

namespace details {

struct ThreadBody
{
    GenericService* m_service;
    std::thread m_thread;

    void main_cycle() const noexcept;
};

class task_base {
public:
    virtual ~task_base() = default;
    virtual void operator()() noexcept = 0;
};


template<typename Callable, typename... Args>
class task : public task_base {
    Callable m_action;
    std::tuple<Args...> m_args;
public:
    static_assert(std::is_invocable_v<Callable, Args&&...>);

    explicit task(Callable action, Args&&... args) : m_action(move(action)), m_args(std::forward<Args>(args)...) {}

    void operator()() noexcept override
    { std::apply(m_action, move(m_args)); }
};

}

class GenericService
{
    friend class details::ThreadBody;

    std::atomic<bool> m_exit;
    std::vector<details::ThreadBody> m_threads;
    std::list<std::unique_ptr<details::task_base>> m_task_que;
    std::mutex m_task_que_mutex;
    std::counting_semaphore<> m_task_sem;

    void ServeInternal(std::unique_ptr<details::task_base>&& task);

public:
    explicit GenericService(size_t thread_count);
    ~GenericService();

    template <typename Callable, typename... Args>
    void Serve(Callable action, Args&&... args)
    {
        std::unique_ptr<details::task<Callable, Args...>> task
            = std::make_unique<details::task<Callable, Args...>>(std::forward<Callable>(action), std::forward<Args>(args)...);

        ServeInternal(move(task));
    }
};

} // l15::signer_service

