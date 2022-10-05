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

    void main_cycle() const;
};

class task_base {
public:
    virtual ~task_base() = default;
    virtual void run() = 0;
};

template<typename R, typename A>
class task;

template<typename R>
class task<R, std::function<R()>> : public task_base {
    std::promise<R> m_promise;
    std::function<R()> m_action;
public:

    task(std::promise<R>&& p, std::function<R()>&& a) : m_promise(move(p)), m_action(move(a)) {}
    void run() override
    { m_promise.set_value(m_action()); }

    std::future<R> get_future()
    { return m_promise.get_future(); }
};

template<typename R>
class task<R, std::function<void(std::promise<R>&&)>> : public task_base {
    std::promise<R> m_promise;
    std::function<void(std::promise<R>&&)> m_action;
public:

    task(std::promise<R>&& p, std::function<void(std::promise<R>&&)>&& a) : m_promise(move(p)), m_action(move(a)) {}

    void run() override
    { m_action(move(m_promise)); }

    std::future<R> get_future()
    { return m_promise.get_future(); }
};

template<>
class task<void, std::function<void()>> : public task_base {
    std::promise<void> m_promise;
    std::function<void()> m_action;

public:
    task(std::promise<void>&& p, std::function<void()>&& a) : m_promise(move(p)), m_action(move(a)) {}
    void run() override
    {
        m_action();
        m_promise.set_value();
    }

    std::future<void> get_future()
    { return m_promise.get_future(); }
};

template<>
class task<void, std::function<void(std::promise<void>&&)>> : public task_base {
    std::promise<void> m_promise;
    std::function<void(std::promise<void>&&)> m_action;

public:
    task(std::promise<void>&& p, std::function<void(std::promise<void>&&)>&& a) : m_promise(move(p)), m_action(move(a)) {}
    void run() override
    {
        m_action(move(m_promise));
    }

    std::future<void> get_future()
    { return m_promise.get_future(); }
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

    std::future<void> Serve(std::function<void()> action)
    {
        std::unique_ptr<details::task<void, std::function<void()>>> task
            = std::make_unique<details::task<void, std::function<void()>>>(std::promise<void>(), move(action));

        auto res = task->get_future();
        ServeInternal(move(task));
        return res;

    }

    template <class R>
    std::future<R> Serve(std::function<R()> action)
    {
        std::unique_ptr<details::task<R, std::function<R()>>> task
            = std::make_unique<details::task<R, std::function<R()>>>(std::promise<R>(), move(action));

        auto res = task->get_future();
        ServeInternal(move(task));
        return res;
    }

    std::future<void> Serve(std::function<void(std::promise<void>&&)> action)
    {
        std::unique_ptr<details::task<void, std::function<void(std::promise<void>&&)>>> task
            = std::make_unique<details::task<void, std::function<void(std::promise<void>&&)>>>(std::promise<void>(), move(action));

        auto res = task->get_future();
        ServeInternal(move(task));
        return res;

    }

    template <class R>
    std::future<R> Serve(std::function<void(std::promise<R>&&)> action)
    {
        std::unique_ptr<details::task<R, std::function<void(std::promise<R>&&)>>> task
            = std::make_unique<details::task<R, std::function<void(std::promise<R>&&)>>>(std::promise<R>(), move(action));

        auto res = task->get_future();
        ServeInternal(move(task));
        return res;
    }

};

} // l15::signer_service

