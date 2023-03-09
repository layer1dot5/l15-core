#pragma once

#include <tuple>
#include <memory>
#include <concepts>

namespace cex {

template <typename RES>
class async_result_base
{
protected:
    async_result_base() = default;
public:
    virtual ~async_result_base() = default;
    virtual void operator()(const RES& res) = 0;
    virtual void operator()(RES&& res) = 0;
    virtual void on_error() = 0;
};

template <typename RES>
class async_result_base<RES&>
{
protected:
    async_result_base() = default;
public:
    virtual ~async_result_base() = default;
    virtual void operator()(RES& res) = 0;
    virtual void on_error() = 0;
};


template <>
class async_result_base<void>
{
protected:
    async_result_base() = default;
public:
    virtual ~async_result_base() = default;
    virtual void operator()() = 0;
    virtual void on_error() = 0;
};

template <typename RES, typename SUCCESS_HANDLER, typename ERROR_HANDLER, typename ...ARGS>
class async_result;

template <typename RES, typename SUCCESS_HANDLER, typename ERROR_HANDLER, typename ...ARGS>
class async_result<RES, const SUCCESS_HANDLER&, const ERROR_HANDLER&, ARGS...> : public async_result_base<RES>
{
    SUCCESS_HANDLER m_res;
    ERROR_HANDLER m_err;
    std::tuple<ARGS...> m_args;
public:
    async_result(const SUCCESS_HANDLER& res, const ERROR_HANDLER& err, ARGS&&... args)
        : m_res(res), m_err(err), m_args(std::forward<ARGS>(args)...)
    {}

    async_result(const async_result& other) = default;
    ~async_result() override = default;

    async_result& operator=(const async_result& other) = default;

    void operator()(const RES& res) override
    { std::apply(m_res, std::tuple_cat(std::make_tuple(res), std::move(m_args))); }

    void operator()(RES&& res) override
    { std::apply(m_res, std::tuple_cat(std::make_tuple(std::forward<RES>(res)), std::move(m_args))); }

    void on_error() override
    { std::apply(m_err, std::move(m_args)); }

    const async_result& forward() const
    { return *this; }

    async_result clone() const
    { return async_result(*this); }
};

template <typename RES, typename SUCCESS_HANDLER, typename ERROR_HANDLER, typename ...ARGS>
class async_result<RES&, const SUCCESS_HANDLER&, const ERROR_HANDLER&, ARGS...> : public async_result_base<RES&>
{
    SUCCESS_HANDLER m_res;
    ERROR_HANDLER m_err;
    std::tuple<ARGS...> m_args;
public:
    async_result(const SUCCESS_HANDLER& res, const ERROR_HANDLER& err, ARGS&&... args)
            : m_res(res), m_err(err), m_args(std::forward<ARGS>(args)...)
    {}

    async_result(const async_result& other) = default;
    ~async_result() override = default;

    async_result& operator=(const async_result& other) = default;

    void operator()(RES& res) override
    { std::apply(m_res, std::tuple_cat(std::make_tuple(res), std::move(m_args))); }

    void on_error() override
    { std::apply(m_err, std::move(m_args)); }

    const async_result& forward() const
    { return *this; }

    async_result clone() const
    { return async_result(*this); }
};

template <typename SUCCESS_HANDLER, typename ERROR_HANDLER, typename ...ARGS>
class async_result<void, const SUCCESS_HANDLER&, const ERROR_HANDLER&, ARGS...> : public async_result_base<void>
{
    SUCCESS_HANDLER m_res;
    ERROR_HANDLER m_err;
    std::tuple<ARGS...> m_args;
public:
    async_result(const SUCCESS_HANDLER& res, const ERROR_HANDLER& err, ARGS&&... args)
            : m_res(res), m_err(err), m_args(std::forward<ARGS>(args)...)
    {}

    async_result(const async_result& other) = default;
    ~async_result() override = default;

    async_result& operator=(const async_result& other) = default;

    void operator()() override
    { std::apply(m_res, std::move(m_args)); }

    void on_error() override
    { std::apply(m_err, std::move(m_args)); }

    const async_result& forward() const
    { return *this; }

    async_result clone() const
    { return async_result(*this); }
};


template <typename RES, typename SUCCESS_HANDLER, typename ERROR_HANDLER, typename ...ARGS>
class async_result<RES, SUCCESS_HANDLER&&, ERROR_HANDLER&&, ARGS...> : public async_result_base<RES>
{
    SUCCESS_HANDLER m_res;
    ERROR_HANDLER m_err;
    std::tuple<ARGS...> m_args;
public:
    async_result(SUCCESS_HANDLER&& res, ERROR_HANDLER&& err, ARGS&&... args)
            : m_res(std::move(res)), m_err(std::move(err)), m_args(std::forward<ARGS>(args)...)
    {}

    async_result(async_result&& other) noexcept = default;
    ~async_result() override = default;

    async_result& operator=(async_result&& other) noexcept = default;

    void operator()(const RES& res) override
    { std::apply(m_res, std::tuple_cat(std::make_tuple(res), std::move(m_args))); }

    void operator()(RES&& res) override
    { std::apply(m_res, std::tuple_cat(std::make_tuple(std::forward<RES>(res)), std::move(m_args))); }

    void on_error() override
    { std::apply(m_err, std::move(m_args)); }

    async_result&& forward()
    { return std::move(*this); }
};

template <typename RES, typename SUCCESS_HANDLER, typename ERROR_HANDLER, typename ...ARGS>
class async_result<RES&, SUCCESS_HANDLER&&, ERROR_HANDLER&&, ARGS...> : public async_result_base<RES&>
{
    SUCCESS_HANDLER m_res;
    ERROR_HANDLER m_err;
    std::tuple<ARGS...> m_args;
public:
    async_result(SUCCESS_HANDLER&& res, ERROR_HANDLER&& err, ARGS&&... args)
            : m_res(std::move(res)), m_err(std::move(err)), m_args(std::forward<ARGS>(args)...)
    {}

    async_result(async_result&& other) noexcept = default;
    ~async_result() override = default;

    async_result& operator=(async_result&& other) noexcept = default;

    void operator()(RES& res) override
    { std::apply(m_res, std::tuple_cat(std::make_tuple(res), std::move(m_args))); }

    void on_error() override
    { std::apply(m_err, std::move(m_args)); }

    async_result&& forward()
    { return std::move(*this); }
};


template <typename SUCCESS_HANDLER, typename ERROR_HANDLER, typename ...ARGS>
class async_result<void, SUCCESS_HANDLER&&, ERROR_HANDLER&&, ARGS...> : public async_result_base<void>
{
    SUCCESS_HANDLER m_res;
    ERROR_HANDLER m_err;
    std::tuple<ARGS...> m_args;
public:
    async_result(SUCCESS_HANDLER&& res, ERROR_HANDLER&& err, ARGS&&... args)
            : m_res(std::move(res)), m_err(std::move(err)), m_args(std::forward<ARGS>(args)...)
    {}

    async_result(async_result&& other) noexcept = default;
    ~async_result() override = default;

    async_result& operator=(async_result&& other) noexcept = default;

    void operator()() override
    { std::apply(std::move(m_res), std::move(m_args)); }

    void on_error() override
    { std::apply(m_err, std::move(m_args)); }

    async_result&& forward()
    { return std::move(*this); }

};


template <typename RES>
class shared_async_result : public async_result_base<RES>
{
    std::shared_ptr<async_result_base<RES>> m_handler;
public:

#pragma clang diagnostic push
#pragma ide diagnostic ignored "google-explicit-constructor"
    template <typename SUCCESS_HANDLER, typename ERROR_HANDLER, typename ...ARGS>
    shared_async_result(const async_result<RES, const SUCCESS_HANDLER&, const ERROR_HANDLER&, ARGS...>& res)
        : m_handler(std::make_shared<async_result<RES, const SUCCESS_HANDLER&, const ERROR_HANDLER&, ARGS...>>(res))
    {}

    template <typename SUCCESS_HANDLER, typename ERROR_HANDLER, typename ...ARGS>
    shared_async_result(async_result<RES, SUCCESS_HANDLER&&, ERROR_HANDLER&&, ARGS...>&& res)
        : m_handler(std::make_shared<async_result<RES, SUCCESS_HANDLER&&, ERROR_HANDLER&&, ARGS...>>(move(res)))
    {}
#pragma clang diagnostic pop

    shared_async_result(const shared_async_result& other) : m_handler(other.m_handler) {}
    shared_async_result(shared_async_result&& other) noexcept : m_handler(std::move(other.m_handler)) {}

    ~shared_async_result() override = default;

    shared_async_result& operator=(const shared_async_result& other) = default;
    shared_async_result& operator=(shared_async_result&& other) noexcept = default;

    void operator()(const RES& res) override
    { (*m_handler)(res); }

    void operator()(RES&& res) override
    { (*m_handler)(std::move(res));; }

    void on_error() override
    { m_handler->on_error(); }

    shared_async_result& forward()
    { return *this; }
};

template <typename RES>
class shared_async_result<RES&> : public async_result_base<RES&>
{
    std::shared_ptr<async_result_base<RES&>> m_handler;
public:

#pragma clang diagnostic push
#pragma ide diagnostic ignored "google-explicit-constructor"
    template <typename SUCCESS_HANDLER, typename ERROR_HANDLER, typename ...ARGS>
    shared_async_result(const async_result<RES&, const SUCCESS_HANDLER&, const ERROR_HANDLER&, ARGS...>& res)
            : m_handler(std::make_shared<async_result<RES&, const SUCCESS_HANDLER&, const ERROR_HANDLER&, ARGS...>>(res))
    {}

    template <typename SUCCESS_HANDLER, typename ERROR_HANDLER, typename ...ARGS>
    shared_async_result(async_result<RES&, SUCCESS_HANDLER&&, ERROR_HANDLER&&, ARGS...>&& res)
            : m_handler(std::make_shared<async_result<RES&, SUCCESS_HANDLER&&, ERROR_HANDLER&&, ARGS...>>(move(res)))
    {}
#pragma clang diagnostic pop

    shared_async_result(const shared_async_result& other) : m_handler(other.m_handler) {}
    shared_async_result(shared_async_result&& other) noexcept : m_handler(std::move(other.m_handler)) {}

    ~shared_async_result() override = default;

    shared_async_result& operator=(const shared_async_result& other) = default;
    shared_async_result& operator=(shared_async_result&& other) noexcept = default;

    void operator()(RES& res) override
    { (*m_handler)(res); }

    void on_error() override
    { m_handler->on_error(); }

    shared_async_result& forward()
    { return *this; }
};

template <>
class shared_async_result<void> : public async_result_base<void>
{
    std::shared_ptr<async_result_base<void>> m_handler;
public:

#pragma clang diagnostic push
#pragma ide diagnostic ignored "google-explicit-constructor"
    template <typename SUCCESS_HANDLER, typename ERROR_HANDLER, typename ...ARGS>
    shared_async_result(const async_result<void, const SUCCESS_HANDLER&, const ERROR_HANDLER&, ARGS...>& res)
            : m_handler(std::make_shared<async_result<void, const SUCCESS_HANDLER&, const ERROR_HANDLER&, ARGS...>>(res))
    {}

    template <typename SUCCESS_HANDLER, typename ERROR_HANDLER, typename ...ARGS>
    shared_async_result(async_result<void, SUCCESS_HANDLER&&, ERROR_HANDLER&&, ARGS...>&& res)
            : m_handler(std::make_shared<async_result<void, SUCCESS_HANDLER&&, ERROR_HANDLER&&, ARGS...>>(std::move(res)))
    {}
#pragma clang diagnostic pop

    shared_async_result(const shared_async_result& other) : m_handler(other.m_handler) {}
    shared_async_result(shared_async_result&& other) noexcept : m_handler(std::move(other.m_handler)) {}

    ~shared_async_result() override = default;

    shared_async_result& operator=(const shared_async_result& other) = default;
    shared_async_result& operator=(shared_async_result&& other) noexcept = default;

    void operator()() override
    { (*m_handler)(); }

    void on_error() override
    { m_handler->on_error(); }

    shared_async_result& forward()
    { return *this; }
};

template <typename RES, typename SUCCESS_HANDLER, typename ERROR_HANDLER, typename ...ARGS>
async_result<RES, const SUCCESS_HANDLER&, const ERROR_HANDLER&, ARGS...> make_async_result(const SUCCESS_HANDLER& on_success, const ERROR_HANDLER& on_error, ARGS&& ... args)
{
    return async_result<RES, const SUCCESS_HANDLER&, const ERROR_HANDLER&, ARGS...>(on_success, on_error, std::forward<ARGS>(args)...);
}

template <typename SUCCESS_HANDLER, typename ERROR_HANDLER, typename ...ARGS>
async_result<void, const SUCCESS_HANDLER&, const ERROR_HANDLER&, ARGS...> make_async_result(const SUCCESS_HANDLER& on_success, const ERROR_HANDLER& on_error, ARGS&& ... args)
{
    return async_result<void, const SUCCESS_HANDLER&, const ERROR_HANDLER&, ARGS...>(on_success, on_error, std::forward<ARGS>(args)...);
}

template <typename RES, typename SUCCESS_HANDLER, typename ERROR_HANDLER, typename ...ARGS>
async_result<RES, SUCCESS_HANDLER&&, ERROR_HANDLER&&, ARGS...> make_async_result(SUCCESS_HANDLER&& on_success, ERROR_HANDLER&& on_error, ARGS&& ... args)
{
    return async_result<RES, SUCCESS_HANDLER&&, ERROR_HANDLER&&, ARGS...>(std::move(on_success), std::move(on_error), std::forward<ARGS>(args)...);
}

template <typename SUCCESS_HANDLER, typename ERROR_HANDLER, typename ...ARGS>
async_result<void, SUCCESS_HANDLER&&, ERROR_HANDLER&&, ARGS...> make_async_result(SUCCESS_HANDLER&& on_success, ERROR_HANDLER&& on_error, ARGS&& ... args)
{
    return async_result<void, SUCCESS_HANDLER&&, ERROR_HANDLER&&, ARGS...>(std::move(on_success), std::move(on_error), std::forward<ARGS>(args)...);
}
}