#pragma once

#include <algorithm>
#include <stop_token>
#include <stdexcept>
#include <type_traits>

namespace cex {

template <class ExecPolicy, class It, class F>
void for_each(ExecPolicy&& exec, It first, It last, F f)
{
    std::stop_source stop;
    std::exception_ptr err = nullptr;

    std::for_each(std::forward<ExecPolicy>(exec), move(first), move(last), [&, stop](auto& l){
        if (stop.stop_requested()) return;
        try {
            f(l);
        }
        catch(...) {
            stop.request_stop();
            err = std::current_exception();
        }
    });

    if(err != nullptr) {
        std::rethrow_exception(err);
    }
}


template <class ExecPolicy, class It1, class It2, class F>
void transform(ExecPolicy&& exec, It1 first, It1 last, It2 result, F op)
{
    typedef typename It2::value_type value_type;

    std::stop_source stop;
    std::exception_ptr err = nullptr;

    auto r = std::transform(std::forward<ExecPolicy>(exec), move(first), move(last), move(result), [&, stop](auto& l) {
        if (stop.stop_requested()) return value_type();
        try {
            return op(l);
        }
        catch (...) {
            stop.request_stop();
            err = std::current_exception();
            return value_type();
        }
    });

    if(err != nullptr) {
        std::rethrow_exception(err);
    }
}

}