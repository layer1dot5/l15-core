#pragma once

#include <exception>
#include <memory.h>

#include "common_error.hpp"


namespace python_binding {

class Exception : public std::exception, public std::enable_shared_from_this<Exception> {
public:
    Exception(std::shared_ptr<const l15::Error> error) : m_error(error) {}

    ~Exception() override = default;

    const char *what() const noexcept override {
        return m_error->what();
    }

    std::shared_ptr<const l15::Error> error() const {
        return m_error;
    };

private:
    std::shared_ptr<const l15::Error> m_error;

};

} // namespace python_binding
