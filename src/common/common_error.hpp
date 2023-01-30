#pragma once

#include <stdexcept>

namespace l15 {

class Error : public std::exception {
    const std::string m_details;
public:
    Error() noexcept = default;
    Error(const Error&) = default;
    Error(Error&&) noexcept = default;
    explicit Error(std::string&& details) noexcept : m_details(move(details)) {}
    ~Error() override = default;

    const char* what() const noexcept override  = 0;
    virtual const char* details() const noexcept { return m_details.c_str(); }
};

class KeyError : public Error {
public:
    ~KeyError() override = default;

    const char* what() const noexcept override
    { return "KeyError"; }
};

class WrongKeyError : public KeyError {
public:
    ~WrongKeyError() override = default;

    const char* what() const noexcept override
    { return "WrongKeyError"; }
};

class SignatureError : public Error {
public:
    explicit SignatureError(std::string&& details) : Error(move(details)) {}
    ~SignatureError() override = default;

    const char* what() const noexcept override
    { return "SignatureError"; }

};

template <typename STREAM>
void print_error(const Error& e, STREAM& out, size_t level = 0);

template <typename STREAM>
void print_error(const std::exception& e, STREAM& out, size_t level = 0);

template <typename E, typename STREAM>
void rethrow_nested_to_print(const E& e, STREAM& out, size_t level) {
    try {
        std::rethrow_if_nested(e);
    }
    catch (const Error &nested) {
        print_error(nested, out, level+1);
    }
    catch (const std::exception &nested) {
        print_error(nested, out, level+1);
    }

}

template <typename STREAM>
void print_error(const Error& e, STREAM& out, size_t level) {
    out << std::string(level, ' ') << e.what() << ": " << e.details() << "\n";
    rethrow_nested_to_print(e, out, level);
}

template <typename STREAM>
void print_error(const std::exception& e, STREAM& out, size_t level) {
    out << e.what() << "\n";
    rethrow_nested_to_print(e, out, level);
}

template <typename STREAM>
void print_error(STREAM& out) noexcept {
    try {
        std::rethrow_exception(std::current_exception());
    }
    catch(const Error& e) {
        print_error(e, out);
    }
    catch(const std::exception& e) {
        print_error(e, out);
    }
}


}