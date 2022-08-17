#pragma once

namespace l15::core {

class Error {
public:
    virtual ~Error() = default;

    virtual const char* what() const = 0;
    virtual const char* details() const {return ""; }
};

class KeyError : public Error {
public:
    ~KeyError() override = default;

    const char* what() const override
    { return "KeyError"; }
};

class WrongKeyError : public KeyError {
public:
    ~WrongKeyError() override = default;

    const char* what() const override
    { return "WrongKeyError"; }
};

class SignatureError : public Error {
public:
    ~SignatureError() override = default;

    const char* what() const override
    { return "SignatureError"; }

};

}