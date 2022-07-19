#pragma once

namespace l15 { namespace core {

class Error {
public:
    virtual ~Error() = default;

    virtual const char* what() const = 0;
    virtual const char* details() const {return ""; }
};

}}