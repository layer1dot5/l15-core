#pragma once

#include <unordered_map>
#include <list>
#include <algorithm>

#include "smartinserter.hpp"

#include "common.hpp"
#include "common_error.hpp"

namespace l15::storage {

class NoDataError : public Error
{
    const std::string m_details;
public:
    explicit NoDataError(std::string&& details) : m_details(std::move(details)) {}
    ~NoDataError() override = default;

    const char* what() const override
    { return "NoDataError"; }

    const char* details() const override
    { return m_details.c_str(); }

};

class StorageService {
public:
    typedef bytevector member_id_t;
    typedef std::tuple<bytevector, bytevector> member_commitment_t;

private:
    std::unordered_map<member_id_t, std::list<member_commitment_t>, hash<member_id_t>> m_members_data;

public:
    template<class I>
    void SaveMemberCommitments(const member_id_t& member, I& begin, I&end)
    {
        auto& member_data = m_members_data[member];
        std::transform(begin, end, cex::smartinserter(member_data, member_data.end()));
    }


    const member_commitment_t& NextMemberCommitment(const member_id_t& member) const;
    void InvalidateMemberCommitment(const member_id_t& member, const member_commitment_t& commit);

};

}
