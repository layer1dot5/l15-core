#include "storage_service.hpp"

#include "util/strencodings.h"

namespace l15::storage {


const StorageService::member_commitment_t &StorageService::NextMemberCommitment(const StorageService::member_id_t &member) const
{
    auto member_it = m_members_data.find(member);

    if (member_it != m_members_data.end() && !member_it->second.empty()) {
        return member_it->second.front();
    }

    throw NoDataError(HexStr(member));
}

void StorageService::InvalidateMemberCommitment(const StorageService::member_id_t &member, const StorageService::member_commitment_t& commit)
{
    auto member_it = m_members_data.find(member);

    if (member_it != m_members_data.end() && !member_it->second.empty()) {
        auto it = std::find(member_it->second.begin(), member_it->second.end(), commit);
        if (it != member_it->second.end()) {
            member_it->second.erase(member_it->second.begin(), ++it);
        }
    }


}

}
