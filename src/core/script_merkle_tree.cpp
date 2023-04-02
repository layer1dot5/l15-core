#include <optional>

#include "script_merkle_tree.hpp"
#include "hash_helper.hpp"
#include "common_error.hpp"


namespace l15 {


const CSHA256 TAPSIG_HASH = PrecalculatedTaggedHash("TapSighash");
const CSHA256 TAPLEAF_HASH = PrecalculatedTaggedHash("TapLeaf");
const CSHA256 TAPBRANCH_HASH = PrecalculatedTaggedHash("TapBranch");

constexpr uint8_t TAPLEAF_VERSION = 0xc0;


uint256 TapBranchHash(const uint256& a, const uint256& b)
{
    HashWriter writer(TAPBRANCH_HASH);
    if (a < b) {
        writer << a << b;
    } else {
        writer << b << a;
    }
    return writer;
}

uint256 TapLeafHash(const CScript &script)
{
    HashWriter writer(TAPLEAF_HASH);
    writer << TAPLEAF_VERSION << script;
    return writer;
}

uint256 ScriptMerkleTree::CalculateRoot() const
{

    auto node_it = GetScripts().crbegin();
    uint256 hash = TapLeafHash(*node_it);

    // Weighted case only so far!!!
    for(++node_it; node_it != GetScripts().crend(); ++node_it)
    {
        uint256 hash2 = TapLeafHash(*node_it);
        hash = TapBranchHash(hash, hash2);
    }

    return hash;
}

std::vector<uint256> ScriptMerkleTree::CalculateScriptPath(const CScript &script) const
{
    std::vector<uint256> res;
    bool path_stage = false;

    std::optional<uint256> hash;// = TapLeafHash(*node_it);

    // Weighted case only so far!!!
    for (auto node_it = GetScripts().crbegin(); node_it != GetScripts().crend(); ++node_it)
    {
        if (path_stage) {
            res.push_back(TapLeafHash(*node_it));
        }
        else if (*node_it == script) {
            path_stage = true;
            if (hash) res.push_back(*hash);
        }
        else if (hash) {
            hash = TapBranchHash(*hash, TapLeafHash(*node_it));
        }
        else {
            hash = TapLeafHash(*node_it);
        }
    }

    if (!path_stage) {
        throw TransactionError("The script was not found at the script tree");
    }

    return res;
}


}