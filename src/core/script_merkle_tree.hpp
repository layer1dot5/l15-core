#pragma once

#include <vector>
#include <string>

#include "script/script.h"
#include "uint256.h"
#include "crypto/sha256.h"


namespace l15 {

class ScriptNotFoundError {
};

extern const CSHA256 TAPSIG_HASH;
extern const CSHA256 TAPLEAF_HASH;
extern const CSHA256 TAPBRANCH_HASH;


uint256 TapLeafHash(const CScript &script);

// TODO: Implement balanced tap-script tree
enum class TreeBalanceType {WEIGHTED /*, BALANCED*/};

class ScriptMerkleTree {
    TreeBalanceType mTreeType;
    std::vector<CScript> mScripts;
public:
    explicit ScriptMerkleTree(const TreeBalanceType treeType, std::vector<CScript>&& scripts = {}): mTreeType(treeType), mScripts(std::move(scripts)) {}
    ScriptMerkleTree(const ScriptMerkleTree& ) = default;
    ScriptMerkleTree(ScriptMerkleTree&& ) noexcept = default;

    ScriptMerkleTree& operator=(const ScriptMerkleTree& ) = default;
    ScriptMerkleTree& operator=(ScriptMerkleTree&& ) noexcept = default;

    std::vector<CScript>& GetScripts() { return mScripts; }
    const std::vector<CScript>& GetScripts() const { return mScripts; }

    uint256 CalculateRoot() const;

    std::vector<uint256> CalculateScriptPath(const CScript& script) const;
};


}