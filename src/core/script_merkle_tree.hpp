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
    const TreeBalanceType mTreeType;
    std::vector<CScript> mScripts;
public:
    explicit ScriptMerkleTree(const TreeBalanceType treeType, std::vector<CScript>&& scripts = {}): mTreeType(treeType), mScripts(std::move(scripts)) {}

    std::vector<CScript>& GetScripts() { return mScripts; }
    const std::vector<CScript>& GetScripts() const { return mScripts; }

    uint256 CalculateRoot() const;

    std::vector<uint256> CalculateScriptPath(const CScript& script) const;
};


}