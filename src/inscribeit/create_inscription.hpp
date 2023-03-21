#pragma once

#include <string>
#include <vector>

namespace inscribeit {

class CreateInscription
{
public:
    void AddPrivKey(const std::string&);
    void AddSignature(const std::string& pubkey, const std::string& signature);

    std::vector<std::string> GetTransactions();
    std::vector<std::string> GetSignatures();
};

} // inscribeit

