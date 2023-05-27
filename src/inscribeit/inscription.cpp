
#include "transaction.h"
#include "streams.h"
#include "version.h"


#include "inscription.hpp"
#include "inscription_common.hpp"


namespace l15::inscribeit {

opcodetype GetNextScriptData(const CScript& script, CScript::const_iterator& it, bytevector& data, const std::string errtag) {
    opcodetype opcode;
    if (it < script.end()) {
        if (!script.GetOp(it, opcode, data))
            throw InscriptionFormatError(std::string(errtag));
    }
    else {
        throw InscriptionFormatError(std::string(errtag));
    }

    return opcode;
}

void Inscription::ParseEnvelopeScript(const CScript &script)
{
    size_t i = 0;

    CScript::const_iterator it = script.begin();
    CScript::const_iterator end = script.end();
    opcodetype prev_opcode_2 = OP_INVALIDOPCODE;
    opcodetype prev_opcode = OP_INVALIDOPCODE;
    opcodetype opcode = OP_INVALIDOPCODE;
    bytevector data;
    bool has_ord_envelope = false;
    bool has_ord_parent_envelope = false;

    while (it < end && !has_ord_envelope && !has_ord_parent_envelope) {
        prev_opcode_2 = prev_opcode;
        prev_opcode = opcode;

        if (!script.GetOp(it, opcode, data))
            throw TransactionError("script");

        has_ord_envelope = (prev_opcode_2 == OP_0 &&
            prev_opcode == OP_IF &&
            opcode == ORD_TAG.size() &&
            data == ORD_TAG);

        has_ord_parent_envelope = (prev_opcode_2 == OP_0 &&
            prev_opcode == OP_IF &&
            opcode == ORD_PARENT_TAG.size() &&
            data == ORD_PARENT_TAG);
    }

    bool fetching_content = false;

    while (it < end) {
        opcode = GetNextScriptData(script, it, data, "inscription envelope");
//        if (!script.GetOp(it, opcode, data))
//            throw InscriptionFormatError("inscription envelope");

        if (opcode == CONTENT_TAG) {
            if (!fetching_content && !m_content.empty()) throw InscriptionFormatError("second CONTENT tag");
            fetching_content = true;
        }
        else if (opcode == CONTENT_TYPE_TAG.size() && data == CONTENT_TYPE_TAG) {
            if (!m_content_type.empty()) throw InscriptionFormatError("second CONTENT_TYPE tag");

            GetNextScriptData(script, it, data, "content type");
            m_content_type.assign(data.begin(), data.end());

            fetching_content = false;
        }
        else if (opcode == COLLECTION_ID_TAG.size() && data == COLLECTION_ID_TAG) {
            if (!m_collection_id.empty()) throw InscriptionFormatError("second COLLECTION_ID tag");

            GetNextScriptData(script, it, data, "collection id");

            std::string collection_id;
            collection_id.assign(data.begin(), data.end());
            CheckCollectionId(collection_id);

            m_collection_id = move(collection_id);
            fetching_content = false;
        }
        else if (opcode == OP_ENDIF) {
            break;
        }
        else if (fetching_content) {
            m_content.insert(m_content.end(), data.begin(), data.end());
        }
    }
}

Inscription::Inscription(const std::string &hex_tx)
{
    CDataStream stream(unhex<bytevector>(hex_tx), SER_NETWORK, PROTOCOL_VERSION);

    CMutableTransaction tx;

    try {
        stream >> tx;
    }
    catch (const std::exception& e) {
        std::throw_with_nested(TransactionError("TX parse error"));
    }

    if (tx.vin[0].scriptWitness.stack.size() < 3) throw InscriptionFormatError("no witness script");

    const auto& witness_stack = tx.vin[0].scriptWitness.stack;
    CScript script(witness_stack[witness_stack.size() - 2].begin(), witness_stack[witness_stack.size() - 2].end());

    ParseEnvelopeScript(script);

    if (m_content.empty()) throw InscriptionError("no content");

    if (tx.vin[1].scriptWitness.stack.size() >= 3) {
        const auto &witness_stack = tx.vin[1].scriptWitness.stack;
        CScript script(witness_stack[witness_stack.size() - 2].begin(), witness_stack[witness_stack.size() - 2].end());

        ParseEnvelopeScript(script);
    }

    m_inscription_id = tx.GetHash().GetHex() + "i0";
}


} // inscribeit
