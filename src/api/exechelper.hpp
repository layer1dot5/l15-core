#pragma once

#include <string>
#include <list>
#include <memory>
#include <vector>

//TODO: Move to tools folder after migrating API to JSON RPC

namespace l15 {

class NoOutputException : public std::exception {

};

class ExecHelper {
    std::string m_command;
    std::vector<std::string> m_args;
    std::string m_out;
    int m_exitcode;
public:
    explicit ExecHelper(const std::string& command, bool autorun = true);
    ~ExecHelper() = default;
    std::vector<std::string>& Arguments()
    {
        return m_args;
    }

    const std::string& Run()
    {
        RunInternal();
        return m_out;
    }
    const std::string& Output() const {
        return m_out;
    }
    int ExitCode() const {
        return m_exitcode;
    }

protected:
    void RunInternal();
};

}
