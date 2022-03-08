#include "exechelper.hpp"

#include <boost/process.hpp>

#include <iostream>
#include <sstream>
#include <limits>

namespace l15 {

namespace pr = boost::process;
namespace fs = boost::filesystem;


ExecHelper::ExecHelper(const char* command, bool autorun) : m_command(command), m_exitcode(std::numeric_limits<int>::min())
{
    if(autorun)
    {
        RunInternal();
    }
}


void ExecHelper::RunInternal() {
    pr::ipstream is;
    std::string line;
    std::ostringstream outstream;
    m_out = std::string();
    m_exitcode = std::numeric_limits<int>::min();

    try
    {
        std::clog << "$" << m_command;
        for(const std::string& arg: m_args)
        {
            std::clog << " " << arg;
        }
        std::clog << std::endl;

        auto path = pr::search_path(m_command);
        if(path.empty()) {
            throw std::runtime_error(std::string("Command not found: ") + m_command);
        }

        pr::child check(path, m_args, pr::std_out > is, pr::std_in < pr::null);
        //pr::child check(path, pr::args = {"--rpcconnect=10.1.10.240", "--rpcport=18334", "--rpcuser=rpcuser", "--rpcpassword=r89869mAMNFiwFDwdrpt24DDf8mbZ", "getblockcount"}, pr::std_out > is, pr::std_in < pr::null);

        unsigned nline = 0;
        while(check.running() && std::getline(is, line) && !line.empty())
        {
            if(nline++) outstream << std::endl;
            outstream << line;
        }
        m_out = outstream.str();

        check.wait();

        m_exitcode = check.exit_code();
    }
    catch(std::runtime_error& e) {
        std::cerr << "Error executing " << m_command << ": <" << e.what() << ">." << std::endl;
        m_exitcode = -1;
    }
    
    if(m_exitcode != 0)
    {
        std::ostringstream buf;
        buf << "Error connecting bitcoin: " << m_exitcode;
        if(!m_out.empty())
            buf << " (" << m_out << ")";
        throw std::runtime_error(buf.str());
    }
    else
    {
        std::clog << ">>" << m_out << "<<" << std::endl;
    }
}

}
