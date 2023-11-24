
#include "hex.h"
#include <sstream>

namespace iar { namespace utils {

    bool Hex::encode(const std::string& input, std::string& output) {
        output.clear();
        std::stringstream ss;
        for(auto& ch : input) {
            ss << std::hex << (int)ch;
        }
        output = ss.str();
        return output.size() != 0;
    }

    bool Hex::decode(const std::string& input, std::string& output) {
        std::stringstream ss;
        if(input.size() % 2 == 0) {     // Every two characters make up 1 ASCII character
            std::string part; char ch;
            for(auto i = 0; i < input.size(); i += 2) {
                part = input.substr(i, 2);
                ch = stoul(part, nullptr, 16);
                ss << ch;
            }
        }
        output = ss.str();
        return output.size() != 0;
    }

}}
