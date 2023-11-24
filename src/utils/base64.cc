
#include "base64.h"
#include <sstream>

namespace iar { namespace utils {

    const std::string Base64::base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<int> Base64::base64_ints = std::vector<int>(256, -1);
    bool Base64::_init = false;

    bool Base64::encode(const std::vector<uchar>& input, std::vector<uchar>& output) {
        output.clear();
        int val = 0, valb = -6;
        for(auto& c : input) {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                output.push_back(base64_chars[(val>>valb)&0x3F]);
                valb -= 6;
            }
        }
        if(valb > -6)
            output.push_back(base64_chars[((val<<8)>>(valb+8))&0x3F]);
        while(output.size()%4)
            output.push_back('=');
        return (output.size() != 0);
    }

    bool Base64::decode(const std::vector<uchar>& input, std::vector<uchar>& output) {
        output.clear();
        if( !_init ) {    // Should only execute once
            for(int i=0; i<base64_chars.size(); i++)
                base64_ints[base64_chars[i]] = i;
            _init = true;
        }

        unsigned int val=0;
        int valb=-8;
        for(auto& c : input) {
            if (base64_ints[c] == -1)
                break;
            val = (val << 6) + base64_ints[c];
            valb += 6;
            if (valb >= 0) {
                output.push_back(char((val>>valb)&0xFF));
                valb -= 8;
            }
        }
        return (output.size() != 0);
    }

    bool Base64::encode(const std::string& input, std::string& output) {
        std::vector<uchar> uc_input;
        std::vector<uchar> uc_output;
        for(auto& ch : input)
            uc_input.push_back(ch);
        auto success = encode(uc_input, uc_output);
        std::stringstream ss;
        for(auto& ch : uc_output)
            ss << (uchar)ch;
        output = ss.str();
        return success;
    }

    bool Base64::decode(const std::string& input, std::string& output) {
        std::vector<uchar> uc_input;
        std::vector<uchar> uc_output;
        for(auto& ch : input)
            uc_input.push_back(ch);
        auto success = decode(uc_input, uc_output);
        std::stringstream ss;
        for(auto& ch : uc_output)
            ss << (uchar)ch;
        output = ss.str();
        return success;
    }

}}
