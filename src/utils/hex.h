
#ifndef IAR_UTILS_HEX_H
#define IAR_UTILS_HEX_H

#include "common.h"

namespace iar { namespace utils {

    class Hex {
    public:
        //static bool encode(const std::vector<uchar>& input, std::vector<uchar>& output);
        //static bool decode(const std::vector<uchar>& input, std::vector<uchar>& output);

        static bool encode(const std::string& input, std::string& output);
        static bool decode(const std::string& input, std::string& output);
    };
}}


#endif
