
#ifndef IAR_UTILS_BASE64_H
#define IAR_UTILS_BASE64_H

#include "common.h"

namespace iar { namespace utils {

    class Base64 {

    private:
        static const std::string base64_chars;
        static std::vector<int> base64_ints;
        static bool _init;

        static inline bool is_base64(uchar c) {
            return (isalnum(c) || (c == '+') || (c == '/'));
        }

    public:
        static bool encode(const std::vector<uchar>& input, std::vector<uchar>& output);
        static bool decode(const std::vector<uchar>& input, std::vector<uchar>& output);

        static bool encode(const std::string& input, std::string& output);
        static bool decode(const std::string& input, std::string& output);
    };

}}

#endif
