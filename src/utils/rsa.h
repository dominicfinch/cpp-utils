
#ifndef IAR_UTILS_RSA_H
#define IAR_UTILS_RSA_H

#include <openssl/evp.h>
#include <openssl/pem.h>
#include "common.h"

#define XS_RSA_KEY_SIZE     1 << 10                     // 1024
#define S_RSA_KEY_SIZE      XS_RSA_KEY_SIZE << 1        // 2048
#define M_RSA_KEY_SIZE      S_RSA_KEY_SIZE << 1         // 4096
#define L_RSA_KEY_SIZE      M_RSA_KEY_SIZE << 1         // 8192
#define XL_RSA_KEY_SIZE     L_RSA_KEY_SIZE << 1         // 16384
#define XXL_RSA_KEY_SIZE    XL_RSA_KEY_SIZE << 1        // 32768

#define DEFAULT_RSA_KEYSIZE     M_RSA_KEY_SIZE

namespace iar { namespace utils {

    class RSA {
    public:
        RSA();
        ~RSA();

        void clear_keypair();
        bool generate_keypair(unsigned int bitsize=DEFAULT_RSA_KEYSIZE);

        bool public_key(std::string& key);
        bool private_key(std::string& key);

        bool export_public_key(const std::string& fpath);
        bool export_private_key(const std::string& fpath);

        bool import_private_key(const std::string& fpath);
        bool import_public_key(const std::string& fpath);

        bool encrypt(const std::string& input, std::string& output, int padding=RSA_PKCS1_OAEP_PADDING);
        bool decrypt(const std::string& input, std::string& output, int padding= RSA_PKCS1_OAEP_PADDING);

        bool encrypt(const std::vector<uchar>& input, std::vector<uchar>& output, int padding=RSA_PKCS1_OAEP_PADDING);
        bool decrypt(const std::vector<uchar>& input, std::vector<uchar>& output, int padding=RSA_PKCS1_OAEP_PADDING);

        //bool sign(const std::string& content, std::string& signature);
        //bool verify(const std::string& content, std::string& signature);

        //bool sign(const std::vector<uchar>& content, std::vector<uchar>& signature);
        //bool verify(const std::vector<uchar>& content, std::vector<uchar>& signature);

    private:
        EVP_PKEY * key = nullptr;
    };

}}

/*
#ifdef DEFAULT_RSA_KEYSIZE
#undef DEFAULT_RSA_KEYSIZE
#endif
*/

#endif
