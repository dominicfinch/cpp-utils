
#include "rsa.h"
#include "file.h"
#include "base64.h"
#include <openssl/err.h>

namespace iar { namespace utils {

    RSA::RSA() {

    }

    RSA::~RSA() {
        clear_keypair();
    }

    bool RSA::public_key(std::string& pubkey) {
        bool success = false;

        if(key != nullptr) {
            BIO * bio = BIO_new(BIO_s_mem());
            if(PEM_write_bio_PUBKEY(bio, key) == 1) {
                pubkey.clear();

                unsigned char * data;
                unsigned int nsize = -1;
                if((nsize = BIO_get_mem_data(bio, &data)) > 0) {
                    pubkey = std::string((const char *)data);
                    success = true;
                }
            }
            BIO_free(bio);
        }
        return success;
    }

    bool RSA::private_key(std::string& pkey) {
        bool success = false;

        if(key != nullptr) {
            BIO * bio = BIO_new(BIO_s_mem());
            if(PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr) == 1) {
                pkey.clear();

                unsigned char * data;
                unsigned int nsize = -1;
                if((nsize = BIO_get_mem_data(bio, &data)) > 0) {
                    pkey = std::string((const char *)data);
                    success = true;
                }
            }
            BIO_free(bio);
        }
        return success;
    }

    bool RSA::generate_keypair(unsigned int bitsize) {
        bool success = false;

        if( (bitsize & (bitsize-1)) == 0) {     // Ensures bitsize is power of two
            EVP_PKEY_CTX * ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
            if(!key) {
                if(EVP_PKEY_keygen_init(ctx) > 0) {
                    if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bitsize) > 0) {
                        if(EVP_PKEY_keygen(ctx, &key) > 0) {
                            success = true;
                        }
                    }
                }
            }
            EVP_PKEY_CTX_free(ctx);
        }
        return success;
    }

    void RSA::clear_keypair() {
        if(key) {
            EVP_PKEY_free(key);
            key = nullptr;
        }
    }

    bool RSA::export_public_key(const std::string& fpath) {
        bool success = false;
        std::string pubkey;
        if(public_key(pubkey)) {
            if(writeFileContents(fpath, pubkey)) {
                success = true;
            }
        }
        return success;
    }

    bool RSA::export_private_key(const std::string& fpath) {
        bool success = false;
        std::string privkey;
        if(private_key(privkey)) {
            if(writeFileContents(fpath, privkey)) {
                success = true;
            }
        }
        return success;
    }

    bool RSA::import_private_key(const std::string& fpath) {
        bool success = false;
        if(fileExists(fpath)) {
            BIO * bio = BIO_new(BIO_s_file());
            if(BIO_read_filename(bio, fpath.c_str()) > 0) {
                if(PEM_read_bio_PrivateKey(bio, &key, nullptr, nullptr) != nullptr) {
                    success = true;
                }
            }
            BIO_free(bio);
        }
        return success;
    }

    bool RSA::import_public_key(const std::string& fpath) {
        bool success = false;
        if(fileExists(fpath)) {
            BIO * bio = BIO_new(BIO_s_file());
            if(BIO_read_filename(bio, fpath.c_str()) > 0) {
                if(PEM_read_bio_PUBKEY(bio, &key, nullptr, nullptr) != nullptr) {
                    success = true;
                }
            }
            BIO_free(bio);
        }
        return success;
    }

    bool RSA::encrypt(const std::string& input, std::string& output, int padding) {
        std::vector<uchar> uc_input;
        std::vector<uchar> uc_output;
        for(auto& ch : input)
            uc_input.push_back((uchar)ch);

        // Ensures string is null-terminating
        if(uc_input.back() != '\0')
            uc_input.push_back('\0');

        auto success = encrypt(uc_input, uc_output);
        std::stringstream ss;
        for(auto& ch : uc_output)
            ss << (uchar)ch;
        output = ss.str();
        return success;
    }

    bool RSA::decrypt(const std::string& input, std::string& output, int padding) {
        std::vector<uchar> uc_input;
        std::vector<uchar> uc_output;
        for(auto& ch : input)
            uc_input.push_back((uchar)ch);

        auto success = decrypt(uc_input, uc_output);
        std::stringstream ss;
        for(auto& ch : uc_output)
            ss << (uchar)ch;
        output = ss.str();
        return success;
    }

    bool RSA::encrypt(const std::vector<uchar>& input, std::vector<uchar>& output, int padding) {
        bool success = false;

        if(key != nullptr) {
            output.clear();
            auto keysize = EVP_PKEY_get_size(key);
            auto batch_size = keysize;
            switch(padding) {
                case RSA_PKCS1_PADDING: batch_size = keysize - 11; break;
                case RSA_PKCS1_OAEP_PADDING: batch_size = keysize - 42; break;
            }
            int batch_count = (int)(input.size() / batch_size) + 1;
            auto batch_success_count = 0;

            EVP_PKEY_CTX * enc_ctx = EVP_PKEY_CTX_new(key, nullptr);
            if(EVP_PKEY_encrypt_init(enc_ctx) > 0) {
                if(EVP_PKEY_CTX_set_rsa_padding(enc_ctx, padding) > 0) {
                    size_t outlen;
                    for(int i=0; i<batch_count; i++) {
                        if(EVP_PKEY_encrypt(enc_ctx, nullptr, &outlen, &input[i*batch_size], batch_size) > 0)
                        {
                            int rc; uchar * buffer = new uchar[outlen] { '\0' };
                            if((rc = EVP_PKEY_encrypt(enc_ctx, buffer, &outlen, &input[i*batch_size], batch_size)) > 0)
                            {
                                output.insert(output.end(), buffer, buffer + outlen);
                                batch_success_count++;
                            } else {
                                printf("\nError encrypting output buffer, rc=%d \n", rc);
                                ERR_print_errors_fp(stdout);
                            }
                            delete buffer;
                        }
                    }
                }
            }
            EVP_PKEY_CTX_free(enc_ctx);

            success = (batch_success_count == batch_count);
            if(!success) {
                char err[130];
                ERR_error_string(ERR_get_error(), err);
                fprintf(stderr, "\nError encrypting message: %s\n", err);
            }
        }
        return success;
    }

    bool RSA::decrypt(const std::vector<uchar>& input, std::vector<uchar>& output, int padding) {
        bool success = false;

        if(key != nullptr) {
            output.clear();
            auto keysize = EVP_PKEY_get_size(key);
            auto batch_size = keysize;
            int batch_count = (int)(input.size() / batch_size);
            auto batch_success_count = 0;

            EVP_PKEY_CTX * dec_ctx = EVP_PKEY_CTX_new(key, nullptr);
            if(EVP_PKEY_decrypt_init(dec_ctx) > 0) {
                if(EVP_PKEY_CTX_set_rsa_padding(dec_ctx, padding) > 0) {
                    size_t outlen;
                    for(int i=0; i<batch_count; i++) {
                        if(EVP_PKEY_decrypt(dec_ctx, nullptr, &outlen, &input[i*batch_size], batch_size) > 0)
                        {
                            int rc; uchar * buffer = new uchar[outlen] { '\0' };
                            if((rc = EVP_PKEY_decrypt(dec_ctx, buffer, &outlen, &input[i*batch_size], batch_size)) > 0)
                            {
                                output.insert(output.end(), buffer, buffer + outlen);
                                batch_success_count++;
                            } else {
                                printf("\nError decrypting output buffer, rc=%d \n", rc);
                                ERR_print_errors_fp(stdout);
                            }
                            delete buffer;
                        }
                    }
                }
            }
            EVP_PKEY_CTX_free(dec_ctx);

            success = (batch_success_count == batch_count);
            if(!success) {
                char err[130];
                ERR_error_string(ERR_get_error(), err);
                fprintf(stderr, "\nError decrypting message: %s\n", err);
            }
        }
        return success;
    }

}}
