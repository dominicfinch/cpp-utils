
#include <iostream>
#include "utils/rsa.h"
#include "utils/base64.h"
#include "utils/hex.h"
#include "utils/file.h"

int main(int argc, char * argv[]) {

    using namespace iar::utils;

    iar::utils::RSA rsa;

    puts("Generating keypair, please wait...");
    rsa.generate_keypair();

    rsa.export_public_key("public_key.pem");
    rsa.export_private_key("private_key.pem");

    std::string encrypted;
    std::string decrypted;
    std::string plaintext;

    std::cout << "Please write an input message to encrypt:\n";
    std::getline(std::cin, plaintext);

    //int padding = RSA_PKCS1_OAEP_PADDING;
    int padding = RSA_NO_PADDING;
    rsa.encrypt(plaintext, encrypted, padding);
    rsa.decrypt(encrypted, decrypted, padding);

    puts("\n");
    //puts(encrypted.c_str());        // Not printable because it is a byte array (rather than a valid ASCII std::string)
    std::string ciphertext;
    std::string hexciphertext;
    Base64::encode(encrypted, ciphertext);      // Base64 encode makes it printable as a string

    puts(ciphertext.c_str());

    puts("\n");
    puts(decrypted.c_str());

    return 0;
}
