#include <iostream>

#include "ossl_cw.hpp"

/*
** This file does not contain anything important or relevant to the wrapper.
** This is simply a test file, used for debugging purposes to quickly write
** and compile code.
 */

int main() {
    std::cout << "Testing AES Encryption..." << std::endl;

    std::vector<uint8_t> aes_random_sequence = ossl::random::byte_vector(AES_BLOCK_SIZE * 4);
    std::vector<uint8_t> aes_random_key = ossl::random::byte_vector(32);

    std::cout << "Random Sequence: " << ossl::encoding::base16_encode(aes_random_sequence) << std::endl;
    std::cout << "Random Key: " << ossl::encoding::base16_encode(aes_random_key) << std::endl;

    std::cout << "encrypt_auto_pad_iv() output (hex)" << std::endl << std::string(100, '-') << std::endl;
    const auto& aes_encrypted_1 = ossl::aes::encrypt_auto_pad_iv<ossl::aes::KS_256_BIT>(aes_random_sequence, aes_random_key);
    std::cout << ossl::encoding::base16_encode(aes_encrypted_1) << std::endl << std::string(100, '-') << std::endl << std::endl;

    std::cout << "encrypt_auto_pad_iv_rand() output (hex)" << std::endl << std::string(100, '-') << std::endl;
    const auto& aes_encrypted_2 = ossl::aes::encrypt_auto_pad_iv_rand<ossl::aes::KS_256_BIT>(aes_random_sequence, aes_random_key);
    std::cout << ossl::encoding::base16_encode(aes_encrypted_2) << std::endl << std::string(100, '-') << std::endl << std::endl;

    std::cout << "decrypt_auto_pad_iv() output (hex)" << std::endl << std::string(100, '-') << std::endl;
    const auto& aes_decrypted_1 = ossl::aes::decrypt_auto_pad_iv<ossl::aes::KS_256_BIT>(aes_encrypted_1, aes_random_key);
    std::cout << ossl::encoding::base16_encode(aes_decrypted_1) << std::endl << std::string(100, '-') << std::endl << std::endl;

    std::cout << "decrypt_auto_pad_iv_rand() output (hex)" << std::endl << std::string(100, '-') << std::endl;
    const auto& aes_decrypted_2 = ossl::aes::decrypt_auto_pad_iv_rand<ossl::aes::KS_256_BIT>(aes_encrypted_2, aes_random_key);
    std::cout << ossl::encoding::base16_encode(aes_decrypted_1) << std::endl << std::string(100, '-') << std::endl << std::endl;

    return 0;
}
