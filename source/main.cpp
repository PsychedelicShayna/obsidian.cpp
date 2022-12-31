#include <string>
#include <vector>
#include <array>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <random>

#include "obsidian.hpp"
using namespace obsidian;
using namespace obsidian::symmetric;
using namespace obsidian::asymmetric;

int main()
{
    std::vector<uint8_t> random_input = random::bytes(32);
    std::vector<uint8_t> random_key   = random::bytes(32);
    std::vector<uint8_t> random_iv    = random::bytes(16);

    std::array<uint8_t, 16> key_128;
    std::array<uint8_t, 24> key_192;
    std::array<uint8_t, 32> key_256;

    std::array<uint8_t, AES_BLOCK_SIZE> iv;

    std::copy_n(random_key.begin(), key_128.size(), key_128.begin());
    std::copy_n(random_key.begin(), key_192.size(), key_192.begin());
    std::copy_n(random_key.begin(), key_256.size(), key_256.begin());
    std::copy_n(random_iv.begin(), iv.size(), iv.begin());

    std::cout << "Random Input : " << encoding::b16_encode(random_input)
              << "\n";

    std::cout << "Random Key   : " << encoding::b16_encode(random_key) << "\n";

    std::cout << "Random IV    : " << encoding::b16_encode(random_iv) << "\n\n";

    std::cout << "Performing encrypt_cbc_raw test...\n";

    const auto& encrypted_256 =
        aes::encrypt_cbc_raw<aes::KS_256_BIT>(random_input, key_256, iv);

    // std::cout << "Encrypted 256: " << encoding::b16_encode(encrypted_256)
    //           << " -- length " << encrypted_256.size() << "\n";
    //
    // const auto& decrypted_256 =
    //     aes::decrypt_cbc_raw<aes::KS_256_BIT>(encrypted_256, key_256, iv);
    //
    // std::cout << "Decrypted 256: " << encoding::b16_encode(decrypted_256)
    //           << " -- length " << decrypted_256.size() << "\n\n";
    //
    // const auto& encrypted_ez_256 =
    //     aes::encrypt_cbc_scrypt<aes::KS_256_BIT>(random_input, random_key);
    //
    // std::cout << "Encrypted 256 Easy: "
    //           << encoding::b16_encode(encrypted_ez_256) << " -- length "
    //           << encrypted_ez_256.size() << "\n";
    //
    // const auto& decrypted_ez_256 =
    //     aes::decrypt_cbc_scrypt<aes::KS_256_BIT>(encrypted_ez_256,
    //     random_key);
    //
    // std::cout << "Decrypted 256 Easy: "
    //           << encoding::b16_encode(decrypted_ez_256) << " -- length "
    //           << decrypted_ez_256.size() << "\n";
    //
    // const auto& random_input_sha256 = hashing::sha256_digest(random_input);
    //
    // std::cout << "Random Input Sha256: "
    //           << encoding::b16_encode(random_input_sha256) << "\n";
    //
    // const std::string& hello_world = "Hello World!";
    //
    // const std::vector<uint8_t> hello_world_b(hello_world.begin(),
    //                                          hello_world.end());
    //
    // std::cout << "\"Hello World!\" Sha256: "
    //           << encoding::b16_encode(hashing::sha256_digest(hello_world_b))
    //           << "\n";
    //
    //
    // const auto& choice = random::pick_from<int>({1, 0, 2}, 100);
    //
    // std::cout << "Random Double: " << std::fixed << random::rf32() << "\n";

    std::cout << "\nReached the end of the main function.\n";

    return 0;
}
