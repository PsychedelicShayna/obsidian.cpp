#ifndef OBSIDIAN_ASYMMETRIC_ENCRYPTION_HPP
#define OBSIDIAN_ASYMMETRIC_ENCRYPTION_HPP

#include <cstdint>
#include <vector>
#include <memory>
#include <string>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

namespace obsidian::asymmetric::rsa {

enum KeySize { KS_1024_B = 1024, KS_2048_B = 2048, KS_4096_B = 4096 };

std::shared_ptr<EVP_PKEY> generate_keypair(
    const KeySize&  key_size,
    const uint64_t& public_exponent = 65537);

std::vector<uint8_t> encrypt(
    const std::shared_ptr<EVP_PKEY>& public_key,
    const std::vector<uint8_t>&      plaintext,
    const int32_t&                   padding_mode = RSA_PKCS1_OAEP_PADDING);

std::vector<uint8_t> decrypt(
    const std::shared_ptr<EVP_PKEY>& private_key,
    const std::vector<uint8_t>&      ciphertext,
    const int32_t&                   padding_mode = RSA_PKCS1_OAEP_PADDING);

std::shared_ptr<EVP_PKEY> import_public(const std::string& key_pem);
std::shared_ptr<EVP_PKEY> import_private(const std::string& key_pem);

std::string export_public(const std::shared_ptr<EVP_PKEY>& key);
std::string export_private(const std::shared_ptr<EVP_PKEY>& key);

} // namespace obsidian::asymmetric::rsa

#endif // OBSIDIAN_ASYMMETRIC_ENCRYPTION_HPP
