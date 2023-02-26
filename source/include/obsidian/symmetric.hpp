#ifndef OBSIDIAN_SYMMETRIC_ENCRYPTION_HPP
#define OBSIDIAN_SYMMETRIC_ENCRYPTION_HPP

#include <memory>
#include <vector>
#include <string>
#include <array>

#include <openssl/evp.h>
#include <openssl/aes.h>

#include "kderivation.hpp"
#include "encoding.hpp"
#include "random.hpp"

namespace obsidian::symmetric::aes {

enum KeySize { KS_128_BIT = 16, KS_192_BIT = 24, KS_256_BIT = 32 };

std::string cbc_cipher_name(const KeySize& key_size);

template<KeySize S>
std::vector<uint8_t> encrypt_cbc_raw(std::vector<uint8_t>                input,
                                     std::array<uint8_t, S>              key,
                                     std::array<uint8_t, AES_BLOCK_SIZE> iv)
{
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(
        EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);

    const std::string& cipher_name = cbc_cipher_name(S);

    std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)> cipher(
        EVP_CIPHER_fetch(nullptr, cipher_name.c_str(), nullptr),
        &EVP_CIPHER_free);

    std::vector<uint8_t> output(input.size(), '\0');
    int32_t              bytes_written = output.size();

    EVP_CIPHER_CTX_set_padding(context.get(), 0);

    EVP_EncryptInit_ex(
        context.get(), cipher.get(), nullptr, key.data(), iv.data());

    EVP_EncryptUpdate(context.get(),
                      output.data(),
                      &bytes_written,
                      input.data(),
                      input.size());

    EVP_EncryptFinal_ex(context.get(), output.data(), &bytes_written);

    return output;
}

template<KeySize KS>
std::vector<uint8_t> decrypt_cbc_raw(std::vector<uint8_t>                input,
                                     std::array<uint8_t, KS>             key,
                                     std::array<uint8_t, AES_BLOCK_SIZE> iv)
{
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(
        EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);

    const std::string& cipher_name = cbc_cipher_name(KS);

    std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)> cipher(
        EVP_CIPHER_fetch(nullptr, cipher_name.c_str(), nullptr),
        &EVP_CIPHER_free);

    std::vector<uint8_t> output(input.size(), '\0');
    int32_t              bytes_written = output.size();

    EVP_CIPHER_CTX_set_padding(context.get(), 0);

    EVP_DecryptInit_ex(
        context.get(), cipher.get(), nullptr, key.data(), iv.data());

    EVP_DecryptUpdate(context.get(),
                      output.data(),
                      &bytes_written,
                      input.data(),
                      input.size());

    EVP_DecryptFinal_ex(context.get(), output.data(), &bytes_written);
    EVP_CIPHER_CTX_free(context.get());

    return output;
}

template<KeySize KS>
std::vector<uint8_t> encrypt_cbc_scrypt(std::vector<uint8_t>        input,
                                        const std::vector<uint8_t>& varlen_key)
{
    const auto& random_block = random::bytes(AES_BLOCK_SIZE);
    input.insert(input.begin(), random_block.begin(), random_block.end());
    input = encoding::apply_pkcs7_padding(input, AES_BLOCK_SIZE);

    std::array<uint8_t, AES_BLOCK_SIZE> iv;
    random::write_n(iv.data(), iv.size());

    std::array<uint8_t, KS> key;

    const auto& scrypt_salt = random::bytes(32);
    const auto& derived_key =
        kderivation::scrypt(varlen_key, scrypt_salt, 1024, 8, 4, KS);

    std::copy_n(derived_key.begin(), key.size(), key.begin());

    auto encrypted = encrypt_cbc_raw<KS>(input, key, iv);

    encrypted.insert(encrypted.begin(), scrypt_salt.begin(), scrypt_salt.end());

    return encrypted;
}

template<KeySize KS>
std::vector<uint8_t> decrypt_cbc_scrypt(std::vector<uint8_t>        input,
                                        const std::vector<uint8_t>& varlen_key)
{
    std::vector<uint8_t> scrypt_salt(32, '\0');
    std::copy_n(input.begin(), 32, scrypt_salt.begin());
    input.erase(input.begin(), input.begin() + 32);

    std::array<uint8_t, AES_BLOCK_SIZE> empty_iv;
    std::fill(empty_iv.begin(), empty_iv.end(), '\0');

    std::array<uint8_t, KS> key;

    const auto& derived_key =
        kderivation::scrypt(varlen_key, scrypt_salt, 1024, 8, 4, KS);

    std::copy_n(derived_key.begin(), key.size(), key.begin());

    auto decrypted = decrypt_cbc_raw<KS>(input, key, empty_iv);
    decrypted      = encoding::strip_pkcs7_padding(decrypted);
    decrypted.erase(decrypted.begin(), decrypted.begin() + AES_BLOCK_SIZE);

    return decrypted;
}

} // namespace obsidian::symmetric::aes

#endif
