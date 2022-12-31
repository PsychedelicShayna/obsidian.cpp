#ifndef CRYPTO_HXX
#define CRYPTO_HXX

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <random>
#include <sstream>
#include <variant>
#include <optional>
#include <string>
#include <vector>

#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/types.h>
#include <openssl/core_names.h>

namespace obsidian {

namespace encoding {
    std::string          b64_encode(const std::vector<uint8_t>& bytes);
    std::vector<uint8_t> b64_decode(const std::string& b64_string);

    std::string          b16_encode(const std::vector<uint8_t>& bytes);
    std::vector<uint8_t> b16_decode(const std::string& hexstr);

    std::vector<uint8_t> apply_pkcs7_padding(std::vector<uint8_t> bytes,
                                             const uint8_t&       multiple);

    std::vector<uint8_t> strip_pkcs7_padding(std::vector<uint8_t> bytes);
} // namespace encoding

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

namespace random {
    template<typename T>
    T mt19937_urd_from(const T& min, const T& max)
    {
        static std::random_device device;
        static std::mt19937       generator(device());

        std::uniform_real_distribution<T> uniform_distributer(min, max);

        T generated = uniform_distributer(generator);
        return generated;
    }

    extern float (*rf32_from)(const float& from, const float& to);
    extern double (*rf64_from)(const double& from, const double& to);

    extern float (*rf32)();
    extern double (*rf64)();

    template<typename T>
    T mt19937_uid_from(const T& min, const T& max)
    {
        static std::random_device device;
        static std::mt19937       generator(device());

        std::uniform_int_distribution<T> uniform_distributer(min, max);

        T generated = uniform_distributer(generator);
        return generated;
    }

    extern uint8_t (*rui8_from)(const uint8_t& from, const uint8_t& to);
    extern uint16_t (*rui16_from)(const uint16_t& from, const uint16_t& to);
    extern uint32_t (*rui32_from)(const uint32_t& from, const uint32_t& to);
    extern uint64_t (*rui64_from)(const uint64_t& from, const uint64_t& to);

    extern int8_t (*ri8_from)(const int8_t& from, const int8_t& to);
    extern int16_t (*ri16_from)(const int16_t& from, const int16_t& to);
    extern int32_t (*ri32_from)(const int32_t& from, const int32_t& to);
    extern int64_t (*ri64_from)(const int64_t& from, const int64_t& to);

    extern uint8_t (*rui8)();
    extern uint16_t (*rui16)();
    extern uint32_t (*rui32)();
    extern uint64_t (*rui64)();

    extern int8_t (*ri8)();
    extern int16_t (*ri16)();
    extern int32_t (*ri32)();
    extern int64_t (*ri64)();

    void write_n(uint8_t* data, const size_t& size);

    std::vector<uint8_t> bytes(const size_t& size);

    template<typename T>
    std::vector<T> pick_from(const std::vector<T>& set, const size_t& amount)
    {
        std::vector<T> random_selections(amount);

        for(size_t i = 0; i < amount; ++i) {
            const uint64_t& index = rui64_from(0, set.size() - 1);
            random_selections[i]  = set[index];
        }

        return random_selections;
    }

    double get_ms_since_epoch();

} // namespace random

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

namespace hashing {
    template<const EVP_MD* (*F)()>
    std::vector<uint8_t> generic_digest(const std::vector<uint8_t>& input)
    {
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> digest_context(
            EVP_MD_CTX_new(), &EVP_MD_CTX_free);

        EVP_DigestInit_ex(digest_context.get(), F(), nullptr);
        EVP_DigestUpdate(digest_context.get(), input.data(), input.size());

        std::vector<uint8_t> digest(EVP_MD_size(F()), '\0');
        uint32_t             digest_length = digest.size();

        EVP_DigestFinal_ex(digest_context.get(), digest.data(), &digest_length);

        digest.resize(digest_length);
        return digest;
    }

    extern std::vector<uint8_t> (*sha1_digest)(
        const std::vector<uint8_t>& input_data);

    extern std::vector<uint8_t> (*sha224_digest)(
        const std::vector<uint8_t>& input_data);

    extern std::vector<uint8_t> (*sha256_digest)(
        const std::vector<uint8_t>& input_data);

    extern std::vector<uint8_t> (*sha384_digest)(
        const std::vector<uint8_t>& input_data);

    extern std::vector<uint8_t> (*sha512_digest)(
        const std::vector<uint8_t>& input_data);
} // namespace hashing

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

namespace key_derivation {
    std::vector<uint8_t> scrypt(std::vector<uint8_t> key,
                                std::vector<uint8_t> salt,
                                uint64_t             cost_factor,
                                uint32_t             block_size_factor,
                                uint32_t             parallelization_factor,
                                const size_t&        desired_key_length);

    std::vector<uint8_t> scrypt_easy(const std::vector<uint8_t>& input);
}; // namespace key_derivation

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

namespace symmetric {
    namespace aes {
        enum KeySize { KS_128_BIT = 16, KS_192_BIT = 24, KS_256_BIT = 32 };

        std::string cbc_cipher_name(const KeySize& key_size);

        template<KeySize S>
        std::vector<uint8_t> encrypt_cbc_raw(
            std::vector<uint8_t>                input,
            std::array<uint8_t, S>              key,
            std::array<uint8_t, AES_BLOCK_SIZE> iv)
        {
            std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>
                context(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);

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
        std::vector<uint8_t> decrypt_cbc_raw(
            std::vector<uint8_t>                input,
            std::array<uint8_t, KS>             key,
            std::array<uint8_t, AES_BLOCK_SIZE> iv)
        {
            std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>
                context(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);

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
        std::vector<uint8_t> encrypt_cbc_scrypt(
            std::vector<uint8_t>        input,
            const std::vector<uint8_t>& varlen_key)
        {
            const auto& random_block = random::bytes(AES_BLOCK_SIZE);
            input.insert(
                input.begin(), random_block.begin(), random_block.end());
            input = encoding::apply_pkcs7_padding(input, AES_BLOCK_SIZE);

            std::array<uint8_t, AES_BLOCK_SIZE> iv;
            random::write_n(iv.data(), iv.size());

            std::array<uint8_t, KS> key;

            const auto& scrypt_salt = random::bytes(32);
            const auto& derived_key =
                key_derivation::scrypt(varlen_key, scrypt_salt, 1024, 8, 4, KS);

            std::copy_n(derived_key.begin(), key.size(), key.begin());

            auto encrypted = encrypt_cbc_raw<KS>(input, key, iv);

            encrypted.insert(
                encrypted.begin(), scrypt_salt.begin(), scrypt_salt.end());

            return encrypted;
        }

        template<KeySize KS>
        std::vector<uint8_t> decrypt_cbc_scrypt(
            std::vector<uint8_t>        input,
            const std::vector<uint8_t>& varlen_key)
        {
            std::vector<uint8_t> scrypt_salt(32, '\0');
            std::copy_n(input.begin(), 32, scrypt_salt.begin());
            input.erase(input.begin(), input.begin() + 32);

            std::array<uint8_t, AES_BLOCK_SIZE> empty_iv;
            std::fill(empty_iv.begin(), empty_iv.end(), '\0');

            std::array<uint8_t, KS> key;

            const auto& derived_key =
                key_derivation::scrypt(varlen_key, scrypt_salt, 1024, 8, 4, KS);

            std::copy_n(derived_key.begin(), key.size(), key.begin());

            auto decrypted = decrypt_cbc_raw<KS>(input, key, empty_iv);
            decrypted      = encoding::strip_pkcs7_padding(decrypted);
            decrypted.erase(decrypted.begin(),
                            decrypted.begin() + AES_BLOCK_SIZE);

            return decrypted;
        }
    } // namespace aes
} // namespace symmetric

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
namespace asymmetric {
    namespace rsa {
        enum KeySize { KS_1024_B = 1024, KS_2048_B = 2048, KS_4096_B = 4096 };

        std::shared_ptr<EVP_PKEY> generate_keypair(
            const KeySize&  key_size,
            const uint64_t& public_exponent = 65537);

        std::vector<uint8_t> encrypt(
            const std::shared_ptr<EVP_PKEY>& public_key,
            const std::vector<uint8_t>&      plaintext,
            const int32_t& padding_mode = RSA_PKCS1_OAEP_PADDING);

        std::vector<uint8_t> decrypt(
            const std::shared_ptr<EVP_PKEY>& private_key,
            const std::vector<uint8_t>&      ciphertext,
            const int32_t& padding_mode = RSA_PKCS1_OAEP_PADDING);

        std::shared_ptr<EVP_PKEY> import_public(const std::string& key_pem);
        std::shared_ptr<EVP_PKEY> import_private(const std::string& key_pem);

        std::string export_public(const std::shared_ptr<EVP_PKEY>& key);
        std::string export_private(const std::shared_ptr<EVP_PKEY>& key);

    } // namespace rsa
} // namespace asymmetric
} // namespace obsidian

#endif // CRYPTO_HXX
