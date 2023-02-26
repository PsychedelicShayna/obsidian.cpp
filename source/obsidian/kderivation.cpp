#include "../include/obsidian/kderivation.hpp"

namespace obsidian::kderivation {

std::vector<uint8_t> scrypt(std::vector<uint8_t> key,
                            std::vector<uint8_t> salt,
                            uint64_t             cost_factor,
                            uint32_t             block_size_factor,
                            uint32_t             parallelization_factor,
                            const size_t&        desired_key_length)

{
    std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)> key_derivation_function(
        EVP_KDF_fetch(nullptr, "SCRYPT", nullptr), &EVP_KDF_free);

    std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)>
        key_derivation_context(EVP_KDF_CTX_new(key_derivation_function.get()),
                               &EVP_KDF_CTX_free);

    const std::vector<OSSL_PARAM>& parameters {
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_PASSWORD, key.data(), key.size()),

        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT, salt.data(), key.size()),

        OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N, &cost_factor),

        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_R,
                                    &block_size_factor),

        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_P,
                                    &parallelization_factor),

        OSSL_PARAM_construct_end()};

    std::vector<uint8_t> derived_key(desired_key_length, '\0');

    EVP_KDF_derive(key_derivation_context.get(),
                   derived_key.data(),
                   derived_key.size(),
                   parameters.data());

    return derived_key;
}

std::vector<uint8_t> scrypt_easy(const std::vector<uint8_t>& input)
{
    return scrypt(input, obsidian::random::bytes(256), 1024, 8, 4, 64);
}

}; // namespace obsidian::kderivation
