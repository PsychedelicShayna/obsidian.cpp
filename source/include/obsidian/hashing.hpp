#ifndef OBSIDIAN_HASHING_HPP
#define OBSIDIAN_HASHING_HPP

#include <cstdint>
#include <memory>
#include <vector>

#include <openssl/evp.h>
#include <openssl/sha.h>

namespace obsidian::hashing {
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
} // namespace obsidian::hashing

#endif // OBSIDIAN_HASHING_HPP
