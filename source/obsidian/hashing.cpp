#include "../include/obsidian/hashing.hpp"

namespace obsidian::hashing {

std::vector<uint8_t> (*sha1_digest)(const std::vector<uint8_t>&) =
    generic_digest<EVP_sha1>;

std::vector<uint8_t> (*sha224_digest)(const std::vector<uint8_t>&) =
    generic_digest<EVP_sha224>;

std::vector<uint8_t> (*sha256_digest)(const std::vector<uint8_t>&) =
    generic_digest<EVP_sha256>;

std::vector<uint8_t> (*sha384_digest)(const std::vector<uint8_t>&) =
    generic_digest<EVP_sha384>;

std::vector<uint8_t> (*sha512_digest)(const std::vector<uint8_t>&) =
    generic_digest<EVP_sha512>;

} // namespace obsidian::hashing



