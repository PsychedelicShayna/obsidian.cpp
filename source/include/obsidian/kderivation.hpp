#ifndef OBSIDIAN_KEY_DERIVATION_HPP
#define OBSIDIAN_KEY_DERIVATION_HPP

#include <cstdint>
#include <memory>
#include <vector>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include "random.hpp"

namespace obsidian::kderivation {

std::vector<uint8_t> scrypt(std::vector<uint8_t> key,
                            std::vector<uint8_t> salt,
                            uint64_t             cost_factor,
                            uint32_t             block_size_factor,
                            uint32_t             parallelization_factor,
                            const size_t&        desired_key_length);

std::vector<uint8_t> scrypt_easy(const std::vector<uint8_t>& input);

}; // namespace obsidian::kderivation

#endif
