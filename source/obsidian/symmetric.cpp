#include "../include/obsidian/symmetric.hpp"

namespace obsidian::symmetric::aes {

std::string cbc_cipher_name(const KeySize& key_size)
{
    switch(key_size) {
        case KS_128_BIT: return "aes-128-cbc";
        case KS_192_BIT: return "aes-192-cbc";
        case KS_256_BIT: return "aes-256-cbc";
    }
}

}; // namespace obsidian::symmetric::aes
